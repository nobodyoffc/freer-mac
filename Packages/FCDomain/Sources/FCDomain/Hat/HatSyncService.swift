import Foundation
import FCCore
import FCTransport

/// Moves HAT data between local storage and a FAPI DISK service. Port
/// of `DataSyncManager` from the Android app.
///
/// **The two-HAT cipher model.** Data on DISK is always encrypted, and
/// the encrypted copy gets its own HAT:
///
/// - the **raw HAT** describes the plaintext; its DID is the hash of
///   the original content, and its `cipherIds` point at the encrypted
///   copies;
/// - a **cipher HAT** describes one encrypted copy; its DID is the hash
///   of the *cipher file*, `rawDid` points back at the raw HAT,
///   `kCipher` holds the symmetric key sealed to the owner's pubkey,
///   and `locas` says which DISK service holds it.
///
/// Nothing is trusted on the way back: every download is hashed and
/// compared against the DID it was fetched under, so a server that
/// returns the wrong or tampered bytes is rejected rather than written
/// to disk.
public struct HatSyncService {

    public enum Failure: Error, CustomStringConvertible {
        case hatNotFound(String)
        case noLocalBytes(String)
        case missingPubkey
        case downloadFailed(hatId: String, diagnostics: String)
        case integrityMismatch(expected: String, got: String)
        case underlying(Error)

        public var description: String {
            switch self {
            case .hatNotFound(let id):
                return "HatSync: no HAT with id \(id)"
            case .noLocalBytes(let id):
                return "HatSync: HAT \(id) has no local bytes to upload"
            case .missingPubkey:
                return "HatSync: the live identity has no public key, so the file key cannot be sealed"
            case let .downloadFailed(hatId, diagnostics):
                return "HatSync: could not fetch \(hatId) — \(diagnostics)"
            case let .integrityMismatch(expected, got):
                return "HatSync: content does not match its DID (expected \(expected), got \(got))"
            case .underlying(let e):
                return "HatSync: \(e)"
            }
        }
    }

    /// What an upload produced.
    public struct UploadResult: Sendable {
        /// The raw HAT, with the new cipher id linked in.
        public var rawHat: Hat
        /// The cipher HAT describing the uploaded encrypted copy.
        public var cipherHat: Hat
        public var diskItem: DiskItem
        /// The symmetric key the file was encrypted with.
        ///
        /// Sharing a file over IM means handing this to the recipient
        /// (Android puts it in the message's `Hat.key`), which is why
        /// it is returned rather than kept private — **but it is a
        /// secret**: anyone holding it can decrypt the copy on DISK.
        /// Only attach it to a message the owner meant to share.
        public var symkey: Data
    }

    /// Location prefixes, as `DataSyncManager` writes them.
    public static let fudpLocationPrefix = Hat.fudpLocationPrefix
    public static let sidLocationPrefix = Hat.sidLocationPrefix

    public let disk: DiskService
    public let hats: HatsStore
    public let files: FileVault
    /// The DISK service id used for new locations. A `(sid)` entry is
    /// preferred over a raw `fudp://` URL because it survives the
    /// server changing address — the client re-resolves it.
    public let serviceSid: String?
    /// Fallback location when no sid is known.
    public let serviceUrl: String?

    public init(
        disk: DiskService,
        hats: HatsStore,
        files: FileVault,
        serviceSid: String? = nil,
        serviceUrl: String? = nil
    ) {
        self.disk = disk
        self.hats = hats
        self.files = files
        self.serviceSid = serviceSid
        self.serviceUrl = serviceUrl
    }

    /// The location string new uploads are tagged with.
    public var currentLocation: String {
        if let serviceSid, !serviceSid.isEmpty { return Self.sidLocationPrefix + serviceSid }
        if let serviceUrl, !serviceUrl.isEmpty {
            return serviceUrl.lowercased().hasPrefix(Self.fudpLocationPrefix)
                ? serviceUrl
                : Self.fudpLocationPrefix + serviceUrl
        }
        return Self.fudpLocationPrefix + "unknown"
    }

    // MARK: - upload

    /// Encrypt a HAT's local bytes and store them on DISK, creating the
    /// cipher HAT and linking it to the raw one.
    ///
    /// - parameters:
    ///   - permanent: `disk.carve` (kept forever) vs `disk.put`.
    ///   - ownPubkey: the 33-byte compressed pubkey the file key is
    ///     sealed to — normally the live identity's, so only its holder
    ///     can decrypt later.
    public func upload(
        hatId: String,
        permanent: Bool = false,
        dataLifeDays: Int64? = nil,
        ownPubkey: Data,
        progress: (@Sendable (Int64, Int64) -> Void)? = nil
    ) async throws -> UploadResult {
        guard var rawHat = try hats.hat(id: hatId) else { throw Failure.hatNotFound(hatId) }
        guard ownPubkey.count == 33 else { throw Failure.missingPubkey }
        guard let plaintextURL = try files.localURL(hatId: hatId) else {
            throw Failure.noLocalBytes(hatId)
        }

        // 1. A fresh key per upload: two files never share one, and
        //    re-uploading the same file produces an unrelated cipher.
        let symkey = FileCipher.randomSymkey()

        // 2. Encrypt to a temp file (deleted however we exit).
        let cipherURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("fc-upload-\(UUID().uuidString).cipher")
        defer { try? FileManager.default.removeItem(at: cipherURL) }
        do {
            try FileCipher.encrypt(plaintextAt: plaintextURL, to: cipherURL, symkey: symkey)
        } catch {
            throw Failure.underlying(error)
        }

        // 3. The cipher file's own DID — what DISK stores it under.
        let cipherDid: String
        let cipherSize: Int64
        do {
            cipherDid = try Hash.doubleSha256(fileAt: cipherURL)
                .map { String(format: "%02x", $0) }.joined()
            cipherSize = Int64((try FileManager.default.attributesOfItem(
                atPath: cipherURL.path)[.size] as? NSNumber)?.int64Value ?? 0)
        } catch {
            throw Failure.underlying(error)
        }

        // 4. Seal the key to the owner's pubkey. Without the matching
        //    private key the copy on DISK is inert.
        let kCipher: String
        do {
            kCipher = try AsyOneWayCipher.encrypt(plaintext: symkey, toPubkey: ownPubkey)
        } catch {
            throw Failure.underlying(error)
        }

        // 5. Ship it.
        let item: DiskItem
        if permanent {
            item = try await disk.carve(fileURL: cipherURL, progress: progress)
        } else {
            item = try await disk.put(fileURL: cipherURL, dataLifeDays: dataLifeDays, progress: progress)
        }

        // 6/7. Record the cipher HAT and link it to the raw one.
        let cipherHat = try hats.createCipherHat(
            cipherId: cipherDid,
            rawDid: hatId,
            kCipher: kCipher,
            size: cipherSize,
            locas: [currentLocation]
        )
        rawHat = try hats.addCipherId(cipherDid, toRawId: hatId) ?? rawHat

        return UploadResult(rawHat: rawHat, cipherHat: cipherHat, diskItem: item, symkey: symkey)
    }

    /// Store a HAT's bytes **unencrypted**, for content that is meant to
    /// be world-readable and content-addressed (a team's consensus
    /// document, say). The DISK location is added to the raw HAT
    /// itself; there is no cipher HAT and no key.
    @discardableResult
    public func uploadRaw(
        hatId: String,
        permanent: Bool = false,
        dataLifeDays: Int64? = nil,
        progress: (@Sendable (Int64, Int64) -> Void)? = nil
    ) async throws -> DiskItem {
        guard try hats.hat(id: hatId) != nil else { throw Failure.hatNotFound(hatId) }
        guard let plaintextURL = try files.localURL(hatId: hatId) else {
            throw Failure.noLocalBytes(hatId)
        }
        let item: DiskItem
        if permanent {
            item = try await disk.carve(fileURL: plaintextURL, progress: progress)
        } else {
            item = try await disk.put(fileURL: plaintextURL, dataLifeDays: dataLifeDays, progress: progress)
        }
        try hats.addLoca(currentLocation, toId: hatId)
        return item
    }

    /// Prepare a HAT for sharing over IM: the recipient gets the
    /// plaintext key and the DISK locations of the cipher copies, so
    /// they can fetch and decrypt without any key of their own.
    ///
    /// The returned HAT is what belongs in the message body; it is not
    /// stored, because the local copy has no business carrying a
    /// plaintext key.
    public func shareableHat(from result: UploadResult) throws -> Hat {
        var hat = result.rawHat
        hat.key = result.symkey.map { String(format: "%02x", $0) }.joined()
        for loca in result.cipherHat.locas ?? [] {
            hat.addLoca(loca)
        }
        return hat
    }

    // MARK: - download

    /// Fetch a HAT's bytes into local storage, trying every source the
    /// record offers, and verifying the result against the DID.
    ///
    /// Order mirrors `DataSyncManager.downloadData`:
    ///
    /// 1. **Direct locations** on the raw HAT — for unencrypted,
    ///    content-addressed data. The bytes are hashed before being
    ///    trusted, because a public DISK server is not.
    /// 2. **Plain-key path** — when the HAT carries a `key` (it came
    ///    over IM). Works even though we hold no cipher HAT and no
    ///    private key of the sender's.
    /// 3. **kCipher path** — the owner's own upload: unseal the file
    ///    key from the cipher HAT with `privkey`.
    ///
    /// Every failed attempt is recorded, and the accumulated reasons
    /// travel in the thrown error — a transfer that quietly finds
    /// nothing is otherwise impossible to diagnose.
    @discardableResult
    public func download(
        hatId: String,
        privkey: Data? = nil,
        progress: (@Sendable (Int64) -> Void)? = nil
    ) async throws -> URL {
        guard let rawHat = try hats.hat(id: hatId) else { throw Failure.hatNotFound(hatId) }
        let destination = files.defaultLocalURL(did: hatId)
        try ensureDataDirectory()

        var diagnostics: [String] = []

        // 1. Direct, unencrypted locations.
        if !rawHat.remoteLocas.isEmpty {
            do {
                try await fetchAndVerify(did: hatId, to: destination, progress: progress)
                return try await adopt(hatId: hatId, at: destination)
            } catch {
                diagnostics.append("direct=\(short(error))")
                try? FileManager.default.removeItem(at: destination)
            }
        } else {
            diagnostics.append("rawLocas=none")
        }

        let cipherIds = rawHat.cipherIds ?? []
        if cipherIds.isEmpty {
            throw Failure.downloadFailed(hatId: hatId, diagnostics: diagnostics.joined(separator: "; "))
        }

        for cipherId in cipherIds {
            let cipherHat = try hats.hat(id: cipherId)

            // 2. Plain key: no cipher HAT and no private key needed, so
            //    try it first — it is the path an IM recipient has.
            if let keyHex = rawHat.key, !keyHex.isEmpty {
                do {
                    let symkey = try symkeyFromHex(keyHex)
                    try await fetchCipherAndDecrypt(
                        cipherId: cipherId,
                        symkey: symkey,
                        rawDid: hatId,
                        to: destination,
                        progress: progress
                    )
                    return try await adopt(hatId: hatId, at: destination)
                } catch {
                    diagnostics.append("plainKey[\(brief(cipherId))]=\(short(error))")
                }
            }

            // 3. kCipher: unseal the file key with our private key.
            if let cipherHat, let privkey {
                do {
                    guard cipherHat.rawDid == hatId else {
                        throw Failure.integrityMismatch(
                            expected: hatId, got: cipherHat.rawDid ?? "nil")
                    }
                    guard let kCipher = cipherHat.kCipher, !kCipher.isEmpty else {
                        throw Failure.underlying(DiskService.Failure.emptyResponse(api: "kCipher"))
                    }
                    let symkey = try AsyOneWayCipher.decrypt(cipherString: kCipher, privkey: privkey)
                    guard symkey.count == FileCipher.keyLength else {
                        throw Failure.underlying(FileCipher.Failure.invalidKeyLength(got: symkey.count))
                    }
                    try await fetchCipherAndDecrypt(
                        cipherId: cipherId,
                        symkey: symkey,
                        rawDid: hatId,
                        to: destination,
                        progress: progress
                    )
                    return try await adopt(hatId: hatId, at: destination)
                } catch {
                    diagnostics.append("kCipher[\(brief(cipherId))]=\(short(error))")
                }
            }

            if cipherHat == nil && (rawHat.key ?? "").isEmpty {
                diagnostics.append("noKeyNoCipherHat[\(brief(cipherId))]")
            }
        }

        try? FileManager.default.removeItem(at: destination)
        throw Failure.downloadFailed(hatId: hatId, diagnostics: diagnostics.joined(separator: "; "))
    }

    // MARK: - download helpers

    /// Fetch `did` straight into `destination` and refuse it unless the
    /// bytes hash back to `did`.
    private func fetchAndVerify(
        did: String,
        to destination: URL,
        progress: (@Sendable (Int64) -> Void)?
    ) async throws {
        try await disk.get(did: did, to: destination, progress: progress)
        let got = try hashFile(at: destination)
        guard got == did else {
            try? FileManager.default.removeItem(at: destination)
            throw Failure.integrityMismatch(expected: did, got: got)
        }
    }

    /// Fetch a cipher file, decrypt it with `symkey`, and accept the
    /// plaintext only if it hashes to the raw DID.
    private func fetchCipherAndDecrypt(
        cipherId: String,
        symkey: Data,
        rawDid: String,
        to destination: URL,
        progress: (@Sendable (Int64) -> Void)?
    ) async throws {
        let cipherURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("fc-download-\(UUID().uuidString).cipher")
        defer { try? FileManager.default.removeItem(at: cipherURL) }

        try await disk.get(did: cipherId, to: cipherURL, progress: progress)

        // The cipher file must be the one we asked for. Checking here
        // means a bad server is caught before we spend a decrypt on it.
        let cipherGot = try hashFile(at: cipherURL)
        guard cipherGot == cipherId else {
            throw Failure.integrityMismatch(expected: cipherId, got: cipherGot)
        }

        do {
            try FileCipher.decrypt(cipherAt: cipherURL, to: destination, symkey: symkey)
        } catch {
            try? FileManager.default.removeItem(at: destination)
            throw Failure.underlying(error)
        }

        let plainGot = try hashFile(at: destination)
        guard plainGot == rawDid else {
            try? FileManager.default.removeItem(at: destination)
            throw Failure.integrityMismatch(expected: rawDid, got: plainGot)
        }
    }

    /// Register freshly downloaded bytes as this HAT's app-managed copy.
    private func adopt(hatId: String, at url: URL) async throws -> URL {
        do {
            try files.adoptAppCopy(hatId: hatId, at: url)
        } catch {
            throw Failure.underlying(error)
        }
        return url
    }

    private func ensureDataDirectory() throws {
        do {
            try FileManager.default.createDirectory(
                at: files.dataDirectory, withIntermediateDirectories: true)
        } catch {
            throw Failure.underlying(error)
        }
    }

    private func hashFile(at url: URL) throws -> String {
        do {
            return try Hash.doubleSha256(fileAt: url).map { String(format: "%02x", $0) }.joined()
        } catch {
            throw Failure.underlying(error)
        }
    }

    private func symkeyFromHex(_ hex: String) throws -> Data {
        var out = Data(capacity: hex.utf8.count / 2)
        var index = hex.startIndex
        while index < hex.endIndex, let next = hex.index(index, offsetBy: 2, limitedBy: hex.endIndex) {
            guard let byte = UInt8(hex[index..<next], radix: 16) else { break }
            out.append(byte)
            index = next
        }
        guard out.count == FileCipher.keyLength else {
            throw Failure.underlying(FileCipher.Failure.invalidKeyLength(got: out.count))
        }
        return out
    }

    /// Short forms keep the accumulated diagnostics readable.
    private func brief(_ id: String) -> String { String(id.prefix(8)) }

    private func short(_ error: Error) -> String {
        if let e = error as? Failure { return e.description }
        if let e = error as? DiskService.Failure { return e.description }
        if let e = error as? FileCipher.Failure { return e.description }
        return String(describing: error)
    }
}
