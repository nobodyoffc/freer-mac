import Foundation
import FCCore

/// The bytes behind ``TextRecord/did`` — putting a body where the
/// carve can point at it, and getting one back.
///
/// **Why the body is not on the chain.** FEIP21 has no content field.
/// A published work is catalogued on chain and stored off it, and the
/// only thing tying the two together is `did`. That field is opaque to
/// the indexer, so the convention is this app's to choose, and the
/// choice is the one the rest of the app already runs on: **`did` is
/// the raw DID — hex `sha256x2` of the body — and the bytes go to DISK
/// through the Phase 8.4 stack.**
///
/// The point of hashing rather than naming is that the pointer becomes
/// self-verifying. A location can lie; a hash cannot. Every read below
/// hashes what arrived and refuses it unless it matches the `did` the
/// carve committed to, so a DISK that serves the wrong bytes — or the
/// right bytes for a different work — is caught rather than believed.
///
/// **Public, unencrypted, permanent.** This is ``HatSyncService/uploadRaw(hatId:permanent:dataLifeDays:progress:)``,
/// not the two-HAT cipher flow a shared file uses: a published work is
/// meant to be readable by strangers who hold no key of ours, and it is
/// carved (`disk.carve`) rather than `put`, because a catalogue entry
/// that outlives its body is a dead link with a permanent record.
public struct PublishBody {

    /// A DISK client for somebody else's server. Supplied by the app
    /// shell, which is the only layer that can open connections; nil in
    /// tests and headless callers, where the third read attempt below
    /// simply does not happen.
    public typealias DiskResolver = @Sendable (_ publisherFid: String) async -> DiskService?

    public enum Failure: Error, CustomStringConvertible {
        case emptyBody
        case notUtf8(did: String)
        case unreachable(did: String, diagnostics: String)
        case underlying(Error)

        public var description: String {
            switch self {
            case .emptyBody:
                return "PublishBody: nothing to publish — the body is empty"
            case .notUtf8(let did):
                return "PublishBody: the bytes at \(did) are not UTF-8 text. They hash correctly, so this is the right file for the wrong kind of record."
            case let .unreachable(did, diagnostics):
                return "PublishBody: could not fetch the body at \(did) — \(diagnostics). The record is on chain; its bytes are not on any DISK this identity can reach."
            case .underlying(let e):
                return "PublishBody: \(e)"
            }
        }
    }

    public let files: FileVault
    public let hats: HatsStore
    public let sync: HatSyncService
    public let disk: DiskService
    public let foreignDisk: DiskResolver?

    public init(
        files: FileVault,
        hats: HatsStore,
        sync: HatSyncService,
        disk: DiskService,
        foreignDisk: DiskResolver? = nil
    ) {
        self.files = files
        self.hats = hats
        self.sync = sync
        self.disk = disk
        self.foreignDisk = foreignDisk
    }

    // MARK: - writing

    /// The DID a body *will* have, without storing anything.
    ///
    /// Lets a compose form show the pointer it is about to carve, and
    /// lets a caller notice that a re-publish of unchanged text needs
    /// no upload at all: identical bytes are identical content, and
    /// content-addressing means the second copy is the first one.
    public static func did(for body: String) -> String {
        Hex.encode(Hash.doubleSha256(Data(body.utf8)))
    }

    /// Store `body` and return its DID — what goes in the carve.
    ///
    /// Writes an app-managed copy under the vault's data directory,
    /// registers it as a HAT, and uploads it. Re-storing the same text
    /// is idempotent: the DID is the same, the local copy is already
    /// there, and the upload adds a location to a HAT that already
    /// exists rather than making a second one.
    ///
    /// **The upload is the slow part and the one that can fail.** It is
    /// deliberately done *before* the carve is built, so a publish that
    /// cannot reach a DISK fails while it is still free — carving a
    /// pointer to bytes nobody can fetch costs a fee and produces a
    /// permanent dead link.
    @discardableResult
    public func store(
        _ body: String,
        name: String? = nil,
        progress: (@Sendable (Int64, Int64) -> Void)? = nil
    ) async throws -> String {
        let did = try storeLocally(body, name: name)
        do {
            try await sync.uploadRaw(hatId: did, permanent: true, progress: progress)
        } catch {
            throw Failure.underlying(error)
        }
        return did
    }

    /// Write the body and register it, without uploading — what a
    /// **draft** needs.
    ///
    /// A draft has to remember its text somewhere, and the record has
    /// nowhere to put it: FEIP21 has no content field, so ``TextRecord``
    /// has none either. Keeping the draft's body in the HAT store under
    /// the DID it will eventually be published as means a draft and its
    /// published form are the same bytes in the same place — saving,
    /// reopening and finally publishing never re-derive it — and it
    /// costs nothing until somebody chooses to pay.
    @discardableResult
    public func storeLocally(_ body: String, name: String? = nil) throws -> String {
        guard !body.isEmpty else { throw Failure.emptyBody }
        let data = Data(body.utf8)
        let did = Hex.encode(Hash.doubleSha256(data))
        let url = files.defaultLocalURL(did: did)
        do {
            try FileManager.default.createDirectory(
                at: files.dataDirectory, withIntermediateDirectories: true
            )
            if !FileManager.default.fileExists(atPath: url.path) {
                try data.write(to: url, options: .atomic)
            }
            _ = try files.registerFile(
                at: url,
                name: name ?? "\(String(did.prefix(8))).txt",
                types: ["text/plain"]
            )
        } catch {
            throw Failure.underlying(error)
        }
        return did
    }

    /// Store a **file** as a work's body and return its DID — the
    /// image, sound or video case, where the body is bytes the user
    /// picked rather than text they typed.
    ///
    /// **The original is referenced, not copied.** ``FileVault`` hashes
    /// the file where it lies and registers that path as the HAT's
    /// location, which is the Phase 8.4 decision: importing a 40 MB
    /// photograph costs one hash pass, not a duplicate on disk. The
    /// upload then streams from the user's own file.
    @discardableResult
    public func storeFile(
        at url: URL,
        name: String? = nil,
        types: [String]? = nil,
        progress: (@Sendable (Int64, Int64) -> Void)? = nil
    ) async throws -> String {
        let did = try storeFileLocally(at: url, name: name, types: types)
        do {
            try await sync.uploadRaw(hatId: did, permanent: true, progress: progress)
        } catch {
            throw Failure.underlying(error)
        }
        return did
    }

    /// Register a file without uploading it — the draft case, matching
    /// ``storeLocally(_:name:)`` for text.
    @discardableResult
    public func storeFileLocally(
        at url: URL, name: String? = nil, types: [String]? = nil
    ) throws -> String {
        let hat: Hat
        do {
            hat = try files.registerFile(at: url, name: name, types: types)
        } catch {
            throw Failure.underlying(error)
        }
        guard let did = hat.id, !did.isEmpty else {
            throw Failure.underlying(Failure.emptyBody)
        }
        return did
    }

    // MARK: - reading

    /// Fetch the body a `did` points at and hand back the file holding
    /// it. The generic read — text, image, sound and video all want
    /// bytes on disk, and only the caller knows what they mean.
    ///
    /// Three attempts, in order, and the order is the point:
    ///
    /// 1. **Local.** We published it, or read it once already. Costs a
    ///    `stat` — ``FileVault/resolve(hatId:)`` re-hashes only when
    ///    the file has actually changed underneath us.
    /// 2. **Our own DISK.** The common case for a work published on the
    ///    same server we use, which on a network with few DISKs is most
    ///    of them.
    /// 3. **The publisher's DISK**, if `publisher` is known and the app
    ///    shell supplied a ``DiskResolver``. Their home map is where
    ///    their bytes are; ours has no reason to hold them.
    ///
    /// Every attempt verifies the hash. A failure carries what each
    /// attempt said, because a fetch that quietly finds nothing is
    /// otherwise impossible to diagnose — the same reason
    /// ``HatSyncService/download(hatId:privkey:progress:)`` accumulates
    /// its `diag` string.
    public func fetchURL(
        did: String,
        publisher: String? = nil,
        progress: (@Sendable (Int64) -> Void)? = nil
    ) async throws -> URL {
        var diagnostics: [String] = []

        // 1. Local.
        if (try? hats.exists(id: did)) == true {
            if case .available(let url) = try files.resolve(hatId: did) {
                return url
            }
            diagnostics.append("local=none")
        } else {
            diagnostics.append("local=noHat")
        }

        // 2. Our own DISK. `download` fetches through the session's own
        //    client whatever the locations say, so the HAT needs a
        //    remote location for the direct path to be attempted at all.
        do {
            try ensureRemoteHat(did: did)
            return try await sync.download(hatId: did, progress: progress)
        } catch {
            diagnostics.append("ownDisk=\(Self.short(error))")
        }

        // 3. The publisher's DISK.
        if let publisher, !publisher.isEmpty, let foreignDisk {
            if let remote = await foreignDisk(publisher) {
                do {
                    return try await fetch(did: did, from: remote, progress: progress)
                } catch {
                    diagnostics.append("publisherDisk=\(Self.short(error))")
                }
            } else {
                diagnostics.append("publisherDisk=unresolved")
            }
        }

        throw Failure.unreachable(did: did, diagnostics: diagnostics.joined(separator: "; "))
    }

    /// The body as text — ``fetchURL(did:publisher:progress:)`` plus a
    /// UTF-8 decode.
    ///
    /// **The decode is deliberately not part of the retry.** Bytes that
    /// arrive, hash correctly and turn out not to be text are a final
    /// answer, not a failed attempt: asking a second server for the
    /// same DID can only return the same bytes. Folding that into the
    /// fetch loop reported a successfully fetched file as unreachable.
    public func read(
        did: String,
        publisher: String? = nil,
        progress: (@Sendable (Int64) -> Void)? = nil
    ) async throws -> String {
        let url = try await fetchURL(did: did, publisher: publisher, progress: progress)
        return try Self.text(at: url, did: did)
    }

    /// Whether a body is already on this machine — what a list uses to
    /// decide between showing the text and offering to fetch it.
    public func isLocal(did: String) -> Bool {
        guard (try? hats.exists(id: did)) == true else { return false }
        guard let resolution = try? files.resolve(hatId: did) else { return false }
        if case .available = resolution { return true }
        return false
    }

    // MARK: - internals

    /// Make sure a HAT exists for `did` carrying at least one remote
    /// location, so the direct-fetch path is tried.
    ///
    /// A record we are reading for the first time has no HAT at all;
    /// one we published has a local location and possibly no remote.
    private func ensureRemoteHat(did: String) throws {
        let now = Hat.currentTimeMillis()
        if let existing = try hats.hat(id: did) {
            if existing.remoteLocas.isEmpty {
                _ = try hats.addLoca(sync.currentLocation, toId: did)
            }
            return
        }
        _ = try hats.upsert(Hat(
            born: now,
            last: now,
            name: String(did.prefix(8)),
            types: ["text/plain"],
            state: .active,
            locas: [sync.currentLocation],
            id: did
        ))
    }

    /// Pull `did` from a foreign DISK, verify it against the DID, and
    /// adopt it as an app-managed copy so the next read is local.
    private func fetch(
        did: String,
        from remote: DiskService,
        progress: (@Sendable (Int64) -> Void)?
    ) async throws -> URL {
        let destination = files.defaultLocalURL(did: did)
        try FileManager.default.createDirectory(
            at: files.dataDirectory, withIntermediateDirectories: true
        )
        try await remote.get(did: did, to: destination, progress: progress)
        let got = try Hex.encode(Hash.doubleSha256(fileAt: destination))
        guard got == did else {
            try? FileManager.default.removeItem(at: destination)
            throw Failure.unreachable(
                did: did, diagnostics: "publisher's DISK served \(String(got.prefix(12)))…"
            )
        }
        try ensureRemoteHat(did: did)
        _ = try files.adoptAppCopy(hatId: did, at: destination)
        return destination
    }

    private static func text(at url: URL, did: String) throws -> String {
        let data: Data
        do {
            data = try Data(contentsOf: url)
        } catch {
            throw Failure.underlying(error)
        }
        guard let string = String(data: data, encoding: .utf8) else {
            throw Failure.notUtf8(did: did)
        }
        return string
    }

    private static func short(_ error: Error) -> String {
        let text = "\(error)"
        return text.count > 120 ? String(text.prefix(120)) + "…" : text
    }
}
