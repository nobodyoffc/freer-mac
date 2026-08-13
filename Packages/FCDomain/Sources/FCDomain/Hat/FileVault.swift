import Foundation
import UniformTypeIdentifiers
import FCCore

/// The local file layer behind the HAT database — where the Mac port
/// deliberately diverges from Android.
///
/// **Reference, don't copy.** Android copies every imported file into
/// app storage, because a SAF content URI is not a stable path. On
/// macOS we register the *original* file's path instead: no copy, no
/// doubled disk usage, and importing a multi-gigabyte file costs one
/// hash pass rather than a full duplication.
///
/// What copying was quietly buying is immutability — an app-private
/// copy cannot be moved, deleted, or edited behind our back, and a HAT
/// id **is** the hash of its content, so any of those silently breaks
/// the DID. This type is the guard that buys it back:
///
/// - Every referenced path gets a ``HatLocal/FileStamp`` (size +
///   modification time) at registration.
/// - ``resolve(hatId:)`` stats the path. Unchanged stamp → trust it,
///   no hashing. Changed or absent stamp → re-hash and compare to the
///   DID.
/// - Gone → the location is pruned. Content changed → the location is
///   detached and the caller is told the new DID, so the UI can offer
///   to register it as a new version (`preDid`/`srcDid`).
///
/// So the cost of the common case is one `stat`, and a file is never
/// served under a DID it no longer matches.
///
/// Downloads and explicit copies live in ``dataDirectory`` as
/// `<did>`, which is also probed implicitly — the same fallback
/// Android uses when a `local://` entry is missing. Those copies are
/// app-managed and may be deleted with the HAT; referenced originals
/// belong to the user and are never touched.
public struct FileVault {

    public enum Failure: Error, CustomStringConvertible {
        case notAFile(URL)
        case unreadable(URL, underlying: Error)
        case hatNotFound(String)
        case noLocalBytes(String)
        case io(Error)

        public var description: String {
            switch self {
            case .notAFile(let url):
                return "FileVault: not a readable file — \(url.path)"
            case let .unreadable(url, underlying):
                return "FileVault: cannot read \(url.path) — \(underlying)"
            case .hatNotFound(let id):
                return "FileVault: no HAT with id \(id)"
            case .noLocalBytes(let id):
                return "FileVault: HAT \(id) has no usable local copy"
            case .io(let e):
                return "FileVault: I/O — \(e)"
            }
        }
    }

    /// Outcome of asking a HAT for its local bytes.
    public enum Resolution: Equatable {
        /// Bytes are present at this URL and match the HAT's DID.
        case available(URL)
        /// No usable local copy. Any dead locations have been pruned
        /// from the HAT.
        case unavailable
        /// A file **we registered** still exists but no longer hashes
        /// to the HAT's DID — it was edited in place. The location has
        /// been detached; `newDid` is what the file holds now, so the
        /// caller can offer to register it as a new version.
        ///
        /// Only ever reported for a path this vault had stamped. A
        /// mismatching path we never registered (a `local://` that
        /// arrived inside someone else's HAT) is simply pruned and
        /// reported ``unavailable`` — it was never our file to call
        /// modified.
        case modified(url: URL, newDid: String)
    }

    public let hats: HatsStore
    /// Where app-managed copies live (downloads, materialized copies).
    public let dataDirectory: URL

    public init(hats: HatsStore, dataDirectory: URL) {
        self.hats = hats
        self.dataDirectory = dataDirectory
    }

    /// Path an app-managed copy of `did` would occupy.
    public func defaultLocalURL(did: String) -> URL {
        dataDirectory.appendingPathComponent(did)
    }

    // MARK: - registering

    /// Register an existing file **by reference**: hash it to get the
    /// DID, then store a HAT whose only location is the original path.
    /// The file is not copied and not modified.
    ///
    /// Registering content that is already known adds the new path as
    /// an additional location rather than duplicating the HAT — the
    /// same bytes in two places are one DID.
    @discardableResult
    public func registerFile(
        at url: URL,
        name: String? = nil,
        desc: String? = nil,
        types: [String]? = nil
    ) throws -> Hat {
        let attributes = try fileAttributes(at: url)
        let did = try hashFile(at: url)
        let path = url.standardizedFileURL.path
        let loca = Hat.localLocationPrefix + path
        let now = Hat.currentTimeMillis()

        let stamp = HatLocal.FileStamp(
            path: path,
            size: attributes.size,
            modifiedAtMs: attributes.modifiedAtMs
        )

        if var existingRecord = try hats.record(id: did) {
            existingRecord.wire.addLoca(loca, nowMs: now)
            if existingRecord.wire.name == nil { existingRecord.wire.name = name ?? url.lastPathComponent }
            if existingRecord.wire.size == nil { existingRecord.wire.size = attributes.size }
            existingRecord.local.setStamp(stamp)
            return try hats.upsert(existingRecord.wire, local: existingRecord.local).wire
        }

        let hat = Hat(
            size: attributes.size,
            born: now,
            last: now,
            name: name ?? url.lastPathComponent,
            desc: desc,
            types: types ?? Self.mimeTypes(for: url),
            state: .active,
            locas: [loca],
            id: did
        )
        var local = HatLocal()
        local.setStamp(stamp)
        return try hats.upsert(hat, local: local).wire
    }

    /// Record an app-managed copy that already exists on disk — used by
    /// the download path once bytes have landed at
    /// ``defaultLocalURL(did:)``. The file is verified against the DID
    /// before it is adopted.
    @discardableResult
    public func adoptAppCopy(hatId: String, at url: URL) throws -> Hat {
        guard var record = try hats.record(id: hatId) else { throw Failure.hatNotFound(hatId) }
        let attributes = try fileAttributes(at: url)
        let did = try hashFile(at: url)
        guard did == hatId else {
            throw Failure.unreadable(url, underlying: Failure.noLocalBytes(
                "content hashes to \(did), not \(hatId)"))
        }
        let path = url.standardizedFileURL.path
        record.wire.addLoca(Hat.localLocationPrefix + path)
        record.wire.size = attributes.size
        record.local.appManagedCopy = true
        record.local.setStamp(HatLocal.FileStamp(
            path: path, size: attributes.size, modifiedAtMs: attributes.modifiedAtMs))
        return try hats.upsert(record.wire, local: record.local).wire
    }

    // MARK: - resolving

    /// Find usable local bytes for a HAT, healing the record as it goes.
    ///
    /// Candidates are the HAT's `local://` locations in order, then the
    /// app-managed copy at ``defaultLocalURL(did:)`` even when it isn't
    /// listed (Android's fallback). Each is verified before use, so a
    /// `local://` path that arrived inside someone else's HAT can never
    /// serve unrelated bytes: with no stamp of ours it is always
    /// re-hashed, and a mismatch detaches it.
    public func resolve(hatId: String) throws -> Resolution {
        guard var record = try hats.record(id: hatId) else { throw Failure.hatNotFound(hatId) }

        var candidates = record.wire.localPaths
        let appCopyPath = defaultLocalURL(did: hatId).path
        if !candidates.contains(appCopyPath) { candidates.append(appCopyPath) }

        var dirty = false
        var modified: Resolution?

        for path in candidates {
            let url = URL(fileURLWithPath: path)
            guard let attributes = try? fileAttributes(at: url) else {
                // Gone (moved, deleted, or never ours). Prune the claim.
                if record.wire.localPaths.contains(path) {
                    record.wire.locas = (record.wire.locas ?? [])
                        .filter { $0 != Hat.localLocationPrefix + path }
                    dirty = true
                }
                if record.local.stamps[path] != nil {
                    record.local.removeStamp(for: path)
                    dirty = true
                }
                continue
            }

            // Fast path: the stamp says nothing changed, so the bytes
            // still hash to the DID and we skip the hash entirely.
            if let stamp = record.local.stamps[path],
               stamp.size == attributes.size,
               stamp.modifiedAtMs == attributes.modifiedAtMs {
                if dirty { try persist(record) }
                return .available(url)
            }

            // No stamp, or the file changed: the DID is the authority.
            let knownToUs = record.local.stamps[path] != nil
            let did = try hashFile(at: url)
            if did == hatId {
                record.local.setStamp(HatLocal.FileStamp(
                    path: path, size: attributes.size, modifiedAtMs: attributes.modifiedAtMs))
                if !record.wire.localPaths.contains(path) {
                    record.wire.addLoca(Hat.localLocationPrefix + path)
                }
                try persist(record)
                return .available(url)
            }

            // Content doesn't match the DID. Detach the claim either
            // way, but only call it `.modified` for a file we had
            // stamped — that is genuinely "your file was edited, here
            // is its new DID". An unstamped path is someone else's
            // claim (a `local://` that arrived inside their HAT) that
            // happens to exist here; treating that as a modification
            // would invite the UI to offer "save as new version" for
            // an unrelated file we never owned.
            record.wire.locas = (record.wire.locas ?? [])
                .filter { $0 != Hat.localLocationPrefix + path }
            record.local.removeStamp(for: path)
            dirty = true
            if knownToUs, modified == nil {
                modified = .modified(url: url, newDid: did)
            }
        }

        if dirty { try persist(record) }
        return modified ?? .unavailable
    }

    /// Convenience for callers that only care whether bytes are there.
    public func localURL(hatId: String) throws -> URL? {
        if case .available(let url) = try resolve(hatId: hatId) { return url }
        return nil
    }

    // MARK: - copying

    /// Copy a HAT's bytes into app storage, so they survive the
    /// original being moved or deleted. No-op if an app copy already
    /// exists and verifies.
    @discardableResult
    public func materialize(hatId: String) throws -> URL {
        let destination = defaultLocalURL(did: hatId)

        switch try resolve(hatId: hatId) {
        case .available(let url):
            if url.standardizedFileURL == destination.standardizedFileURL {
                return destination   // already an app copy
            }
            do {
                try FileManager.default.createDirectory(
                    at: dataDirectory, withIntermediateDirectories: true)
                if FileManager.default.fileExists(atPath: destination.path) {
                    try FileManager.default.removeItem(at: destination)
                }
                try FileManager.default.copyItem(at: url, to: destination)
            } catch {
                throw Failure.io(error)
            }
            try adoptAppCopy(hatId: hatId, at: destination)
            return destination
        case .modified, .unavailable:
            throw Failure.noLocalBytes(hatId)
        }
    }

    // MARK: - removing

    /// Drop this HAT's local bytes but keep the record — Android's
    /// "remove local data". App-managed copies are deleted; referenced
    /// originals are only forgotten, never touched.
    @discardableResult
    public func removeLocalData(hatId: String) throws -> Hat? {
        guard var record = try hats.record(id: hatId) else { return nil }
        deleteAppManagedCopies(of: record)
        record.wire.removeLocalLocas()
        record.local.stamps.removeAll()
        record.local.appManagedCopy = false
        try persist(record)
        return record.wire
    }

    /// Delete a HAT. Any app-managed copy goes with it; **files the
    /// user owns are never deleted** — we only ever held a path to them.
    @discardableResult
    public func delete(hatId: String) throws -> Bool {
        guard let record = try hats.record(id: hatId) else { return false }
        deleteAppManagedCopies(of: record)
        return try hats.remove(id: hatId)
    }

    /// Remove copies that live in ``dataDirectory``. A path outside it
    /// is a user file by definition and is left alone, whatever the
    /// sidecar claims.
    private func deleteAppManagedCopies(of record: HatRecord) {
        let root = dataDirectory.standardizedFileURL.path
        var paths = record.wire.localPaths
        if let id = record.wire.id { paths.append(defaultLocalURL(did: id).path) }
        for path in paths {
            let standardized = URL(fileURLWithPath: path).standardizedFileURL.path
            guard standardized.hasPrefix(root + "/") else { continue }
            try? FileManager.default.removeItem(atPath: standardized)
        }
    }

    // MARK: - helpers

    private func persist(_ record: HatRecord) throws {
        try hats.upsert(record.wire, local: record.local, touch: false)
    }

    private struct Attributes {
        let size: Int64
        let modifiedAtMs: Int64
    }

    private func fileAttributes(at url: URL) throws -> Attributes {
        let values: URLResourceValues
        do {
            values = try url.resourceValues(forKeys: [
                .fileSizeKey, .contentModificationDateKey, .isRegularFileKey,
            ])
        } catch {
            throw Failure.unreadable(url, underlying: error)
        }
        guard values.isRegularFile == true else { throw Failure.notAFile(url) }
        let size = Int64(values.fileSize ?? 0)
        let modified = values.contentModificationDate ?? Date(timeIntervalSince1970: 0)
        return Attributes(size: size, modifiedAtMs: Int64(modified.timeIntervalSince1970 * 1000))
    }

    private func hashFile(at url: URL) throws -> String {
        do {
            return try Hash.doubleSha256(fileAt: url)
                .map { String(format: "%02x", $0) }.joined()
        } catch {
            throw Failure.unreadable(url, underlying: error)
        }
    }

    /// Best-effort MIME type from the path extension, mirroring the
    /// `types` list Android fills from the content resolver.
    static func mimeTypes(for url: URL) -> [String]? {
        guard let type = UTType(filenameExtension: url.pathExtension),
              let mime = type.preferredMIMEType else { return nil }
        return [mime]
    }
}
