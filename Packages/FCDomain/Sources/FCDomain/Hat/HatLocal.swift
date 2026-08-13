import Foundation

/// Mac-only bookkeeping that rides alongside a ``Hat`` in the store and
/// is **never** serialized into the wire JSON.
///
/// Android copies every imported file into app storage, so a
/// `local://` path there always points at a private copy that cannot
/// change underneath it. On macOS we register the **original** file
/// instead — no copy, no doubled disk usage, and importing a multi-GB
/// file costs one hash pass. The risk that copying was quietly buying
/// is that the original can be moved, deleted, or edited in place,
/// which silently breaks the content-addressed DID.
///
/// This sidecar is the guard: for each referenced path we record the
/// size and modification time seen at registration. Checking a
/// reference is then one `stat`; only a real change costs a re-hash.
/// See ``FileVault`` (8.4.4) for the resolve/detach policy that uses it.
///
/// If the app is ever sandboxed for distribution, ``bookmark`` carries
/// the security-scoped bookmark data; it is unused today.
public struct HatLocal: Codable, Equatable, Sendable {

    /// What we knew about one referenced file when it was registered.
    public struct FileStamp: Codable, Equatable, Sendable {
        /// Absolute path (the `local://` loca minus its prefix).
        public var path: String
        public var size: Int64
        /// Modification time, epoch ms.
        public var modifiedAtMs: Int64
        /// Security-scoped bookmark, for a future sandboxed build.
        public var bookmark: Data?

        public init(path: String, size: Int64, modifiedAtMs: Int64, bookmark: Data? = nil) {
            self.path = path
            self.size = size
            self.modifiedAtMs = modifiedAtMs
            self.bookmark = bookmark
        }
    }

    /// Stamps for referenced originals, keyed by path.
    public var stamps: [String: FileStamp]
    /// True when the bytes live in a copy this app owns (a download, or
    /// an explicit "materialize"), which lives under Application
    /// Support and may be deleted with the HAT. References to files the
    /// user owns are never deleted.
    public var appManagedCopy: Bool
    /// When this row was first written locally.
    public var addedAt: Date
    /// Last local mutation (distinct from the wire `last`, which also
    /// moves when a peer's copy is used).
    public var updatedAt: Date

    public init(
        stamps: [String: FileStamp] = [:],
        appManagedCopy: Bool = false,
        addedAt: Date = Date(),
        updatedAt: Date = Date()
    ) {
        self.stamps = stamps
        self.appManagedCopy = appManagedCopy
        self.addedAt = addedAt
        self.updatedAt = updatedAt
    }

    public func stamp(for path: String) -> FileStamp? { stamps[path] }

    public mutating func setStamp(_ stamp: FileStamp) {
        stamps[stamp.path] = stamp
        updatedAt = Date()
    }

    public mutating func removeStamp(for path: String) {
        stamps.removeValue(forKey: path)
        updatedAt = Date()
    }
}

/// One stored row: the portable HAT plus its local-only sidecar.
///
/// Splitting them keeps ``Hat/wireJson()`` honest — anything Mac-specific
/// is structurally unable to leak into a message or an export file.
public struct HatRecord: Codable, Equatable, Sendable {
    public var wire: Hat
    public var local: HatLocal

    public init(wire: Hat, local: HatLocal = HatLocal()) {
        self.wire = wire
        self.local = local
    }

    public var id: String? { wire.id }
}
