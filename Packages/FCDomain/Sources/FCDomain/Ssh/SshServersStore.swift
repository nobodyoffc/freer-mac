import Foundation
import FCStorage

/// Per-identity list of saved SSH destinations.
///
/// Namespace `ssh.servers.v1`, keyed by ``SshServer/id`` (a UUID, not
/// `user@host`) so two entries may point at one machine.
///
/// Rows are encrypted by ``EncryptedKVStore`` like everything else in
/// the vault, which matters more here than it does for most stores: a
/// plaintext list of hostnames and login names is a map of everything
/// the user administers.
public struct SshServersStore {

    public enum Failure: Error, CustomStringConvertible {
        case emptyHost
        case emptyUser
        case badPort(Int)

        public var description: String {
            switch self {
            case .emptyHost: return "SshServersStore: the host is empty"
            case .emptyUser: return "SshServersStore: the login name is empty"
            case let .badPort(p): return "SshServersStore: port \(p) is outside 1...65535"
            }
        }
    }

    public static let namespace = "ssh.servers.v1"

    private let inner: TypedStore<SshServer>

    public init(kv: EncryptedKVStore) {
        self.inner = TypedStore(kv: kv, namespace: Self.namespace)
    }

    /// Insert or replace. Validates here rather than at the call site
    /// because a blank host or a port of 0 does not fail loudly later —
    /// it makes `ssh` print something obscure into the terminal long
    /// after the typo.
    public func upsert(_ server: SshServer) throws {
        let host = server.host.trimmingCharacters(in: .whitespaces)
        let user = server.user.trimmingCharacters(in: .whitespaces)
        guard !host.isEmpty else { throw Failure.emptyHost }
        guard !user.isEmpty else { throw Failure.emptyUser }
        guard (1...65535).contains(server.port) else { throw Failure.badPort(server.port) }

        var s = server
        s.host = host
        s.user = user
        s.label = s.label.trimmingCharacters(in: .whitespaces)
        s.updatedAt = Date()
        try inner.put(s, key: s.id)
    }

    public func get(id: String) throws -> SshServer? {
        try inner.get(id)
    }

    @discardableResult
    public func remove(id: String) throws -> Bool {
        guard try inner.exists(id) else { return false }
        try inner.delete(id)
        return true
    }

    /// Stamp a successful connection, so ``all()`` floats it to the top.
    public func touchLastUsed(id: String) throws {
        guard var s = try inner.get(id) else { return }
        s.lastUsedAt = Date()
        try inner.put(s, key: s.id)
    }

    @discardableResult
    public func togglePin(id: String) throws -> Date? {
        guard var s = try inner.get(id) else { return nil }
        s.pinnedAt = (s.pinnedAt == nil) ? Date() : nil
        s.updatedAt = Date()
        try inner.put(s, key: s.id)
        return s.pinnedAt
    }

    /// Pinned first, then most recently used, then by name. A server
    /// never connected to sorts below every one that has been.
    public func all() throws -> [SshServer] {
        try inner.all().map(\.value).sorted { lhs, rhs in
            switch (lhs.pinnedAt, rhs.pinnedAt) {
            case (.some, .none): return true
            case (.none, .some): return false
            default: break
            }
            switch (lhs.lastUsedAt, rhs.lastUsedAt) {
            case let (.some(l), .some(r)) where l != r: return l > r
            case (.some, .none): return true
            case (.none, .some): return false
            default:
                return lhs.name.localizedCaseInsensitiveCompare(rhs.name) == .orderedAscending
            }
        }
    }
}
