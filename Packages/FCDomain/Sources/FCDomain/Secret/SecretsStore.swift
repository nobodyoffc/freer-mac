import Foundation
import FCStorage

/// Per-identity secret vault. Keyed by ``Secret/id`` so a chain sync
/// merging by carve id is idempotent. Content is stored cipher-only
/// (Pattern B) — see ``Secret``.
public struct SecretsStore {

    public static let namespace = "secrets.v1"

    private let inner: TypedStore<Secret>

    public init(kv: EncryptedKVStore) {
        self.inner = TypedStore(kv: kv, namespace: Self.namespace)
    }

    public func upsert(_ secret: Secret) throws {
        var s = secret
        s.updatedAt = Date()
        try inner.put(s, key: s.id)
    }

    public func get(id: String) throws -> Secret? {
        try inner.get(id)
    }

    @discardableResult
    public func remove(id: String) throws -> Bool {
        guard try inner.exists(id) else { return false }
        try inner.delete(id)
        return true
    }

    /// All secrets, newest saved first (Android lists by insertion
    /// order, newest at top).
    public func all() throws -> [Secret] {
        try inner.all().map(\.value).sorted { $0.addedAt > $1.addedAt }
    }

    /// All TOTP secrets — the TOTP tab's data source.
    public func totps() throws -> [Secret] {
        try all().filter(\.isTotp)
    }
}
