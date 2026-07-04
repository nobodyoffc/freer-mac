import Foundation
import FCCore
import FCStorage

/// Per-identity address book. Keyed by FID so add-or-update is
/// idempotent without a separate uniqueness check.
///
/// Namespace `contacts.v2`: the schema changed in Phase 7.6 to mirror
/// the Android `Contact` shape (cid / titles / memo / on-chain stats),
/// and old `contacts` rows would fail to decode under the new struct.
/// Bumping the namespace orphans them silently rather than tripping a
/// loud decode error on first list load.
public struct ContactsStore {

    public enum Failure: Error, CustomStringConvertible {
        case invalidFid(String, underlying: Error)

        public var description: String {
            switch self {
            case let .invalidFid(fid, e):
                return "ContactsStore: '\(fid)' is not a valid FID — \(e)"
            }
        }
    }

    public static let namespace = "contacts.v2"

    private let inner: TypedStore<Contact>

    public init(kv: EncryptedKVStore) {
        self.inner = TypedStore(kv: kv, namespace: Self.namespace)
    }

    /// Insert or replace a contact. `updatedAt` is bumped so callers
    /// don't need to remember to set it. FID is validated against the
    /// FCH Base58Check encoding — silently storing a malformed string
    /// would break `send()` later when `TxBuilder` tries to derive a
    /// recipient hash160 from it.
    public func upsert(_ contact: Contact) throws {
        do {
            _ = try FchAddress(fid: contact.id)
        } catch {
            throw Failure.invalidFid(contact.id, underlying: error)
        }
        var c = contact
        c.updatedAt = Date()
        try inner.put(c, key: c.id)
    }

    public func get(fid: String) throws -> Contact? {
        try inner.get(fid)
    }

    @discardableResult
    public func remove(fid: String) throws -> Bool {
        guard try inner.exists(fid) else { return false }
        try inner.delete(fid)
        return true
    }

    /// Flip the pin state. Returns the new `pinnedAt` (nil = unpinned).
    /// A FID that isn't in the store is a no-op returning nil.
    @discardableResult
    public func togglePin(fid: String) throws -> Date? {
        guard var c = try inner.get(fid) else { return nil }
        c.pinnedAt = (c.pinnedAt == nil) ? Date() : nil
        c.updatedAt = Date()
        try inner.put(c, key: c.id)
        return c.pinnedAt
    }

    /// All contacts, sorted with pinned first, then ``Contact/name``
    /// (cid → fid) A→Z. Cheap for human-scale address books (hundreds
    /// of entries); switch to a SQL-backed query if it ever needs to
    /// scale.
    public func all() throws -> [Contact] {
        let rows = try inner.all().map(\.value)
        return rows.sorted { lhs, rhs in
            switch (lhs.pinnedAt, rhs.pinnedAt) {
            case (.some, .none): return true
            case (.none, .some): return false
            default:
                return lhs.name.localizedCaseInsensitiveCompare(rhs.name) == .orderedAscending
            }
        }
    }
}
