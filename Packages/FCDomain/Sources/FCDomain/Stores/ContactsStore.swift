import Foundation
import FCStorage

/// One entry in the identity's local address book. Maps an FID to a
/// human-friendly nickname plus opportunistic profile data we've
/// learned over time.
///
/// `nickname` is the user's local label and is authoritative for UI.
/// `displayName` is what the remote profile claims (cached from FAPI
/// lookups) — we keep both so a user can rename someone locally
/// without losing the remote-claimed name.
public struct Contact: Codable, Equatable, Hashable, Sendable {
    public var fid: String
    public var nickname: String
    public var displayName: String?
    public var note: String?
    public var pinnedAt: Date?
    public var addedAt: Date
    public var updatedAt: Date

    public init(
        fid: String,
        nickname: String,
        displayName: String? = nil,
        note: String? = nil,
        pinnedAt: Date? = nil,
        addedAt: Date = Date(),
        updatedAt: Date = Date()
    ) {
        self.fid = fid
        self.nickname = nickname
        self.displayName = displayName
        self.note = note
        self.pinnedAt = pinnedAt
        self.addedAt = addedAt
        self.updatedAt = updatedAt
    }
}

/// Per-identity contacts list. Keyed by FID so add-or-update is
/// idempotent without a separate uniqueness check.
public struct ContactsStore {

    public static let namespace = "contacts"

    private let inner: TypedStore<Contact>

    public init(_ identity: Identity) throws {
        self.inner = TypedStore(kv: try identity.storage(), namespace: Self.namespace)
    }

    /// Insert or replace a contact. `updatedAt` is bumped so callers
    /// don't need to remember to set it.
    public func upsert(_ contact: Contact) throws {
        var c = contact
        c.updatedAt = Date()
        try inner.put(c, key: c.fid)
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

    /// All contacts, sorted with pinned first, then nickname A→Z.
    /// Cheap for human-scale address books (hundreds of entries);
    /// switch to a SQL-backed query if it ever needs to scale.
    public func all() throws -> [Contact] {
        let rows = try inner.all().map(\.value)
        return rows.sorted { lhs, rhs in
            switch (lhs.pinnedAt, rhs.pinnedAt) {
            case (.some, .none): return true
            case (.none, .some): return false
            default:
                return lhs.nickname.localizedCaseInsensitiveCompare(rhs.nickname) == .orderedAscending
            }
        }
    }
}
