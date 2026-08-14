import Foundation
import FCStorage

/// The teams we know about, keyed by ``Team/id`` (the `create` carve's
/// txid).
///
/// Unlike ``RoomsStore`` this really is **a cache**, and a replaceable
/// one: every row is a copy of an on-chain record that `base.search`
/// will hand back again. Deleting this store loses nothing but a sync.
/// That difference — rooms are authoritative locally, teams are not —
/// is the whole distinction between the two flavours.
public struct TeamsStore {

    public static let namespace = "im.teams.v1"

    private let inner: TypedStore<Team>

    public init(kv: EncryptedKVStore) {
        self.inner = TypedStore(kv: kv, namespace: Self.namespace)
    }

    public func get(id: String) throws -> Team? {
        try inner.get(id)
    }

    public func upsert(_ team: Team) throws {
        guard let id = team.id, !id.isEmpty else { throw GroupStoreFailure.noId }
        try inner.put(team, key: id)
    }

    /// Every team, most recently changed first.
    public func all() throws -> [Team] {
        try inner.all().map(\.value).sorted { ($0.lastHeight ?? 0) > ($1.lastHeight ?? 0) }
    }

    /// Teams `fid` is currently in and that have not been disbanded.
    public func joined(by fid: String) throws -> [Team] {
        try all().filter { $0.isMember(fid) && $0.isActive }
    }

    public func owned(by fid: String) throws -> [Team] {
        try all().filter { $0.isOwner(fid) }
    }

    /// Teams that have invited `fid` and are waiting on a `join` carve.
    public func invitations(for fid: String) throws -> [Team] {
        try all().filter { $0.isInvited(fid) && !$0.isMember(fid) && $0.isActive }
    }

    public func search(_ query: String) throws -> [Team] {
        let needle = query.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !needle.isEmpty else { return try all() }
        return try all().filter { $0.matches(query: needle) }
    }

    /// The highest `lastHeight` we hold — the watermark an incremental
    /// sync resumes from.
    public func highestKnownHeight() throws -> Int64? {
        try all().compactMap(\.lastHeight).max()
    }

    @discardableResult
    public func remove(id: String) throws -> Bool {
        guard try inner.exists(id) else { return false }
        try inner.delete(id)
        return true
    }
}

/// The squares we know about, keyed by ``Square/id``. Same cache
/// character as ``TeamsStore``.
public struct SquaresStore {

    public static let namespace = "im.squares.v1"

    private let inner: TypedStore<Square>

    public init(kv: EncryptedKVStore) {
        self.inner = TypedStore(kv: kv, namespace: Self.namespace)
    }

    public func get(id: String) throws -> Square? {
        try inner.get(id)
    }

    public func upsert(_ square: Square) throws {
        guard let id = square.id, !id.isEmpty else { throw GroupStoreFailure.noId }
        try inner.put(square, key: id)
    }

    public func all() throws -> [Square] {
        try inner.all().map(\.value).sorted { ($0.lastHeight ?? 0) > ($1.lastHeight ?? 0) }
    }

    /// Squares `fid` is in. There is no `active` flag to check: a square
    /// cannot be disbanded, because nobody owns it.
    public func joined(by fid: String) throws -> [Square] {
        try all().filter { $0.isMember(fid) }
    }

    public func search(_ query: String) throws -> [Square] {
        let needle = query.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !needle.isEmpty else { return try all() }
        return try all().filter { $0.matches(query: needle) }
    }

    public func highestKnownHeight() throws -> Int64? {
        try all().compactMap(\.lastHeight).max()
    }

    @discardableResult
    public func remove(id: String) throws -> Bool {
        guard try inner.exists(id) else { return false }
        try inner.delete(id)
        return true
    }
}

public enum GroupStoreFailure: Error, Equatable, CustomStringConvertible {
    case noId

    public var description: String {
        switch self {
        case .noId: return "the group record has no id"
        }
    }
}
