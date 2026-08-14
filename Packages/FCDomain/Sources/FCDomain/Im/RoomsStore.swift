import Foundation
import FCStorage

/// The rooms we belong to, or used to. Keyed by ``Room/id``.
///
/// Human-scale, so it loads whole. Unlike ``ConversationsStore`` this is
/// **not** a cache: a room's membership exists nowhere else on this
/// device, and for the owner it exists nowhere else at all. Losing this
/// store loses the room.
public struct RoomsStore {

    public static let namespace = "im.rooms.v1"

    private let inner: TypedStore<Room>

    public init(kv: EncryptedKVStore) {
        self.inner = TypedStore(kv: kv, namespace: Self.namespace)
    }

    public func get(id: String) throws -> Room? {
        try inner.get(id)
    }

    public func upsert(_ room: Room) throws {
        guard let id = room.id, !id.isEmpty else { throw Failure.roomHasNoId }
        try inner.put(room, key: id)
    }

    /// Every room, most recently active first.
    public func all() throws -> [Room] {
        try inner.all().map(\.value).sorted { ($0.lastActive ?? 0) > ($1.lastActive ?? 0) }
    }

    /// Rooms still running — the list a chat sidebar shows.
    public func active() throws -> [Room] {
        try all().filter { !$0.isInactive }
    }

    /// Rooms that were disbanded, or that we were removed from. Kept,
    /// because the transcript outlives the room and a closed room still
    /// has to be readable.
    public func closed() throws -> [Room] {
        try all().filter(\.isInactive)
    }

    /// Rooms we own — the ones where our copy of the membership is the
    /// membership.
    public func owned(by fid: String) throws -> [Room] {
        try all().filter { $0.isOwner(fid) }
    }

    public func search(_ query: String) throws -> [Room] {
        let needle = query.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !needle.isEmpty else { return try all() }
        return try all().filter { $0.matches(query: needle) }
    }

    /// Apply a change to one room, if it exists.
    @discardableResult
    public func mutate(id: String, _ change: (inout Room) -> Void) throws -> Room? {
        guard var room = try get(id: id) else { return nil }
        change(&room)
        try upsert(room)
        return room
    }

    @discardableResult
    public func remove(id: String) throws -> Bool {
        guard try inner.exists(id) else { return false }
        try inner.delete(id)
        return true
    }

    public enum Failure: Error, Equatable, CustomStringConvertible {
        case roomHasNoId

        public var description: String {
            switch self {
            case .roomHasNoId: return "RoomsStore: the room has no id"
            }
        }
    }
}
