import Foundation
import FCStorage

/// An invitation to a room we are not in.
///
/// **Kept rather than acted on.** A `ROOM_INFO` for a room this device
/// does not have cannot be checked against anything — the `owner` field
/// in it was written by whoever sent it — so joining is a decision only
/// a person can make. Android raises a dialog and loses the invitation
/// if nobody is looking; this stores it, because an invitation that
/// arrives while the app is collecting in the background is exactly the
/// one you want to still be there later.
public struct RoomInvite: Codable, Equatable, Sendable, Identifiable {

    /// The room the invitation names. Also the key: a second invitation
    /// to the same room replaces the first rather than piling up.
    public var roomId: String
    /// Who sent it. **Not** to be trusted as the room's owner — it is
    /// simply who this device heard it from.
    public var from: String
    /// The `RoomInfo` payload, verbatim, so accepting applies exactly
    /// what was received.
    public var roomInfoJson: String
    public var name: String?
    public var receivedAt: Int64

    public var id: String { roomId }

    public init(
        roomId: String,
        from: String,
        roomInfoJson: String,
        name: String? = nil,
        receivedAt: Int64 = 0
    ) {
        self.roomId = roomId
        self.from = from
        self.roomInfoJson = roomInfoJson
        self.name = name
        self.receivedAt = receivedAt
    }
}

/// Room invitations waiting for an answer. Human-scale.
public struct RoomInvitesStore {

    public static let namespace = "im.roominvites.v1"

    private let inner: TypedStore<RoomInvite>

    public init(kv: EncryptedKVStore) {
        self.inner = TypedStore(kv: kv, namespace: Self.namespace)
    }

    public func get(roomId: String) throws -> RoomInvite? {
        try inner.get(roomId)
    }

    public func upsert(_ invite: RoomInvite) throws {
        try inner.put(invite, key: invite.roomId)
    }

    /// Newest first.
    public func all() throws -> [RoomInvite] {
        try inner.all().map(\.value).sorted { $0.receivedAt > $1.receivedAt }
    }

    @discardableResult
    public func remove(roomId: String) throws -> Bool {
        guard try inner.exists(roomId) else { return false }
        try inner.delete(roomId)
        return true
    }
}
