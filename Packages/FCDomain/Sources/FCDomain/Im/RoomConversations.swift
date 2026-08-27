import Foundation

/// Keeps a room's row in the conversation list in step with the room
/// record it describes.
///
/// A ``Conversation`` is a **cache**, and for a team or a square it is a
/// cache with a refill: ``GroupService`` rewrites the row — name, member
/// count, membership — every time the chain is synced, because the chain
/// is where those facts live. A room has no chain, so nothing was ever
/// going to come along and repair its row, and the copy written when the
/// room was created was the only one ever written. That is why renaming a
/// room left the old name in the list, and why adding a member left the
/// header counting the membership as it stood at creation: the room
/// record was right and nothing carried it across.
///
/// This is that missing refill. It is deliberately a projection in one
/// direction only — ``RoomsStore`` and ``SymkeyStore`` are the facts, this
/// row is a picture of them — so calling it twice costs nothing and
/// calling it late is always a repair rather than a second opinion.
public struct RoomConversations {

    private let rooms: RoomsStore
    private let symkeys: SymkeyStore
    private let conversations: ConversationsStore

    public init(rooms: RoomsStore, symkeys: SymkeyStore, conversations: ConversationsStore) {
        self.rooms = rooms
        self.symkeys = symkeys
        self.conversations = conversations
    }

    /// Mirror `roomId`'s record onto its conversation row, **opening the
    /// row if the room has one and the list does not**.
    ///
    /// Opening is not a side effect worth avoiding: a room this device
    /// holds and the list does not show is a room the user cannot reach,
    /// which is exactly what accepting an invitation used to produce —
    /// the room was stored, the invitation was consumed, and the thread
    /// appeared only once somebody happened to say something in it.
    ///
    /// Only the fields that *describe the room* are touched. The
    /// preview, the unread count and the local preferences are the
    /// conversation's own and are none of the room's business.
    ///
    /// Returns nil for a room that is not on this device — nothing to
    /// mirror, and inventing a row for it would be inventing the room.
    @discardableResult
    public func sync(_ roomId: String) throws -> Conversation? {
        guard let room = try rooms.get(id: roomId) else { return nil }
        let id = Conversation.id(type: .room, targetId: roomId)

        var conversation = try conversations.get(id: id)
            ?? Conversation(id: id, targetId: roomId, type: .room, unreadCount: 0, createdAt: room.created)

        conversation.displayName = room.name
        conversation.memberNum = Int64(room.memberCount)
        // Who the avatar badges, not what the avatar *is*: the tile
        // itself comes from the room id, which is the only thing about a
        // room that survives a transfer. Mirroring the owner here means
        // the badge follows a transfer without the mark moving.
        conversation.avatarDid = room.owner
        // The version we can actually open, not the one the owner last
        // announced: the two differ exactly while a rotation is in
        // flight, and this row should not claim a key we are still
        // waiting for.
        let version = try symkeys.currentVersion(for: roomId)
        conversation.hasSymkey = version >= SymkeyStore.minimumVersion
        conversation.symkeyVersion = version >= SymkeyStore.minimumVersion ? version : nil

        try conversations.upsert(conversation)
        return conversation
    }
}
