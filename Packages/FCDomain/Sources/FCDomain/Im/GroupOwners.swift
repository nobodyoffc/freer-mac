import Foundation

/// Fills in ``Conversation/avatarDid`` — the FID a group's avatar badges
/// — from the group records this device already holds.
///
/// The avatar itself is drawn from the group id and needs nothing from
/// this type. What needs filling is the badge: who owns the group, or for
/// a square, who last named it.
///
/// It exists because the places that *learn* an owner are all events, and
/// events only fire once. ``RoomConversations`` runs when a room is made
/// or its membership moves; ``GroupService`` runs on a chain sync. A row
/// written before either of those learned to record the owner is a row
/// nothing will ever come back to — the same shape of gap that
/// ``RoomConversations`` was written to close for a room's name and
/// member count, one level up and across all three group flavours.
///
/// **No network.** Every fact it needs is already in ``RoomsStore``,
/// ``TeamsStore`` and ``SquaresStore``, put there by syncs that have
/// already happened. That is what makes it safe to run on every list
/// load: it is a projection from local truth, so calling it twice costs
/// two reads and changes nothing the second time.
public struct GroupOwners {

    private let rooms: RoomsStore
    private let teams: TeamsStore
    private let squares: SquaresStore
    private let conversations: ConversationsStore

    public init(
        rooms: RoomsStore,
        teams: TeamsStore,
        squares: SquaresStore,
        conversations: ConversationsStore
    ) {
        self.rooms = rooms
        self.teams = teams
        self.squares = squares
        self.conversations = conversations
    }

    /// Bring every group row's badge into step with its group record.
    ///
    /// Returns the number of rows actually rewritten, which is zero on
    /// every call after the first unless something really changed — the
    /// property that lets a caller run this from a view's reload without
    /// thinking about it.
    ///
    /// A group we hold no record for is left exactly as it is rather than
    /// cleared. Not knowing who owns a group is not the same fact as
    /// knowing it has no owner, and a row that has been showing a badge
    /// should not lose it because a store was pruned.
    @discardableResult
    public func refill() throws -> Int {
        var rewritten = 0
        for var conversation in try conversations.all() {
            guard let owner = try owner(of: conversation) else { continue }
            guard conversation.avatarDid != owner else { continue }
            conversation.avatarDid = owner
            try conversations.upsert(conversation)
            rewritten += 1
        }
        return rewritten
    }

    /// The FID a conversation's avatar should badge, or nil when this
    /// device cannot say.
    ///
    /// A P2P thread has no badge: its avatar *is* the other person, drawn
    /// from `targetId`, and writing that FID in here as well would be
    /// storing the same fact twice in a field that means something else.
    public func owner(of conversation: Conversation) throws -> String? {
        switch conversation.type {
        case .p2p:
            return nil
        case .room:
            return try rooms.get(id: conversation.targetId)?.owner
        case .team:
            return try teams.get(id: conversation.targetId)?.owner
        case .square:
            // Nobody owns a square, so the badge falls to the last namer
            // — the only member the chain singles out.
            return try squares.get(id: conversation.targetId)?.namers?.last
        }
    }
}
