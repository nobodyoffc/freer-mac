import Foundation

/// Getting a group's key to the people who need it.
///
/// **Key traffic is always P2P**, whatever it is about. A team's key
/// cannot travel on the team's own channel, because the whole reason
/// someone needs it is that they cannot read that channel yet; the same
/// argument ``RoomService`` already makes for invitations and removals.
/// The entity the key belongs to therefore rides *inside* the payload
/// (``SymkeyShare``) rather than in the message's routing fields.
///
/// This builds messages and does not send them — the same split
/// ``RoomService`` and ``DeliveryPolicy`` use, so the rules are testable
/// with no network under them. What it builds is **named**
/// (``ImMessage/named()``), because the caller's next move is the
/// outbox and the outbox refuses a message with no id.
public enum KeyExchange {

    /// Push our current key for `entityId` at one member.
    ///
    /// Returns nil when we cannot seal it: either we hold no key at that
    /// version, or we have no public key for the recipient. Both are
    /// ordinary answers — a member whose pubkey has never appeared on
    /// the chain simply has to be reached another way — and neither is
    /// worth failing a whole share round over.
    public static func share(
        entityId: String,
        version: Int64,
        to fid: String,
        recipientPubkey: Data,
        from senderFid: String,
        symkeys: SymkeyStore,
        now: Date = Date()
    ) throws -> ImMessage? {
        guard let cipher = try symkeys.shareCipher(
            for: entityId, version: version, to: recipientPubkey
        ) else { return nil }

        return ImMessage.symkey(
            type: .p2p,
            from: senderFid,
            to: fid,
            symkeyData: SymkeyShare.payload(entityId: entityId, cipher: cipher),
            version: version,
            now: now
        ).named()
    }

    /// **There is deliberately no "share with everyone" here.**
    ///
    /// A key pushed at a whole membership unasked is an announcement
    /// about which conversation everyone is having, and only an entity's
    /// owner may make one — otherwise a member could mint a key, push it
    /// round, and split the group in two with nothing to say which half
    /// was real. That check needs the entity's record, which this type
    /// does not have and should not learn, so the broadcast lives with
    /// whoever can check: ``TeamKeyService`` for a team and
    /// ``RoomService`` for a room. What is left here is the envelope and
    /// the two things any member may legitimately do — answer a request
    /// (``share(entityId:version:to:recipientPubkey:from:symkeys:now:)``,
    /// which ``SignalRouter`` calls) and ask one.

    /// Ask someone for the key to `entityId`.
    ///
    /// The content is the bare entity id, which is the form
    /// ``SymkeyShare/requestedEntityId(_:)`` reads back and the one
    /// Android sends.
    public static func request(
        entityId: String,
        from senderFid: String,
        to fid: String,
        now: Date = Date()
    ) -> ImMessage {
        ImMessage.request(
            type: .p2p, from: senderFid, to: fid,
            requestType: .symkey, data: entityId, now: now
        ).named()
    }

    /// Ask someone for a room's details — its name, its membership and
    /// the key, in one answer.
    ///
    /// Distinct from ``request(entityId:from:to:now:)`` because the two
    /// answers are different sizes: a key share is a key, while a
    /// `ROOM_INFO` is the whole record. Asking the **owner** is what
    /// repairs a stale membership, since only their answer may rewrite
    /// who is in the room; any member's answer still carries the key,
    /// which is usually the part that was actually missing.
    public static func roomInfoRequest(
        roomId: String,
        from senderFid: String,
        to fid: String,
        now: Date = Date()
    ) -> ImMessage {
        ImMessage.request(
            type: .p2p, from: senderFid, to: fid,
            requestType: .roomInfo, data: roomId, now: now
        ).named()
    }

    /// Ask several people at once. Whoever answers first wins, and the
    /// rest are harmless: ``SymkeyStore`` refuses to overwrite a version
    /// it already holds unless the sender owns the entity, so a second
    /// answer is an ordinary no-op rather than a race.
    public static func requests(
        entityId: String,
        kind: RequestType,
        from senderFid: String,
        to fids: [String],
        now: Date = Date()
    ) -> [ImMessage] {
        fids.compactMap { fid in
            guard fid != senderFid else { return nil }
            switch kind {
            case .symkey:
                return request(entityId: entityId, from: senderFid, to: fid, now: now)
            case .roomInfo:
                return roomInfoRequest(roomId: entityId, from: senderFid, to: fid, now: now)
            default:
                return nil
            }
        }
    }
}
