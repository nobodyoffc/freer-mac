import Foundation

/// The room protocol: who may change a room's membership, and what has
/// to be sent when they do. The port of Android's `RoomHandler`, minus
/// the sending.
///
/// **It returns messages rather than sending them.** Every method hands
/// back the outbound messages its decision implies, and the caller puts
/// them on the wire (9.2.4b). That keeps the entire protocol — which is
/// where the security of a room lives — testable without a network, and
/// it is the same split ``DeliveryPolicy`` uses.
///
/// **Every inbound rule is an owner check**, because a room has no
/// on-chain state and therefore no arbiter. Three claims in particular
/// are only meaningful from the owner, and a client that believed them
/// from anyone else would be trivially hijackable:
///
/// - `ROOM_DISBAND` — "this room is over"
/// - `ROOM_REMOVED` — "you are out"
/// - `ROOM_INFO` that rewrites the member list
///
/// The rule is not "the message says it is from the owner": a `RoomInfo`
/// payload carries an `owner` field that its sender wrote. It is "the
/// sender is the owner **of the room we already have**". For a room we
/// do not have, there is nothing to check against, which is precisely
/// why accepting an invitation is a decision only a person makes.
public struct RoomService {

    private let rooms: RoomsStore
    private let symkeys: SymkeyStore

    public init(rooms: RoomsStore, symkeys: SymkeyStore) {
        self.rooms = rooms
        self.symkeys = symkeys
    }

    /// Looks up a member's pubkey, so a room key can be sealed to them.
    /// Supplied by the caller — a contact lookup, or the chain — so this
    /// type has no opinion about where identities come from.
    public typealias PubkeyProvider = (String) throws -> Data?

    // MARK: - creating

    /// Create a room, generate its first key, and produce one invitation
    /// per member.
    ///
    /// Invited members are recorded as **pending** until their
    /// `ROOM_ACCEPT` arrives. They are full members from the moment they
    /// are invited — pending is about whether they have *answered*, not
    /// about whether they may read — because the invitation already
    /// carries the key and nothing could take it back.
    ///
    /// A member whose pubkey we cannot find is still invited, but their
    /// invitation carries no key; they will have to ask for it. Failing
    /// the whole creation because one contact is unresolved would be a
    /// worse trade.
    public func create(
        name: String?,
        desc: String? = nil,
        owner: String,
        invite members: [String] = [],
        home: [String: String]? = nil,
        pubkeys: PubkeyProvider,
        now: Date = Date()
    ) throws -> (room: Room, invitations: [ImMessage]) {
        var room = Room.create(owner: owner, name: name, desc: desc, now: now)
        room.home = home
        guard let roomId = room.id else { throw Failure.roomHasNoId }

        for fid in members where fid != owner {
            room.addMember(fid, now: now)
            room.addPendingMember(fid)
        }
        let key = try symkeys.generate(for: roomId, version: 1, now: now)
        room.symkeyVersion = key.version
        try rooms.upsert(room)

        let invitations = try room.others(than: owner).map { fid in
            try invitation(for: room, to: fid, from: owner, pubkeys: pubkeys, now: now)
        }
        return (room, invitations)
    }

    /// A `ROOM_INFO` describing `room`, with the current key sealed to
    /// `fid` when we can seal it.
    public func invitation(
        for room: Room,
        to fid: String,
        from senderFid: String,
        pubkeys: PubkeyProvider,
        now: Date = Date()
    ) throws -> ImMessage {
        guard let roomId = room.id else { throw Failure.roomHasNoId }
        var info = RoomInfo.from(room)
        let version = try symkeys.currentVersion(for: roomId)
        if version >= SymkeyStore.minimumVersion, let pubkey = try pubkeys(fid) {
            info.symkey = try symkeys.shareCipher(for: roomId, version: version, to: pubkey)
            info.symkeyVersion = version
        }
        // P2P: an invitation has to reach someone who is not in the room
        // yet, so it cannot travel on the room's own channel.
        return ImMessage.roomNotice(.roomInfo, from: senderFid, to: fid, content: info.wireJson(), now: now)
            .asP2P()
    }

    // MARK: - membership changes (owner side)

    /// Add members to a room we own, and invite them.
    @discardableResult
    public func addMembers(
        _ fids: [String],
        to roomId: String,
        as liveFid: String,
        pubkeys: PubkeyProvider,
        now: Date = Date()
    ) throws -> (added: [String], outbound: [ImMessage]) {
        var room = try requireOwned(roomId, by: liveFid)

        var added: [String] = []
        for fid in fids where fid != liveFid {
            if room.addMember(fid, now: now) {
                room.addPendingMember(fid)
                added.append(fid)
            }
        }
        guard !added.isEmpty else { return ([], []) }
        try rooms.upsert(room)

        // Everyone gets the new membership; the newcomers' copies carry
        // the key.
        let outbound = try room.others(than: liveFid).map { fid in
            try invitation(for: room, to: fid, from: liveFid, pubkeys: pubkeys, now: now)
        }
        return (added, outbound)
    }

    /// Remove a member from a room we own.
    ///
    /// **The key is rotated**, and that is the point of the operation. A
    /// removed member keeps every key they ever held and every message
    /// those keys open — nothing can claw that back — so removal can
    /// only mean "from here on". Without the rotation it would mean
    /// nothing at all.
    ///
    /// The removed member is told (`ROOM_REMOVED`) and everyone left
    /// gets the new membership and the new key.
    @discardableResult
    public func removeMember(
        _ fid: String,
        from roomId: String,
        as liveFid: String,
        pubkeys: PubkeyProvider,
        now: Date = Date()
    ) throws -> (removed: Bool, outbound: [ImMessage]) {
        var room = try requireOwned(roomId, by: liveFid)
        guard room.removeMember(fid, now: now) else { return (false, []) }
        try rooms.upsert(room)

        let rotated = try symkeys.rotate(for: roomId, now: now)
        room.symkeyVersion = rotated.version
        try rooms.upsert(room)

        var outbound: [ImMessage] = [
            ImMessage.roomNotice(.roomRemoved, from: liveFid, to: fid, content: roomId, now: now).asP2P(),
        ]
        outbound += try room.others(than: liveFid).map { member in
            try invitation(for: room, to: member, from: liveFid, pubkeys: pubkeys, now: now)
        }
        return (true, outbound)
    }

    /// Rotate a room's key and give the new one to every member —
    /// Android's `reset_symkey`, and the way out for an owner whose
    /// device holds no key for a room it owns.
    ///
    /// **Rotating is additive**, like every other rotation here: the old
    /// version stays, because it is the only thing that can still open
    /// what was said under it. So this closes off *future* messages from
    /// anyone who does not get the new key, and changes nothing about
    /// the past — which is exactly what it should mean.
    ///
    /// The new key rides in a `ROOM_INFO`, the same envelope an
    /// invitation uses, because a member receiving one needs the
    /// membership and the key together and there is no version of this
    /// where they should be applied separately.
    @discardableResult
    public func resetSymkey(
        _ roomId: String,
        as liveFid: String,
        pubkeys: PubkeyProvider,
        now: Date = Date()
    ) throws -> (version: Int64, outbound: [ImMessage]) {
        var room = try requireOwned(roomId, by: liveFid)

        let rotated = try symkeys.rotate(for: roomId, now: now)
        room.symkeyVersion = rotated.version
        room.lastUpdated = Int64(now.timeIntervalSince1970 * 1000)
        try rooms.upsert(room)

        let outbound = try room.others(than: liveFid).map { fid in
            try invitation(for: room, to: fid, from: liveFid, pubkeys: pubkeys, now: now)
        }
        return (rotated.version, outbound)
    }

    /// Close a room we own, and tell everyone.
    ///
    /// The keys are **kept**: disbanding ends the conversation, it does
    /// not burn the transcript, and members still have to be able to
    /// read what was said.
    @discardableResult
    public func disband(
        _ roomId: String, as liveFid: String, now: Date = Date()
    ) throws -> [ImMessage] {
        var room = try requireOwned(roomId, by: liveFid)
        guard !room.isInactive else { return [] }

        room.active = false
        room.lastUpdated = Int64(now.timeIntervalSince1970 * 1000)
        try rooms.upsert(room)

        return room.others(than: liveFid).map { fid in
            ImMessage.roomNotice(.roomDisband, from: liveFid, to: fid, content: roomId, now: now).asP2P()
        }
    }

    // MARK: - membership changes (member side)

    /// Leave a room. Returns the `ROOM_LEAVE` for the owner, who is the
    /// one that can actually act on it.
    ///
    /// We mark ourselves inactive immediately rather than waiting to be
    /// removed: leaving is our decision, and it should not depend on the
    /// owner being online to take effect on our own screen.
    @discardableResult
    public func leave(
        _ roomId: String, as liveFid: String, now: Date = Date()
    ) throws -> ImMessage? {
        guard var room = try rooms.get(id: roomId) else { throw Failure.noSuchRoom(roomId) }
        guard !room.isOwner(liveFid) else { throw Failure.ownerCannotLeave }

        room.removeMember(liveFid, now: now)
        room.active = false
        try rooms.upsert(room)

        guard let owner = room.owner else { return nil }
        return ImMessage.roomNotice(.roomLeave, from: liveFid, to: owner, content: roomId, now: now).asP2P()
    }

    /// Accept an invitation: create the room, store the key it carries,
    /// and confirm to the owner.
    ///
    /// **Refuses an invitation for a room we already have under a
    /// different owner.** An invitation names its own owner, and that
    /// field is written by whoever sent it, so a stranger who learns a
    /// room id can offer you an "invitation" to a room you are already
    /// in and take it over on one tap — replacing the member list and
    /// the key. Android accepts this (logged as Android issue C12); we
    /// do not. An invitation from the room's actual owner is still
    /// honoured, since that is a legitimate re-invite.
    @discardableResult
    public func acceptInvite(
        roomInfoJson: String, as liveFid: String, now: Date = Date()
    ) throws -> (room: Room, accept: ImMessage?) {
        let info = try RoomInfo.fromJson(roomInfoJson)
        guard let roomId = info.id, !roomId.isEmpty else { throw Failure.malformedInvitation }

        var room: Room
        if var existing = try rooms.get(id: roomId) {
            guard existing.owner == nil || existing.owner == info.owner else {
                throw Failure.invitationOwnerMismatch(roomId: roomId)
            }
            info.apply(to: &existing, now: now)
            existing.active = true
            room = existing
        } else {
            room = info.toRoom(now: now)
        }
        room.addMember(liveFid, now: now)
        try rooms.upsert(room)

        if let symkey = info.symkey {
            // `allowOverwrite: false` — we may already hold this
            // version from a previous invitation, and the copy we have
            // been decrypting with is the one to keep.
            try symkeys.receiveShared(
                cipher: symkey,
                for: roomId,
                version: info.symkeyVersion ?? SymkeyStore.minimumVersion,
                privkey: try privkeyForReceive(),
                allowOverwrite: false,
                now: now
            )
        }

        guard let owner = info.owner, owner != liveFid else { return (room, nil) }
        let accept = ImMessage
            .roomNotice(.roomAccept, from: liveFid, to: owner, content: roomId, now: now)
            .asP2P()
        return (room, accept)
    }

    /// Decline an invitation — a `ROOM_LEAVE` to the owner, so they can
    /// drop us from the membership they are keeping.
    public func rejectInvite(
        roomInfoJson: String, as liveFid: String, now: Date = Date()
    ) throws -> ImMessage? {
        let info = try RoomInfo.fromJson(roomInfoJson)
        guard let roomId = info.id, let owner = info.owner, owner != liveFid else { return nil }
        return ImMessage.roomNotice(.roomLeave, from: liveFid, to: owner, content: roomId, now: now).asP2P()
    }

    // MARK: - inbound

    /// What an inbound room notification did.
    public enum Handled: Equatable, Sendable {
        /// A member left; the owner should rotate and re-share. The
        /// outbound messages are included.
        case memberLeft(fid: String, outbound: [ImMessage])
        /// A pending member confirmed.
        case memberConfirmed(fid: String)
        /// The owner closed the room.
        case disbanded
        /// The owner removed us.
        case removed
        /// A room we are in was updated.
        case updated(Room)
        /// An invitation to a room we do not have. **Not applied** —
        /// joining a room is a person's decision, so this hands the
        /// payload back for the UI to offer.
        case invitation(from: String, roomInfoJson: String)
        /// Not a room notification, or one we will not act on. The
        /// reason is for logs, not for the user.
        case ignored(reason: String)
    }

    /// Apply one inbound `ROOM_*` message.
    ///
    /// `pubkeys` is only consulted for the one case that produces
    /// outbound traffic — a member leaving a room we own, which forces a
    /// rotation and a re-share.
    @discardableResult
    public func handle(
        _ message: ImMessage,
        as liveFid: String,
        pubkeys: PubkeyProvider = { _ in nil },
        now: Date = Date()
    ) throws -> Handled {
        guard let contentType = message.contentType else { return .ignored(reason: "no content type") }
        guard let senderFid = message.senderId, !senderFid.isEmpty else {
            return .ignored(reason: "no sender")
        }
        guard let content = message.content, !content.isEmpty else {
            return .ignored(reason: "no content")
        }

        switch contentType {
        case .roomLeave:
            return try handleLeave(roomId: content, from: senderFid, as: liveFid, pubkeys: pubkeys, now: now)
        case .roomAccept:
            return try handleAccept(roomId: content, from: senderFid, as: liveFid)
        case .roomDisband:
            return try handleDisband(roomId: content, from: senderFid, as: liveFid, now: now)
        case .roomRemoved:
            return try handleRemoved(roomId: content, from: senderFid, as: liveFid, now: now)
        case .roomInfo:
            return try handleInfo(json: content, from: senderFid, as: liveFid, now: now)
        default:
            return .ignored(reason: "not a room notification")
        }
    }

    /// Only the owner acts on a leave — everyone else finds out through
    /// the `ROOM_INFO` that follows it.
    private func handleLeave(
        roomId: String, from senderFid: String, as liveFid: String,
        pubkeys: PubkeyProvider, now: Date
    ) throws -> Handled {
        guard let room = try rooms.get(id: roomId) else { return .ignored(reason: "unknown room") }
        guard room.isOwner(liveFid) else { return .ignored(reason: "not the owner") }
        guard !room.isInactive else { return .ignored(reason: "room is closed") }
        guard room.isMember(senderFid) else { return .ignored(reason: "not a member") }

        let (removed, outbound) = try removeMember(
            senderFid, from: roomId, as: liveFid, pubkeys: pubkeys, now: now
        )
        guard removed else { return .ignored(reason: "not a member") }
        // No ROOM_REMOVED for someone who left of their own accord —
        // they know.
        let withoutRedundantNotice = outbound.filter { $0.contentType != .roomRemoved }
        return .memberLeft(fid: senderFid, outbound: withoutRedundantNotice)
    }

    private func handleAccept(roomId: String, from senderFid: String, as liveFid: String) throws -> Handled {
        guard var room = try rooms.get(id: roomId) else { return .ignored(reason: "unknown room") }
        guard room.isOwner(liveFid) else { return .ignored(reason: "not the owner") }
        guard !room.isInactive else { return .ignored(reason: "room is closed") }
        guard room.isMember(senderFid) else { return .ignored(reason: "not a member") }
        guard room.confirmMember(senderFid) else { return .ignored(reason: "not pending") }

        try rooms.upsert(room)
        return .memberConfirmed(fid: senderFid)
    }

    private func handleDisband(
        roomId: String, from senderFid: String, as liveFid: String, now: Date
    ) throws -> Handled {
        guard var room = try rooms.get(id: roomId) else { return .ignored(reason: "unknown room") }
        guard room.isOwner(senderFid) else { return .ignored(reason: "sender is not the owner") }
        // Our own disband coming back to us off the room channel.
        guard senderFid != liveFid else { return .ignored(reason: "own echo") }
        guard !room.isInactive else { return .ignored(reason: "already closed") }

        room.active = false
        room.lastUpdated = Int64(now.timeIntervalSince1970 * 1000)
        try rooms.upsert(room)
        return .disbanded
    }

    private func handleRemoved(
        roomId: String, from senderFid: String, as liveFid: String, now: Date
    ) throws -> Handled {
        guard var room = try rooms.get(id: roomId) else { return .ignored(reason: "unknown room") }
        guard room.isOwner(senderFid) else { return .ignored(reason: "sender is not the owner") }
        guard !room.isOwner(liveFid) else { return .ignored(reason: "the owner cannot be removed") }
        guard !room.isInactive else { return .ignored(reason: "already closed") }

        room.removeMember(liveFid, now: now)
        room.active = false
        try rooms.upsert(room)
        return .removed
    }

    /// A `ROOM_INFO` is an update for a room we have and an invitation
    /// for one we do not.
    ///
    /// For a room we have, the sender must be a **member of the room we
    /// already hold** — not merely someone claiming to be. The key it
    /// carries is only allowed to overwrite a version we hold when the
    /// sender is that room's owner, which is ``SymkeyStore``'s
    /// `allowOverwrite` argument doing exactly the job it exists for.
    private func handleInfo(
        json: String, from senderFid: String, as liveFid: String, now: Date
    ) throws -> Handled {
        guard let info = try? RoomInfo.fromJson(json), let roomId = info.id, !roomId.isEmpty else {
            return .ignored(reason: "malformed room info")
        }
        guard var room = try rooms.get(id: roomId) else {
            return .invitation(from: senderFid, roomInfoJson: json)
        }
        guard room.isMember(senderFid) else { return .ignored(reason: "sender is not a member") }

        let fromOwner = room.isOwner(senderFid)
        // Only the owner may rewrite who is in the room. A member's
        // update can still carry name, description and the key.
        var applied = info
        if !fromOwner {
            applied.members = nil
            applied.owner = nil
        }
        applied.apply(to: &room, now: now)
        try rooms.upsert(room)

        if let symkey = info.symkey {
            try symkeys.receiveShared(
                cipher: symkey,
                for: roomId,
                version: info.symkeyVersion ?? SymkeyStore.minimumVersion,
                privkey: try privkeyForReceive(),
                allowOverwrite: fromOwner,
                now: now
            )
        }
        return .updated(room)
    }

    // MARK: - key material

    /// The identity privkey used to open a shared room key.
    ///
    /// Supplied at construction time in the app; this default exists so
    /// the membership rules — which are the bulk of this type — can be
    /// exercised without one. A `RoomInfo` that carries a key when no
    /// privkey is available simply does not yield one, and the room is
    /// joined without it, which is the same state as a member who has
    /// not been sent the key yet: they ask for it.
    public var privkey: Data?

    private func privkeyForReceive() throws -> Data {
        guard let privkey else { throw Failure.noPrivkey }
        return privkey
    }

    /// A copy of this service that can open shared keys.
    public func withPrivkey(_ privkey: Data) -> RoomService {
        var copy = self
        copy.privkey = privkey
        return copy
    }

    // MARK: - helpers

    private func requireOwned(_ roomId: String, by liveFid: String) throws -> Room {
        guard let room = try rooms.get(id: roomId) else { throw Failure.noSuchRoom(roomId) }
        guard room.isOwner(liveFid) else { throw Failure.notTheOwner(roomId: roomId) }
        return room
    }

    public enum Failure: Error, Equatable, CustomStringConvertible {
        case roomHasNoId
        case noSuchRoom(String)
        case notTheOwner(roomId: String)
        case ownerCannotLeave
        case malformedInvitation
        case invitationOwnerMismatch(roomId: String)
        case noPrivkey

        public var description: String {
            switch self {
            case .roomHasNoId:
                return "RoomService: the room has no id"
            case .noSuchRoom(let id):
                return "RoomService: no room \(id)"
            case .notTheOwner(let id):
                return "RoomService: only the owner of \(id) can do that"
            case .ownerCannotLeave:
                return "RoomService: the owner cannot leave their own room — disband it instead"
            case .malformedInvitation:
                return "RoomService: the invitation names no room"
            case .invitationOwnerMismatch(let id):
                return "RoomService: an invitation to \(id) claims an owner the room does not have"
            case .noPrivkey:
                return "RoomService: no privkey, so a shared room key cannot be opened"
            }
        }
    }
}

private extension ImMessage {
    /// Room control traffic travels **P2P**, not on the room's own
    /// channel: an invitation has to reach someone who is not in the
    /// room yet, and a removal has to reach someone who no longer is.
    /// ``ImMessage/roomNotice(_:from:to:content:now:)`` builds them as
    /// `.room` because that is what they are *about*; this says how they
    /// travel.
    func asP2P() -> ImMessage {
        var copy = self
        copy.type = .p2p
        return copy
    }
}
