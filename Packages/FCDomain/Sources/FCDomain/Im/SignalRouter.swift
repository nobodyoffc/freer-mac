import Foundation

/// What to do with an inbound message that is not a message.
///
/// ``ChatService/receive(_:as:privkey:now:)`` files anything displayable
/// and hands everything else back as ``ChatService/Received/signal(_:)``
/// — room notifications, key shares, key requests. Until now the courier
/// **counted those and dropped them**, which meant a room invitation
/// never arrived, a rotated key never landed, and a member asking for a
/// key was never answered. The protocol existed in ``RoomService`` and
/// ``SymkeyStore`` with nothing calling it.
///
/// This is the one place that routes them, and it is deliberately a
/// separate type rather than a branch inside the courier: the rules for
/// what a room notification may do are ``RoomService``'s, the rules for
/// whose key may overwrite whose are ``SymkeyStore``'s, and the courier
/// should not learn either.
///
/// **Answering a key request is not automatic.** A request from someone
/// outside the entity is refused here, and the check is membership *as
/// this device already understands it* — never what the request claims.
public struct SignalRouter {

    private let rooms: RoomsStore
    private let teams: TeamsStore
    private let symkeys: SymkeyStore
    private let invites: RoomInvitesStore
    private let roomService: RoomService
    private let roomConversations: RoomConversations
    private let privkey: Data?
    private let pubkeys: (String) throws -> Data?

    public init(
        rooms: RoomsStore,
        teams: TeamsStore,
        symkeys: SymkeyStore,
        invites: RoomInvitesStore,
        roomService: RoomService,
        roomConversations: RoomConversations,
        privkey: Data?,
        pubkeys: @escaping (String) throws -> Data? = { _ in nil }
    ) {
        self.rooms = rooms
        self.teams = teams
        self.symkeys = symkeys
        self.invites = invites
        self.roomService = roomService
        self.roomConversations = roomConversations
        self.privkey = privkey
        self.pubkeys = pubkeys
    }

    /// What routing one signal produced.
    public struct Outcome: Equatable, Sendable {
        /// Messages to queue in reply — a key we agreed to share, or the
        /// re-share a member leaving a room we own forces.
        public var outbound: [ImMessage]
        /// A room invitation that a person has to answer. Held rather
        /// than applied, for the reason ``RoomService/Handled`` gives.
        public var invitation: (from: String, roomInfoJson: String)?
        /// An entity whose key we just learned, so the caller can retry
        /// the messages that were sealed to it.
        public var learnedKeyFor: String?
        public var note: String?

        public init(
            outbound: [ImMessage] = [],
            invitation: (from: String, roomInfoJson: String)? = nil,
            learnedKeyFor: String? = nil,
            note: String? = nil
        ) {
            self.outbound = outbound
            self.invitation = invitation
            self.learnedKeyFor = learnedKeyFor
            self.note = note
        }

        public static func == (a: Outcome, b: Outcome) -> Bool {
            a.outbound == b.outbound
                && a.invitation?.from == b.invitation?.from
                && a.invitation?.roomInfoJson == b.invitation?.roomInfoJson
                && a.learnedKeyFor == b.learnedKeyFor
                && a.note == b.note
        }

        public static let nothing = Outcome()
    }

    public func route(
        _ message: ImMessage, as liveFid: String, now: Date = Date()
    ) throws -> Outcome {
        guard let contentType = message.contentType else { return .nothing }

        switch contentType {
        case .roomInfo, .roomLeave, .roomAccept, .roomDisband, .roomRemoved:
            return try routeRoom(message, as: liveFid, now: now)
        case .symkey:
            return try routeSymkeyShare(message, as: liveFid, now: now)
        case .request:
            return try routeRequest(message, as: liveFid, now: now)
        default:
            return .nothing
        }
    }

    // MARK: - rooms

    private func routeRoom(
        _ message: ImMessage, as liveFid: String, now: Date
    ) throws -> Outcome {
        switch try roomService.handle(message, as: liveFid, pubkeys: pubkeys, now: now) {
        case .memberLeft(let fid, let outbound):
            try mirrorRoom(named: message.content)
            return Outcome(outbound: outbound, note: "\(fid) left the room; key rotated")
        case .memberConfirmed(let fid):
            // Nothing the list shows has changed: a confirmation clears
            // the owner's pending flag, and the member was already one.
            return Outcome(note: "\(fid) accepted the invitation")
        case .disbanded:
            return Outcome(note: "a room was closed by its owner")
        case .removed:
            try mirrorRoom(named: message.content)
            return Outcome(note: "removed from a room")
        case .updated(let room):
            // An update carries the current key when the owner could
            // seal one to us, so this is also how a rotation lands.
            if let roomId = room.id { try roomConversations.sync(roomId) }
            return Outcome(learnedKeyFor: room.id, note: "room updated")
        case .invitation(let from, let json):
            // Stored, because a collect that runs in the background is
            // exactly when one of these arrives, and an invitation that
            // only existed as a dialog nobody saw would be gone.
            if let info = try? RoomInfo.fromJson(json), let roomId = info.id {
                try invites.upsert(
                    RoomInvite(
                        roomId: roomId,
                        from: from,
                        roomInfoJson: json,
                        name: info.name,
                        receivedAt: message.timestamp ?? Int64(now.timeIntervalSince1970 * 1000)
                    )
                )
            }
            return Outcome(invitation: (from, json))
        case .ignored:
            return .nothing
        }
    }

    /// Carry a changed room record across into the row the chat list
    /// draws, for the notices that name their room in the content —
    /// which is every `ROOM_*` except `ROOM_INFO`, whose room is named
    /// inside its payload and which is handled where it is parsed.
    ///
    /// A room has no chain sync to repair this later, so a membership
    /// that changed here and not there is a header counting the room as
    /// it was, indefinitely.
    private func mirrorRoom(named roomId: String?) throws {
        guard let roomId, !roomId.isEmpty else { return }
        try roomConversations.sync(roomId)
    }

    // MARK: - keys

    /// Someone pushed us a key.
    ///
    /// **Overwriting an existing version needs the sender to be the
    /// entity's owner**, and that answer comes from the room or team
    /// record we already hold — never from the message. Without the
    /// rule, any member could push a bogus key at a version everyone
    /// already uses and make the whole history unreadable.
    private func routeSymkeyShare(
        _ message: ImMessage, as liveFid: String, now: Date
    ) throws -> Outcome {
        guard let privkey else { return Outcome(note: "no key to open a shared symkey with") }
        guard let payload = message.content,
              let (entityId, cipher) = SymkeyShare.parse(payload),
              let senderFid = message.senderId
        else { return .nothing }

        // A key for something we are not in is not a key we want. It
        // would sit in the store forever, and accepting it is how an
        // unsolicited "room" appears out of nowhere.
        guard isMember(of: entityId, fid: liveFid) else {
            return Outcome(note: "symkey for an entity we are not in")
        }

        let stored = try symkeys.receiveShared(
            cipher: cipher,
            for: entityId,
            version: message.symkeyVersion ?? SymkeyStore.minimumVersion,
            privkey: privkey,
            allowOverwrite: isOwner(of: entityId, fid: senderFid),
            now: now
        )
        return stored
            ? Outcome(learnedKeyFor: entityId, note: "key received for \(entityId)")
            : Outcome(note: "key not stored (already held, or would not open)")
    }

    /// Someone asked us for a key.
    ///
    /// We answer only for an entity we are both in, and only with a key
    /// we hold. Anything else is silence rather than an error: a request
    /// from a stranger is not a failure, it is a question with no answer.
    private func routeRequest(
        _ message: ImMessage, as liveFid: String, now: Date
    ) throws -> Outcome {
        guard let requestType = message.requestType else { return .nothing }
        guard let senderFid = message.senderId,
              let entityId = SymkeyShare.requestedEntityId(message.content)
        else { return .nothing }

        switch requestType {
        case .symkey:
            return try answerSymkeyRequest(
                entityId: entityId, from: senderFid, as: liveFid, now: now
            )
        case .roomInfo:
            return try answerRoomInfoRequest(
                roomId: entityId, from: senderFid, as: liveFid, now: now
            )
        default:
            return .nothing
        }
    }

    private func answerSymkeyRequest(
        entityId: String, from senderFid: String, as liveFid: String, now: Date
    ) throws -> Outcome {
        guard isMember(of: entityId, fid: liveFid), isMember(of: entityId, fid: senderFid) else {
            return Outcome(note: "key request from a non-member")
        }
        guard let pubkey = try pubkeys(senderFid) else {
            return Outcome(note: "no pubkey to seal a key to \(senderFid)")
        }

        let version = try symkeys.currentVersion(for: entityId)
        guard version >= SymkeyStore.minimumVersion else {
            return Outcome(note: "asked for a key we do not hold")
        }
        guard let reply = try KeyExchange.share(
            entityId: entityId, version: version, to: senderFid,
            recipientPubkey: pubkey, from: liveFid, symkeys: symkeys, now: now
        ) else { return Outcome(note: "could not seal the key") }

        return Outcome(outbound: [reply], note: "shared \(entityId) key v\(version)")
    }

    /// Someone in the room asked for its details.
    ///
    /// **Any member may answer, and that is not a hole.** The receiving
    /// side already knows what a non-owner's `ROOM_INFO` is worth:
    /// ``RoomService`` strips `members` and `owner` from it and keeps
    /// only the name, the description and the key. So a member's answer
    /// delivers the part that was usually missing, while only the
    /// owner's can rewrite who is in the room.
    private func answerRoomInfoRequest(
        roomId: String, from senderFid: String, as liveFid: String, now: Date
    ) throws -> Outcome {
        guard let room = try rooms.get(id: roomId) else {
            return Outcome(note: "asked about a room we do not have")
        }
        guard room.isOwner(liveFid) || room.isMember(liveFid) else {
            return Outcome(note: "asked about a room we are not in")
        }
        guard room.isOwner(senderFid) || room.isMember(senderFid) else {
            return Outcome(note: "room info request from a non-member")
        }

        // The same envelope an invitation uses, so the answer carries
        // the membership and the current key together — there is no
        // version of this where they should be applied separately.
        let reply = try roomService.invitation(
            for: room, to: senderFid, from: liveFid, pubkeys: pubkeys, now: now
        )
        return Outcome(outbound: [reply], note: "sent room details for \(roomId)")
    }

    // MARK: - membership

    /// Membership as *this device* understands it. A square is left out
    /// on purpose: it has no key, so nothing here has anything to say
    /// about one.
    private func isMember(of entityId: String, fid: String) -> Bool {
        if let room = try? rooms.get(id: entityId) {
            return room.isOwner(fid) || room.isMember(fid)
        }
        if let team = try? teams.get(id: entityId) {
            return team.isOwner(fid) || team.isMember(fid)
        }
        return false
    }

    private func isOwner(of entityId: String, fid: String) -> Bool {
        if let room = try? rooms.get(id: entityId) { return room.isOwner(fid) }
        if let team = try? teams.get(id: entityId) { return team.isOwner(fid) }
        return false
    }
}
