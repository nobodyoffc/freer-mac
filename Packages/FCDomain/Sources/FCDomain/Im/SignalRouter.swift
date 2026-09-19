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
    /// Where history asks and answers are kept. Nil turns the history
    /// exchange off, which is what a router built for key traffic alone
    /// wants.
    private let historyShares: HistorySharesStore?
    /// Only history needs a square: it is the one question a square's
    /// members can ask each other, since a square has no key.
    private let squares: SquaresStore?
    /// Where team invitation and transfer notices are kept. Nil drops
    /// them, as a router built for key traffic alone wants.
    private let teamOffers: TeamOffersStore?
    /// The key requests this device has outstanding, which is how a
    /// member's answer is told from an unsolicited push (FIMP §4.2).
    ///
    /// **Nil is not permissive.** A router with no ask record knows of no
    /// request, so a non-owner's key is unsolicited and is dropped — the
    /// same answer it would give if the record were there and empty. A
    /// security rule that switches itself off when a dependency is
    /// missing is a rule that is off in the one build nobody checked.
    private let keyAsks: KeyAsksStore?
    /// Where every key in and out is written down — FIMP §9.7. Nil keeps
    /// no record, which only a router built for a test wants: a device
    /// that hands out keys and remembers nothing cannot answer who can
    /// read what.
    private let keyLedger: KeyLedger?

    public init(
        rooms: RoomsStore,
        teams: TeamsStore,
        symkeys: SymkeyStore,
        invites: RoomInvitesStore,
        roomService: RoomService,
        roomConversations: RoomConversations,
        privkey: Data?,
        pubkeys: @escaping (String) throws -> Data? = { _ in nil },
        historyShares: HistorySharesStore? = nil,
        squares: SquaresStore? = nil,
        teamOffers: TeamOffersStore? = nil,
        keyAsks: KeyAsksStore? = nil,
        keyLedger: KeyLedger? = nil
    ) {
        self.rooms = rooms
        self.teams = teams
        self.symkeys = symkeys
        self.invites = invites
        self.roomService = roomService
        self.roomConversations = roomConversations
        self.privkey = privkey
        self.pubkeys = pubkeys
        self.historyShares = historyShares
        self.squares = squares
        self.teamOffers = teamOffers
        self.keyAsks = keyAsks
        self.keyLedger = keyLedger
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
        /// Somebody asked for a conversation's messages. Stored for a
        /// person to answer, like an invitation.
        public var historyRequest: IncomingHistoryRequest?
        /// An answer to one of our history asks, stored for
        /// ``HistoryShareService/importReceived(now:)`` to fetch.
        public var historyReceived: ReceivedHistoryShare?
        /// A team invitation or transfer this device had not heard of.
        /// Only a hint — see ``TeamNotice``.
        public var teamNotice: TeamNotice?
        public var note: String?

        public init(
            outbound: [ImMessage] = [],
            invitation: (from: String, roomInfoJson: String)? = nil,
            learnedKeyFor: String? = nil,
            historyRequest: IncomingHistoryRequest? = nil,
            historyReceived: ReceivedHistoryShare? = nil,
            teamNotice: TeamNotice? = nil,
            note: String? = nil
        ) {
            self.outbound = outbound
            self.invitation = invitation
            self.learnedKeyFor = learnedKeyFor
            self.historyRequest = historyRequest
            self.historyReceived = historyReceived
            self.teamNotice = teamNotice
            self.note = note
        }

        /// Whether routing changed anything a person or a later pass
        /// will see.
        public var acted: Bool {
            !outbound.isEmpty || invitation != nil || learnedKeyFor != nil
                || historyRequest != nil || historyReceived != nil
                || teamNotice != nil
        }

        public static func == (a: Outcome, b: Outcome) -> Bool {
            a.outbound == b.outbound
                && a.invitation?.from == b.invitation?.from
                && a.invitation?.roomInfoJson == b.invitation?.roomInfoJson
                && a.learnedKeyFor == b.learnedKeyFor
                && a.historyRequest == b.historyRequest
                && a.historyReceived == b.historyReceived
                && a.teamNotice == b.teamNotice
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
        case .history:
            return try routeHistoryAnswer(message, as: liveFid, now: now)
        case .text:
            // Only a team notice reaches here as a signal — see
            // ``ChatService/receive(_:as:privkey:now:)``.
            return try routeTeamNotice(message, as: liveFid, now: now)
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
            try mirrorRoom(named: message.content)
            return Outcome(note: "a room was closed by its owner")
        case .removed:
            try mirrorRoom(named: message.content)
            return Outcome(note: "removed from a room")
        case .updated(let room):
            // An update carries the current key when the owner could
            // seal one to us, so this is also how a rotation lands.
            if let roomId = room.id {
                try roomConversations.sync(roomId)
                // A `ROOM_INFO` does not say which request it answers, so
                // what settles an outstanding ask is whether the key it
                // brought is the one we were waiting for.
                _ = try keyAsks?.resolve(
                    entityId: roomId, heldVersions: Set(try symkeys.versions(for: roomId))
                )
            }
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
    /// **Nothing is overwritten, so there is no longer an authority to
    /// check here.** This used to hand ``SymkeyStore`` an
    /// `allowOverwrite` granted when the sender owned the entity, which
    /// meant an owner's key at an existing version replaced the row and
    /// destroyed every message sealed under the displaced key. A key
    /// that differs from one we hold at the same version is now kept
    /// beside it and tried when opening, so a bogus key is a candidate
    /// that fails its tag rather than a loss.
    ///
    /// **Who may push at all is the check that remains**, and it is
    /// ``admits(version:for:from:answering:)``: the entity's owner, one
    /// of our own devices, or an answer to a request we actually made.
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

        let version = message.symkeyVersion ?? SymkeyStore.minimumVersion
        let solicited = try keyAsks?.isSolicited(
            entityId: entityId, version: version, requestId: message.requestId
        ) ?? false
        guard try admits(
            version: version, for: entityId, from: senderFid,
            as: liveFid, answering: message.requestId
        ) else {
            try note(
                entityId: entityId, version: version, counterparty: senderFid,
                direction: .received, outcome: .refused, solicited: false,
                requestId: message.requestId, now: now
            )
            return Outcome(note: "unsolicited key from \(senderFid) for \(entityId) — dropped")
        }

        // Whether we already held it has to be asked before storing, or
        // the two answers are indistinguishable afterwards: `store`
        // returns false both for a duplicate and for a cipher that would
        // not open, and those mean opposite things to whoever reads this
        // row — one is a second member answering, the other is a key we
        // were handed and cannot use.
        let heldBefore = try symkeys.has(entityId: entityId, version: version)
            ? Set(try symkeys.keys(for: entityId, version: version))
            : []
        let stored = try symkeys.receiveShared(
            cipher: cipher,
            for: entityId,
            version: version,
            privkey: privkey,
            now: now
        )
        guard stored else {
            let held = Set(try symkeys.keys(for: entityId, version: version))
            try note(
                entityId: entityId, version: version, counterparty: senderFid,
                direction: .received,
                outcome: held == heldBefore && !held.isEmpty ? .duplicate : .unreadable,
                solicited: solicited, requestId: message.requestId, now: now
            )
            return Outcome(note: "key not stored (already held, or would not open)")
        }
        try note(
            entityId: entityId, version: version, counterparty: senderFid,
            direction: .received, outcome: .stored, solicited: solicited,
            requestId: message.requestId, now: now
        )
        // The question this answers is over. Resolving on a *stored* key
        // rather than on arrival is deliberate: a cipher that would not
        // open left us no better off, and the ask has to stay outstanding
        // for whoever else was asked.
        _ = try keyAsks?.resolve(entityId: entityId, version: version)
        return Outcome(learnedKeyFor: entityId, note: "key received for \(entityId)")
    }

    /// Write one key event down — FIMP §9.7. A ledger that is not there
    /// keeps nothing, and that is never a reason to fail the exchange:
    /// the record exists to be read later, and losing a row must not cost
    /// somebody the key.
    private func note(
        entityId: String,
        version: Int64,
        counterparty: String,
        direction: KeyLedgerEntry.Direction,
        outcome: KeyLedgerEntry.Outcome,
        solicited: Bool,
        requestId: String?,
        now: Date
    ) throws {
        guard let keyLedger else { return }
        do {
            try keyLedger.record(
                entityId: entityId, version: version, counterparty: counterparty,
                direction: direction, outcome: outcome, solicited: solicited,
                requestId: requestId, now: now
            )
        } catch {
            SystemLog.shared.warning(
                SystemSource.messages,
                "Could not record a key exchange with \(counterparty.middleElided())",
                detail: "\(error)"
            )
        }
    }

    /// Whether a delivered key may be stored at all — FIMP §4.2.
    ///
    /// Three ways in, and no fourth:
    ///
    /// 1. **The owner.** The one party whose unsolicited key is expected,
    ///    because pushing after a rotation is their job.
    /// 2. **Ourselves.** A message signed by our own key came from a
    ///    device holding our prikey, which is this identity by
    ///    definition — and a second Mac signed in here, holding keys
    ///    this one lost, is the only copy a reinstalled owner has. The
    ///    signature is the proof; nothing else is taken on trust.
    /// 3. **An answer we asked for**, matched by `requestId` against
    ///    ``KeyAsksStore``.
    ///
    /// Everything else is dropped rather than stored. A member who was
    /// not asked has no business writing to the store that decides what
    /// this device can read, and since ``SymkeyStore`` overwrites
    /// nothing, admitting them would let any member add rows to any
    /// other member's key store indefinitely.
    private func admits(
        version: Int64,
        for entityId: String,
        from senderFid: String,
        as liveFid: String,
        answering requestId: String?
    ) throws -> Bool {
        if isOwner(of: entityId, fid: senderFid) { return true }
        if senderFid == liveFid { return true }
        return try keyAsks?.isSolicited(
            entityId: entityId, version: version, requestId: requestId
        ) ?? false
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
        // Its content is a JSON object, not an entity id, so it cannot
        // share the guard below.
        if requestType == .history {
            return try routeHistoryRequest(message, as: liveFid, now: now)
        }
        guard let senderFid = message.senderId else { return .nothing }

        // A batch names a comma-separated list, so it parses differently
        // from everything else here.
        if requestType == .symkeyHistory {
            guard let asked = SymkeyShare.requestedHistory(message.content) else { return .nothing }
            return try answerSymkeyHistoryRequest(
                entityId: asked.entityId, versions: asked.versions,
                from: senderFid, as: liveFid, answering: message.id, now: now
            )
        }

        guard let asked = SymkeyShare.requested(message.content) else { return .nothing }
        let entityId = asked.entityId

        switch requestType {
        case .symkey:
            return try answerSymkeyRequest(
                entityId: entityId, version: asked.version,
                from: senderFid, as: liveFid, answering: message.id, now: now
            )
        case .roomInfo:
            return try answerRoomInfoRequest(
                roomId: entityId, from: senderFid, as: liveFid, now: now
            )
        default:
            return .nothing
        }
    }

    /// `version` is the one the requester named, or nil for "whatever
    /// you have now" — FIMP4V3 §5.1.
    ///
    /// **A named version is answered with that version or not at all.**
    /// Substituting our current key for the one asked for is worse than
    /// silence: it looks like a successful exchange, the requester
    /// stores a key it very likely already had, and the messages it
    /// cannot read stay unreadable with nothing to show why. Silence at
    /// least leaves the request outstanding for a member who does hold
    /// it.
    private func answerSymkeyRequest(
        entityId: String, version wanted: Int64? = nil,
        from senderFid: String, as liveFid: String,
        answering requestId: String? = nil, now: Date
    ) throws -> Outcome {
        guard isMember(of: entityId, fid: liveFid), isMember(of: entityId, fid: senderFid) else {
            try note(
                entityId: entityId, version: wanted ?? KeyAsksStore.currentVersion,
                counterparty: senderFid, direction: .sent, outcome: .notAMember,
                solicited: true, requestId: requestId, now: now
            )
            return Outcome(note: "key request from a non-member")
        }
        guard let pubkey = try pubkeys(senderFid) else {
            try note(
                entityId: entityId, version: wanted ?? KeyAsksStore.currentVersion,
                counterparty: senderFid, direction: .sent, outcome: .noPubkey,
                solicited: true, requestId: requestId, now: now
            )
            return Outcome(note: "no pubkey to seal a key to \(senderFid)")
        }

        let version = try wanted ?? symkeys.currentVersion(for: entityId)
        guard version >= SymkeyStore.minimumVersion,
              try symkeys.has(entityId: entityId, version: version)
        else {
            try note(
                entityId: entityId, version: version, counterparty: senderFid,
                direction: .sent, outcome: .notHeld, solicited: true,
                requestId: requestId, now: now
            )
            return Outcome(note: "asked for \(entityId) key v\(version), which we do not hold")
        }
        let replies = try KeyExchange.share(
            entityId: entityId, version: version, to: senderFid,
            recipientPubkey: pubkey, from: liveFid, symkeys: symkeys,
            answering: requestId, now: now
        )
        guard !replies.isEmpty else { return Outcome(note: "could not seal the key") }

        try note(
            entityId: entityId, version: version, counterparty: senderFid,
            direction: .sent, outcome: .shared, solicited: true,
            requestId: requestId, now: now
        )
        return Outcome(outbound: replies, note: "shared \(entityId) key v\(version)")
    }

    /// Answer a batch — one `SYMKEY` per version we hold, all carrying
    /// the request's id (FIMP4V3 §5.2, FIMP2V3 §5.3).
    ///
    /// **Versions we do not hold are simply absent from the answer**, as
    /// for a single version: a batch of eight where we hold five is five
    /// keys the asker needs, and refusing because of the other three
    /// would leave them with none. The asker learns what arrived by what
    /// opens, which is the only thing they can act on anyway.
    ///
    /// The membership check is the same one and is made once: it is a
    /// property of the asker, not of any version.
    private func answerSymkeyHistoryRequest(
        entityId: String, versions: [Int64],
        from senderFid: String, as liveFid: String,
        answering requestId: String?, now: Date
    ) throws -> Outcome {
        guard isMember(of: entityId, fid: liveFid), isMember(of: entityId, fid: senderFid) else {
            try note(
                entityId: entityId, version: KeyAsksStore.currentVersion,
                counterparty: senderFid, direction: .sent, outcome: .notAMember,
                solicited: true, requestId: requestId, now: now
            )
            return Outcome(note: "key history request from a non-member")
        }
        guard let pubkey = try pubkeys(senderFid) else {
            try note(
                entityId: entityId, version: KeyAsksStore.currentVersion,
                counterparty: senderFid, direction: .sent, outcome: .noPubkey,
                solicited: true, requestId: requestId, now: now
            )
            return Outcome(note: "no pubkey to seal keys to \(senderFid)")
        }

        var outbound: [ImMessage] = []
        var shared: [Int64] = []
        for version in versions {
            guard try symkeys.has(entityId: entityId, version: version) else {
                // A row per version asked for and not held: a member
                // asking repeatedly for a version nobody has is a stalled
                // recovery somebody can act on.
                try note(
                    entityId: entityId, version: version, counterparty: senderFid,
                    direction: .sent, outcome: .notHeld, solicited: true,
                    requestId: requestId, now: now
                )
                continue
            }
            let replies = try KeyExchange.share(
                entityId: entityId, version: version, to: senderFid,
                recipientPubkey: pubkey, from: liveFid, symkeys: symkeys,
                answering: requestId, now: now
            )
            guard !replies.isEmpty else { continue }
            outbound.append(contentsOf: replies)
            shared.append(version)
            try note(
                entityId: entityId, version: version, counterparty: senderFid,
                direction: .sent, outcome: .shared, solicited: true,
                requestId: requestId, now: now
            )
        }
        guard !outbound.isEmpty else {
            return Outcome(note: "asked for \(entityId) keys we do not hold")
        }
        return Outcome(
            outbound: outbound,
            note: "shared \(entityId) keys \(shared.map { "v\($0)" }.joined(separator: ", "))"
        )
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

    // MARK: - history

    /// Somebody asked for a conversation's messages.
    ///
    /// **Never answered here.** Handing over a transcript hands over
    /// what *other* people said in it, so a person decides — this only
    /// checks that the question is one they could legitimately be asked,
    /// and keeps it. Membership is this device's understanding, as for a
    /// key request, and the asker's claim about the thread is turned
    /// round for P2P rather than trusted (see
    /// ``HistoryRequestPayload/responderConversation(requester:as:)``).
    private func routeHistoryRequest(
        _ message: ImMessage, as liveFid: String, now: Date
    ) throws -> Outcome {
        guard let historyShares else { return .nothing }
        guard let senderFid = message.senderId,
              let nonce = message.requestId, !nonce.isEmpty,
              let payload = HistoryRequestPayload.parse(message.content)
        else { return Outcome(note: "unreadable history request") }

        // Our own ask, collected back off our own DOCK on its way to our
        // other device. It is not a question for us.
        if senderFid == liveFid, try historyShares.ask(nonce: nonce) != nil {
            return .nothing
        }
        guard let (type, targetId) = payload.responderConversation(requester: senderFid, as: liveFid) else {
            return Outcome(note: "history request from \(senderFid) about a chat they are not in")
        }
        if type != .p2p {
            guard isInGroup(type, targetId, fid: liveFid), isInGroup(type, targetId, fid: senderFid) else {
                return Outcome(note: "history request from a non-member")
            }
        }

        let request = IncomingHistoryRequest(
            nonce: nonce,
            from: senderFid,
            type: type,
            targetId: targetId,
            since: payload.since,
            before: payload.before,
            receivedAt: message.timestamp ?? Int64(now.timeIntervalSince1970 * 1000),
            requestedTargetId: payload.targetId
        )
        try historyShares.recordIncoming(request)
        return Outcome(historyRequest: request, note: "\(senderFid) asked for message history")
    }

    /// An answer arrived. Kept only when it answers an ask of ours, from
    /// the person we asked — Android checks the nonce and not the sender,
    /// so anyone who saw a nonce could answer in the asked member's
    /// place.
    private func routeHistoryAnswer(
        _ message: ImMessage, as liveFid: String, now: Date
    ) throws -> Outcome {
        guard let historyShares else { return .nothing }
        guard let nonce = message.requestId, !nonce.isEmpty,
              let ask = try historyShares.ask(nonce: nonce)
        else { return Outcome(note: "unsolicited history share") }
        guard let senderFid = message.senderId, senderFid == ask.askedFid else {
            return Outcome(note: "history share from someone who was not asked")
        }
        guard let hatJson = message.content, !hatJson.isEmpty else {
            return Outcome(note: "history share with nothing in it")
        }

        let share = ReceivedHistoryShare(
            nonce: nonce,
            from: senderFid,
            conversationId: ask.conversationId,
            since: ask.since,
            before: ask.before,
            hatJson: hatJson,
            receivedAt: Int64(now.timeIntervalSince1970 * 1000)
        )
        try historyShares.recordReceived(share)
        try historyShares.removeAsk(nonce: nonce)
        return Outcome(historyReceived: share, note: "history arrived from \(senderFid)")
    }

    // MARK: - teams

    /// Somebody says a team invited us, or is being handed to us.
    ///
    /// **Kept as an unconfirmed offer, and nothing more.** Whether the
    /// team really lists us is a question for the chain, which the
    /// offers sheet asks before anything is carved. What is worth
    /// refusing here is only what this device can already see is
    /// stale: an invitation to a team we are in.
    private func routeTeamNotice(
        _ message: ImMessage, as liveFid: String, now: Date
    ) throws -> Outcome {
        guard let teamOffers else { return .nothing }
        guard let notice = TeamNotice.parse(message.content),
              let senderFid = message.senderId
        else { return .nothing }
        // Our own notice, read back off our own DOCK.
        guard senderFid != liveFid else { return .nothing }
        if notice.kind == .invitation,
           let team = try? teams.get(id: notice.teamId), team.isMember(liveFid) {
            return Outcome(note: "team invitation to a team we are already in")
        }
        let raised = try teamOffers.note(notice, from: senderFid, for: liveFid, now: now)
        return Outcome(
            teamNotice: raised ? notice : nil,
            note: "\(senderFid) says team \(notice.teamId) \(notice.kind == .transfer ? "is being handed to us" : "invited us")"
        )
    }

    /// Membership of a group of a named flavour. Unlike ``isMember(of:fid:)``
    /// this includes squares, since a square's transcript is as much a
    /// member's to ask for as a team's.
    private func isInGroup(_ type: ImType, _ id: String, fid: String) -> Bool {
        switch type {
        case .room:
            guard let room = try? rooms.get(id: id) else { return false }
            return room.isOwner(fid) || room.isMember(fid)
        case .team:
            guard let team = try? teams.get(id: id) else { return false }
            return team.isOwner(fid) || team.isMember(fid)
        case .square:
            guard let square = (try? squares?.get(id: id)) ?? nil else { return false }
            return square.isMember(fid)
        case .p2p:
            return false
        }
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
