import Foundation
import FCCore
import FCStorage
import FCTransport

/// The thing that actually moves messages: drains the outbox onto a
/// DOCK, and collects what a DOCK is holding for us.
///
/// Everything below it was built to be driven from here —
/// ``DeliveryPolicy`` decided the route order, ``MessageQueue`` decided
/// what is due and what an outcome means, ``HomeServiceResolver`` turned
/// a `home` map into an address, ``DockService`` speaks the protocol,
/// and ``ChatService`` files what arrives. This is the loop that joins
/// them, and it is deliberately thin: it makes no decisions of its own,
/// so every rule stays in the tested piece that owns it.
///
/// **DOCK only, for now.** ``DeliveryPolicy`` plans three routes and
/// this takes the third. FUDP direct and ROAD relay are latency
/// optimisations that Android keeps behind settings that default to
/// off; DOCK works whether or not the recipient is there, so a courier
/// that speaks only DOCK is slower than the finished thing and not less
/// capable. Nothing here assumes it is the only route — a plan with
/// `.fudpDirect` first simply finds no sender for it yet and falls
/// through, which is the same path a peer being unreachable takes.
///
/// **There is no single DOCK.** Both directions here run against
/// ``DockRegistry``, because every party keeps its own server: a send
/// connects to the *recipient's* DOCK and only falls back to asking
/// ours to forward, and a collect polls our DOCK **and every group's**,
/// since a group's messages rest where the group lives. Routing all of
/// it through one connection is what limited sending to parties sharing
/// our server and stopped group messages arriving at all.
public struct MessageCourier {

    private let outbox: MessageQueue
    private let messages: MessagesStore
    private let chat: ChatService
    private let peers: PeerBook
    /// Our own DOCK — the one route that is not addressed by URL,
    /// because it is whatever server ``fapi`` already points at. Used
    /// for forwarding, and for the explicit-recipients collect.
    private let dock: DockService
    private let resolver: HomeServiceResolver
    private let directory: DirectoryService
    /// Who lives on which server, and a client for each.
    private let registry: DockRegistry

    /// Where a group's `home` map comes from. Supplied by the app so
    /// this type can look up a team's DOCK without reaching into three
    /// stores it does not own — and so that the group syncs stay the
    /// single copy of that answer.
    private let groupHome: (@Sendable (String) -> [String: String]?)?

    /// Where a signal goes. Supplied as a closure rather than as a
    /// ``SignalRouter`` so this type keeps knowing nothing about rooms,
    /// teams or keys — it only knows that something else decides, and
    /// that whatever comes back may need queueing.
    private let routeSignal: (@Sendable (ImMessage, String, Date) throws -> SignalRouter.Outcome)?
    /// Whether a square message's sender is a member (FIMP3V2 §8). Nil
    /// keeps every square message, which is what tests without a chain
    /// want.
    private let squareSender: (@Sendable (_ sender: String, _ squareId: String, _ storedAt: Int64?) async -> SquareRoster.Answer)?
    /// The prikey of a FID this device holds: every envelope is signed with
    /// its sender's key, and a P2P message queued in the clear is sealed
    /// with it. Nil means no key is on hand, and nothing can be sent.
    private let prikeyFor: (@Sendable (_ fid: String) -> Data?)?
    /// Messages already taken in, by author and id. Nil does no replay
    /// check, which is what tests that re-read on purpose want.
    private let seen: SeenMessagesStore?
    /// The asks this device has outstanding. Nil turns automatic asking
    /// off, which is what a courier built for sending alone wants.
    private let keyAsks: KeyAsksStore?

    /// ``outbox`` and ``messages`` must be over the same
    /// ``EncryptedKVStore``: a delivery writes to both in one
    /// transaction. Every session builds them from its one store.
    public init(
        outbox: MessageQueue,
        messages: MessagesStore,
        chat: ChatService,
        peers: PeerBook,
        dock: DockService,
        resolver: HomeServiceResolver,
        directory: DirectoryService,
        registry: DockRegistry,
        groupHome: (@Sendable (String) -> [String: String]?)? = nil,
        routeSignal: (@Sendable (ImMessage, String, Date) throws -> SignalRouter.Outcome)? = nil,
        squareSender: (@Sendable (_ sender: String, _ squareId: String, _ storedAt: Int64?) async -> SquareRoster.Answer)? = nil,
        prikeyFor: (@Sendable (_ fid: String) -> Data?)? = nil,
        seen: SeenMessagesStore? = nil,
        keyAsks: KeyAsksStore? = nil
    ) {
        self.prikeyFor = prikeyFor
        self.seen = seen
        self.keyAsks = keyAsks
        self.groupHome = groupHome
        self.squareSender = squareSender
        self.routeSignal = routeSignal
        self.outbox = outbox
        self.messages = messages
        self.chat = chat
        self.peers = peers
        self.dock = dock
        self.resolver = resolver
        self.directory = directory
        self.registry = registry
    }

    public struct SendReport: Equatable, Sendable {
        public let attempted: Int
        public let sent: Int
        public let retrying: Int
        public let failed: Int
        /// Due, but claimed by a drain that was already under way. Not a
        /// failure of any kind — it is the count of envelopes that were
        /// not sent twice.
        public let skipped: Int

        public init(
            attempted: Int, sent: Int, retrying: Int, failed: Int, skipped: Int = 0
        ) {
            self.attempted = attempted
            self.sent = sent
            self.retrying = retrying
            self.failed = failed
            self.skipped = skipped
        }
    }

    /// Which of the registered DOCKs a collect should touch.
    ///
    /// The two-lane split exists because polling is a trade between
    /// latency and traffic: the conversation on screen wants an answer
    /// in seconds, and the twenty servers behind the other threads do
    /// not. Matching is by endpoint, not by string, so a selection can
    /// be built from a `home` value and still match a normalised
    /// registration — see ``FudpUrl``.
    public enum DockSelection: Equatable, Sendable {
        case all
        /// Only these — the fast lane.
        case only(Set<String>)
        /// Everything but these — the slow lane, skipping whatever the
        /// fast lane is already covering so the same server is not
        /// polled twice per cycle.
        case excluding(Set<String>)

        func includes(_ dockUrl: String) -> Bool {
            switch self {
            case .all:
                return true
            case .only(let urls):
                return urls.contains { FudpUrl.sameEndpoint($0, dockUrl) }
            case .excluding(let urls):
                return !urls.contains { FudpUrl.sameEndpoint($0, dockUrl) }
            }
        }

        var isEmptySelection: Bool {
            if case .only(let urls) = self { return urls.isEmpty }
            return false
        }
    }

    /// Hand one signal to the router, and queue whatever it answers
    /// with. Returns 1 when something actually happened, so a collect
    /// can report it.
    ///
    /// Anything the router produces is **queued, not sent**: the reply
    /// to a key request goes into the outbox and leaves on the next
    /// drain, exactly like a message the user typed. A collect that also
    /// sent would be two loops in one, and the second would be the one
    /// nobody remembered to retry.
    private func route(_ signal: ImMessage, as liveFid: String, now: Date) -> Int {
        guard let routeSignal else { return 0 }
        guard let outcome = try? routeSignal(signal, liveFid, now) else { return 0 }

        for reply in outcome.outbound {
            guard let to = reply.targetId else { continue }
            _ = try? outbox.enqueue(reply, in: Conversation.id(type: .p2p, targetId: to))
        }
        // **A key that arrives is retroactive.** The rows already filed
        // sealed under it are kept precisely so they can be opened later
        // (``ChatService/receive(_:as:privkey:now:)``), and until this
        // was here nothing ever went back for them: the key was stored,
        // `learnedKeyFor` was returned, and the transcript went on
        // saying the key was not held. Android has always done this
        // (`ImManager.redecryptPendingMessages`).
        if let entityId = outcome.learnedKeyFor {
            let opened = (try? chat.openSealed(forEntity: entityId, as: liveFid)) ?? []
            if !opened.isEmpty {
                SystemLog.shared.info(
                    SystemSource.messages,
                    "Opened \(opened.count) message(s) with the key for \(entityId.middleElided())"
                )
            }
        }
        if let note = outcome.note {
            SystemLog.shared.info(SystemSource.dock, note)
        }
        return outcome.acted ? 1 : 0
    }

    /// A message we filed but could not open: ask the one member who
    /// certainly holds the key — whoever sent it.
    ///
    /// **Automatic, because the alternative is that nothing happens.**
    /// FIMP §7.4 says recovery asks for the missing version, and until
    /// now the only thing that ever asked was a person opening a sheet
    /// and picking members by hand. A device that files a locked row and
    /// says nothing to anybody leaves the user to notice, guess who to
    /// ask, and ask — for a key the sender is provably holding.
    ///
    /// The sender is the right first question for the same reason: every
    /// other member *might* hold that version, while the sender sealed a
    /// message with it. Asking more members is the escalation a person
    /// chooses, and it is the sheet's job.
    ///
    /// Paced by ``KeyAsksStore/cooldown`` per person per version, so a
    /// backlog of a hundred locked rows under three versions is three
    /// questions, not a hundred. Enqueued rather than sent, like
    /// everything else a collect produces.
    private func ask(
        for message: ImMessage, version: Int64?, as liveFid: String, now: Date
    ) {
        guard let keyAsks,
              let entityId = message.targetId, !entityId.isEmpty,
              let sender = message.senderId, !sender.isEmpty,
              message.type == .team || message.type == .room
        else { return }
        // A version we cannot name is one we cannot ask for: a request
        // naming none asks for the current key, which is the one this
        // row is already telling us we do not need.
        guard let version, version >= SymkeyStore.minimumVersion else { return }

        let askable = (try? keyAsks.askable([sender], entityId: entityId, version: version, now: now))
        guard let allowed = askable?.allowed, !allowed.isEmpty else { return }

        let request = KeyExchange.request(
            entityId: entityId, version: version, from: liveFid, to: sender, now: now
        )
        guard let requestId = request.id else { return }
        do {
            try outbox.enqueue(request, in: Conversation.id(type: .p2p, targetId: sender))
            try keyAsks.record(
                entityId: entityId, version: version, kind: .symkey,
                sent: [(fid: sender, requestId: requestId)], now: now
            )
            SystemLog.shared.info(
                SystemSource.messages,
                "Asked \(sender.middleElided()) for the key v\(version) that \(entityId.middleElided()) needs"
            )
        } catch {
            // The row is filed and locked either way; the ask is retried
            // on the next collect that sees it.
            SystemLog.shared.warning(
                SystemSource.messages,
                "Could not queue a key request for \(entityId.middleElided())",
                detail: "\(error)"
            )
        }
    }

    public struct ReceiveReport: Equatable, Sendable {
        public let fetched: Int
        /// Filed into a transcript.
        public let filed: Int
        /// Kept but not openable — the cue to ask for a key.
        public let sealed: Int
        /// Held as message requests — from senders this identity has
        /// not agreed to hear from. Counted apart from `filed` because
        /// they are deliberately *not* in any conversation.
        public let held: Int
        /// Signals that were acted on: a room notification applied, a
        /// key stored, a key request answered.
        public let routed: Int
        /// Receipts, signals and things addressed to nobody we know.
        public let other: Int

        public init(
            fetched: Int, filed: Int, sealed: Int,
            held: Int = 0, routed: Int = 0, other: Int
        ) {
            self.fetched = fetched
            self.filed = filed
            self.sealed = sealed
            self.held = held
            self.routed = routed
            self.other = other
        }

        /// A pass that found nothing — what a caller reports when it
        /// could not even start.
        public static let none = ReceiveReport(fetched: 0, filed: 0, sealed: 0, held: 0, routed: 0, other: 0)
    }

    // MARK: - sending

    /// Attempt every message that is due.
    ///
    /// One pass, not a loop: *when* to run this is the app's business —
    /// on send, on wake, on a timer — and a courier that owned its own
    /// schedule would be a second place to look when messages stop
    /// moving.
    ///
    /// `ownDockUrl` names our own server, so a put aimed at it can drop
    /// the forwarding field. Omit it and the ``DockRegistry`` is asked
    /// instead, which is what the app does — passing it explicitly is
    /// for tests that run without a configured registry.
    @discardableResult
    public func drainOutbox(
        as liveFid: String,
        ownDockUrl: String? = nil,
        now: Date = Date(),
        timeoutMs: Int = 15_000
    ) async throws -> SendReport {
        let due = try outbox.due(now: now)
        var sent = 0, retrying = 0, failed = 0, skipped = 0
        var ownDock = ownDockUrl
        if ownDock == nil { ownDock = await registry.ownDockUrl }

        for queued in due {
            // **Claimed, not just read.** This pass is one of several —
            // a thirty-second timer, and every screen that sends
            // something — and the gap between listing what is due and
            // attempting it is wide enough for another drain to walk
            // through. The one that loses the claim skips the message
            // rather than putting a second copy of it on the recipient's
            // DOCK.
            guard let claimed = try? outbox.claim(id: queued.id, now: now) else {
                skipped += 1
                continue
            }
            let outcome = await deliver(
                claimed, as: liveFid, ownDockUrl: ownDock, now: now, timeoutMs: timeoutMs
            )
            switch outcome {
            case .sent: sent += 1
            case .retrying: retrying += 1
            case .failed: failed += 1
            case .unknown: break
            }
        }
        return SendReport(
            attempted: due.count - skipped, sent: sent, retrying: retrying,
            failed: failed, skipped: skipped
        )
    }

    /// Tell the sender their message arrived.
    ///
    /// Without this a peer's message sits at `sent` forever: the status
    /// past `sent` is not something a sender can observe, only something
    /// the recipient can report. Android sends one of these for every
    /// message it takes off a DOCK, and expects the same back.
    ///
    /// Delivery only. The jump to `read` is a user action, not an
    /// arrival, and is sent when a thread is opened —
    /// ``ChatService/markRead(_:now:)`` returns what is owed.
    ///
    /// Failing to acknowledge must not fail the collect: the message is
    /// already filed, and losing a receipt costs the sender a status
    /// update, not the message. So every path here logs and returns.
    private func acknowledgeDelivery(
        of message: ImMessage, as liveFid: String, privkey: Data?, now: Date
    ) async {
        guard message.type == .p2p else { return }
        guard let senderId = message.senderId, senderId != liveFid else { return }
        guard let privkey else { return }
        guard let pubkey = await peerPubkey(senderId) else {
            SystemLog.shared.warning(
                SystemSource.messages,
                "No pubkey for \(senderId.middleElided()), so their message cannot be acknowledged",
                detail: "They will see it as sent rather than delivered."
            )
            return
        }
        do {
            try chat.acknowledge(
                message, kind: .delivered, as: liveFid,
                keys: .init(privkey: privkey, recipientPubkey: pubkey), now: now
            )
        } catch {
            SystemLog.shared.warning(
                SystemSource.messages,
                "Could not acknowledge a message from \(senderId.middleElided())",
                detail: String(describing: error)
            )
        }
    }

    /// A peer's published public key, from their on-chain record.
    ///
    /// Nil is an ordinary answer: a FID that has never spent has never
    /// published a key, and there is nothing to seal a receipt to.
    private func peerPubkey(_ fid: String, timeoutMs: Int = 10_000) async -> Data? {
        let freer = try? await directory.freerByIds([fid], timeoutMs: timeoutMs)[fid]
        return freer?.pubkey.flatMap { Data(fcHex: $0) }
    }

    /// What one message to `targetId` may weigh, in bytes.
    ///
    /// The same question ``overBudget(_:dockUrl:id:targetId:)`` asks at
    /// send time, asked *before* composing — which is what a caller
    /// building an inline payload needs, since the alternative is
    /// discovering the ceiling with a message already queued that can
    /// never move. A voice note is the case that matters: it is the one
    /// payload the user can make arbitrarily large without picking a
    /// file, so ``VoiceNote`` measures against this and takes the
    /// DISK-and-HAT path when it does not fit.
    ///
    /// Falls back to ``ImMessage/assumedDockItemLimit`` when the route
    /// cannot be resolved, which is the same assumption the delivery
    /// path makes: a guess that is right for an unconfigured server and
    /// conservative for every other.
    public func itemBudget(forTarget targetId: String, type: ImType?) async -> Int {
        let home = await home(of: targetId, type: type)
        guard let dockUrl = await resolver.dockUrl(home: home) else {
            return ImMessage.assumedDockItemLimit
        }
        return await resolver.dockItemLimit(url: dockUrl)
    }

    /// Whether `envelope` is too large for `dockUrl` to accept — the
    /// reason string if so, nil if it fits.
    ///
    /// The budget belongs to the **destination**, so it is checked per
    /// route rather than once per message: two DOCKs may advertise
    /// different ceilings, and the one that matters is the one we are
    /// about to post to.
    ///
    /// The measurement is of the fully encoded envelope, because that byte
    /// string is exactly what `dock.put` receives — not of the body, and
    /// not of the payload before framing and sealing.
    ///
    /// This is permanent, not transient. A message that does not fit will
    /// not fit later either; retrying it would burn the queue against a
    /// server that is behaving correctly. The fix is upstream — the
    /// payload belongs on a DISK, referenced by a HAT.
    private func overBudget(
        _ envelope: Data, dockUrl: String, id: String, targetId: String
    ) async -> String? {
        let budget = await resolver.dockItemLimit(url: dockUrl)
        guard envelope.count > budget else { return nil }
        SystemLog.shared.error(
            SystemSource.messages,
            "Message to \(targetId.middleElided()) is too large for its DOCK",
            detail: "\(envelope.count) bytes against a \(budget)-byte limit at \(dockUrl). "
                + "Send the payload to a DISK and share it as a HAT instead."
        )
        return "over the \(budget)-byte limit at \(dockUrl) (\(envelope.count) bytes)"
    }

    private func deliver(
        _ queued: QueuedMessage,
        as liveFid: String,
        ownDockUrl: String?,
        now: Date,
        timeoutMs: Int
    ) async -> MessageQueue.Outcome {
        guard let id = queued.message.id, let targetId = queued.message.targetId else {
            return (try? outbox.record(.failPermanent, for: queued.id, error: "no target", now: now))
                ?? .unknown
        }

        let capabilities = await capabilities(for: targetId, type: queued.message.type, ownDockUrl: ownDockUrl)
        let plan = DeliveryPolicy.plan(capabilities)
        guard !plan.isEmpty else {
            // No address and no DOCK of our own: nothing about waiting
            // produces one.
            SystemLog.shared.error(
                SystemSource.messages,
                "No route to \(targetId.middleElided())",
                detail: "Their home map names no DOCK we could resolve, so the message "
                    + "cannot be delivered and will not be retried."
            )
            return record(
                .failPermanent, for: id, in: queued.conversationId,
                error: "no route to \(targetId)", now: now
            )
        }

        var outgoing = queued.message
        switch await sealForPeer(&outgoing, targetId: targetId) {
        case .ready:
            break
        case .retry(let reason):
            return record(.retryTransient, for: id, in: queued.conversationId, error: reason, now: now)
        case .fail(let reason):
            return record(.failPermanent, for: id, in: queued.conversationId, error: reason, now: now)
        }

        // Every envelope is signed by its author (FIMP0V3). A message queued
        // under an identity that is not on hand now waits for it.
        guard let sender = outgoing.senderId, let signingKey = prikeyFor?(sender) else {
            return record(
                .retryTransient, for: id, in: queued.conversationId,
                error: "no prikey on hand for \(outgoing.senderId ?? "the sender") to sign with", now: now
            )
        }
        let envelope: Data
        do {
            envelope = try outgoing.toWireBytes(signingWith: signingKey)
        } catch {
            return record(
                .failPermanent, for: id, in: queued.conversationId,
                error: String(describing: error), now: now
            )
        }

        var lastError: String?
        for route in plan {
            switch route {
            case .fudpDirect, .roadRelay:
                // Not wired yet — see the type's note. Falling through
                // is the same path an unreachable peer takes.
                continue
            case .recipientDock(let url):
                // Straight into the recipient's own server, over a
                // connection to *that* server. One hop, and it works
                // whether or not ours forwards — which is why it is
                // first, and why a client per DOCK is the whole point
                // of ``DockRegistry``.
                if let tooBig = await overBudget(envelope, dockUrl: url, id: id, targetId: targetId) {
                    return record(
                        .failPermanent, for: id, in: queued.conversationId,
                        error: tooBig, now: now
                    )
                }
                guard let client = await registry.client(for: url, now: now) else {
                    lastError = "no connection to recipient DOCK \(url)"
                    continue
                }
                do {
                    let item = try await DockService(fapi: client).put(
                        envelope, recipients: [targetId],
                        // No forwarding: this connection *is* the target.
                        targetDockUrl: nil, ownDockUrl: nil, timeoutMs: timeoutMs
                    )
                    return await succeed(queued, route: route, dockId: item.id, targetId: targetId, now: now)
                } catch {
                    // A server that answered and refused is not a dead
                    // socket, so only drop the client — starting the
                    // cooldown here would stall the next send behind a
                    // DOCK that is merely busy.
                    await registry.invalidate(url)
                    lastError = "recipient DOCK \(url) did not take it: \(error)"
                }
            case .ownDockForward(let recipientDockUrl):
                // Forwarding crosses two servers, and either may refuse.
                // The governing ceiling is the smaller of the two.
                for hop in [ownDockUrl, recipientDockUrl].compactMap({ $0 }) {
                    if let tooBig = await overBudget(envelope, dockUrl: hop, id: id, targetId: targetId) {
                        return record(
                            .failPermanent, for: id, in: queued.conversationId,
                            error: tooBig, now: now
                        )
                    }
                }
                if let item = try? await dock.put(
                    envelope, recipients: [targetId], targetDockUrl: recipientDockUrl,
                    ownDockUrl: ownDockUrl, timeoutMs: timeoutMs
                ) {
                    return await succeed(queued, route: route, dockId: item.id, targetId: targetId, now: now)
                }
                lastError = "own DOCK would not forward"
            }
        }
        SystemLog.shared.warning(
            SystemSource.messages,
            "Could not deliver to \(targetId.middleElided()) — will retry",
            detail: lastError ?? "no route succeeded"
        )
        return record(
            .retryTransient, for: id, in: queued.conversationId,
            error: lastError ?? "no route succeeded", now: now
        )
    }

    private enum Sealing {
        case ready
        case retry(String)
        case fail(String)
    }

    /// Seal a P2P message that was queued in the clear — a key request, a
    /// key share, a room invitation.
    ///
    /// **A receiver keeps only P2P messages it can tie to their sender**,
    /// and an unsealed body ties to nobody: anyone can write any FID into
    /// the sender field. So a clear message with something in it would be
    /// dropped on arrival, and the control traffic that is built in the
    /// clear is sealed here, from the sender's key to the recipient's, the
    /// same way ``ChatService`` seals a chat line. The copy in the
    /// transcript stays readable; only the wire copy is sealed.
    private func sealForPeer(_ message: inout ImMessage, targetId: String) async -> Sealing {
        guard message.type == .p2p,
              (message.body ?? Data()).isEmpty,
              message.content != nil || message.data != nil
        else { return .ready }
        guard let sender = message.senderId, let privkey = prikeyFor?(sender) else {
            // Queued under an identity that is not the one live now.
            return .retry("no prikey on hand for \(message.senderId ?? "the sender") to seal with")
        }
        let pubkey: Data
        if sender == targetId {
            guard let own = try? Secp256k1.publicKey(fromPrivateKey: privkey) else {
                return .fail("could not derive our own pubkey")
            }
            pubkey = own
        } else {
            guard let theirs = await peerPubkey(targetId) else {
                return .retry("no pubkey for \(targetId) to seal to")
            }
            pubkey = theirs
        }
        do {
            try message.sealBody(privkey: privkey, recipientPubkey: pubkey)
            return .ready
        } catch {
            return .fail("could not seal: \(error)")
        }
    }

    private func succeed(
        _ queued: QueuedMessage,
        route: DeliveryPolicy.Route,
        dockId: String?,
        targetId: String,
        now: Date
    ) async -> MessageQueue.Outcome {
        guard let id = queued.message.id else { return .unknown }

        // **One transaction, because these are one fact.** The message
        // is delivered and its outbox entry is spent. A build where only
        // the first lands shows the message as sent and sends it again
        // on the next drain; one where only the second lands leaves it
        // saying "sending" for ever, with nothing left that would ever
        // correct it. Both were reachable while these were two `try?`s
        // in a row.
        do {
            var changes: [EncryptedKVStore.Change] = []
            if let stamped = try messages.change(messageId: id, in: queued.conversationId, {
                $0.status = .sent
                $0.deliveryMethod = route.deliveryMethod
                $0.dockId = dockId
            }) {
                changes.append(stamped)
            }
            changes.append(outbox.change(removing: id))
            try messages.kv.write(changes)
        } catch {
            // Neither row moved, so the message is still queued and will
            // be attempted again. The recipient drops the second copy as
            // a replay — it carries the same id — which is the cheaper
            // of the two ways this can be wrong.
            SystemLog.shared.error(
                SystemSource.messages,
                "Delivered a message but could not record it",
                detail: "\(error)\nIt stays in the outbox and will be sent again."
            )
            return .unknown
        }
        // A DOCK delivery is evidence the peer was *not* reachable, so
        // `PeerBook` deliberately does not treat it as a sighting. Kept
        // out of the transaction above: a sighting is a hint, and losing
        // one must not undo a delivery.
        _ = try? peers.delivered(to: targetId, via: route.deliveryMethod, now: now)
        return .sent
    }

    @discardableResult
    private func record(
        _ result: SendResult,
        for id: String,
        in conversationId: String,
        error: String?,
        now: Date
    ) -> MessageQueue.Outcome {
        let outcome = (try? outbox.record(result, for: id, error: error, now: now)) ?? .unknown
        if let status = outcome.messageStatus {
            _ = try? messages.mutate(messageId: id, in: conversationId) { $0.status = status }
        }
        return outcome
    }

    /// What we can do for this target right now.
    ///
    /// The FUDP and ROAD flags are read from ``PeerBook`` and the
    /// settings that gate them; both are false today, so the plan comes
    /// out DOCK-only. Wiring the other two routes is a matter of
    /// flipping these on and filling in the `continue` arms above.
    ///
    /// `ownDockAvailable` is unconditionally true because ``dock`` is a
    /// connection, not an address: we can always *ask* our server to
    /// forward. Whether we know its URL decides only whether the
    /// forwarding field can be dropped as redundant, and gating the
    /// route on that is what left a message with nowhere to go whenever
    /// the app had not told the courier where it was connected.
    private func capabilities(
        for targetId: String,
        type: ImType?,
        ownDockUrl: String?
    ) async -> DeliveryPolicy.Capabilities {
        let home = await home(of: targetId, type: type)
        let dockUrl = await resolver.dockUrl(home: home)
        return DeliveryPolicy.Capabilities(
            fudpDirectEnabled: false,
            peerFudpReachable: (try? peers.get(fid: targetId))??.fudpReachable ?? false,
            roadRelayEnabled: false,
            roadUrl: nil,
            recipientDockUrl: dockUrl,
            ownDockAvailable: true
        )
    }

    /// The `home` map of whoever a message is addressed to. A P2P target
    /// is a FID and its home comes off the chain; a group's home is on
    /// the group record, which the caller has already synced.
    private func home(of targetId: String, type: ImType?) async -> [String: String]? {
        switch type {
        case .p2p, .none:
            return try? await directory.freer(byId: targetId)?.home
        case .team, .square, .room:
            // Group homes come from the stores the group syncs fill; a
            // courier that fetched them itself would be a second,
            // disagreeing copy.
            return groupHome?(targetId)
        }
    }

    // MARK: - receiving

    /// Collect what every DOCK we are known at is holding, and file it.
    ///
    /// **Every DOCK, not ours.** A group's messages are addressed to the
    /// group and stored on the server the group's `home` names, which is
    /// usually not ours. ``DockRegistry`` knows that map; this asks it
    /// for one fetch per distinct server, naming the ids that server is
    /// responsible for — our FID at our own DOCK, each group's id at the
    /// group's.
    ///
    /// Pass `recipientIds` to bypass the registry and ask **our own**
    /// DOCK for exactly those ids. That is the single-server shape, kept
    /// for tests and for a session whose registry is not configured yet.
    ///
    /// `docks` narrows which servers a pass touches, which is how
    /// ``DockFetchScheduler`` runs the open conversation's DOCK on a
    /// fast lane without polling every other one at the same rate.
    ///
    /// A server that fails takes only its own fetch down with it: the
    /// others still run, and the failure is recorded so the next pass
    /// leaves that one alone for a while. Reporting a thrown error
    /// instead would let one unreachable group's DOCK silence every
    /// conversation.
    @discardableResult
    public func collect(
        as liveFid: String,
        recipientIds: [String]? = nil,
        docks: DockSelection = .all,
        privkey: Data? = nil,
        maxPages: Int = 20,
        pageSize: Int = 50,
        now: Date = Date(),
        timeoutMs: Int = 15_000
    ) async throws -> ReceiveReport {
        var total = ReceiveReport(fetched: 0, filed: 0, sealed: 0, held: 0, routed: 0, other: 0)

        if let recipientIds {
            guard !recipientIds.isEmpty else { return total }
            let report = try? await collect(
                from: dock, dockUrl: await registry.ownDockUrl, recipientIds: recipientIds,
                as: liveFid, privkey: privkey, maxPages: maxPages, pageSize: pageSize,
                now: now, timeoutMs: timeoutMs
            )
            return report ?? total
        }

        for target in await registry.fetchTargets() where docks.includes(target.dockUrl) {
            guard let client = await registry.client(for: target.dockUrl, now: now) else { continue }
            do {
                let report = try await collect(
                    from: DockService(fapi: client), dockUrl: target.dockUrl,
                    recipientIds: target.recipientIds, as: liveFid, privkey: privkey,
                    maxPages: maxPages, pageSize: pageSize, now: now, timeoutMs: timeoutMs
                )
                total = total.adding(report)
            } catch {
                // The socket, not the message: a DOCK that cannot be
                // fetched from gets its client dropped and a cooldown,
                // and the cursor is deliberately left where it is so
                // recovery resumes rather than re-reading everything.
                await registry.markFailed(target.dockUrl, now: now)
                SystemLog.shared.error(
                    SystemSource.dock,
                    "Could not collect from \(target.dockUrl)",
                    detail: "\(error)\nWaiting for: \(target.recipientIds.joined(separator: ", "))"
                )
            }
        }
        return total
    }

    /// One server's worth of collecting: page through what it holds for
    /// `recipientIds`, file each item, and remember where we got to.
    private func collect(
        from dock: DockService,
        dockUrl: String?,
        recipientIds: [String],
        as liveFid: String,
        privkey: Data?,
        maxPages: Int,
        pageSize: Int,
        now: Date,
        timeoutMs: Int
    ) async throws -> ReceiveReport {
        var fetched = 0, filed = 0, sealed = 0, held = 0, routed = 0, other = 0
        var cursor: [String]?
        if let dockUrl { cursor = await registry.cursor(for: dockUrl) }
        // Set when an item could not be filed locally. The cursor stops
        // where it is and the walk ends, so the page that failed is read
        // again next pass rather than skipped for good.
        var localFailure = false

        for _ in 0..<maxPages {
            let page = try await dock.fetch(
                recipientIds: recipientIds, after: cursor, size: pageSize, timeoutMs: timeoutMs
            )
            if page.items.isEmpty { break }
            fetched += page.items.count

            for item in page.items {
                guard let payload = item.data,
                      let message = try? ImMessage.fromWireBytes(payload)
                else {
                    other += 1
                    continue
                }
                var named = message
                if !named.hasFudpId, let dockId = item.id {
                    // A message that reached us without its own id is
                    // named by the DOCK's, so a receipt can refer to it.
                    named.id = String(dockId.prefix(16))
                }
                named.dockId = item.id
                named.deliveryMethod = .dockStored

                // FIMP0V3 §3.5 step 3: the signature binds the target, but
                // a validly signed message can still be put on a DOCK for
                // someone it was never for. Only what is addressed to a
                // recipient this fetch was asking about is taken in.
                if let reason = misaddressed(named, item: item, askedFor: recipientIds) {
                    SystemLog.shared.info(
                        SystemSource.messages,
                        "Dropped a message not addressed to us",
                        detail: "From \(named.senderId?.middleElided() ?? "nobody"): \(reason)"
                    )
                    other += 1
                    continue
                }

                // Step 4: a replay verifies as well as the original did.
                let seenKey = named.senderId.flatMap { sender in named.id.map { (sender, $0) } }
                if let (sender, messageId) = seenKey, let seen,
                   (try? seen.hasSeen(sender: sender, id: messageId)) == true {
                    other += 1
                    if let dockId = item.id, isOursAlone(item, named, liveFid: liveFid) {
                        _ = try? await dock.delete(id: dockId, timeoutMs: timeoutMs)
                    }
                    continue
                }

                if await !fromSquareMember(named, item: item, liveFid: liveFid) {
                    other += 1
                    continue
                }

                // **A message we could not file is a message we still
                // need.** Filing is the whole reason the DOCK copy is
                // redundant; when it throws — the store is full, the
                // vault went away underneath us, SQLite is unhappy —
                // the remote copy is the only copy left. Swallowing
                // that into `.ignored` and carrying on deleted the
                // message from the DOCK, marked it seen so a refetch
                // would be rejected as a replay, and walked the cursor
                // past it: three independent ways to never see it
                // again. So: leave it on the DOCK, leave it unseen, and
                // stop the walk here so the next pass re-reads this
                // page from the cursor we have not moved.
                let received: ChatService.Received
                do {
                    received = try chat.receive(named, as: liveFid, privkey: privkey, now: now)
                } catch {
                    SystemLog.shared.error(
                        SystemSource.messages,
                        "Could not file an incoming message — leaving it on the DOCK",
                        detail: "From \(named.senderId?.middleElided() ?? "nobody"): \(error)"
                    )
                    other += 1
                    localFailure = true
                    break
                }

                switch received {
                case .message(let stored):
                    filed += 1
                    await acknowledgeDelivery(of: stored, as: liveFid, privkey: privkey, now: now)
                case .sealed(let stored, let symkeyVersion):
                    sealed += 1
                    ask(for: stored, version: symkeyVersion, as: liveFid, now: now)
                case .held: held += 1
                case .signal(let signal):
                    // Room notifications, key shares and key requests.
                    // These used to be counted and dropped, which is why
                    // a room invitation never arrived and a rotated key
                    // never landed: the protocol was implemented and
                    // nothing called it.
                    routed += route(signal, as: liveFid, now: now)
                    other += 1
                case .receipt, .ignored: other += 1
                }
                if let (sender, messageId) = seenKey {
                    try? seen?.markSeen(sender: sender, id: messageId, now: now)
                }
                if let dockId = item.id, isOursAlone(item, named, liveFid: liveFid) {
                    _ = try? await dock.delete(id: dockId, timeoutMs: timeoutMs)
                }
            }

            if localFailure { break }

            // No new cursor means there is no way to ask for the *next*
            // page — asking again with the old one would hand back the
            // page we just filed, forever.
            guard let next = page.cursor, !next.isEmpty else { break }
            cursor = next
            if let dockUrl { await registry.setCursor(next, for: dockUrl) }
            guard page.items.count >= pageSize else { break }
        }
        return ReceiveReport(fetched: fetched, filed: filed, sealed: sealed, held: held, routed: routed, other: other)
    }

    /// Why `message` is not for this fetch, or nil when it is: its target
    /// must be one of the recipients asked for and, when the DOCK says who
    /// the item is addressed to, one of those too.
    private func misaddressed(_ message: ImMessage, item: DockItem, askedFor recipientIds: [String]) -> String? {
        guard let target = message.targetId, !target.isEmpty else { return "it names no target" }
        guard recipientIds.contains(target) else { return "it is for \(target.middleElided())" }
        if let recipients = item.recipients, !recipients.isEmpty, !recipients.contains(target) {
            return "it is for \(target.middleElided()) but was stored for someone else"
        }
        return nil
    }

    /// Keep a square message only if its sender is one of the square's
    /// members; every other kind of message passes. Our own messages always
    /// pass — they are ours whether or not the join has confirmed.
    ///
    /// **A chain that cannot be asked keeps the message.** The cursor moves
    /// past whatever is dropped, so a drop is for good, and losing a
    /// member's message to a network blip is worse than showing one
    /// stranger's post.
    private func fromSquareMember(_ message: ImMessage, item: DockItem, liveFid: String) async -> Bool {
        guard message.type == .square, let squareSender else { return true }
        guard let sender = message.senderId, !sender.isEmpty,
              let squareId = message.targetId, !squareId.isEmpty
        else { return false }
        guard sender != liveFid else { return true }
        switch await squareSender(sender, squareId, item.createTime) {
        case .member:
            return true
        case .notMember:
            SystemLog.shared.info(
                SystemSource.messages,
                "Dropped a square message from \(sender.middleElided()), who is not a member",
                detail: "Square \(squareId.middleElided())"
            )
            return false
        case .unknown:
            SystemLog.shared.warning(
                SystemSource.messages,
                "Couldn't check whether \(sender.middleElided()) is in square \(squareId.middleElided())",
                detail: "The message was kept: the chain could not be asked."
            )
            return true
        }
    }

    /// Whether an item is addressed to us and nobody else, **and was
    /// not sent by us**.
    ///
    /// **Only those may be deleted.** Deleting is the receiver's half of
    /// the bargain for a P2P message — the sender paid for storage, and
    /// leaving read items to expire spends their money on nothing. But a
    /// group's item is *one* copy that every member fetches, so deleting
    /// it after we have read it takes it from everyone who has not. For
    /// those, the per-DOCK cursor is what stops us re-reading it, and
    /// the item is left for its TTL to clear.
    ///
    /// **A message we sent to our own FID is the same shape as a
    /// group's**, and for the same reason: an identity can be signed in
    /// on several devices, every one of them polls that FID, and each
    /// has its own cursor. A symkey request to ourselves is *for* the
    /// other device — so reaping it the moment the sending device reads
    /// its own copy back would delete the question before the only
    /// machine that can answer it ever sees it, which is a race the
    /// sender wins nearly every time (it is already awake, and it
    /// polls immediately after the put). The cursor keeps us from
    /// re-reading it; the TTL clears it.
    private func isOursAlone(_ item: DockItem, _ message: ImMessage, liveFid: String) -> Bool {
        guard let recipients = item.recipients, !recipients.isEmpty else { return false }
        guard message.senderId != liveFid else { return false }
        return recipients.allSatisfy { $0 == liveFid }
    }
}

extension MessageCourier.ReceiveReport {
    func adding(_ other: MessageCourier.ReceiveReport) -> MessageCourier.ReceiveReport {
        .init(
            fetched: fetched + other.fetched,
            filed: filed + other.filed,
            sealed: sealed + other.sealed,
            held: held + other.held,
            routed: routed + other.routed,
            other: self.other + other.other
        )
    }
}
