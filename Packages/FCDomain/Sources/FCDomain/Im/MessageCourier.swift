import Foundation
import FCCore
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
        routeSignal: (@Sendable (ImMessage, String, Date) throws -> SignalRouter.Outcome)? = nil
    ) {
        self.groupHome = groupHome
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
            try? outbox.enqueue(reply, in: Conversation.id(type: .p2p, targetId: to))
        }
        if let note = outcome.note {
            SystemLog.shared.info(SystemSource.dock, note)
        }
        let acted = !outcome.outbound.isEmpty
            || outcome.invitation != nil
            || outcome.learnedKeyFor != nil
        return acted ? 1 : 0
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
        var sent = 0, retrying = 0, failed = 0
        var ownDock = ownDockUrl
        if ownDock == nil { ownDock = await registry.ownDockUrl }

        for queued in due {
            let outcome = await deliver(
                queued, as: liveFid, ownDockUrl: ownDock, now: now, timeoutMs: timeoutMs
            )
            switch outcome {
            case .sent: sent += 1
            case .retrying: retrying += 1
            case .failed: failed += 1
            case .unknown: break
            }
        }
        return SendReport(attempted: due.count, sent: sent, retrying: retrying, failed: failed)
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
                "No public key for \(senderId.middleElided()), so their message cannot be acknowledged",
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

        let envelope: Data
        do {
            envelope = try queued.message.toWireBytes()
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

    private func succeed(
        _ queued: QueuedMessage,
        route: DeliveryPolicy.Route,
        dockId: String?,
        targetId: String,
        now: Date
    ) async -> MessageQueue.Outcome {
        guard let id = queued.message.id else { return .unknown }
        try? messages.mutate(messageId: id, in: queued.conversationId) { message in
            message.status = .sent
            message.deliveryMethod = route.deliveryMethod
            message.dockId = dockId
        }
        // A DOCK delivery is evidence the peer was *not* reachable, so
        // `PeerBook` deliberately does not treat it as a sighting.
        try? peers.delivered(to: targetId, via: route.deliveryMethod, now: now)
        return (try? outbox.record(.success, for: id, now: now)) ?? .unknown
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
            try? messages.mutate(messageId: id, in: conversationId) { $0.status = status }
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

                switch (try? chat.receive(named, as: liveFid, privkey: privkey, now: now)) ?? .ignored(reason: "receive failed") {
                case .message(let stored):
                    filed += 1
                    await acknowledgeDelivery(of: stored, as: liveFid, privkey: privkey, now: now)
                case .sealed: sealed += 1
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
                if let dockId = item.id, isOursAlone(item, liveFid: liveFid) {
                    _ = try? await dock.delete(id: dockId, timeoutMs: timeoutMs)
                }
            }

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

    /// Whether an item is addressed to us and nobody else.
    ///
    /// **Only those may be deleted.** Deleting is the receiver's half of
    /// the bargain for a P2P message — the sender paid for storage, and
    /// leaving read items to expire spends their money on nothing. But a
    /// group's item is *one* copy that every member fetches, so deleting
    /// it after we have read it takes it from everyone who has not. For
    /// those, the per-DOCK cursor is what stops us re-reading it, and
    /// the item is left for its TTL to clear.
    private func isOursAlone(_ item: DockItem, liveFid: String) -> Bool {
        guard let recipients = item.recipients, !recipients.isEmpty else { return false }
        return recipients.allSatisfy { $0 == liveFid }
    }
}

extension MessageCourier.ReceiveReport {
    func adding(_ other: MessageCourier.ReceiveReport) -> MessageCourier.ReceiveReport {
        .init(
            fetched: fetched + other.fetched,
            filed: filed + other.filed,
            sealed: sealed + other.sealed,
            other: self.other + other.other
        )
    }
}
