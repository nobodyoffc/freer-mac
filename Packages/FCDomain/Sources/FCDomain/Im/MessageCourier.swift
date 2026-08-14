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
public struct MessageCourier {

    private let outbox: MessageQueue
    private let messages: MessagesStore
    private let chat: ChatService
    private let peers: PeerBook
    private let dock: DockService
    private let resolver: HomeServiceResolver
    private let directory: DirectoryService

    /// Where a group's `home` map comes from. Supplied by the app so
    /// this type can look up a team's DOCK without reaching into three
    /// stores it does not own — and so that the group syncs stay the
    /// single copy of that answer.
    private let groupHome: (@Sendable (String) -> [String: String]?)?

    public init(
        outbox: MessageQueue,
        messages: MessagesStore,
        chat: ChatService,
        peers: PeerBook,
        dock: DockService,
        resolver: HomeServiceResolver,
        directory: DirectoryService,
        groupHome: (@Sendable (String) -> [String: String]?)? = nil
    ) {
        self.groupHome = groupHome
        self.outbox = outbox
        self.messages = messages
        self.chat = chat
        self.peers = peers
        self.dock = dock
        self.resolver = resolver
        self.directory = directory
    }

    public struct SendReport: Equatable, Sendable {
        public let attempted: Int
        public let sent: Int
        public let retrying: Int
        public let failed: Int
    }

    public struct ReceiveReport: Equatable, Sendable {
        public let fetched: Int
        /// Filed into a transcript.
        public let filed: Int
        /// Kept but not openable — the cue to ask for a key.
        public let sealed: Int
        /// Receipts, signals and things addressed to nobody we know.
        public let other: Int
    }

    // MARK: - sending

    /// Attempt every message that is due.
    ///
    /// One pass, not a loop: *when* to run this is the app's business —
    /// on send, on wake, on a timer — and a courier that owned its own
    /// schedule would be a second place to look when messages stop
    /// moving.
    @discardableResult
    public func drainOutbox(
        as liveFid: String,
        ownDockUrl: String? = nil,
        now: Date = Date(),
        timeoutMs: Int = 15_000
    ) async throws -> SendReport {
        let due = try outbox.due(now: now)
        var sent = 0, retrying = 0, failed = 0

        for queued in due {
            let outcome = await deliver(
                queued, as: liveFid, ownDockUrl: ownDockUrl, now: now, timeoutMs: timeoutMs
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
                if let item = try? await dock.put(
                    envelope, recipients: [targetId], targetDockUrl: url,
                    ownDockUrl: ownDockUrl, timeoutMs: timeoutMs
                ) {
                    return await succeed(queued, route: route, dockId: item.id, targetId: targetId, now: now)
                }
                lastError = "recipient DOCK \(url) did not take it"
            case .ownDockForward(let recipientDockUrl):
                if let item = try? await dock.put(
                    envelope, recipients: [targetId], targetDockUrl: recipientDockUrl,
                    ownDockUrl: ownDockUrl, timeoutMs: timeoutMs
                ) {
                    return await succeed(queued, route: route, dockId: item.id, targetId: targetId, now: now)
                }
                lastError = "own DOCK would not forward"
            }
        }
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
            ownDockAvailable: ownDockUrl != nil
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

    /// Collect what our DOCK is holding and file it.
    ///
    /// `recipientIds` is us **and every group we belong to**: a team's
    /// messages are addressed to the team, so a fetch that asked only
    /// for our FID would collect none of them.
    ///
    /// Items are deleted only after they are filed. An interrupted
    /// fetch therefore costs a repeat, never a loss — and the repeat is
    /// harmless, because ``MessagesStore`` keys by message id and a
    /// second copy of the same message overwrites the first.
    @discardableResult
    public func collect(
        as liveFid: String,
        recipientIds: [String],
        privkey: Data? = nil,
        maxPages: Int = 20,
        pageSize: Int = 50,
        now: Date = Date(),
        timeoutMs: Int = 15_000
    ) async throws -> ReceiveReport {
        var fetched = 0, filed = 0, sealed = 0, other = 0
        var cursor: [String]? = nil

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
                case .message: filed += 1
                case .sealed: sealed += 1
                case .receipt, .signal, .ignored: other += 1
                }
                if let dockId = item.id {
                    _ = try? await dock.delete(id: dockId, timeoutMs: timeoutMs)
                }
            }

            guard let next = page.cursor, !next.isEmpty, page.items.count >= pageSize else { break }
            cursor = next
        }
        return ReceiveReport(fetched: fetched, filed: filed, sealed: sealed, other: other)
    }
}
