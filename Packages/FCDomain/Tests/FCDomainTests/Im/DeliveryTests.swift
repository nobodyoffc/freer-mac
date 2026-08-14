import XCTest
import FCCore
import FCTransport
import FCStorage
@testable import FCDomain

/// The delivery machinery: the durable outbox and its backoff, the route
/// preference order, receipts advancing a message's status, and the peer
/// book's view of who is around.
final class DeliveryTests: XCTestCase {

    private var baseDir: URL!
    private var manager: ConfigureManager!
    private var configure: ConfigureSession!
    private var session: ActiveSession!

    private let me = "FEk41Kqjar45fLDriztUDTUkdki7mmcjWK"
    private let them = "F6vqNGkbAqZQ1YkPWLcXfNfwvJXCTGmzUM"

    /// Every time in this suite is relative to this, so nothing depends
    /// on the wall clock.
    private let t0 = Date(timeIntervalSince1970: 1_755_100_000)
    private func at(_ seconds: TimeInterval) -> Date { t0.addingTimeInterval(seconds) }
    private func ms(_ seconds: TimeInterval) -> Int64 { Int64(at(seconds).timeIntervalSince1970 * 1000) }

    override func setUpWithError() throws {
        baseDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("DeliveryTests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: baseDir, withIntermediateDirectories: true)

        manager = try ConfigureManager(baseDirectory: baseDir)
        configure = try manager.createConfigure(password: Data("pwd".utf8), kdfKind: .legacySha256)
        let info = try configure.addMain(privkey: Data(repeating: 0xA1, count: 32), label: "A")
        session = try configure.unlockMain(fid: info.fid, fapi: MockFapiClient())
    }

    override func tearDownWithError() throws {
        session = nil
        configure = nil
        manager = nil
        if let baseDir { try? FileManager.default.removeItem(at: baseDir) }
    }

    private var queue: MessageQueue { session.outbox }
    private var messages: MessagesStore { session.messages }
    private var peers: PeerBook { session.peers }
    private var conversationId: String { Conversation.id(type: .p2p, targetId: them) }

    private func outgoing(_ text: String = "hi", id: String = "0000000000000001") -> ImMessage {
        var m = ImMessage.text(type: .p2p, from: me, to: them, text, now: t0)
        m.id = id
        return m
    }

    // MARK: - the outbox

    /// The outbox is durable because the alternative is that quitting
    /// between "send" and "sent" drops the message silently.
    func testEnqueuedMessageIsDueImmediatelyAndSurvives() throws {
        try queue.enqueue(outgoing(), in: conversationId, now: t0)

        let reopened = MessageQueue(kv: session.storage)
        XCTAssertEqual(try reopened.count(), 1)
        XCTAssertEqual(try reopened.due(now: t0).map(\.id), ["0000000000000001"])
        XCTAssertEqual(try reopened.get(id: "0000000000000001")?.conversationId, conversationId)
    }

    func testEnqueueRejectsAMessageWithNoId() throws {
        var m = outgoing()
        m.id = nil
        XCTAssertThrowsError(try queue.enqueue(m, in: conversationId, now: t0)) { error in
            XCTAssertEqual(error as? MessageQueue.Failure, .messageHasNoId)
        }
    }

    /// Oldest first, so a conversation does not arrive backwards after
    /// the app has been offline.
    func testQueueDrainsInTheOrderItWasFilled() throws {
        try queue.enqueue(outgoing("second", id: "0000000000000002"), in: conversationId, now: at(10))
        try queue.enqueue(outgoing("first", id: "0000000000000001"), in: conversationId, now: at(5))
        XCTAssertEqual(try queue.all().map(\.message.content), ["first", "second"])
    }

    func testSuccessLeavesTheQueue() throws {
        try queue.enqueue(outgoing(), in: conversationId, now: t0)
        XCTAssertEqual(try queue.record(.success, for: "0000000000000001", now: t0), .sent)
        XCTAssertEqual(try queue.count(), 0)
        // A second outcome for the same message says so rather than
        // resurrecting it — two overlapping attempts are ordinary.
        XCTAssertEqual(try queue.record(.success, for: "0000000000000001", now: t0), .unknown)
    }

    /// A malformed message must not be retried every fifteen minutes
    /// forever; that is the whole reason the result is a three-way
    /// classification and not a Bool.
    func testPermanentFailureDoesNotRetry() throws {
        try queue.enqueue(outgoing(), in: conversationId, now: t0)
        let outcome = try queue.record(.failPermanent, for: "0000000000000001", error: "no target", now: t0)
        XCTAssertEqual(outcome, .failed(reason: "no target"))
        XCTAssertEqual(outcome.messageStatus, .failed)
        XCTAssertEqual(try queue.count(), 0)
    }

    /// The backoff walks the whole schedule — including the 5 s entry
    /// that Android's off-by-one never reaches (issue C11).
    func testTransientFailureWalksTheBackoffSchedule() throws {
        try queue.enqueue(outgoing(), in: conversationId, now: t0)
        let expected: [Int64] = [5_000, 15_000, 60_000, 300_000]

        for (index, delay) in expected.enumerated() {
            let outcome = try queue.record(.retryTransient, for: "0000000000000001", now: at(0))
            XCTAssertEqual(outcome, .retrying(attempt: index + 1, at: ms(0) + delay), "attempt \(index + 1)")
            XCTAssertEqual(outcome.messageStatus, .pending)
            // Not due until the delay has passed.
            XCTAssertTrue(try queue.due(now: at(Double(delay) / 1000 - 1)).isEmpty)
            XCTAssertEqual(try queue.due(now: at(Double(delay) / 1000)).count, 1)
        }

        // The fifth attempt is the last one.
        XCTAssertEqual(
            try queue.record(.retryTransient, for: "0000000000000001", now: at(0)),
            .failed(reason: "max retries exceeded")
        )
        XCTAssertEqual(try queue.count(), 0)
    }

    func testLastErrorIsKeptForTheUi() throws {
        try queue.enqueue(outgoing(), in: conversationId, now: t0)
        try queue.record(.retryTransient, for: "0000000000000001", error: "peer offline", now: t0)
        XCTAssertEqual(try queue.get(id: "0000000000000001")?.lastError, "peer offline")
    }

    /// Retrying is something a person does. Nothing resets the counter
    /// on its own — a message that has run out of attempts stays failed.
    func testRetryNowMakesAMessageDueAgainWithoutResettingTheCount() throws {
        try queue.enqueue(outgoing(), in: conversationId, now: t0)
        try queue.record(.retryTransient, for: "0000000000000001", now: t0)
        XCTAssertTrue(try queue.due(now: at(1)).isEmpty)

        XCTAssertTrue(try queue.retryNow(id: "0000000000000001", now: at(1)))
        XCTAssertEqual(try queue.due(now: at(1)).count, 1)
        XCTAssertEqual(try queue.get(id: "0000000000000001")?.retryCount, 1)
        XCTAssertFalse(try queue.retryNow(id: "ffffffffffffffff", now: at(1)))
    }

    func testCancelAndClearAll() throws {
        try queue.enqueue(outgoing(id: "0000000000000001"), in: conversationId, now: t0)
        try queue.enqueue(outgoing(id: "0000000000000002"), in: conversationId, now: t0)
        XCTAssertTrue(try queue.cancel(id: "0000000000000001"))
        XCTAssertFalse(try queue.cancel(id: "0000000000000001"))
        XCTAssertEqual(try queue.clearAll(), 1)
        XCTAssertEqual(try queue.count(), 0)
    }

    // MARK: - route preference

    /// Direct, then relay, then the recipient's DOCK, then ours.
    func testFullPlanIsInPreferenceOrder() {
        let plan = DeliveryPolicy.plan(.init(
            fudpDirectEnabled: true,
            peerFudpReachable: true,
            roadRelayEnabled: true,
            roadUrl: "https://road.example",
            recipientDockUrl: "https://dock.them",
            ownDockAvailable: true
        ))
        XCTAssertEqual(plan, [
            .fudpDirect,
            .roadRelay(url: "https://road.example"),
            .recipientDock(url: "https://dock.them"),
            .ownDockForward(recipientDockUrl: "https://dock.them"),
        ])
    }

    /// Both DOCK routes end with the envelope stored — the difference
    /// between them is who pays, not what happens to the message.
    func testBothDockRoutesReportStored() {
        XCTAssertEqual(DeliveryPolicy.Route.recipientDock(url: "u").deliveryMethod, .dockStored)
        XCTAssertEqual(DeliveryPolicy.Route.ownDockForward(recipientDockUrl: nil).deliveryMethod, .dockStored)
        XCTAssertEqual(DeliveryPolicy.Route.fudpDirect.deliveryMethod, .fudpDirect)
        XCTAssertEqual(DeliveryPolicy.Route.roadRelay(url: "u").deliveryMethod, .roadRelay)
    }

    /// Every omission is traceable to one capability being absent — a
    /// setting the user turned off, or an address we could not resolve.
    func testEachRouteIsGatedIndependently() {
        // The user has direct sends off, so a reachable peer is skipped.
        XCTAssertEqual(
            DeliveryPolicy.plan(.init(fudpDirectEnabled: false, peerFudpReachable: true, ownDockAvailable: true)),
            [.ownDockForward(recipientDockUrl: nil)]
        )
        // Relay is on but we have no relay address for them.
        XCTAssertEqual(
            DeliveryPolicy.plan(.init(roadRelayEnabled: true, roadUrl: nil, recipientDockUrl: "d")),
            [.recipientDock(url: "d")]
        )
        // An empty string is not an address.
        XCTAssertTrue(DeliveryPolicy.plan(.init(recipientDockUrl: "")).isEmpty)
    }

    /// No plan at all is permanent — nothing about waiting produces an
    /// address. A plan whose routes all failed is transient: the
    /// addresses were real, the network was not.
    func testEmptyPlanIsPermanentAndAFailedPlanIsTransient() {
        XCTAssertEqual(DeliveryPolicy.outcome(plan: [], allRoutesFailed: true), .failPermanent)
        XCTAssertEqual(DeliveryPolicy.outcome(plan: [.fudpDirect], allRoutesFailed: true), .retryTransient)
        XCTAssertEqual(DeliveryPolicy.outcome(plan: [.fudpDirect], allRoutesFailed: false), .success)
    }

    // MARK: - receipts

    private func sentMessage(id: String = "0000000000000001") throws -> ImMessage {
        var m = outgoing(id: id)
        m.status = .sent
        try messages.put(m, in: conversationId)
        return m
    }

    func testDeliveredThenReadAdvancesTheMessage() throws {
        try sentMessage()
        var receipt = ImMessage.receipt(
            from: them, to: me, originalMessageId: "0000000000000001", read: false, now: at(5)
        )
        receipt.id = "00000000000000aa"

        let delivered = try XCTUnwrap(
            try Receipt.apply(receipt, in: conversationId, messages: messages)
        )
        XCTAssertEqual(delivered.status, .delivered)
        XCTAssertEqual(delivered.deliveredAt, ms(5))
        XCTAssertNil(delivered.readAt)

        var readReceipt = ImMessage.receipt(
            from: them, to: me, originalMessageId: "0000000000000001", read: true, now: at(9)
        )
        readReceipt.id = "00000000000000bb"
        let read = try XCTUnwrap(try Receipt.apply(readReceipt, in: conversationId, messages: messages))
        XCTAssertEqual(read.status, .read)
        XCTAssertEqual(read.readAt, ms(9))
        XCTAssertEqual(read.deliveredAt, ms(5), "the original delivery time is not overwritten")
    }

    /// Delivery is unordered, so a `delivered` receipt can arrive after
    /// the `read` that followed it. Applying it in arrival order would
    /// flip a message the recipient has already read back to delivered.
    func testALateDeliveredReceiptDoesNotUndoRead() throws {
        try sentMessage()
        var read = ImMessage.receipt(from: them, to: me, originalMessageId: "0000000000000001", read: true, now: at(9))
        read.id = "00000000000000bb"
        try Receipt.apply(read, in: conversationId, messages: messages)

        var late = ImMessage.receipt(from: them, to: me, originalMessageId: "0000000000000001", read: false, now: at(5))
        late.id = "00000000000000aa"
        XCTAssertNil(try Receipt.apply(late, in: conversationId, messages: messages), "no change to report")
        XCTAssertEqual(try messages.get(messageId: "0000000000000001", in: conversationId)?.status, .read)
    }

    /// A read receipt may be the only one that arrives — a peer who read
    /// the message on sight sends one receipt, not two — so it has to
    /// stamp the delivery time as well.
    func testAReadReceiptAloneStampsDelivery() throws {
        try sentMessage()
        var read = ImMessage.receipt(from: them, to: me, originalMessageId: "0000000000000001", read: true, now: at(4))
        read.id = "00000000000000bb"
        let updated = try XCTUnwrap(try Receipt.apply(read, in: conversationId, messages: messages))
        XCTAssertEqual(updated.deliveredAt, ms(4))
        XCTAssertEqual(updated.readAt, ms(4))
    }

    /// A message we gave up on that turns out to have arrived did
    /// arrive.
    func testAReceiptOverridesAFailedStatus() throws {
        var m = outgoing()
        m.status = .failed
        try messages.put(m, in: conversationId)

        var receipt = ImMessage.receipt(from: them, to: me, originalMessageId: "0000000000000001", read: false, now: at(5))
        receipt.id = "00000000000000aa"
        XCTAssertEqual(try Receipt.apply(receipt, in: conversationId, messages: messages)?.status, .delivered)
    }

    func testNonReceiptsAndUnknownSubjectsAreIgnored() throws {
        try sentMessage()
        let text = outgoing(id: "0000000000000002")
        XCTAssertNil(Receipt.kind(of: text))
        XCTAssertNil(try Receipt.apply(text, in: conversationId, messages: messages))

        var orphan = ImMessage.receipt(from: them, to: me, originalMessageId: "ffffffffffffffff", read: true, now: at(5))
        orphan.id = "00000000000000cc"
        XCTAssertNil(try Receipt.apply(orphan, in: conversationId, messages: messages))
    }

    func testReceiptKindAndOriginThread() throws {
        var receipt = ImMessage.receipt(from: them, to: me, originalMessageId: "0000000000000001", read: true, now: at(5))
        receipt.id = "00000000000000bb"
        XCTAssertEqual(Receipt.kind(of: receipt), .read)
        XCTAssertEqual(Receipt.kind(of: receipt)?.status, .read)
        // The subject of a receipt lives in the P2P thread with whoever
        // sent it — a receipt is P2P even when the message was not.
        XCTAssertEqual(Receipt.originConversationId(for: receipt), conversationId)
        XCTAssertNil(Receipt.originConversationId(for: ImMessage()))
    }

    // MARK: - presence

    /// Presence is a question about age, not a stored flag: nothing
    /// tells us when someone leaves, because a peer that closes their
    /// laptop sends no goodbye.
    func testPresenceDecaysWithTime() throws {
        try peers.sighted(them, now: t0)
        XCTAssertTrue(try XCTUnwrap(try peers.get(fid: them)).isOnline(now: at(60)))
        XCTAssertFalse(try XCTUnwrap(try peers.get(fid: them)).isOnline(now: at(300)))
        XCTAssertEqual(try peers.online(now: at(60)).map(\.fid), [them])
        XCTAssertTrue(try peers.online(now: at(300)).isEmpty)
        XCTAssertFalse(PeerInfo(fid: them).isOnline(now: t0), "never seen is not online")
    }

    /// A DOCK delivery is evidence the peer was *not* reachable, so it
    /// must not refresh presence — otherwise every offline send would
    /// mark them present and keep the direct route at the front of the
    /// plan forever.
    func testDockDeliveryDoesNotCountAsASighting() throws {
        try peers.sighted(them, now: t0)
        let after = try peers.delivered(to: them, via: .dockStored, now: at(600))
        XCTAssertEqual(after.lastDeliveryMethod, .dockStored)
        XCTAssertEqual(after.lastSeenAt, ms(0), "unchanged")
        XCTAssertFalse(after.isOnline(now: at(600)))

        let live = try peers.delivered(to: them, via: .fudpDirect, now: at(700))
        XCTAssertEqual(live.lastSeenAt, ms(700))
        XCTAssertEqual(live.fudpReachable, true)
        XCTAssertTrue(live.isOnline(now: at(700)))
    }

    func testFudpReachabilityIsRecordedSeparately() throws {
        XCTAssertEqual(try peers.setFudpReachable(true, for: them).fudpReachable, true)
        XCTAssertEqual(try peers.setFudpReachable(false, for: them).fudpReachable, false)
        // A relay delivery says nothing about a FUDP endpoint either way.
        XCTAssertEqual(try peers.delivered(to: them, via: .roadRelay, now: t0).fudpReachable, false)
    }

    func testPeersAreListedMostRecentlySeenFirst() throws {
        try peers.sighted(them, now: t0)
        try peers.sighted("F-other", now: at(60))
        XCTAssertEqual(try peers.all().map(\.fid), ["F-other", them])
        XCTAssertTrue(try peers.remove(fid: them))
        XCTAssertFalse(try peers.remove(fid: them))
        XCTAssertEqual(try peers.all().count, 1)
    }
}
