import XCTest
import FCCore
import FCTransport
@testable import FCDomain

/// Asking another member for a conversation's messages, approving, and
/// filing what comes back — end to end over the in-process DISK the file
/// share tests use, with every message passing through
/// ``ChatService/receive(_:as:privkey:now:)`` and ``SignalRouter`` the
/// way a collect would pass it.
final class HistoryShareTests: XCTestCase {

    private var baseDir: URL!
    private var server: FakeDiskServer!

    private let t0 = Date(timeIntervalSince1970: 1_755_100_000)
    private func ms(_ seconds: TimeInterval) -> Int64 {
        Int64(t0.addingTimeInterval(seconds).timeIntervalSince1970 * 1000)
    }
    private func at(_ seconds: TimeInterval) -> Date { t0.addingTimeInterval(seconds) }

    override func setUpWithError() throws {
        baseDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("HistoryShareTests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: baseDir, withIntermediateDirectories: true)
        server = FakeDiskServer()
    }

    override func tearDownWithError() throws {
        server = nil
        if let baseDir { try? FileManager.default.removeItem(at: baseDir) }
    }

    // MARK: - fixtures

    private struct Peer {
        let session: ActiveSession
        let service: HistoryShareService
        let privkey: Data
        let pubkey: Data
        let exportDirectory: URL
        var fid: String { session.liveFid }
    }

    private func makePeer(_ byte: UInt8, label: String) throws -> Peer {
        let mgr = try ConfigureManager(baseDirectory: baseDir.appendingPathComponent("vault-\(label)"))
        let configure = try mgr.createConfigure(password: Data("pwd".utf8), kdfKind: .legacySha256)
        let privkey = Data(repeating: byte, count: 32)
        let info = try configure.addMain(privkey: privkey, label: label)
        let session = try configure.unlockMain(fid: info.fid, fapi: server)
        let sync = HatSyncService(
            disk: DiskService(fapi: server), hats: session.hats,
            files: session.files, serviceSid: "disk-svc-1"
        )
        let exports = session.dataDirectory.appendingPathComponent("history-exports", isDirectory: true)
        let service = HistoryShareService(
            messages: session.messages, conversations: session.conversations,
            symkeys: session.symkeys, outbox: session.outbox, shares: session.historyShares,
            files: session.files, hats: session.hats, sync: sync, exportDirectory: exports
        )
        return Peer(
            session: session, service: service, privkey: privkey,
            pubkey: try Secp256k1.publicKey(fromPrivateKey: privkey), exportDirectory: exports
        )
    }

    private func router(for peer: Peer, knowing others: [Peer] = []) throws -> SignalRouter {
        let keys = Dictionary(uniqueKeysWithValues: ([peer] + others).map { ($0.fid, $0.pubkey) })
        return SignalRouter(
            rooms: peer.session.rooms, teams: peer.session.teams, symkeys: peer.session.symkeys,
            invites: peer.session.roomInvites, roomService: try peer.session.roomService,
            roomConversations: peer.session.roomConversations, privkey: peer.privkey,
            pubkeys: { keys[$0] },
            historyShares: peer.session.historyShares, squares: peer.session.squares
        )
    }

    /// Deliver one message the way a collect does: open, then route
    /// whatever is not for a transcript.
    @discardableResult
    private func deliver(_ message: ImMessage, to peer: Peer, knowing others: [Peer] = [], now: Date) throws -> SignalRouter.Outcome {
        let received = try peer.session.chat.receive(message, as: peer.fid, privkey: peer.privkey, now: now)
        guard case .signal(let signal) = received else {
            XCTFail("expected a signal, got \(received)")
            return .nothing
        }
        return try router(for: peer, knowing: others).route(signal, as: peer.fid, now: now)
    }

    private func onlyQueued(_ peer: Peer) throws -> ImMessage {
        let queued = try peer.session.outbox.all()
        XCTAssertEqual(queued.count, 1)
        return try XCTUnwrap(queued.first?.message)
    }

    private func text(_ body: String, from: String, to: String, at seconds: TimeInterval, id: Int64) -> ImMessage {
        var m = ImMessage.text(type: .p2p, from: from, to: to, body, now: at(seconds))
        m.setId(fudpId: id)
        m.status = .delivered
        m.dockId = "dock-item-\(id)"
        return m
    }

    /// `owner` holds a P2P thread with `other`: three messages at
    /// t+10/20/30 seconds.
    private func seedThread(on owner: Peer, with other: Peer) throws -> String {
        let id = Conversation.id(type: .p2p, targetId: other.fid)
        let rows = [
            text("hello", from: other.fid, to: owner.fid, at: 10, id: 1_001),
            text("hi back", from: owner.fid, to: other.fid, at: 20, id: 1_002),
            text("see you", from: other.fid, to: owner.fid, at: 30, id: 1_003),
        ]
        for row in rows {
            try owner.session.messages.put(row, in: id)
            try owner.session.conversations.record(row, myFid: owner.fid)
        }
        return id
    }

    private func conversation(_ peer: Peer, with other: Peer) throws -> Conversation {
        var c = Conversation(id: Conversation.id(type: .p2p, targetId: other.fid), targetId: other.fid, type: .p2p)
        c.unreadCount = 0
        try peer.session.conversations.upsert(c)
        return c
    }

    // MARK: - the round trip

    /// Alice lost her transcript with Bob. She asks; Bob approves; the
    /// three messages are back in the thread she asked about, marked as
    /// imported, and nothing about the thread claims they are news.
    func testAnAskApprovedByTheOtherPartyRefillsTheThread() async throws {
        let alice = try makePeer(0xA1, label: "alice")
        let bob = try makePeer(0xB2, label: "bob")
        _ = try seedThread(on: bob, with: alice)
        var aliceThread = try conversation(alice, with: bob)
        aliceThread.unreadCount = 2
        try alice.session.conversations.upsert(aliceThread)

        // 1. Ask.
        let ask = try alice.service.ask(
            about: aliceThread, of: bob.fid, since: ms(0), before: ms(3600),
            as: alice.fid, privkey: alice.privkey, recipientPubkey: bob.pubkey, now: at(100)
        )
        let request = try onlyQueued(alice)
        XCTAssertEqual(request.requestType, .history)
        XCTAssertNil(request.content, "which chat and when is sealed, not in the clear")
        XCTAssertEqual(request.requestId, ask.nonce)

        // 2. Bob's collect files it for a person.
        let asked = try deliver(request, to: bob, knowing: [alice], now: at(110))
        let incoming = try XCTUnwrap(asked.historyRequest)
        XCTAssertEqual(incoming.from, alice.fid)
        XCTAssertEqual(incoming.conversationId, Conversation.id(type: .p2p, targetId: alice.fid),
                       "turned round: Alice named Bob, and the thread on Bob's side is the one with Alice")
        XCTAssertEqual(try bob.session.historyShares.incoming(), [incoming])
        XCTAssertEqual(try bob.service.messageCount(for: incoming), 3)

        // 3. Bob approves.
        let shared = try await bob.service.approve(
            incoming, as: bob.fid, privkey: bob.privkey, requesterPubkey: alice.pubkey, now: at(120)
        )
        XCTAssertEqual(shared, 3)
        XCTAssertTrue(try bob.session.historyShares.incoming().isEmpty)
        let leftovers = (try? FileManager.default.contentsOfDirectory(atPath: bob.exportDirectory.path)) ?? []
        XCTAssertTrue(leftovers.isEmpty, "no plaintext export is left on disk: \(leftovers)")

        let answer = try onlyQueued(bob)
        XCTAssertEqual(answer.contentType, .history)
        XCTAssertEqual(answer.requestId, ask.nonce)
        XCTAssertNil(answer.content, "the file key rides sealed — the courier does not seal for us")

        // 4. Alice's collect matches it, and the import files it.
        let answered = try deliver(answer, to: alice, knowing: [bob], now: at(130))
        XCTAssertNotNil(answered.historyReceived)
        XCTAssertNil(try alice.session.historyShares.ask(nonce: ask.nonce))

        let results = await alice.service.importReceived(as: alice.fid, now: at(140))
        XCTAssertEqual(results.map(\.imported), [3], "\(results)")
        XCTAssertTrue(try alice.session.historyShares.received().isEmpty)

        let page = try alice.session.messages.page(in: aliceThread.id)
        XCTAssertEqual(page.messages.map(\.content), ["hello", "hi back", "see you"])
        XCTAssertTrue(page.messages.allSatisfy { $0.status == .imported && $0.unread == false })
        XCTAssertTrue(page.messages.allSatisfy { $0.dockId == nil }, "Bob's delivery facts are Bob's")
        XCTAssertEqual(try alice.session.conversations.get(id: aliceThread.id)?.unreadCount, 2)
    }

    /// An identity is not a device. A second Mac asks its own FID, and
    /// the first one — which holds the thread with Carol — answers.
    func testAskingOurOwnFidReachesOurOtherDevice() async throws {
        let first = try makePeer(0xA1, label: "first")
        let second = try makePeer(0xA1, label: "second")
        let carol = try makePeer(0xC3, label: "carol")
        _ = try seedThread(on: first, with: carol)
        let thread = try conversation(second, with: carol)

        let ask = try second.service.ask(
            about: thread, of: second.fid, since: 0, before: ms(3600),
            as: second.fid, privkey: second.privkey, recipientPubkey: second.pubkey, now: at(100)
        )
        let request = try onlyQueued(second)

        // The asking device reads its own ask back off the DOCK. It is
        // not a question for it.
        let echo = try deliver(request, to: second, now: at(105))
        XCTAssertNil(echo.historyRequest)
        XCTAssertTrue(try second.session.historyShares.incoming().isEmpty)

        let incoming = try XCTUnwrap(try deliver(request, to: first, now: at(110)).historyRequest)
        XCTAssertEqual(incoming.conversationId, thread.id, "our other device names the thread as it is")

        _ = try await first.service.approve(
            incoming, as: first.fid, privkey: first.privkey, requesterPubkey: first.pubkey, now: at(120)
        )
        let answer = try onlyQueued(first)
        // The answering device reads its own answer back too, and has no
        // ask to match it to.
        XCTAssertNil(try deliver(answer, to: first, now: at(125)).historyReceived)
        XCTAssertNotNil(try deliver(answer, to: second, now: at(130)).historyReceived)

        let results = await second.service.importReceived(as: second.fid, now: at(140))
        XCTAssertEqual(results.map(\.imported), [3])
        XCTAssertEqual(try second.session.messages.count(in: thread.id), 3)
        _ = ask
    }

    // MARK: - who may ask

    /// **Android's P2P shape, and the bug it hides.** The ask names the
    /// responder's own FID as its target; looked up directly that is the
    /// responder's note-to-self thread.
    func testAP2PAskNamingUsIsAboutTheThreadWithTheAsker() {
        let payload = HistoryRequestPayload(imType: .p2p, targetId: "F-bob", since: 0, before: 10)
        XCTAssertEqual(payload.responderConversation(requester: "F-alice", as: "F-bob")?.targetId, "F-alice")
        XCTAssertEqual(payload.responderConversation(requester: "F-alice", as: "F-bob")?.type, .p2p)
    }

    /// A conversation between us and Carol is not Bob's to ask for.
    func testAP2PAskAboutSomeoneElsesThreadIsRefused() throws {
        let payload = HistoryRequestPayload(imType: .p2p, targetId: "F-carol", since: 0, before: 10)
        XCTAssertNil(payload.responderConversation(requester: "F-alice", as: "F-bob"))

        let bob = try makePeer(0xB2, label: "bob")
        var ask = ImMessage.request(type: .p2p, from: "F-alice", to: bob.fid, requestType: .history,
                                    data: payload.json(), now: t0).named()
        ask.requestId = "0123456789abcdef"
        let outcome = try router(for: bob).route(ask, as: bob.fid, now: t0)
        XCTAssertNil(outcome.historyRequest)
        XCTAssertTrue(try bob.session.historyShares.incoming().isEmpty)
    }

    /// A group ask is answered only for a group both parties are in, as
    /// this device understands it.
    func testARoomAskNeedsBothPartiesInTheRoom() throws {
        let bob = try makePeer(0xB2, label: "bob")
        let roomId = "room_b4c9a1f2e8d73065b4c9"
        try bob.session.rooms.upsert(Room(owner: bob.fid, name: "r", members: [bob.fid, "F-carol"], id: roomId))
        let payload = HistoryRequestPayload(imType: .room, targetId: roomId, since: 0, before: 10)

        func ask(from fid: String) -> ImMessage {
            var m = ImMessage.request(type: .p2p, from: fid, to: bob.fid, requestType: .history,
                                      data: payload.json(), now: t0).named()
            m.requestId = HistoryShare.newNonce()
            return m
        }
        XCTAssertNil(try router(for: bob).route(ask(from: "F-mallory"), as: bob.fid, now: t0).historyRequest)
        let carols = try router(for: bob).route(ask(from: "F-carol"), as: bob.fid, now: t0).historyRequest
        XCTAssertEqual(carols?.conversationId, Conversation.id(type: .room, targetId: roomId))
    }

    /// Two askers may pick the same nonce; one must not overwrite the
    /// other's ask.
    func testIncomingAsksAreKeyedByAskerAndNonce() throws {
        let store = try makePeer(0xB2, label: "bob").session.historyShares
        let a = IncomingHistoryRequest(nonce: "n", from: "F-a", type: .p2p, targetId: "F-a",
                                       since: 0, before: 1, receivedAt: 1, requestedTargetId: "F-b")
        var b = a
        b.from = "F-c"
        b.targetId = "F-c"
        try store.recordIncoming(a)
        try store.recordIncoming(b)
        XCTAssertEqual(try store.incoming().count, 2)
    }

    // MARK: - who may answer

    func testAnAnswerNobodyAskedForIsIgnored() throws {
        let alice = try makePeer(0xA1, label: "alice")
        var answer = ImMessage.history(type: .p2p, from: "F-bob", to: alice.fid, hatJson: "{}", kCipher: nil, now: t0).named()
        answer.requestId = "feedfacefeedface"
        XCTAssertNil(try router(for: alice).route(answer, as: alice.fid, now: t0).historyReceived)
        XCTAssertTrue(try alice.session.historyShares.received().isEmpty)
    }

    /// The nonce is not a password. Android checks only it, so anybody
    /// who saw one could answer in the asked member's place.
    func testAnAnswerFromSomeoneWhoWasNotAskedIsIgnored() throws {
        let alice = try makePeer(0xA1, label: "alice")
        try alice.session.historyShares.recordAsk(OutgoingHistoryRequest(
            nonce: "feedfacefeedface", askedFid: "F-bob", conversationId: "P2P_F-bob",
            since: 0, before: 10, sentAt: ms(0)
        ))
        var answer = ImMessage.history(type: .p2p, from: "F-mallory", to: alice.fid, hatJson: "{}", kCipher: nil, now: t0).named()
        answer.requestId = "feedfacefeedface"

        XCTAssertNil(try router(for: alice).route(answer, as: alice.fid, now: t0).historyReceived)
        XCTAssertNotNil(try alice.session.historyShares.ask(nonce: "feedfacefeedface"), "Bob can still answer")
    }

    // MARK: - approving

    func testApprovingAnEmptyRangeSendsNothingAndKeepsTheAsk() async throws {
        let bob = try makePeer(0xB2, label: "bob")
        let alice = try makePeer(0xA1, label: "alice")
        _ = try seedThread(on: bob, with: alice)
        let request = IncomingHistoryRequest(
            nonce: "n1", from: alice.fid, type: .p2p, targetId: alice.fid,
            since: ms(1000), before: ms(2000), receivedAt: ms(0), requestedTargetId: bob.fid
        )
        try bob.session.historyShares.recordIncoming(request)

        do {
            _ = try await bob.service.approve(request, as: bob.fid, privkey: bob.privkey, requesterPubkey: alice.pubkey)
            XCTFail("expected nothingInRange")
        } catch let failure as HistoryShareService.Failure {
            XCTAssertEqual(failure, .nothingInRange)
        }
        XCTAssertTrue(try bob.session.outbox.all().isEmpty)
        XCTAssertEqual(try bob.session.historyShares.incoming(), [request])
    }

    // MARK: - importing

    /// **An answer may only fill the thread that was asked about**, and
    /// only the range asked for. Android files each line wherever the
    /// line says, so one answer could plant messages in any thread.
    func testImportIgnoresOtherThreadsOtherTimesAndMessagesWeHold() throws {
        let alice = try makePeer(0xA1, label: "alice")
        let bob = "F-bob"
        let thread = Conversation.id(type: .p2p, targetId: bob)
        let held = text("already here", from: bob, to: alice.fid, at: 20, id: 2_002)
        try alice.session.messages.put(held, in: thread)

        let lines = [
            text("in range", from: bob, to: alice.fid, at: 10, id: 2_001),
            text("changed copy", from: bob, to: alice.fid, at: 20, id: 2_002),
            text("planted", from: "F-mallory", to: alice.fid, at: 15, id: 2_003),
            text("too late", from: bob, to: alice.fid, at: 5000, id: 2_004),
        ]
        let file = HistoryFile.export(lines, meta: HistoryExportMeta(fid: bob, exportTime: 0))
        let share = ReceivedHistoryShare(
            nonce: "n", from: bob, conversationId: thread, since: ms(0), before: ms(3600),
            hatJson: "{}", receivedAt: 0
        )

        XCTAssertEqual(try alice.service.importFile(file, share: share, as: alice.fid), 1)
        XCTAssertEqual(try alice.session.messages.page(in: thread).messages.map(\.content), ["in range", "already here"])
        XCTAssertNil(try alice.session.conversations.get(id: Conversation.id(type: .p2p, targetId: "F-mallory")))
    }

    // MARK: - the pieces

    func testTheRangeIsInclusiveAtTheStartAndExclusiveAtTheEnd() throws {
        let alice = try makePeer(0xA1, label: "alice")
        let thread = try seedThread(on: alice, with: try makePeer(0xB2, label: "bob"))
        let picked = try alice.session.messages.messages(in: thread, since: ms(10), before: ms(30))
        XCTAssertEqual(picked.map(\.content), ["hello", "hi back"])
        XCTAssertEqual(try alice.session.messages.messageIds(in: thread).count, 3)
    }

    func testThePayloadReadsAndroidsNumbersAndRefusesAnEmptyRange() {
        let android = #"{"targetId":"F-bob","before":1.7551036E12,"imType":"P2P","since":1755100000000}"#
        let parsed = HistoryRequestPayload.parse(android)
        XCTAssertEqual(parsed?.imType, .p2p)
        XCTAssertEqual(parsed?.since, 1_755_100_000_000)
        XCTAssertEqual(parsed?.before, 1_755_103_600_000)

        let ours = HistoryRequestPayload(imType: .team, targetId: "t1", since: 5, before: 9)
        XCTAssertEqual(HistoryRequestPayload.parse(ours.json()), ours)
        XCTAssertNil(HistoryRequestPayload.parse(#"{"imType":"P2P","targetId":"x","since":9,"before":5}"#))
        XCTAssertNil(HistoryRequestPayload.parse("room_123"), "a key request's content is not a history ask")
    }

    /// The file an Android client reads: `ExportMeta` first, in Java
    /// field order, then messages; the meta line is recognised the way
    /// Android recognises it and never imported as a message.
    func testTheFileIsMetaThenMessages() {
        let meta = HistoryExportMeta(
            fid: "F-bob", exportTime: 7, imType: "P2P", targetId: "F-bob",
            sinceTs: 1, beforeTs: 2, sharedTo: "F-alice"
        )
        XCTAssertEqual(
            meta.json(),
            #"{"version":"1.0","fid":"F-bob","exportTime":7,"appName":"Freer","entityType":"imMessage","imType":"P2P","targetId":"F-bob","sinceTs":1,"beforeTs":2,"sharedTo":"F-alice"}"#
        )
        let file = HistoryFile.export([text("x", from: "F-bob", to: "F-alice", at: 1, id: 9)], meta: meta)
        XCTAssertEqual(file.split(separator: "\n").count, 2)
        let back = HistoryFile.messages(in: file)
        XCTAssertEqual(back.map(\.content), ["x"])
        XCTAssertNil(back.first?.status)
        XCTAssertNil(back.first?.dockId)
    }

    func testAnswersThatKeepFailingWaitForAPerson() async throws {
        let alice = try makePeer(0xA1, label: "alice")
        let share = ReceivedHistoryShare(
            nonce: "n", from: "F-bob", conversationId: "P2P_F-bob", since: 0, before: 1,
            hatJson: "not a hat", receivedAt: 0
        )
        try alice.session.historyShares.recordReceived(share)

        for _ in 0..<ReceivedHistoryShare.automaticAttempts {
            let results = await alice.service.importReceived(as: alice.fid)
            XCTAssertEqual(results.count, 1)
            XCTAssertNotNil(results.first?.error)
        }
        let skipped = await alice.service.importReceived(as: alice.fid)
        XCTAssertTrue(skipped.isEmpty, "no longer retried on every poll")
        let retried = await alice.service.importReceived(as: alice.fid, retrying: "n")
        XCTAssertEqual(retried.count, 1, "but Retry still tries")
    }
}
