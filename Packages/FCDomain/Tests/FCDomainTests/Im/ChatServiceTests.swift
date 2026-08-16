import XCTest
import FCCore
import FCTransport
import FCStorage
@testable import FCDomain

/// ``ChatService``: the one seam a typed message and an arriving message
/// both go through, and the sealing rule that the call site cannot get
/// wrong because it cannot express it.
final class ChatServiceTests: XCTestCase {

    private var baseDir: URL!
    private var manager: ConfigureManager!
    private var configure: ConfigureSession!
    private var session: ActiveSession!

    private let alicePriv = Data(repeating: 0xA1, count: 32)
    private let bobPriv = Data(repeating: 0xB2, count: 32)
    private let mallory = Data(repeating: 0xC3, count: 32)
    private let them = "F6vqNGkbAqZQ1YkPWLcXfNfwvJXCTGmzUM"
    private let roomId = "room_b4c9a1f2e8d73065b4c9"
    private let squareId = "8e7d6c5b0000000000000000000000000000000000000000000000000000sqr1"

    private let t0 = Date(timeIntervalSince1970: 1_755_100_000)
    private func at(_ seconds: TimeInterval) -> Date { t0.addingTimeInterval(seconds) }

    override func setUpWithError() throws {
        baseDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("ChatServiceTests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: baseDir, withIntermediateDirectories: true)

        manager = try ConfigureManager(baseDirectory: baseDir)
        configure = try manager.createConfigure(password: Data("pwd".utf8), kdfKind: .legacySha256)
        let info = try configure.addMain(privkey: alicePriv, label: "A")
        session = try configure.unlockMain(fid: info.fid, fapi: MockFapiClient())

        // These tests are about sealing, filing and counting, and they
        // all assume the two parties are already talking. Since the
        // stranger gate landed that assumption has to be stated: an
        // unaccepted FID's first P2P message is *held*, not filed, and
        // that rule has its own suite (`ContactPolicyTests`).
        try session.contactPolicy.mutate(liveFid: info.fid) { $0.allow(them) }
    }

    override func tearDownWithError() throws {
        session = nil
        configure = nil
        manager = nil
        if let baseDir { try? FileManager.default.removeItem(at: baseDir) }
    }

    private var chat: ChatService { session.chat }
    private var me: String { session.liveFid }

    private func pubkey(_ privkey: Data) throws -> Data {
        try Secp256k1.publicKey(fromPrivateKey: privkey)
    }

    @discardableResult
    private func openConversation(_ type: ImType, _ targetId: String) throws -> Conversation {
        var conversation = Conversation(
            id: Conversation.id(type: type, targetId: targetId),
            targetId: targetId,
            type: type
        )
        conversation.unreadCount = 0
        try session.conversations.upsert(conversation)
        return conversation
    }

    // MARK: - sealing is decided by the conversation

    /// A P2P body goes AsyTwoWay to the recipient, and what we *keep* is
    /// the plaintext — because we can obviously read our own message, and
    /// because the wire copy is no longer readable to us.
    ///
    /// An AsyTwoWay **bundle** records only `pubkeyA`, unlike the JSON
    /// envelope, so the sender cannot reopen what they sealed. Nothing
    /// depends on their being able to: the stored copy is the plaintext,
    /// and the sealed copy exists only to be handed to a DOCK.
    func testP2PSendSealsToTheRecipientAndKeepsThePlaintext() throws {
        try openConversation(.p2p, them)
        let conversationId = Conversation.id(type: .p2p, targetId: them)

        let sent = try chat.sendText(
            "just between us", in: conversationId, as: me,
            keys: .init(privkey: alicePriv, recipientPubkey: try pubkey(bobPriv)),
            now: t0
        )
        XCTAssertEqual(sent.content, "just between us")
        XCTAssertEqual(sent.status, .pending)
        XCTAssertTrue(sent.hasFudpId)

        // The stored copy is open; the queued copy is sealed.
        let stored = try XCTUnwrap(try session.messages.get(messageId: sent.id!, in: conversationId))
        XCTAssertEqual(stored.content, "just between us")

        let queued = try XCTUnwrap(try session.outbox.get(id: sent.id!)).message
        XCTAssertNil(queued.content)
        var recipientCopy = queued
        XCTAssertTrue(recipientCopy.openBody(privkey: bobPriv))
        XCTAssertEqual(recipientCopy.content, "just between us")
        var senderCopy = queued
        XCTAssertFalse(
            senderCopy.openBody(privkey: alicePriv),
            "the bundle records only pubkeyA, so the sender cannot reopen it — the store holds the plaintext instead"
        )
        var strangerCopy = queued
        XCTAssertFalse(strangerCopy.openBody(privkey: mallory))
    }

    /// A room body goes under the room's current key, stamped with its
    /// version.
    func testRoomSendUsesTheGroupKey() throws {
        try openConversation(.room, roomId)
        let key = try session.symkeys.rotate(for: roomId, now: t0)

        let sent = try chat.sendText(
            "the usual place", in: Conversation.id(type: .room, targetId: roomId), as: me, now: t0
        )
        let queued = try XCTUnwrap(try session.outbox.get(id: sent.id!)).message
        XCTAssertEqual(queued.symkeyVersion, key.version)
        var copy = queued
        XCTAssertTrue(copy.openBody(symkey: key.key))
        XCTAssertEqual(copy.content, "the usual place")
    }

    /// A square is **not** encrypted — anyone may join, so a key shared
    /// with everyone who asks would imply a privacy it does not have.
    func testSquareSendIsNotSealed() throws {
        try openConversation(.square, squareId)
        let sent = try chat.sendText(
            "hello all", in: Conversation.id(type: .square, targetId: squareId), as: me, now: t0
        )
        let queued = try XCTUnwrap(try session.outbox.get(id: sent.id!)).message
        XCTAssertNil(queued.body)
        XCTAssertEqual(queued.content, "hello all")
    }

    /// Sealing must fail loudly. The alternative to a thrown error is a
    /// private message on the wire in the clear.
    func testAGroupSendWithNoKeyThrowsAndQueuesNothing() throws {
        try openConversation(.room, roomId)
        XCTAssertThrowsError(
            try chat.sendText("no key yet", in: Conversation.id(type: .room, targetId: roomId), as: me, now: t0)
        ) { XCTAssertEqual($0 as? SymkeyStore.Failure, .noKey(entityId: roomId)) }
        XCTAssertEqual(try session.outbox.count(), 0)
        XCTAssertEqual(try session.messages.count(in: Conversation.id(type: .room, targetId: roomId)), 0)
    }

    func testAP2PSendWithNoRecipientKeyThrows() throws {
        try openConversation(.p2p, them)
        XCTAssertThrowsError(
            try chat.sendText("hi", in: Conversation.id(type: .p2p, targetId: them), as: me, now: t0)
        ) { XCTAssertEqual($0 as? ChatService.Failure, .noRecipientKey(them)) }
        XCTAssertEqual(try session.outbox.count(), 0)
    }

    func testEmptyAndUnknownAreRefused() throws {
        try openConversation(.square, squareId)
        let id = Conversation.id(type: .square, targetId: squareId)
        XCTAssertThrowsError(try chat.sendText("   ", in: id, as: me, now: t0)) {
            XCTAssertEqual($0 as? ChatService.Failure, .emptyMessage)
        }
        XCTAssertThrowsError(try chat.sendText("hi", in: "SQUARE_nope", as: me, now: t0)) {
            XCTAssertEqual($0 as? ChatService.Failure, .noSuchConversation("SQUARE_nope"))
        }
    }

    /// Sending files the message, bumps the thread, and queues it — the
    /// three things that have to happen together or not at all.
    func testSendUpdatesTranscriptThreadAndOutboxTogether() throws {
        try openConversation(.square, squareId)
        let conversationId = Conversation.id(type: .square, targetId: squareId)

        try chat.sendText("first", in: conversationId, as: me, now: t0)
        try chat.sendText("second", in: conversationId, as: me, now: at(5))

        XCTAssertEqual(try chat.page(conversationId).messages.map(\.content), ["first", "second"])
        let conversation = try XCTUnwrap(try session.conversations.get(id: conversationId))
        XCTAssertEqual(conversation.lastMessageContent, "second")
        XCTAssertEqual(conversation.unreadCount, 0, "our own messages are not unread")
        XCTAssertEqual(try session.outbox.count(), 2)
        XCTAssertEqual(try session.outbox.all().map(\.message.content).count, 2)
    }

    // MARK: - inbound

    private func inbound(
        _ text: String, type: ImType = .p2p, from: String? = nil, target: String? = nil, at date: Date
    ) -> ImMessage {
        var m = ImMessage.text(
            type: type, from: from ?? them, to: target ?? me, text, now: date
        )
        m.setId(fudpId: ChatService.newMessageId())
        return m
    }

    func testAnArrivingMessageIsFiledCountedAndStamped() throws {
        let message = inbound("hello there", at: t0)
        let received = try chat.receive(message, as: me, privkey: alicePriv, now: at(1))
        guard case .message(let stored) = received else { return XCTFail("expected .message") }

        XCTAssertEqual(stored.status, .delivered)
        XCTAssertEqual(stored.unread, true)
        XCTAssertEqual(stored.deliveredAt, Int64(at(1).timeIntervalSince1970 * 1000))

        let conversationId = Conversation.id(type: .p2p, targetId: them)
        XCTAssertEqual(try chat.page(conversationId).messages.map(\.content), ["hello there"])
        XCTAssertEqual(try session.conversations.get(id: conversationId)?.unreadCount, 1)
    }

    /// A sealed body arrives, is opened, and is filed open.
    func testAnArrivingSealedP2PMessageIsOpened() throws {
        var message = inbound("sealed hello", at: t0)
        try message.sealBody(privkey: bobPriv, recipientPubkey: try pubkey(alicePriv))

        guard case .message(let stored) = try chat.receive(message, as: me, privkey: alicePriv, now: at(1))
        else { return XCTFail("expected .message") }
        XCTAssertEqual(stored.content, "sealed hello")
        XCTAssertNil(stored.body, "the store drops a sealed body once the plaintext is beside it")
    }

    /// A body we cannot open is **kept sealed and flagged**, not
    /// dropped. After a rotation a batch will contain some of these, and
    /// each is a key to go and ask for.
    func testAnUnopenableMessageIsKeptAndReported() throws {
        try openConversation(.room, roomId)
        let key = try session.symkeys.rotate(for: roomId, now: t0)
        var message = inbound("after the rotation", type: .room, target: roomId, at: t0)
        try message.sealBody(symkey: key.key, version: 9)

        let received = try chat.receive(message, as: me, privkey: alicePriv, now: at(1))
        guard case .sealed(let stored, let version) = received else {
            return XCTFail("expected .sealed, got \(received)")
        }
        XCTAssertEqual(version, 9)
        XCTAssertTrue(stored.isSealed)

        let conversationId = Conversation.id(type: .room, targetId: roomId)
        XCTAssertEqual(try session.messages.count(in: conversationId), 1, "kept, not dropped")
        // …and it opens later, once the key turns up.
        try session.symkeys.store(key.key, for: roomId, version: 9, allowOverwrite: true, now: at(2))
        var again = try XCTUnwrap(try session.messages.get(messageId: stored.id!, in: conversationId))
        XCTAssertTrue(try session.symkeys.open(&again, for: roomId))
        XCTAssertEqual(again.content, "after the rotation")
    }

    /// A receipt advances one of our own messages instead of becoming a
    /// row in the transcript.
    func testAnArrivingReceiptAdvancesOurMessage() throws {
        try openConversation(.p2p, them)
        let conversationId = Conversation.id(type: .p2p, targetId: them)
        let sent = try chat.sendText(
            "did you get this", in: conversationId, as: me,
            keys: .init(privkey: alicePriv, recipientPubkey: try pubkey(bobPriv)), now: t0
        )

        var receipt = ImMessage.receipt(
            from: them, to: me, originalMessageId: sent.id!, read: true, now: at(5)
        )
        receipt.setId(fudpId: ChatService.newMessageId())

        guard case .receipt(let updated) = try chat.receive(receipt, as: me, now: at(5)) else {
            return XCTFail("expected .receipt")
        }
        XCTAssertEqual(updated.status, .read)
        XCTAssertEqual(try chat.page(conversationId).messages.count, 1, "the receipt is not a row")
    }

    /// The same thing, but sealed — which is how a receipt actually
    /// arrives, because a receipt is an ordinary P2P message and the
    /// DOCK path seals every one of those.
    ///
    /// This is the case that was broken: `receive` read `content` to
    /// decide what kind of receipt it was *before* opening the body, so
    /// every real receipt looked like an empty one and was discarded,
    /// and senders' messages sat at `sent` forever. The unsealed test
    /// above passed throughout, which is why it went unnoticed.
    func testASealedReceiptStillAdvancesOurMessage() throws {
        try openConversation(.p2p, them)
        let conversationId = Conversation.id(type: .p2p, targetId: them)
        let sent = try chat.sendText(
            "did you get this", in: conversationId, as: me,
            keys: .init(privkey: alicePriv, recipientPubkey: try pubkey(bobPriv)), now: t0
        )

        var receipt = ImMessage.receipt(
            from: them, to: me, originalMessageId: sent.id!, read: false, now: at(5)
        )
        receipt.setId(fudpId: ChatService.newMessageId())
        // Sealed by them, to us — exactly what comes off the DOCK.
        try receipt.sealBody(privkey: bobPriv, recipientPubkey: try pubkey(alicePriv))
        XCTAssertNil(receipt.content, "the kind of receipt is inside the seal")

        guard case .receipt(let updated) = try chat.receive(
            receipt, as: me, privkey: alicePriv, now: at(5)
        ) else {
            return XCTFail("expected .receipt")
        }
        XCTAssertEqual(updated.status, .delivered)
        XCTAssertEqual(try chat.page(conversationId).messages.count, 1, "the receipt is not a row")
    }

    /// A receipt we cannot open is reported as such rather than being
    /// silently treated as one that named nothing.
    func testASealedReceiptWeCannotOpenIsIgnoredNotMisread() throws {
        try openConversation(.p2p, them)
        let sent = try chat.sendText(
            "did you get this", in: Conversation.id(type: .p2p, targetId: them), as: me,
            keys: .init(privkey: alicePriv, recipientPubkey: try pubkey(bobPriv)), now: t0
        )

        var receipt = ImMessage.receipt(
            from: them, to: me, originalMessageId: sent.id!, read: true, now: at(5)
        )
        receipt.setId(fudpId: ChatService.newMessageId())
        try receipt.sealBody(privkey: bobPriv, recipientPubkey: try pubkey(mallory))

        guard case .ignored(let reason) = try chat.receive(
            receipt, as: me, privkey: alicePriv, now: at(5)
        ) else {
            return XCTFail("expected .ignored")
        }
        XCTAssertEqual(reason, "receipt still sealed")
    }

    /// Receiving someone else's message produces the receipt that tells
    /// them so — sealed, addressed to them, and not filed as a row.
    func testAcknowledgingAMessageQueuesASealedReceipt() throws {
        try openConversation(.p2p, them)
        let conversationId = Conversation.id(type: .p2p, targetId: them)

        var incoming = ImMessage.text(type: .p2p, from: them, to: me, "hello", now: t0)
        incoming.setId(fudpId: ChatService.newMessageId())
        guard case .message(let filed) = try chat.receive(incoming, as: me, now: at(1)) else {
            return XCTFail("expected .message")
        }

        let receipt = try XCTUnwrap(try chat.acknowledge(
            filed, kind: .delivered, as: me,
            keys: .init(privkey: alicePriv, recipientPubkey: try pubkey(bobPriv)), now: at(2)
        ))
        XCTAssertEqual(receipt.contentType, .receipt)
        XCTAssertEqual(receipt.targetId, them, "addressed to the sender, not the conversation")
        XCTAssertEqual(receipt.requestId, incoming.id)
        XCTAssertNil(receipt.content, "sealed like any other P2P body")

        // It is queued for delivery…
        let queued = try XCTUnwrap(try session.outbox.get(id: receipt.id!)).message
        var opened = queued
        XCTAssertTrue(opened.openBody(privkey: bobPriv))
        XCTAssertEqual(opened.content, "delivered")

        // …and it is not a row in the transcript.
        XCTAssertEqual(try chat.page(conversationId).messages.count, 1)
    }

    /// We do not acknowledge ourselves. A self-chat message would
    /// otherwise generate a receipt addressed to us, which would then be
    /// acknowledged in turn.
    func testOurOwnMessageIsNotAcknowledged() throws {
        try openConversation(.p2p, them)
        var mine = ImMessage.text(type: .p2p, from: me, to: them, "hello", now: t0)
        mine.setId(fudpId: ChatService.newMessageId())

        XCTAssertNil(try chat.acknowledge(
            mine, kind: .delivered, as: me,
            keys: .init(privkey: alicePriv, recipientPubkey: try pubkey(bobPriv)), now: at(2)
        ))
    }

    /// Signals and protocol traffic are handed back for the caller to
    /// route, not filed — otherwise a typing indicator would be a
    /// message in the transcript.
    func testSignalsAreRoutedNotFiled() throws {
        var typing = ImMessage.make(type: .p2p, from: them, to: me, contentType: .typing, now: t0)
        typing.setId(fudpId: ChatService.newMessageId())
        guard case .signal = try chat.receive(typing, as: me, now: t0) else {
            return XCTFail("expected .signal")
        }
        XCTAssertEqual(try session.messages.count(in: Conversation.id(type: .p2p, targetId: them)), 0)
    }

    func testUnnamedAndUnroutedMessagesAreIgnored() throws {
        var unnamed = ImMessage.text(type: .p2p, from: them, to: me, "hi", now: t0)
        unnamed.id = nil
        XCTAssertEqual(try chat.receive(unnamed, as: me, now: t0), .ignored(reason: "unnamed message"))

        var unrouted = ImMessage.text(type: .p2p, from: them, to: me, "hi", now: t0)
        unrouted.setId(fudpId: 7)
        unrouted.type = nil
        XCTAssertEqual(try chat.receive(unrouted, as: me, now: t0), .ignored(reason: "no route"))
    }

    // MARK: - reading

    /// Opening a thread clears both the thread's count and the messages'
    /// own flags — two stores and two facts.
    func testMarkReadClearsBothSides() throws {
        for i in 1...3 {
            _ = try chat.receive(inbound("m\(i)", at: at(Double(i))), as: me, privkey: alicePriv, now: at(Double(i)))
        }
        let conversationId = Conversation.id(type: .p2p, targetId: them)
        XCTAssertEqual(try session.conversations.get(id: conversationId)?.unreadCount, 3)

        XCTAssertEqual(try chat.markRead(conversationId, now: at(10)).count, 3)
        XCTAssertEqual(try session.conversations.get(id: conversationId)?.unreadCount, 0)
        XCTAssertTrue(try chat.page(conversationId).messages.allSatisfy { $0.unread != true })
    }

    /// The id is a random 64-bit number, the same thing the FUDP layer's
    /// `generateMessageId` produces — which is what lets the pane name a
    /// message today and the node take the job over in 9.2.4b.
    func testMessageIdsAreFudpShapedAndDistinct() {
        let ids = (0..<200).map { _ in ImMessage.hexId(fudpId: ChatService.newMessageId()) }
        XCTAssertEqual(Set(ids).count, ids.count)
        XCTAssertTrue(ids.allSatisfy { $0.count == 16 })
    }
}
