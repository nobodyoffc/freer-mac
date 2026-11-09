import XCTest
import FCCore
import FCTransport
import FCStorage
@testable import FCDomain

/// ``MessageAmend``. The rule cases are shared with Android's
/// `MessageAmendTest`: an edit or withdraw must land the same way on
/// every device. The ``ChatService`` cases below them are Mac-only.
final class MessageAmendTests: XCTestCase {

    static let alice = "FEk41Kqjar45fLDriztUDTUkdki7mmcjWK"
    static let bob = "F86zoAvNaQxEuYyvQssV5WxEzapNaiDtTW"
    static let t0: Int64 = 1_762_300_800_000

    static func original() -> ImMessage {
        var m = ImMessage.text(type: .p2p, from: alice, to: bob, "helo")
        m.id = "00000000000000a1"
        m.timestamp = t0
        m.status = .sent
        return m
    }

    static func edit(_ id: String, _ text: String, at: Int64) -> ImMessage {
        var op = MessageAmend.edit(of: original(), text: text, nowMs: at)
        op.id = id
        return op
    }

    static func withdraw(_ id: String, at: Int64) -> ImMessage {
        var op = MessageAmend.withdraw(of: original(), fallbackText: "Withdrew a message", nowMs: at)
        op.id = id
        return op
    }

    // MARK: - shared with Android

    func testEditReplacesTextAndKeepsTheOriginal() {
        var m = Self.original()
        XCTAssertEqual(MessageAmend.apply(Self.edit("00000000000000e1", "hello", at: Self.t0 + 60_000), to: &m), .applied)
        XCTAssertEqual(m.content, "hello")
        XCTAssertEqual(m.editedAt, Self.t0 + 60_000)
        XCTAssertEqual(m.editId, "00000000000000e1")
        XCTAssertEqual(m.editHistory, [.init(content: "helo", at: Self.t0, editId: nil)])
    }

    func testEditsArrivingOutOfOrderEndOnTheNewest() {
        var m = Self.original()
        MessageAmend.apply(Self.edit("00000000000000e2", "hello!", at: Self.t0 + 120_000), to: &m)
        MessageAmend.apply(Self.edit("00000000000000e1", "hello", at: Self.t0 + 60_000), to: &m)
        XCTAssertEqual(m.content, "hello!")
        XCTAssertEqual(m.editedAt, Self.t0 + 120_000)
        XCTAssertEqual(m.editHistory?.map(\.content), ["helo", "hello"])
    }

    func testTheSameEditTwiceIsADuplicate() {
        var m = Self.original()
        MessageAmend.apply(Self.edit("00000000000000e1", "hello", at: Self.t0 + 60_000), to: &m)
        XCTAssertEqual(MessageAmend.apply(Self.edit("00000000000000e1", "hello", at: Self.t0 + 60_000), to: &m), .duplicate)
        XCTAssertEqual(m.editHistory?.count, 1)
        MessageAmend.apply(Self.edit("00000000000000e2", "hello!", at: Self.t0 + 120_000), to: &m)
        XCTAssertEqual(MessageAmend.apply(Self.edit("00000000000000e1", "hello", at: Self.t0 + 60_000), to: &m), .duplicate)
    }

    func testWithdrawDropsEveryVersionAndWinsOverLaterEdits() {
        var m = Self.original()
        MessageAmend.apply(Self.edit("00000000000000e1", "hello", at: Self.t0 + 60_000), to: &m)
        XCTAssertEqual(MessageAmend.apply(Self.withdraw("00000000000000d1", at: Self.t0 + 90_000), to: &m), .applied)
        XCTAssertTrue(m.isWithdrawn)
        XCTAssertEqual(m.withdrawnAt, Self.t0 + 90_000)
        XCTAssertNil(m.content)
        XCTAssertNil(m.editHistory)
        XCTAssertEqual(MessageAmend.apply(Self.edit("00000000000000e2", "again", at: Self.t0 + 80_000), to: &m), .duplicate)
        XCTAssertNil(m.content)
    }

    func testTheWindowIsTenMinutesBetweenSignedTimestamps() {
        var a = Self.original(), b = Self.original(), c = Self.original()
        XCTAssertEqual(MessageAmend.apply(Self.edit("00000000000000e1", "x", at: Self.t0 + MessageAmend.windowMs), to: &a), .applied)
        XCTAssertEqual(MessageAmend.apply(Self.edit("00000000000000e1", "x", at: Self.t0 + MessageAmend.windowMs + 1), to: &b), .rejected)
        XCTAssertEqual(MessageAmend.apply(Self.withdraw("00000000000000d1", at: Self.t0 - 1), to: &c), .rejected)
    }

    func testOnlyTheAuthorInTheSameThread() {
        var m = Self.original()
        var byBob = Self.edit("00000000000000e1", "x", at: Self.t0 + 1)
        byBob.senderId = Self.bob
        byBob.targetId = Self.alice
        XCTAssertEqual(MessageAmend.apply(byBob, to: &m), .rejected)

        var elsewhere = Self.edit("00000000000000e1", "x", at: Self.t0 + 1)
        elsewhere.type = .team
        XCTAssertEqual(MessageAmend.apply(elsewhere, to: &m), .rejected)

        var wrongTarget = Self.edit("00000000000000e1", "x", at: Self.t0 + 1)
        wrongTarget.requestId = "00000000000000ff"
        XCTAssertEqual(MessageAmend.apply(wrongTarget, to: &m), .rejected)
    }

    func testOnlyTextIsEditableButAnythingCanBeWithdrawn() {
        var voice = Self.original()
        voice.contentType = .voice
        voice.data = Data([1, 2, 3])
        XCTAssertEqual(MessageAmend.apply(Self.edit("00000000000000e1", "x", at: Self.t0 + 1), to: &voice), .rejected)
        XCTAssertEqual(MessageAmend.apply(Self.withdraw("00000000000000d1", at: Self.t0 + 1), to: &voice), .applied)
        XCTAssertNil(voice.data)
    }

    func testAnEmptyEditIsRejected() {
        var m = Self.original()
        XCTAssertEqual(MessageAmend.apply(Self.edit("00000000000000e1", "  ", at: Self.t0 + 1), to: &m), .rejected)
    }

    func testVersionsAreBounded() {
        var m = Self.original()
        for i in 1..<MessageAmend.maxVersions {
            XCTAssertEqual(MessageAmend.apply(Self.edit(String(format: "%016x", i), "v\(i)", at: Self.t0 + Int64(i)), to: &m), .applied)
        }
        XCTAssertEqual(MessageAmend.apply(Self.edit("00000000000000ff", "one more", at: Self.t0 + 1000), to: &m), .rejected)
    }

    func testCanAmendOnlyOwnSentMessagesInsideTheWindow() {
        var m = Self.original()
        XCTAssertTrue(MessageAmend.canAmend(m, as: Self.alice, nowMs: Self.t0 + MessageAmend.windowMs))
        XCTAssertFalse(MessageAmend.canAmend(m, as: Self.alice, nowMs: Self.t0 + MessageAmend.windowMs + 1))
        XCTAssertFalse(MessageAmend.canAmend(m, as: Self.bob, nowMs: Self.t0 + 1))
        m.status = .pending
        XCTAssertFalse(MessageAmend.canAmend(m, as: Self.alice, nowMs: Self.t0 + 1))
        m.status = .sent
        m.withdrawn = true
        XCTAssertFalse(MessageAmend.canAmend(m, as: Self.alice, nowMs: Self.t0 + 1))
    }

    /// The history file is read by the other client, so the folded state
    /// goes in Gson's field order: after `deleted`, before `id`.
    func testAmendStateIsInTheHistoryFileInAndroidsOrder() throws {
        var m = Self.original()
        MessageAmend.apply(Self.edit("00000000000000e1", "hello", at: Self.t0 + 60_000), to: &m)
        let json = m.wireJson()
        XCTAssertTrue(json.hasSuffix(
            "\"editedAt\":1762300860000,\"editId\":\"00000000000000e1\","
            + "\"editHistory\":[{\"content\":\"helo\",\"at\":1762300800000}],"
            + "\"id\":\"00000000000000a1\"}"
        ), json)
        let back = try ImMessage.fromJson(json)
        XCTAssertEqual(back.content, "hello")
        XCTAssertEqual(back.editHistory, m.editHistory)
    }

    // MARK: - through ChatService

    private var baseDir: URL!
    private var manager: ConfigureManager!
    private var configure: ConfigureSession!
    private var session: ActiveSession!

    private let alicePriv = Data(repeating: 0xA1, count: 32)
    private let bobPriv = Data(repeating: 0xB2, count: 32)
    private var them: String { (try? FchAddress(publicKey: Secp256k1.publicKey(fromPrivateKey: bobPriv)).fid) ?? "" }
    private let roomId = "room_b4c9a1f2e8d73065b4c9"
    private let start = Date(timeIntervalSince1970: 1_755_100_000)
    private func at(_ seconds: TimeInterval) -> Date { start.addingTimeInterval(seconds) }

    override func setUpWithError() throws {
        baseDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("MessageAmendTests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: baseDir, withIntermediateDirectories: true)
        manager = try ConfigureManager(baseDirectory: baseDir)
        configure = try manager.createConfigure(password: Data("pwd".utf8), kdfKind: .legacySha256)
        let info = try configure.addMain(privkey: alicePriv, label: "A")
        session = try configure.unlockMain(fid: info.fid, fapi: MockFapiClient())
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
    private var p2pId: String { Conversation.id(type: .p2p, targetId: them) }

    /// Bob's message to us, and Bob's amendment of it, both sealed by Bob.
    private func fromBob(_ text: String, at date: Date) throws -> ImMessage {
        var m = ImMessage.text(type: .p2p, from: them, to: me, text, now: date)
        m.setId(fudpId: ChatService.newMessageId())
        try m.sealBody(privkey: bobPriv, recipientPubkey: Secp256k1.publicKey(fromPrivateKey: alicePriv))
        return m
    }

    private func sealedByBob(_ op: ImMessage) throws -> ImMessage {
        var m = op
        m.setId(fudpId: ChatService.newMessageId())
        try m.sealBody(privkey: bobPriv, recipientPubkey: Secp256k1.publicKey(fromPrivateKey: alicePriv))
        return m
    }

    private func plain(_ m: ImMessage) -> ImMessage {
        var p = m
        p.body = nil
        return p
    }

    func testAnIncomingEditChangesTheRowAndThePreview() throws {
        let original = try fromBob("helo", at: start)
        guard case .message(let filed) = try chat.receive(original, as: me, privkey: alicePriv, now: at(1))
        else { return XCTFail("expected .message") }
        var unsealed = filed
        unsealed.content = "helo"
        let edit = try sealedByBob(MessageAmend.edit(of: unsealed, text: "hello", nowMs: ChatService.millis(at(30))))

        guard case .amended(let amended) = try chat.receive(edit, as: me, privkey: alicePriv, now: at(31))
        else { return XCTFail("expected .amended") }
        XCTAssertEqual(amended.content, "hello")
        XCTAssertEqual(try chat.page(p2pId).messages.map(\.content), ["hello"], "an edit is not a row")
        XCTAssertEqual(try session.conversations.get(id: p2pId)?.lastMessageContent, "hello")
        XCTAssertEqual(try session.conversations.get(id: p2pId)?.unreadCount, 1, "an edit is not news")
    }

    func testAWithdrawThatArrivesFirstWaitsForItsOriginal() throws {
        let original = try fromBob("oops", at: start)
        var known = plain(original)
        known.content = "oops"
        let withdraw = try sealedByBob(MessageAmend.withdraw(of: known, fallbackText: "x", nowMs: ChatService.millis(at(20))))

        guard case .ignored = try chat.receive(withdraw, as: me, privkey: alicePriv, now: at(21))
        else { return XCTFail("nothing to apply it to yet") }
        guard case .message(let filed) = try chat.receive(original, as: me, privkey: alicePriv, now: at(22))
        else { return XCTFail("expected .message") }
        XCTAssertTrue(filed.isWithdrawn)
        XCTAssertNil(try chat.page(p2pId).messages.first?.content)
    }

    func testAGroupEditWaitsForItsKey() throws {
        _ = try openConversation(.room, roomId)
        let roomConv = Conversation.id(type: .room, targetId: roomId)

        var original = ImMessage.text(type: .room, from: them, to: roomId, "helo", now: start)
        original.setId(fudpId: ChatService.newMessageId())
        var edit = MessageAmend.edit(of: original, text: "hello", nowMs: ChatService.millis(at(30)))
        edit.setId(fudpId: ChatService.newMessageId())
        // Both sealed under a version this device does not hold yet.
        let missing = Data(repeating: 0x5A, count: 32)
        let version: Int64 = 1_755_100_000
        try original.sealBody(symkey: missing, version: version)
        try edit.sealBody(symkey: missing, version: version)

        guard case .sealed = try chat.receive(original, as: me, now: at(1)) else { return XCTFail("expected .sealed") }
        guard case .ignored = try chat.receive(edit, as: me, now: at(31)) else { return XCTFail("held until its key") }

        try session.symkeys.store(missing, for: roomId, version: version)
        _ = try chat.openSealed(forEntity: roomId, as: me)
        XCTAssertEqual(try chat.page(roomConv).messages.map(\.content), ["hello"])
        XCTAssertEqual(try chat.page(roomConv).messages.first?.editHistory?.map(\.content), ["helo"])
    }

    func testEditingOurOwnMessageQueuesTheEditAndFilesNothingNew() throws {
        let conversation = try openConversation(.room, roomId)
        _ = try session.symkeys.mint(for: roomId, now: start)
        var sent = try chat.sendText("helo", in: conversation.id, as: me, now: start)
        try session.messages.mutate(messageId: sent.id!, in: conversation.id) { $0.status = .sent }
        sent.status = .sent

        let amended = try chat.edit(sent.id!, in: conversation, to: "hello", as: me, now: at(60))
        XCTAssertEqual(amended.content, "hello")
        XCTAssertEqual(try chat.page(conversation.id).messages.map(\.content), ["hello"])
        let queued = try session.outbox.all().map(\.message)
        XCTAssertEqual(queued.last?.contentType, .edit)
        XCTAssertEqual(queued.last?.requestId, sent.id)
        XCTAssertNotNil(queued.last?.body, "the edit travels sealed like the message it changes")

        XCTAssertThrowsError(try chat.edit(sent.id!, in: conversation, to: "late", as: me, now: at(11 * 60)))
    }

    func testWithdrawingIsSignedInsideTheWindowTheUserAskedIn() throws {
        let conversation = try openConversation(.room, roomId)
        _ = try session.symkeys.mint(for: roomId, now: start)
        let sent = try chat.sendText("oops", in: conversation.id, as: me, now: start)
        try session.messages.mutate(messageId: sent.id!, in: conversation.id) { $0.status = .sent }

        // Asked at 9:59; the DOCK delete took until 10:30.
        let amended = try chat.withdraw(sent.id!, in: conversation, as: me,
                                        checkedAt: at(599), now: at(630))
        XCTAssertTrue(amended.isWithdrawn)
        let op = try XCTUnwrap(try session.outbox.all().map(\.message).last)
        XCTAssertEqual(op.contentType, .delete)
        XCTAssertEqual(op.timestamp, ChatService.millis(start) + MessageAmend.windowMs)
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
}
