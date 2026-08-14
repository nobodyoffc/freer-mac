import XCTest
import FCCore
import FCTransport
@testable import FCDomain

/// ``MessagesStore`` on a real per-main ``ActiveSession``: the key
/// ordering that makes paging possible, the per-conversation isolation
/// that makes it cheap, and the storage rule that a message we could
/// open is stored open.
final class MessagesStoreTests: XCTestCase {

    private var baseDir: URL!
    /// Held for the test's lifetime — `ConfigureSession` keeps only a
    /// weak reference to its manager.
    private var manager: ConfigureManager!
    private var configure: ConfigureSession!
    private var session: ActiveSession!

    private let me = "FEk41Kqjar45fLDriztUDTUkdki7mmcjWK"
    private let them = "F6vqNGkbAqZQ1YkPWLcXfNfwvJXCTGmzUM"

    override func setUpWithError() throws {
        baseDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("MessagesStoreTests-\(UUID().uuidString)")
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

    private var store: MessagesStore { session.messages }
    private var conversationId: String { Conversation.id(type: .p2p, targetId: them) }

    @discardableResult
    private func send(_ text: String, at ms: Int64, id: String, from: String? = nil) throws -> ImMessage {
        var m = ImMessage.text(type: .p2p, from: from ?? me, to: them, text)
        m.timestamp = ms
        m.id = id
        try store.put(m, in: conversationId)
        return m
    }

    // MARK: - keys and ordering

    /// The key is what makes paging a slice of a sorted string array, so
    /// it has to be numerically ordered *as text*. A shorter timestamp
    /// sorting before a longer one is the bug this rules out.
    func testKeyPadsSoTextOrderIsTimeOrder() {
        let early = MessagesStore.key(timestamp: 999, id: "aaaa")
        let late = MessagesStore.key(timestamp: 1_755_100_000_000, id: "0000")
        XCTAssertTrue(early < late)
        XCTAssertEqual(early.count, late.count)
        XCTAssertEqual(early, "0000000000000000999-aaaa")
    }

    /// A negative timestamp clamps rather than wrapping into a shorter
    /// string that would sort in the wrong place. The id keeps the key
    /// unique regardless.
    func testNegativeAndMissingTimestampsClampToZero() {
        XCTAssertEqual(MessagesStore.key(timestamp: -5, id: "a"), MessagesStore.key(timestamp: 0, id: "a"))
        XCTAssertEqual(MessagesStore.key(timestamp: nil, id: "a"), MessagesStore.key(timestamp: 0, id: "a"))
        XCTAssertNotEqual(MessagesStore.key(timestamp: -5, id: "a"), MessagesStore.key(timestamp: -5, id: "b"))
    }

    func testMessagesComeBackOldestFirst() throws {
        try send("third", at: 3_000, id: "0000000000000003")
        try send("first", at: 1_000, id: "0000000000000001")
        try send("second", at: 2_000, id: "0000000000000002")

        let page = try store.page(in: conversationId, limit: 10)
        XCTAssertEqual(page.messages.map(\.content), ["first", "second", "third"])
        XCTAssertNil(page.olderCursor)
        XCTAssertFalse(page.hasOlder)
    }

    /// Two messages in the same millisecond still get a total order, and
    /// it is the id — the same tiebreak `Conversation` uses, so the list
    /// and the transcript agree on which one is last.
    func testSameMillisecondBreaksTieOnId() throws {
        try send("b", at: 5_000, id: "00000000000000bb")
        try send("a", at: 5_000, id: "00000000000000aa")
        XCTAssertEqual(
            try store.page(in: conversationId, limit: 10).messages.map(\.content),
            ["a", "b"]
        )
    }

    // MARK: - paging

    func testPagingWalksBackwardsToTheStart() throws {
        for i in 1...25 {
            try send("m\(i)", at: Int64(i) * 1_000, id: String(format: "%016x", i))
        }

        let newest = try store.page(in: conversationId, limit: 10)
        XCTAssertEqual(newest.messages.map(\.content), (16...25).map { "m\($0)" })
        XCTAssertTrue(newest.hasOlder)

        let middle = try store.page(in: conversationId, before: newest.olderCursor, limit: 10)
        XCTAssertEqual(middle.messages.map(\.content), (6...15).map { "m\($0)" })
        XCTAssertTrue(middle.hasOlder)

        let oldest = try store.page(in: conversationId, before: middle.olderCursor, limit: 10)
        XCTAssertEqual(oldest.messages.map(\.content), (1...5).map { "m\($0)" })
        // Reached the beginning: no cursor, so no further round trip.
        XCTAssertFalse(oldest.hasOlder)
    }

    func testEmptyConversationPagesEmpty() throws {
        let page = try store.page(in: Conversation.id(type: .room, targetId: "nobody"), limit: 10)
        XCTAssertTrue(page.messages.isEmpty)
        XCTAssertFalse(page.hasOlder)
        XCTAssertNil(try store.latest(in: conversationId))
        XCTAssertEqual(try store.count(in: conversationId), 0)
    }

    func testLatestReadsTheNewest() throws {
        try send("old", at: 1_000, id: "0000000000000001")
        try send("new", at: 9_000, id: "0000000000000009")
        XCTAssertEqual(try store.latest(in: conversationId)?.content, "new")
        XCTAssertEqual(try store.count(in: conversationId), 2)
    }

    // MARK: - isolation

    /// One namespace per conversation is the whole reason this store
    /// scales; if rows leaked between threads, opening a chat would cost
    /// the size of every other chat.
    func testConversationsDoNotSeeEachOther() throws {
        let room = Conversation.id(type: .room, targetId: "room-1")
        try send("to them", at: 1_000, id: "0000000000000001")

        var roomMessage = ImMessage.text(type: .room, from: me, to: "room-1", "to the room")
        roomMessage.timestamp = 2_000
        roomMessage.id = "0000000000000002"
        try store.put(roomMessage, in: room)

        XCTAssertEqual(try store.count(in: conversationId), 1)
        XCTAssertEqual(try store.count(in: room), 1)
        XCTAssertEqual(try store.page(in: room, limit: 10).messages.map(\.content), ["to the room"])
        XCTAssertNil(try store.get(messageId: "0000000000000002", in: conversationId))
        XCTAssertEqual(Set(try store.conversationIds()), [conversationId, room])
    }

    // MARK: - storage rules

    /// A message we could open is stored open: the cipher is an
    /// ephemeral transport wrapper whose symkey may be rotated away,
    /// while the plaintext beside it stays readable. This is the
    /// opposite of `MailsStore` and is the point of that comparison.
    func testOpenedMessageDropsItsCipher() throws {
        var m = ImMessage.text(type: .p2p, from: them, to: me, "hello")
        m.cipher = "{\"type\":\"Symkey\",\"cipher\":\"c2FtcGxl\"}"
        m.timestamp = 1_000
        m.id = "0000000000000001"
        try store.put(m, in: conversationId)

        let stored = try XCTUnwrap(try store.get(messageId: m.id!, in: conversationId))
        XCTAssertEqual(stored.content, "hello")
        XCTAssertNil(stored.cipher)
    }

    /// A message we could *not* open keeps its cipher — it is the only
    /// copy, and a key we do not have yet might still arrive.
    func testUnopenedMessageKeepsItsCipher() throws {
        var m = ImMessage.make(type: .team, from: them, to: "team-1", contentType: .text)
        m.cipher = "{\"type\":\"Symkey\",\"cipher\":\"c2FtcGxl\"}"
        m.symkeyVersion = 4
        m.timestamp = 1_000
        m.id = "0000000000000001"
        let team = Conversation.id(type: .team, targetId: "team-1")
        try store.put(m, in: team)

        let stored = try XCTUnwrap(try store.get(messageId: m.id!, in: team))
        XCTAssertNil(stored.content)
        XCTAssertEqual(stored.cipher, m.cipher)
        XCTAssertEqual(stored.symkeyVersion, 4)
    }

    /// The store will not name a message. An id is the FUDP layer's to
    /// assign, and a made-up one would not be findable by the receipt
    /// that refers to it.
    func testPutRejectsAMessageWithNoId() throws {
        let m = ImMessage.text(type: .p2p, from: me, to: them, "nameless")
        XCTAssertThrowsError(try store.put(m, in: conversationId)) { error in
            XCTAssertEqual(error as? MessagesStore.Failure, .messageHasNoId)
        }
    }

    /// Re-storing a message whose timestamp changed must not leave the
    /// old copy behind under its old key.
    func testRestoringWithACorrectedTimestampDoesNotDuplicate() throws {
        var m = try send("first try", at: 1_000, id: "0000000000000001")
        m.timestamp = 8_000
        m.content = "corrected"
        try store.put(m, in: conversationId)

        XCTAssertEqual(try store.count(in: conversationId), 1)
        XCTAssertEqual(try store.latest(in: conversationId)?.content, "corrected")
    }

    // MARK: - mutation

    /// A mutation must not move a message in the transcript, whatever it
    /// does to the timestamp field — the key stays put.
    func testMutateKeepsThePosition() throws {
        try send("one", at: 1_000, id: "0000000000000001")
        try send("two", at: 2_000, id: "0000000000000002")

        let updated = try store.mutate(messageId: "0000000000000001", in: conversationId) { m in
            m.status = .delivered
            m.deliveredAt = 4_242
            m.timestamp = 9_999
        }
        XCTAssertEqual(updated?.status, .delivered)
        XCTAssertEqual(
            try store.page(in: conversationId, limit: 10).messages.map(\.content),
            ["one", "two"]
        )
        XCTAssertEqual(try store.count(in: conversationId), 2)
    }

    func testMutateIsNilForAnUnknownMessage() throws {
        XCTAssertNil(try store.mutate(messageId: "ffffffffffffffff", in: conversationId) { $0.pinned = true })
        XCTAssertFalse(try store.markRead(messageId: "ffffffffffffffff", in: conversationId))
    }

    func testMarkReadStampsAndIsIdempotent() throws {
        var m = ImMessage.text(type: .p2p, from: them, to: me, "unread one")
        m.unread = true
        m.timestamp = 1_000
        m.id = "0000000000000001"
        try store.put(m, in: conversationId)

        let at = Date(timeIntervalSince1970: 1_755_100_000)
        XCTAssertTrue(try store.markRead(messageId: m.id!, in: conversationId, at: at))
        let read = try XCTUnwrap(try store.get(messageId: m.id!, in: conversationId))
        XCTAssertEqual(read.unread, false)
        XCTAssertEqual(read.readAt, 1_755_100_000_000)
        XCTAssertFalse(try store.markRead(messageId: m.id!, in: conversationId, at: at))
    }

    func testMarkAllReadReportsWhatChanged() throws {
        for i in 1...3 {
            var m = ImMessage.text(type: .p2p, from: them, to: me, "m\(i)")
            m.unread = true
            m.timestamp = Int64(i) * 1_000
            m.id = String(format: "%016x", i)
            try store.put(m, in: conversationId)
        }
        try send("mine", at: 4_000, id: "0000000000000004")

        XCTAssertEqual(try store.markAllRead(in: conversationId), 3)
        XCTAssertEqual(try store.markAllRead(in: conversationId), 0)
        XCTAssertTrue(try store.page(in: conversationId, limit: 10).messages.allSatisfy { $0.unread != true })
    }

    // MARK: - deleting

    func testDeleteOneAndDeleteAll() throws {
        try send("one", at: 1_000, id: "0000000000000001")
        try send("two", at: 2_000, id: "0000000000000002")

        XCTAssertTrue(try store.delete(messageId: "0000000000000001", in: conversationId))
        XCTAssertFalse(try store.delete(messageId: "0000000000000001", in: conversationId))
        XCTAssertEqual(try store.count(in: conversationId), 1)

        XCTAssertEqual(try store.deleteConversation(conversationId), 1)
        XCTAssertEqual(try store.count(in: conversationId), 0)
        XCTAssertFalse(try store.conversationIds().contains(conversationId))
    }
}
