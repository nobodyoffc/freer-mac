import XCTest
import FCCore
import FCTransport
@testable import FCDomain

/// ``Conversation`` and ``ConversationsStore``: the thread id both
/// clients derive, what folding a message into a thread does, and the
/// fact that the whole index can be rebuilt from the transcript.
final class ConversationsStoreTests: XCTestCase {

    private var baseDir: URL!
    private var manager: ConfigureManager!
    private var configure: ConfigureSession!
    private var session: ActiveSession!

    private let me = "FEk41Kqjar45fLDriztUDTUkdki7mmcjWK"
    private let them = "F6vqNGkbAqZQ1YkPWLcXfNfwvJXCTGmzUM"

    override func setUpWithError() throws {
        baseDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("ConversationsStoreTests-\(UUID().uuidString)")
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

    private var store: ConversationsStore { session.conversations }
    private var messages: MessagesStore { session.messages }

    private func incoming(_ text: String, at ms: Int64, id: String) -> ImMessage {
        var m = ImMessage.text(type: .p2p, from: them, to: me, text)
        m.timestamp = ms
        m.id = id
        m.unread = true
        return m
    }

    private func outgoing(_ text: String, at ms: Int64, id: String) -> ImMessage {
        var m = ImMessage.text(type: .p2p, from: me, to: them, text)
        m.timestamp = ms
        m.id = id
        return m
    }

    // MARK: - identity

    /// A P2P thread is named after the *other* end, so the same exchange
    /// is one conversation from either side's point of view — which is
    /// why deriving the id needs to know who we are.
    func testP2PThreadIsTheSameFromBothEnds() {
        let sent = outgoing("hi", at: 1_000, id: "0000000000000001")
        let received = incoming("hi back", at: 2_000, id: "0000000000000002")
        XCTAssertEqual(sent.conversationId(for: me), "P2P_\(them)")
        XCTAssertEqual(received.conversationId(for: me), "P2P_\(them)")
        // And from their device it is the thread with us.
        XCTAssertEqual(sent.conversationId(for: them), "P2P_\(me)")
    }

    /// For a group the thread is the group, whoever is speaking.
    func testGroupThreadIsTheGroup() {
        var m = ImMessage.text(type: .room, from: them, to: "room-1", "hello room")
        m.id = "0000000000000001"
        XCTAssertEqual(m.conversationId(for: me), "ROOM_room-1")
        XCTAssertEqual(m.conversationId(for: them), "ROOM_room-1")
    }

    /// A frame with no routing names no conversation and must not open
    /// an empty one.
    func testUnroutedMessageNamesNoConversation() throws {
        XCTAssertNil(ImMessage(type: .p2p, senderId: me).conversationId(for: me))
        XCTAssertNil(ImMessage(senderId: me, targetId: them).conversationId(for: me))
        XCTAssertNil(try store.record(ImMessage(), myFid: me))
        XCTAssertTrue(try store.all().isEmpty)
    }

    // MARK: - recording

    func testFirstMessageOpensTheThread() throws {
        let conv = try XCTUnwrap(try store.record(incoming("hello", at: 1_000, id: "0000000000000001"), myFid: me))
        XCTAssertEqual(conv.id, "P2P_\(them)")
        XCTAssertEqual(conv.type, .p2p)
        XCTAssertEqual(conv.targetId, them)
        XCTAssertEqual(conv.lastMessageContent, "hello")
        XCTAssertEqual(conv.unreadCount, 1)
        XCTAssertEqual(conv.createdAt, 1_000)
        XCTAssertEqual(try store.all().count, 1)
    }

    /// Our own messages update the preview but never the unread count.
    func testOutgoingMessageIsNotUnread() throws {
        let conv = try XCTUnwrap(try store.record(outgoing("mine", at: 1_000, id: "0000000000000001"), myFid: me))
        XCTAssertEqual(conv.unreadCount, 0)
        XCTAssertEqual(conv.lastMessageContent, "mine")
    }

    /// Delivery is not ordered — a DOCK-stored message can land after a
    /// direct one that was sent later — so an older message must not
    /// rewrite the preview. It still counts as unread, because it is
    /// still something we have not read.
    func testAnOlderMessageArrivingLateDoesNotRewriteThePreview() throws {
        try store.record(incoming("newest", at: 5_000, id: "0000000000000005"), myFid: me)
        let conv = try XCTUnwrap(try store.record(incoming("backlog", at: 2_000, id: "0000000000000002"), myFid: me))

        XCTAssertEqual(conv.lastMessageContent, "newest")
        XCTAssertEqual(conv.lastMessageTime, 5_000)
        XCTAssertEqual(conv.unreadCount, 2)
        // …but it does move the thread's birthday back.
        XCTAssertEqual(conv.createdAt, 2_000)
    }

    /// A typing indicator must not count as unread or bump the thread —
    /// otherwise a peer could hold a conversation at the top of the list
    /// by doing nothing at all.
    func testSignalsDoNotCountAsUnread() throws {
        try store.record(incoming("real message", at: 1_000, id: "0000000000000001"), myFid: me)

        var typing = ImMessage.make(type: .p2p, from: them, to: me, contentType: .typing)
        typing.timestamp = 2_000
        typing.id = "0000000000000002"
        let conv = try XCTUnwrap(try store.record(typing, myFid: me))

        XCTAssertEqual(conv.unreadCount, 1)
        XCTAssertFalse(ContentType.typing.isDisplayable)
        XCTAssertFalse(ContentType.receipt.isDisplayable)
        XCTAssertFalse(ContentType.symkey.isDisplayable)
        XCTAssertTrue(ContentType.voice.isDisplayable)
        XCTAssertTrue(ContentType.hat.isDisplayable)
    }

    /// Non-text kinds preview as Android's own placeholder strings —
    /// the value is stored, so two clients showing a thread differently
    /// would be a visible disagreement about the same cached field.
    func testPreviewsMatchAndroidsPlaceholders() throws {
        var voice = ImMessage.voice(type: .p2p, from: them, to: me, metaJson: "{}", dataBase64: "AA==")
        voice.timestamp = 1_000
        voice.id = "0000000000000001"
        XCTAssertEqual(try store.record(voice, myFid: me)?.lastMessageContent, "[Voice]")

        var file = ImMessage.hat(type: .p2p, from: them, to: me, hatJson: "{}")
        file.timestamp = 2_000
        file.id = "0000000000000002"
        let conv = try XCTUnwrap(try store.record(file, myFid: me))
        XCTAssertEqual(conv.lastMessageContent, "[File]")
        XCTAssertEqual(conv.lastMessageType, .hat)
    }

    // MARK: - list

    func testListIsPinnedThenMostRecent() throws {
        try store.record(incoming("old", at: 1_000, id: "0000000000000001"), myFid: me)

        var roomMessage = ImMessage.text(type: .room, from: them, to: "room-1", "newer")
        roomMessage.timestamp = 9_000
        roomMessage.id = "0000000000000009"
        try store.record(roomMessage, myFid: me)

        XCTAssertEqual(try store.all().map(\.id), ["ROOM_room-1", "P2P_\(them)"])

        try store.mutate(id: "P2P_\(them)") { $0.pinned = true }
        XCTAssertEqual(try store.all().map(\.id), ["P2P_\(them)", "ROOM_room-1"])
    }

    func testArchivedThreadsAreHiddenButStillCounted() throws {
        try store.record(incoming("hi", at: 1_000, id: "0000000000000001"), myFid: me)
        try store.mutate(id: "P2P_\(them)") { $0.archived = true }

        XCTAssertTrue(try store.visible().isEmpty)
        XCTAssertEqual(try store.all().count, 1)
        // Muting silences a notification; it does not unmake a message.
        XCTAssertEqual(try store.totalUnread(), 1)
    }

    func testMarkReadZeroesTheCountOnce() throws {
        try store.record(incoming("hi", at: 1_000, id: "0000000000000001"), myFid: me)
        XCTAssertTrue(try store.markRead(id: "P2P_\(them)"))
        XCTAssertFalse(try store.markRead(id: "P2P_\(them)"))
        XCTAssertEqual(try store.totalUnread(), 0)
    }

    func testSearchCoversNameTargetAndPreview() throws {
        try store.record(incoming("the quick brown fox", at: 1_000, id: "0000000000000001"), myFid: me)
        try store.mutate(id: "P2P_\(them)") { $0.displayName = "Alice" }

        XCTAssertEqual(try store.search("alice").count, 1)
        XCTAssertEqual(try store.search("BROWN").count, 1)
        XCTAssertEqual(try store.search(them.prefix(6).description).count, 1)
        XCTAssertTrue(try store.search("nothing here").isEmpty)
        XCTAssertEqual(try store.search("   ").count, 1, "a blank query is not a filter")
    }

    func testRemove() throws {
        try store.record(incoming("hi", at: 1_000, id: "0000000000000001"), myFid: me)
        XCTAssertTrue(try store.remove(id: "P2P_\(them)"))
        XCTAssertFalse(try store.remove(id: "P2P_\(them)"))
        XCTAssertTrue(try store.all().isEmpty)
    }

    // MARK: - repair

    /// The index is a cache: every field on it can be recovered from the
    /// messages it summarizes. This is what makes it safe to update
    /// optimistically on the delivery path.
    func testRebuildRecoversAThreadFromItsTranscript() throws {
        let id = Conversation.id(type: .p2p, targetId: them)
        var expected: [String] = []
        for i in 1...12 {
            let m = i % 3 == 0
                ? outgoing("out\(i)", at: Int64(i) * 1_000, id: String(format: "%016x", i))
                : incoming("in\(i)", at: Int64(i) * 1_000, id: String(format: "%016x", i))
            try messages.put(m, in: id)
            expected.append(m.content!)
        }
        try store.upsert(Conversation(id: id, targetId: them, type: .p2p, displayName: "Alice", pinned: true))

        let rebuilt = try XCTUnwrap(try store.rebuild(id: id, from: messages, myFid: me))
        XCTAssertEqual(rebuilt.lastMessageContent, expected.last)
        XCTAssertEqual(rebuilt.lastMessageTime, 12_000)
        XCTAssertEqual(rebuilt.createdAt, 1_000)
        // 8 incoming messages, each stored unread.
        XCTAssertEqual(rebuilt.unreadCount, 8)
        // Preferences are this store's own and survive the rebuild.
        XCTAssertEqual(rebuilt.displayName, "Alice")
        XCTAssertEqual(rebuilt.pinned, true)
    }

    /// Rebuilding counts the messages' own `unread` flags, not "every
    /// incoming message" — otherwise repairing the index would mark a
    /// read conversation unread again.
    func testRebuildTrustsTheMessagesReadState() throws {
        let id = Conversation.id(type: .p2p, targetId: them)
        for i in 1...4 {
            try messages.put(incoming("in\(i)", at: Int64(i) * 1_000, id: String(format: "%016x", i)), in: id)
        }
        try messages.markAllRead(in: id)

        XCTAssertEqual(try store.rebuild(id: id, from: messages, myFid: me)?.unreadCount, 0)
    }

    func testRebuildOfAnEmptyConversationIsNil() throws {
        XCTAssertNil(try store.rebuild(id: "P2P_nobody", from: messages, myFid: me))
    }

    /// Paging in `rebuild` must not lose or double-count a message at a
    /// page boundary. 500 is the page size, so 501 crosses it.
    func testRebuildPagesAcrossItsWindow() throws {
        let id = Conversation.id(type: .p2p, targetId: them)
        for i in 1...501 {
            try messages.put(incoming("in\(i)", at: Int64(i) * 1_000, id: String(format: "%016x", i)), in: id)
        }
        let rebuilt = try XCTUnwrap(try store.rebuild(id: id, from: messages, myFid: me))
        XCTAssertEqual(rebuilt.unreadCount, 501)
        XCTAssertEqual(rebuilt.lastMessageContent, "in501")
        XCTAssertEqual(rebuilt.createdAt, 1_000)
    }
}
