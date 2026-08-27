import XCTest
import FCCore
import FCTransport
import FCStorage
@testable import FCDomain

/// Carrying a room record across into the row the chat list draws.
///
/// A room has no chain and therefore no sync, so the row was written once
/// — when the room was created — and never again. These tests are the
/// proof that a membership or a name that changed on the record reaches
/// the list at all.
final class RoomConversationsTests: XCTestCase {

    private var baseDir: URL!
    private var manager: ConfigureManager!
    private var configure: ConfigureSession!
    private var session: ActiveSession!

    private let privkey = Data(repeating: 0xA1, count: 32)
    private let bob = "F-bob"
    private let carol = "F-carol"
    private let roomId = "room_b4c9a1f2e8d73065b4c9"

    override func setUpWithError() throws {
        baseDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("RoomConversationsTests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: baseDir, withIntermediateDirectories: true)

        manager = try ConfigureManager(baseDirectory: baseDir)
        configure = try manager.createConfigure(password: Data("pwd".utf8), kdfKind: .legacySha256)
        let info = try configure.addMain(privkey: privkey, label: "A")
        session = try configure.unlockMain(fid: info.fid, fapi: MockFapiClient())
    }

    override func tearDownWithError() throws {
        session = nil
        configure = nil
        manager = nil
        if let baseDir { try? FileManager.default.removeItem(at: baseDir) }
    }

    private var me: String { session.liveFid }
    private var conversationId: String { Conversation.id(type: .room, targetId: roomId) }

    private func store(_ room: Room) throws {
        var stored = room
        stored.id = roomId
        try session.rooms.upsert(stored)
    }

    /// The bug this exists for: a member added to a room the owner keeps
    /// on this device, with the header still counting the room as it was
    /// when it was made.
    func testAddingAMemberReachesTheRow() throws {
        try store(Room(owner: me, name: "Ours", members: [me, bob]))
        try session.roomConversations.sync(roomId)
        XCTAssertEqual(try session.conversations.get(id: conversationId)?.memberNum, 2)

        _ = try session.rooms.mutate(id: roomId) { $0.addMember(carol) }
        try session.roomConversations.sync(roomId)
        XCTAssertEqual(try session.conversations.get(id: conversationId)?.memberNum, 3)
    }

    func testRenamingARoomReachesTheRow() throws {
        try store(Room(owner: me, name: "Ours", members: [me]))
        try session.roomConversations.sync(roomId)

        _ = try session.rooms.mutate(id: roomId) { $0.name = "Somewhere else" }
        try session.roomConversations.sync(roomId)
        XCTAssertEqual(try session.conversations.get(id: conversationId)?.displayName, "Somewhere else")
    }

    /// A room on this device with no row is a room the user cannot
    /// reach — which is what accepting an invitation used to produce.
    func testARoomWithNoRowGetsOne() throws {
        try store(Room(owner: bob, name: "Bob's place", members: [bob, me]))
        XCTAssertNil(try session.conversations.get(id: conversationId))

        let opened = try XCTUnwrap(try session.roomConversations.sync(roomId))
        XCTAssertEqual(opened.type, .room)
        XCTAssertEqual(opened.targetId, roomId)
        XCTAssertEqual(opened.memberNum, 2)
        XCTAssertEqual(try session.conversations.visible(type: .room).map(\.id), [conversationId])
    }

    /// The preview and the unread count belong to the conversation, not
    /// to the room, and a mirror that clobbered them would lose the only
    /// copy.
    func testWhatTheRoomDoesNotOwnIsLeftAlone() throws {
        try store(Room(owner: me, name: "Ours", members: [me]))
        var row = Conversation(id: conversationId, targetId: roomId, type: .room)
        row.lastMessageContent = "the last thing said"
        row.unreadCount = 4
        row.pinned = true
        row.muted = true
        try session.conversations.upsert(row)

        try session.roomConversations.sync(roomId)
        let mirrored = try XCTUnwrap(try session.conversations.get(id: conversationId))
        XCTAssertEqual(mirrored.lastMessageContent, "the last thing said")
        XCTAssertEqual(mirrored.unreadCount, 4)
        XCTAssertEqual(mirrored.pinned, true)
        XCTAssertEqual(mirrored.muted, true)
    }

    /// The row reports the key **we can open**, not the version the
    /// owner last announced: the two differ exactly while a rotation is
    /// in flight, and that gap is the cue to ask for the key.
    func testTheRowReportsTheKeyWeActuallyHold() throws {
        var room = Room(owner: bob, name: "Bob's place", members: [bob, me])
        room.symkeyVersion = 4
        try store(room)

        let waiting = try XCTUnwrap(try session.roomConversations.sync(roomId))
        XCTAssertEqual(waiting.hasSymkey, false)
        XCTAssertNil(waiting.symkeyVersion)

        _ = try session.symkeys.store(
            Data(repeating: 0x7E, count: 32), for: roomId, version: 3, allowOverwrite: true
        )
        let held = try XCTUnwrap(try session.roomConversations.sync(roomId))
        XCTAssertEqual(held.hasSymkey, true)
        XCTAssertEqual(held.symkeyVersion, 3)
    }

    /// The row carries the owner so the avatar can badge them. The
    /// avatar's *tile* is drawn from the room id and is not stored
    /// anywhere — which is the point of putting only the owner here:
    /// handing the room to someone else repaints a badge, and the mark
    /// the user recognises the room by does not move.
    func testTheRowCarriesTheOwnerForTheAvatarBadge() throws {
        try store(Room(owner: me, name: "Ours", members: [me, bob]))
        let opened = try XCTUnwrap(try session.roomConversations.sync(roomId))
        XCTAssertEqual(opened.avatarDid, me)
        XCTAssertEqual(opened.targetId, roomId)

        // A transfer moves the badge, and nothing else about the row's
        // identity.
        _ = try session.rooms.mutate(id: roomId) { $0.owner = bob }
        let transferred = try XCTUnwrap(try session.roomConversations.sync(roomId))
        XCTAssertEqual(transferred.avatarDid, bob)
        XCTAssertEqual(transferred.targetId, roomId)
    }

    /// Nothing to mirror, and inventing a row would be inventing the
    /// room.
    func testARoomWeDoNotHaveOpensNothing() throws {
        XCTAssertNil(try session.roomConversations.sync(roomId))
        XCTAssertTrue(try session.conversations.all().isEmpty)
    }
}
