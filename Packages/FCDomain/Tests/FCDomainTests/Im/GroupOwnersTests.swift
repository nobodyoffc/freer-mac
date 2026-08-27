import XCTest
import FCCore
import FCTransport
import FCStorage
@testable import FCDomain

/// Filling in the FID a group avatar badges.
///
/// The bug these exist for: the avatar badge was added after rows had
/// already been written, and every path that *knows* an owner is an event
/// — making a room, a membership signal, a chain sync. None of them was
/// ever going to fire again for a group that was simply sitting in the
/// list, so those rows had no owner and their avatars drew no badge.
final class GroupOwnersTests: XCTestCase {

    private var baseDir: URL!
    private var manager: ConfigureManager!
    private var configure: ConfigureSession!
    private var session: ActiveSession!

    private let privkey = Data(repeating: 0xC3, count: 32)
    private let alice = "F-alice"
    private let bob = "F-bob"
    private let roomId = "room_a1b2c3d4e5f60718293a4b5c"
    private let teamId = "aa11bb22cc33dd44ee55ff6600778899aa11bb22cc33dd44ee55ff6600778899"
    private let squareId = "99887766ff55ee44dd33cc22bb11aa0099887766ff55ee44dd33cc22bb11aa00"

    override func setUpWithError() throws {
        baseDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("GroupOwnersTests-\(UUID().uuidString)")
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

    /// A row exactly as the old code left it: no `avatarDid` at all.
    private func openRow(type: ImType, targetId: String) throws -> String {
        let id = Conversation.id(type: type, targetId: targetId)
        try session.conversations.upsert(
            Conversation(id: id, targetId: targetId, type: type, unreadCount: 0)
        )
        return id
    }

    private func badge(_ id: String) throws -> String? {
        try session.conversations.get(id: id)?.avatarDid
    }

    // MARK: - the repair

    func testARoomRowLearnsItsOwner() throws {
        let id = try openRow(type: .room, targetId: roomId)
        var room = Room(owner: alice, name: "Ours", members: [alice, me])
        room.id = roomId
        try session.rooms.upsert(room)

        XCTAssertNil(try badge(id))
        XCTAssertEqual(try session.groupOwners.refill(), 1)
        XCTAssertEqual(try badge(id), alice)
    }

    func testATeamRowLearnsItsOwner() throws {
        let id = try openRow(type: .team, targetId: teamId)
        try session.teams.upsert(
            Team(owner: alice, stdName: "The Team", members: [alice, me], id: teamId)
        )

        XCTAssertEqual(try session.groupOwners.refill(), 1)
        XCTAssertEqual(try badge(id), alice)
    }

    /// Nobody owns a square, so the badge falls to the last namer.
    func testASquareRowBadgesItsLastNamer() throws {
        let id = try openRow(type: .square, targetId: squareId)
        try session.squares.upsert(
            Square(name: "The Square", namers: [alice, bob], members: [alice, me], id: squareId)
        )

        XCTAssertEqual(try session.groupOwners.refill(), 1)
        XCTAssertEqual(try badge(id), bob)
    }

    // MARK: - what it must not do

    /// A P2P avatar *is* the other person, drawn from `targetId`.
    /// Writing that FID into the badge field as well would store the same
    /// fact twice in a field that means something else.
    func testAP2PRowIsLeftAlone() throws {
        let id = try openRow(type: .p2p, targetId: alice)
        XCTAssertEqual(try session.groupOwners.refill(), 0)
        XCTAssertNil(try badge(id))
    }

    /// Not knowing who owns a group is not the same fact as knowing it
    /// has no owner: a row that has been showing a badge must not lose it
    /// because the group record is missing here.
    func testAGroupWeHoldNoRecordForKeepsItsBadge() throws {
        let id = Conversation.id(type: .team, targetId: teamId)
        var row = Conversation(id: id, targetId: teamId, type: .team, unreadCount: 0)
        row.avatarDid = alice
        try session.conversations.upsert(row)

        XCTAssertEqual(try session.groupOwners.refill(), 0)
        XCTAssertEqual(try badge(id), alice)
    }

    /// Safe to call from a view's reload: the second run rewrites
    /// nothing, so it costs reads and no writes.
    func testRefillIsIdempotent() throws {
        _ = try openRow(type: .room, targetId: roomId)
        var room = Room(owner: alice, members: [alice, me])
        room.id = roomId
        try session.rooms.upsert(room)

        XCTAssertEqual(try session.groupOwners.refill(), 1)
        XCTAssertEqual(try session.groupOwners.refill(), 0)
        XCTAssertEqual(try session.groupOwners.refill(), 0)
    }

    /// A transfer moves the badge on the next pass, without anything
    /// having to notify the list.
    func testATransferMovesTheBadge() throws {
        let id = try openRow(type: .room, targetId: roomId)
        var room = Room(owner: alice, members: [alice, me])
        room.id = roomId
        try session.rooms.upsert(room)
        _ = try session.groupOwners.refill()

        _ = try session.rooms.mutate(id: roomId) { $0.owner = bob }
        XCTAssertEqual(try session.groupOwners.refill(), 1)
        XCTAssertEqual(try badge(id), bob)
    }

    /// The refill touches the badge and nothing else — it is not a second
    /// opinion on the name, the unread count or the preview.
    func testRefillLeavesTheRestOfTheRowAlone() throws {
        let id = Conversation.id(type: .room, targetId: roomId)
        var row = Conversation(id: id, targetId: roomId, type: .room, unreadCount: 7)
        row.displayName = "Ours"
        row.lastMessageContent = "see you there"
        row.pinned = true
        try session.conversations.upsert(row)

        var room = Room(owner: alice, name: "Renamed elsewhere", members: [alice, me])
        room.id = roomId
        try session.rooms.upsert(room)

        _ = try session.groupOwners.refill()
        let after = try XCTUnwrap(try session.conversations.get(id: id))
        XCTAssertEqual(after.avatarDid, alice)
        XCTAssertEqual(after.displayName, "Ours")
        XCTAssertEqual(after.lastMessageContent, "see you there")
        XCTAssertEqual(after.unreadCount, 7)
        XCTAssertEqual(after.pinned, true)
    }
}
