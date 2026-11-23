import XCTest
import FCCore
import FCTransport
import FCStorage
@testable import FCDomain

/// ``Announcements``. The rule cases are shared with Android's
/// `AnnouncementsTest`: an announcement must be one on every device.
final class AnnouncementsTests: XCTestCase {

    static let owner = "FEk41Kqjar45fLDriztUDTUkdki7mmcjWK"
    static let manager = "FBejsS6cJaBrAwPcMjFJYH7iy6Krh2fkRD"
    static let member = "F86zoAvNaQxEuYyvQssV5WxEzapNaiDtTW"

    // MARK: - the rules (shared with Android)

    func testThePrefixMakesAnAnnouncement() {
        XCTAssertEqual(Announcements.text("  Meeting at 9  "), "[ANNOUNCEMENT]Meeting at 9")
        XCTAssertEqual(Announcements.body(of: "[ANNOUNCEMENT]Meeting at 9"), "Meeting at 9")
        XCTAssertEqual(Announcements.body(of: "[ANNOUNCEMENT]\n 会议改到周五 \n"), "会议改到周五")
    }

    func testOnlyAtTheStartAndNeverEmpty() {
        XCTAssertNil(Announcements.body(of: "[ANNOUNCEMENT]"))
        XCTAssertNil(Announcements.body(of: "[ANNOUNCEMENT]   \n"))
        XCTAssertNil(Announcements.body(of: " [ANNOUNCEMENT]late"))
        XCTAssertNil(Announcements.body(of: "[announcement]lower case"))
        XCTAssertNil(Announcements.body(of: "plain text"))
        XCTAssertNil(Announcements.body(of: nil))
    }

    func testOnlyTeamAndRoomTexts() {
        let text = Announcements.text("hello")
        XCTAssertTrue(Announcements.isAnnouncement(ImMessage.text(type: .team, from: Self.owner, to: "t1", text)))
        XCTAssertTrue(Announcements.isAnnouncement(ImMessage.text(type: .room, from: Self.owner, to: "r1", text)))
        XCTAssertFalse(Announcements.isAnnouncement(ImMessage.text(type: .square, from: Self.owner, to: "s1", text)))
        XCTAssertFalse(Announcements.isAnnouncement(ImMessage.text(type: .p2p, from: Self.owner, to: Self.member, text)))
        var withdrawn = ImMessage.text(type: .team, from: Self.owner, to: "t1", text)
        withdrawn.withdrawn = true
        XCTAssertFalse(Announcements.isAnnouncement(withdrawn))
    }

    func testATeamsOwnerAndManagersMayPost() {
        let team = Team(owner: Self.owner, members: [Self.owner, Self.manager, Self.member],
                        managers: [Self.manager], id: "t1")
        XCTAssertTrue(Announcements.mayPost(Self.owner, team: team))
        XCTAssertTrue(Announcements.mayPost(Self.manager, team: team))
        XCTAssertFalse(Announcements.mayPost(Self.member, team: team))
        XCTAssertFalse(Announcements.mayPost(nil, team: team))
        XCTAssertFalse(Announcements.mayPost(Self.owner, team: nil))
    }

    func testOnlyARoomsOwnerMayPost() {
        let room = Room(owner: Self.owner, members: [Self.owner, Self.member], id: "r1")
        XCTAssertTrue(Announcements.mayPost(Self.owner, room: room))
        XCTAssertFalse(Announcements.mayPost(Self.member, room: room))
        XCTAssertFalse(Announcements.mayPost(Self.owner, room: nil))
    }

    // MARK: - filing and confirming (this app's)

    private var baseDir: URL!
    private var configure: ConfigureSession!
    private var session: ActiveSession!
    private let roomId = "room_b4c9a1f2e8d73065b4c9"
    private let t0 = Date(timeIntervalSince1970: 1_755_100_000)

    override func setUpWithError() throws {
        baseDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("AnnouncementsTests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: baseDir, withIntermediateDirectories: true)
        let manager = try ConfigureManager(baseDirectory: baseDir)
        configure = try manager.createConfigure(password: Data("pwd".utf8), kdfKind: .legacySha256)
        let info = try configure.addMain(privkey: Data(repeating: 0xA1, count: 32), label: "A")
        session = try configure.unlockMain(fid: info.fid, fapi: MockFapiClient())
    }

    override func tearDownWithError() throws {
        session = nil
        configure = nil
        if let baseDir { try? FileManager.default.removeItem(at: baseDir) }
    }

    private func room(owner: String) throws -> Conversation {
        try session.rooms.upsert(Room(owner: owner, members: [owner, session.liveFid, Self.member], id: roomId))
        var conversation = Conversation(id: Conversation.id(type: .room, targetId: roomId), targetId: roomId, type: .room)
        conversation.unreadCount = 0
        try session.conversations.upsert(conversation)
        return conversation
    }

    private func arrive(_ text: String, from sender: String, at seconds: TimeInterval) throws {
        var m = ImMessage.text(type: .room, from: sender, to: roomId, text,
                               now: t0.addingTimeInterval(seconds))
        m.setId(fudpId: ChatService.newMessageId())
        _ = try session.chat.receive(m, as: session.liveFid, now: t0.addingTimeInterval(seconds))
    }

    func testTheOwnersAnnouncementWaitsUntilConfirmedAndStaysInHistory() throws {
        let conversation = try room(owner: Self.owner)
        try arrive(Announcements.text("first"), from: Self.owner, at: 1)
        try arrive(Announcements.text("second"), from: Self.owner, at: 2)
        try arrive("just chatting", from: Self.owner, at: 3)

        let waiting = session.unconfirmedAnnouncements()
        XCTAssertEqual(waiting.map(\.body), ["first", "second"])

        session.confirmAnnouncement(waiting[0])
        XCTAssertEqual(session.unconfirmedAnnouncements().map(\.body), ["second"])
        XCTAssertEqual(session.announcements(in: conversation).map(\.body), ["second", "first"])
        XCTAssertEqual(session.announcements(in: conversation).map(\.isConfirmed), [false, true])
    }

    func testAMembersAnnouncementIsAPlainMessage() throws {
        let conversation = try room(owner: Self.owner)
        try arrive(Announcements.text("I am in charge now"), from: Self.member, at: 1)
        XCTAssertTrue(session.unconfirmedAnnouncements().isEmpty)
        XCTAssertTrue(session.announcements(in: conversation).isEmpty)
    }

    func testOurOwnIsConfirmedAsSent() throws {
        let conversation = try room(owner: session.liveFid)
        _ = try session.symkeys.mint(for: roomId, now: t0)
        XCTAssertTrue(session.mayAnnounce(in: conversation))
        _ = try session.chat.sendText(Announcements.text("from me"), in: conversation.id, as: session.liveFid, now: t0)
        XCTAssertTrue(session.unconfirmedAnnouncements().isEmpty)
        XCTAssertEqual(session.announcements(in: conversation).map(\.body), ["from me"])
    }
}
