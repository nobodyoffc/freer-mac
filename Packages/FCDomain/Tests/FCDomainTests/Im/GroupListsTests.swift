import XCTest
import FCCore
import FCTransport
import FCStorage
@testable import FCDomain

/// What the square and room lists show about groups whose state changed
/// somewhere else: a square left from another device, a room its owner
/// closed, a DOCK that refuses, a carve still waiting for the chain — and
/// the join that should not be paid for at all.
final class GroupListsTests: XCTestCase {

    private var baseDir: URL!
    private var manager: ConfigureManager!
    private var mock: MockFapiClient!
    private var session: ActiveSession!

    private let alice = "F-alice"
    private let bob = "F-bob"
    private let carol = "F-carol"
    private let squareId = "8e7d6c5b0000000000000000000000000000000000000000000000000000sqr1"
    private let otherSquareId = "8e7d6c5b0000000000000000000000000000000000000000000000000000sqr2"
    private let teamId = "3f9c1a2b0000000000000000000000000000000000000000000000000000tid1"

    private let t0 = Date(timeIntervalSince1970: 1_755_100_000)
    private func at(_ seconds: TimeInterval) -> Date { t0.addingTimeInterval(seconds) }

    override func setUpWithError() throws {
        baseDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("GroupListsTests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: baseDir, withIntermediateDirectories: true)
        manager = try ConfigureManager(baseDirectory: baseDir)
        mock = MockFapiClient()
        let configure = try manager.createConfigure(password: Data("pwd".utf8), kdfKind: .legacySha256)
        let info = try configure.addMain(privkey: Data(repeating: 0xA1, count: 32), label: "A")
        session = try configure.unlockMain(fid: info.fid, fapi: mock)
    }

    override func tearDownWithError() throws {
        session = nil
        mock = nil
        manager = nil
        if let baseDir { try? FileManager.default.removeItem(at: baseDir) }
    }

    private var me: String { session.liveFid }
    private var service: GroupService { GroupService(fapi: mock) }

    private func openThread(_ type: ImType, _ id: String) throws {
        var thread = Conversation(id: Conversation.id(type: type, targetId: id), targetId: id, type: type)
        thread.leftGroup = false
        try session.conversations.upsert(thread)
    }

    private func thread(_ type: ImType, _ id: String) throws -> Conversation? {
        try session.conversations.get(id: Conversation.id(type: type, targetId: id))
    }

    // MARK: - a square left somewhere else

    /// **The member query never returns a square we left.** So one left
    /// from another device stayed open here. It is read back by id, and
    /// the chain's answer — not us among its members — closes the thread.
    func testASquareLeftElsewhereIsFlaggedFromItsOwnRecord() async throws {
        try session.squares.upsert(Square(name: "S", members: [me, bob], lastHeight: 10, id: squareId))
        try openThread(.square, squareId)
        let squareId = self.squareId, bob = self.bob
        mock.responder = { call in
            switch call.api {
            case "base.search":
                return try makeResponse(code: 404)
            case DirectoryService.getByIdsApi:
                return try makeResponse(code: 0, data: [squareId: [
                    "id": squareId, "name": "S", "members": [bob], "lastHeight": 20,
                ]])
            default:
                return try makeResponse(code: 404)
            }
        }
        let result = try await service.syncSquares(
            fid: me, into: session.squares, conversations: session.conversations
        )
        XCTAssertEqual(result.left, 1)
        XCTAssertEqual(try thread(.square, squareId)?.leftGroup, true)
        XCTAssertEqual(try session.squares.get(id: squareId)?.members, [bob])
    }

    /// The parser deletes a square when its last member leaves, so an id
    /// the chain no longer holds is a square that is gone.
    func testASquareTheChainNoLongerHoldsIsFlaggedAndForgotten() async throws {
        try session.squares.upsert(Square(name: "S", members: [me], lastHeight: 10, id: squareId))
        try openThread(.square, squareId)
        mock.responder = { _ in try makeResponse(code: 404) }
        let result = try await service.syncSquares(
            fid: me, into: session.squares, conversations: session.conversations
        )
        XCTAssertEqual(result.left, 1)
        XCTAssertEqual(try thread(.square, squareId)?.leftGroup, true)
        XCTAssertNil(try session.squares.get(id: squareId))
    }

    /// A read that fails is not an answer. Flagging on it would close
    /// every square the moment a server hiccups.
    func testAFailedReadByIdDecidesNothing() async throws {
        try session.squares.upsert(Square(name: "S", members: [me], lastHeight: 10, id: squareId))
        try openThread(.square, squareId)
        mock.responder = { call in
            call.api == "base.search" ? try makeResponse(code: 404) : try makeResponse(code: 500)
        }
        _ = try await service.syncSquares(fid: me, into: session.squares, conversations: session.conversations)
        XCTAssertEqual(try thread(.square, squareId)?.leftGroup, false)
        XCTAssertNotNil(try session.squares.get(id: squareId))
    }

    /// A square the member query did return is not asked about again.
    func testSquaresTheQueryReturnedAreNotReadAgain() async throws {
        try session.squares.upsert(Square(name: "S", members: [me], lastHeight: 10, id: squareId))
        let squareId = self.squareId, me = self.me
        var served = false
        mock.responder = { call in
            guard call.api == "base.search" else {
                XCTFail("no by-id read expected, got \(call.api)")
                return try makeResponse(code: 404)
            }
            defer { served = true }
            if served { return try makeResponse(code: 404) }
            return try makeResponse(code: 0, data: [["id": squareId, "members": [me], "lastHeight": 20]])
        }
        _ = try await service.syncSquares(fid: me, into: session.squares)
    }

    // MARK: - joining a square

    func testJoiningASquareWeAreInIsRefused() async throws {
        let squareId = self.squareId, me = self.me
        mock.responder = { call in
            guard call.api == DirectoryService.getByIdsApi else { return try makeResponse(code: 404) }
            return try makeResponse(code: 0, data: [squareId: ["id": squareId, "members": [me]]])
        }
        await assertJoinRefused(.alreadyAMember(squareId))
    }

    func testJoiningASquareTheChainDoesNotHoldIsRefused() async throws {
        mock.responder = { _ in try makeResponse(code: 404) }
        await assertJoinRefused(.noSuchSquare(squareId))
    }

    func testSquareSearchMatchesPartOfTheName() async throws {
        mock.responder = { _ in try makeResponse(code: 404) }
        _ = try await service.searchSquares(named: " plaza ")
        let dsl = try XCTUnwrap(
            try JSONSerialization.jsonObject(with: try XCTUnwrap(mock.recorded.last?.fcdsl)) as? [String: Any]
        )
        XCTAssertEqual(dsl["entity"] as? String, "square")
        let part = try XCTUnwrap((dsl["query"] as? [String: Any])?["part"] as? [String: Any])
        XCTAssertEqual(part["fields"] as? [String], ["name"])
        XCTAssertEqual(part["value"] as? String, "plaza")
    }

    /// A square a search turns up that we are in, with no thread for it,
    /// goes straight on the list.
    func testAdoptingASquareWeAreInOpensItsThread() throws {
        let id = try service.adopt(
            Square(name: "S", members: [me], id: squareId), fid: me,
            into: session.squares, conversations: session.conversations
        )
        XCTAssertEqual(id, Conversation.id(type: .square, targetId: squareId))
        XCTAssertEqual(try thread(.square, squareId)?.leftGroup, false)
        XCTAssertNil(try service.adopt(
            Square(name: "T", members: [bob], id: otherSquareId), fid: me,
            into: session.squares, conversations: session.conversations
        ))
    }

    // MARK: - rooms

    private func room(owner: String, members: [String]) throws -> Room {
        var room = Room.create(owner: owner, name: "R", now: t0)
        for member in members { room.addMember(member, now: t0) }
        try session.rooms.upsert(room)
        return room
    }

    /// Closed by its owner, removed from, or left: an inactive record,
    /// and the list says so however the room got there.
    func testAnInactiveRoomIsFlaggedOnTheList() throws {
        var room = try room(owner: alice, members: [me])
        let roomId = try XCTUnwrap(room.id)
        XCTAssertEqual(try session.roomConversations.sync(roomId)?.leftGroup, false)
        room.active = false
        try session.rooms.upsert(room)
        XCTAssertEqual(try session.roomConversations.sync(roomId)?.leftGroup, true)
    }

    /// The owner's `ROOM_DISBAND` reaches the list, not only the composer.
    func testAClosedRoomNoticeFlagsTheThread() throws {
        let room = try room(owner: alice, members: [me])
        let roomId = try XCTUnwrap(room.id)
        try session.roomConversations.sync(roomId)
        var notice = ImMessage.roomNotice(.roomDisband, from: alice, to: me, content: roomId, now: at(10))
        notice.setId(fudpId: 42)
        let router = SignalRouter(
            rooms: session.rooms, teams: session.teams, symkeys: session.symkeys,
            invites: session.roomInvites, roomService: try session.roomService,
            roomConversations: session.roomConversations,
            privkey: Data(repeating: 0xA1, count: 32)
        )
        _ = try router.route(notice, as: me, now: at(10))
        XCTAssertEqual(try thread(.room, roomId)?.leftGroup, true)
    }

    /// Android's owner menu picks who gets the details; somebody named
    /// who is not a member gets nothing.
    func testRoomDetailsGoOnlyToChosenMembers() throws {
        let service = try session.roomService
        let created = try service.create(
            name: "R", owner: me, invite: [bob, carol], pubkeys: { _ in nil }, now: t0
        )
        let roomId = try XCTUnwrap(created.room.id)
        let (outbound, _) = try service.shareInfo(
            roomId, to: [bob, "F-stranger"], as: me, pubkeys: { _ in nil }, now: at(10)
        )
        XCTAssertEqual(outbound.compactMap(\.targetId), [bob])
    }

    // MARK: - DOCKs that refuse

    func testAFailingDockMarksItsGroupsUntilARetryReaches_it() async throws {
        let registry = session.dockRegistry
        let reachable = Flag()
        await registry.configure(
            ownDockUrl: "dock.me:8500", ownClient: mock,
            connect: { _ in
                guard reachable.value else { throw URLError(.cannotConnectToHost) }
                return MockFapiClient()
            }
        )
        await registry.refresh(ownFid: me, groups: [
            .init(id: squareId, type: .square, home: [ServiceName.dock: "https://dock.square"]),
        ])
        _ = await registry.client(for: "https://dock.square", now: t0)
        let failing = await registry.failingTargetIds(type: .square)
        XCTAssertEqual(failing, [squareId])
        let teamsFailing = await registry.failingTargetIds(type: .team)
        XCTAssertTrue(teamsFailing.isEmpty)

        // Still refusing: a retry that fails keeps the mark.
        let stillFailing = await registry.retryFailing(type: .square, now: at(1))
        XCTAssertEqual(stillFailing, [squareId])

        // Reachable again: the retry clears it without waiting out the cooldown.
        reachable.value = true
        let cleared = await registry.retryFailing(type: .square, now: at(2))
        XCTAssertTrue(cleared.isEmpty)
    }

    // MARK: - carves waiting for the chain

    func testAPendingJoinClearsOnlyOnceTheThreadIsOpen() throws {
        session.notePendingGroup(.square, id: squareId, name: "S", act: .join, txid: "tx1", now: t0)
        let store = session.pendingGroups
        func reconcile() throws -> Int {
            try store.reconcile(
                fid: me, teams: session.teams, squares: session.squares,
                conversations: session.conversations
            )
        }

        // A stale record that still lists us, with the thread we left.
        try session.squares.upsert(Square(members: [me], id: squareId))
        var left = Conversation(id: Conversation.id(type: .square, targetId: squareId), targetId: squareId, type: .square)
        left.leftGroup = true
        try session.conversations.upsert(left)
        XCTAssertEqual(try reconcile(), 0)
        XCTAssertEqual(try store.all(fid: me, type: .square).count, 1)

        try openThread(.square, squareId)
        XCTAssertEqual(try reconcile(), 1)
        XCTAssertTrue(try store.all(fid: me, type: .square).isEmpty)
    }

    func testAPendingTakeOverClearsOnceWeOwnTheTeam() throws {
        session.notePendingGroup(.team, id: teamId, name: "T", act: .takeOver, txid: "tx2", now: t0)
        try session.teams.upsert(Team(owner: alice, members: [alice, me], transferee: me, id: teamId))
        try openThread(.team, teamId)
        let store = session.pendingGroups
        XCTAssertEqual(try store.reconcile(fid: me, teams: session.teams, squares: session.squares, conversations: session.conversations), 0)
        try session.teams.upsert(Team(owner: me, members: [alice, me], id: teamId))
        XCTAssertEqual(try store.reconcile(fid: me, teams: session.teams, squares: session.squares, conversations: session.conversations), 1)
    }

    func testAPendingRowIsOverdueAfterADay() throws {
        session.notePendingGroup(.square, id: squareId, name: nil, act: .create, txid: squareId, now: t0)
        let row = try XCTUnwrap(session.pendingGroups.all(fid: me, type: .square).first)
        XCTAssertFalse(row.isOverdue(now: at(3_600)))
        XCTAssertTrue(row.isOverdue(now: at(25 * 3_600)))
    }

    // MARK: - what waits on an answer

    func testInvitationsCountTowardTheirTab() throws {
        try session.roomInvites.upsert(RoomInvite(roomId: "room_1", from: alice, roomInfoJson: "{}", receivedAt: 1))
        try session.teamOffers.note(
            TeamNotice(kind: .invitation, teamId: teamId, teamName: nil), from: alice, for: me, now: t0
        )
        XCTAssertEqual(session.awaitingAnswer(type: .room, now: at(1)), 1)
        XCTAssertEqual(session.awaitingAnswer(type: .team, now: at(1)), 1)
        XCTAssertEqual(session.awaitingAnswer(type: .square, now: at(1)), 0)
    }

    // MARK: - helpers

    private func assertJoinRefused(
        _ expected: SquareJoinFailure, file: StaticString = #filePath, line: UInt = #line
    ) async {
        do {
            _ = try await session.carveSquareJoinOnChain(squareId: squareId)
            XCTFail("expected \(expected)", file: file, line: line)
        } catch let failure as ActiveSession.Failure {
            guard case .underlying(let inner) = failure, let join = inner as? SquareJoinFailure else {
                return XCTFail("expected \(expected), got \(failure)", file: file, line: line)
            }
            XCTAssertEqual(join, expected, file: file, line: line)
        } catch {
            XCTFail("expected \(expected), got \(error)", file: file, line: line)
        }
    }
}

private final class Flag: @unchecked Sendable {
    var value = false
}
