import XCTest
import FCCore
import FCTransport
@testable import FCDomain

/// Teams and squares: the FEIP carves they are changed by, and the sync
/// that reads what the chain says back.
final class GroupServiceTests: XCTestCase {

    private var baseDir: URL!
    private var manager: ConfigureManager!
    private var mock: MockFapiClient!
    private var session: ActiveSession!

    private let alice = "F-alice"
    private let bob = "F-bob"
    private let teamId = "3f9c1a2b0000000000000000000000000000000000000000000000000000tid1"
    private let squareId = "8e7d6c5b0000000000000000000000000000000000000000000000000000sqr1"

    override func setUpWithError() throws {
        baseDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("GroupServiceTests-\(UUID().uuidString)")
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

    // MARK: - the FEIP carves

    /// The multi-word ops carry a **space**. Java builds them by
    /// lowercasing `FeipOp.TAKE_OVER`'s value, and that value is
    /// `"take over"` — every instinct says camel-case, and camel-casing
    /// would produce carves the indexer silently ignores.
    func testMultiWordOpsKeepTheirSpaces() throws {
        XCTAssertTrue(try TeamFeip.takeOverOp(tid: teamId, consensusId: "did").contains("\"op\":\"take over\""))
        XCTAssertTrue(try TeamFeip.agreeConsensusOp(tid: teamId, consensusId: "did").contains("\"op\":\"agree consensus\""))
        XCTAssertTrue(try TeamFeip.withdrawInvitationOp(tid: teamId, fids: [bob]).contains("\"op\":\"withdraw invitation\""))
        XCTAssertTrue(try TeamFeip.cancelAppointmentOp(tid: teamId, fids: [bob]).contains("\"op\":\"cancel appointment\""))
    }

    /// The `confirm` sentences are the mechanism, not decoration: they
    /// are what a member signs, so their exact wording is what makes two
    /// clients' carves the same act.
    func testJoinCarvesTheConsensusAndItsConfirmation() throws {
        let json = try TeamFeip.joinOp(tid: teamId, consensusId: "did:consensus")
        let parsed = try XCTUnwrap(
            try JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String: Any]
        )
        XCTAssertEqual(parsed["op"] as? String, "join")
        XCTAssertEqual(parsed["tid"] as? String, teamId)
        XCTAssertEqual(parsed["consensusId"] as? String, "did:consensus")
        XCTAssertEqual(
            parsed["confirm"] as? String,
            "I join the team and agree with the team consensus."
        )
    }

    /// A nil optional is *absent*, not null — the whole reason these ops
    /// are built field by field rather than from a dictionary.
    func testAbsentOptionalsAreOmitted() throws {
        let json = try TeamFeip.joinOp(tid: teamId, consensusId: nil)
        XCTAssertFalse(json.contains("consensusId"))
        XCTAssertFalse(json.contains("null"))

        let create = try SquareFeip.createOp(name: "The Square", desc: nil, home: nil)
        XCTAssertEqual(create, #"{"op":"create","name":"The Square"}"#)
    }

    func testEnvelopesCarryTheRightProtocolNumbers() throws {
        let team = TeamFeip.envelope(opJson: try TeamFeip.leaveOp(tids: [teamId]))
        XCTAssertTrue(team.hasPrefix(#"{"type":"FEIP","sn":"18","ver":"1","name":"Team","data":"#))
        let square = SquareFeip.envelope(opJson: try SquareFeip.joinOp(squareId: squareId))
        XCTAssertTrue(square.hasPrefix(#"{"type":"FEIP","sn":"19","ver":"4","name":"Square","data":"#))
    }

    /// Leaving takes a list: one carve can walk out of several teams,
    /// which for a paid operation is one fee instead of several.
    func testLeaveIsPlural() throws {
        XCTAssertEqual(
            try TeamFeip.leaveOp(tids: ["a", "b"]),
            #"{"op":"leave","tids":["a","b"]}"#
        )
        XCTAssertEqual(
            try SquareFeip.leaveOp(squareIds: ["a", "b"]),
            #"{"op":"leave","squareIds":["a","b"]}"#
        )
    }

    func testHomeMapIsSortedAndStringsAreEscaped() throws {
        let json = try SquareFeip.createOp(
            name: "a\"b", home: ["road": "https://r", "dock": "https://d"]
        )
        XCTAssertTrue(json.contains(#""home":{"dock":"https://d","road":"https://r"}"#))
        XCTAssertTrue(json.contains(#""name":"a\"b""#))
    }

    /// Joining a group **pays nobody** — it is a statement about us,
    /// like publishing a notice fee, which is what separates it from a
    /// mail, whose payment *is* its addressing.
    ///
    /// Checked structurally: the broadcast transaction carries the FEIP
    /// envelope and exactly one P2PKH output, which is our own change.
    func testJoinCarvePaysNobody() async throws {
        let broadcast = Captured()
        stageFundedWallet(onBroadcast: { broadcast.value = $0 })

        let txid = try await session.carveTeamJoinOnChain(teamId: teamId, consensusId: "did:consensus")
        XCTAssertEqual(txid, "group-txid-001")

        let hex = try XCTUnwrap(broadcast.value)
        let raw = Data(fromHex: hex)
        XCTAssertNotNil(raw.range(of: Data(#"{"type":"FEIP","sn":"18","ver":"1","name":"Team""#.utf8)))
        XCTAssertNotNil(raw.range(of: Data(#""confirm":"I join the team and agree with the team consensus.""#.utf8)))
        XCTAssertEqual(
            hex.ranges(of: "1976a914").count, 1,
            "one P2PKH output, and it is our own change"
        )
    }

    func testSquareLeaveCarvesTheWholeList() async throws {
        let broadcast = Captured()
        stageFundedWallet(onBroadcast: { broadcast.value = $0 })

        _ = try await session.carveSquareLeaveOnChain(squareIds: [squareId, "other"])
        let raw = Data(fromHex: try XCTUnwrap(broadcast.value))
        XCTAssertNotNil(raw.range(of: Data(#""sn":"19","ver":"4","name":"Square""#.utf8)))
        XCTAssertNotNil(raw.range(of: Data(#""squareIds":["\#(squareId)","other"]"#.utf8)))
    }

    // MARK: - the search

    /// `terms`, not `equals`: `members` is an array, and the question is
    /// whether it *contains* our FID.
    func testSearchAsksWhetherMembersContainsUs() async throws {
        stageSearch(rows: [])
        _ = try await service.fetchTeams(fid: me)

        let sent = try XCTUnwrap(mock.recorded.last?.fcdsl)
        let dsl = try XCTUnwrap(try JSONSerialization.jsonObject(with: sent) as? [String: Any])
        XCTAssertEqual(dsl["entity"] as? String, "team")

        let query = try XCTUnwrap(dsl["query"] as? [String: Any])
        let terms = try XCTUnwrap(query["terms"] as? [String: Any])
        XCTAssertEqual(terms["fields"] as? [String], ["members"])
        XCTAssertEqual(terms["values"] as? [String], [me])

        // Ascending, because a group sync resumes from a cursor and
        // walks forward — the opposite question from a mailbox sync.
        let sort = try XCTUnwrap(dsl["sort"] as? [[String: String]])
        XCTAssertEqual(sort.map { $0["field"] }, ["lastHeight", "id"])
        XCTAssertEqual(sort.map { $0["order"] }, ["asc", "asc"])
    }

    /// With an ascending sort the watermark cannot be an early exit, so
    /// it goes on the wire as a range floor instead.
    func testIncrementalSyncSendsAFloorNotAnEarlyExit() async throws {
        try session.teams.upsert(Team(members: [me], lastHeight: 4_100_000, id: teamId))
        stageSearch(rows: [])
        _ = try await service.syncTeams(fid: me, into: session.teams)

        let dsl = try XCTUnwrap(
            try JSONSerialization.jsonObject(with: try XCTUnwrap(mock.recorded.last?.fcdsl)) as? [String: Any]
        )
        let query = try XCTUnwrap(dsl["query"] as? [String: Any])
        // A `fields` array plus a comparator — the shape the wallet's
        // incremental refresh already uses, not a field-keyed object.
        let range = try XCTUnwrap(query["range"] as? [String: Any])
        XCTAssertEqual(range["fields"] as? [String], ["lastHeight"])
        // The watermark, less the reorg window.
        XCTAssertEqual(range["gt"] as? String, "4099970")
        // …and it sits beside the membership clause, not instead of it.
        XCTAssertNotNil(query["terms"])
    }

    func testFullSyncSendsNoFloor() async throws {
        try session.teams.upsert(Team(members: [me], lastHeight: 4_100_000, id: teamId))
        stageSearch(rows: [])
        _ = try await service.syncTeams(fid: me, into: session.teams, incremental: false)

        let dsl = try XCTUnwrap(
            try JSONSerialization.jsonObject(with: try XCTUnwrap(mock.recorded.last?.fcdsl)) as? [String: Any]
        )
        XCTAssertNil((dsl["query"] as? [String: Any])?["range"])
    }

    /// A FID in no groups gets a 404, which is an ordinary answer.
    func testNotFoundIsNotAnError() async throws {
        mock.responder = { _ in try makeResponse(code: 404) }
        let result = try await service.syncTeams(fid: me, into: session.teams)
        XCTAssertEqual(result, GroupService.SyncResult(merged: 0, joined: 0, left: 0, total: 0))
    }

    func testANonZeroCodeThrows() async throws {
        mock.responder = { _ in try makeResponse(code: 500) }
        do {
            _ = try await service.syncTeams(fid: me, into: session.teams)
            XCTFail("expected a throw")
        } catch let failure as GroupService.Failure {
            XCTAssertTrue("\(failure)".contains("code=500"))
        }
    }

    // MARK: - team sync

    func testSyncOpensAConversationForATeamWeAreIn() async throws {
        stageSearch(rows: [teamRow(members: [alice, me], memberNum: 2)])
        let result = try await service.syncTeams(
            fid: me, into: session.teams, conversations: session.conversations
        )

        XCTAssertEqual(result.merged, 1)
        XCTAssertEqual(result.joined, 1)
        XCTAssertEqual(try session.teams.get(id: teamId)?.stdName, "The Team")
        XCTAssertEqual(try session.teams.joined(by: me).map(\.id), [teamId])

        let conv = try XCTUnwrap(try session.conversations.get(type: .team, targetId: teamId))
        XCTAssertEqual(conv.displayName, "The Team")
        XCTAssertEqual(conv.memberNum, 2)
        XCTAssertEqual(conv.leftGroup, false)
        // Nothing has been said yet, so the thread must not sort above
        // this morning's chat on the strength of a decade-old birth time.
        XCTAssertNil(conv.lastActiveAt)
    }

    /// A team that merely invited us is a row in the store, not a thread
    /// in the chat list.
    func testAnInvitationDoesNotOpenAConversation() async throws {
        stageSearch(rows: [teamRow(members: [alice], invitees: [me])])
        let result = try await service.syncTeams(
            fid: me, into: session.teams, conversations: session.conversations
        )
        XCTAssertEqual(result.merged, 1)
        XCTAssertEqual(result.joined, 0)
        XCTAssertNil(try session.conversations.get(type: .team, targetId: teamId))
        XCTAssertEqual(try session.teams.invitations(for: me).map(\.id), [teamId])
    }

    /// Leaving is not forgetting: the transcript is ours, we paid to be
    /// there, and rejoining should not look like meeting strangers.
    func testLeavingFlagsTheConversationRatherThanDeletingIt() async throws {
        stageSearch(rows: [teamRow(members: [alice, me])])
        _ = try await service.syncTeams(
            fid: me, into: session.teams, conversations: session.conversations
        )

        stageSearch(rows: [teamRow(members: [alice], lastHeight: 4_100_010)])
        let result = try await service.syncTeams(
            fid: me, into: session.teams, conversations: session.conversations
        )
        XCTAssertEqual(result.left, 1)
        let conv = try XCTUnwrap(try session.conversations.get(type: .team, targetId: teamId))
        XCTAssertEqual(conv.leftGroup, true)
        XCTAssertTrue(try session.teams.joined(by: me).isEmpty)
    }

    func testRejoiningClearsTheFlag() async throws {
        stageSearch(rows: [teamRow(members: [alice])])
        _ = try await service.syncTeams(fid: me, into: session.teams, conversations: session.conversations)
        stageSearch(rows: [teamRow(members: [alice, me], lastHeight: 4_100_010)])
        let joinResult = try await service.syncTeams(
            fid: me, into: session.teams, conversations: session.conversations
        )
        XCTAssertEqual(joinResult.joined, 1)
        XCTAssertEqual(try session.conversations.get(type: .team, targetId: teamId)?.leftGroup, false)
    }

    /// A disbanded team reads as left, even though we are still listed
    /// among its members.
    func testADisbandedTeamCountsAsLeft() async throws {
        stageSearch(rows: [teamRow(members: [alice, me])])
        _ = try await service.syncTeams(fid: me, into: session.teams, conversations: session.conversations)

        stageSearch(rows: [teamRow(members: [alice, me], active: false, lastHeight: 4_100_010)])
        let result = try await service.syncTeams(
            fid: me, into: session.teams, conversations: session.conversations
        )
        XCTAssertEqual(result.left, 1)
        XCTAssertTrue(try session.teams.joined(by: me).isEmpty)
    }

    /// A missing `active` is not the same as disbanded — the server
    /// simply did not report the field.
    func testAMissingActiveFlagMeansLive() throws {
        XCTAssertTrue(Team(members: [me], id: teamId).isActive)
        XCTAssertTrue(Team(active: true, id: teamId).isActive)
        XCTAssertFalse(Team(active: false, id: teamId).isActive)
    }

    // MARK: - square sync

    /// A square has no owner, so there is nothing to disband and no
    /// `active` field to read.
    func testSquareSyncOpensAConversation() async throws {
        stageSearch(rows: [squareRow(members: [alice, me], memberNum: 2)])
        let result = try await service.syncSquares(
            fid: me, into: session.squares, conversations: session.conversations
        )
        XCTAssertEqual(result.merged, 1)
        XCTAssertEqual(result.joined, 1)

        let conv = try XCTUnwrap(try session.conversations.get(type: .square, targetId: squareId))
        XCTAssertEqual(conv.type, .square)
        XCTAssertEqual(conv.displayName, "The Square")
        XCTAssertEqual(conv.memberNum, 2)
        XCTAssertEqual(try session.squares.joined(by: me).map(\.id), [squareId])
    }

    func testSquareNamersAreItsWholeGovernance() throws {
        let square = Square(name: "n", namers: [alice], members: [alice, me], id: squareId)
        XCTAssertTrue(square.isNamer(alice))
        XCTAssertFalse(square.isNamer(me))
        XCTAssertTrue(square.isMember(me))
    }

    // MARK: - stores

    func testStoresRejectARecordWithNoId() {
        XCTAssertThrowsError(try session.teams.upsert(Team(stdName: "x"))) {
            XCTAssertEqual($0 as? GroupStoreFailure, .noId)
        }
        XCTAssertThrowsError(try session.squares.upsert(Square(name: "x"))) {
            XCTAssertEqual($0 as? GroupStoreFailure, .noId)
        }
    }

    func testStoreSearchAndWatermark() throws {
        try session.teams.upsert(Team(stdName: "The Team", members: [me], lastHeight: 100, id: teamId))
        try session.teams.upsert(Team(stdName: "Another", members: [me], lastHeight: 900, id: "other"))
        XCTAssertEqual(try session.teams.highestKnownHeight(), 900)
        XCTAssertEqual(try session.teams.search("the team").map(\.id), [teamId])
        XCTAssertEqual(try session.teams.all().map(\.id), ["other", teamId], "newest change first")
        XCTAssertTrue(try session.teams.remove(id: teamId))
        XCTAssertFalse(try session.teams.remove(id: teamId))
    }

    // MARK: - staging

    private func teamRow(
        members: [String],
        invitees: [String]? = nil,
        memberNum: Int64? = nil,
        active: Bool? = nil,
        lastHeight: Int64 = 4_100_000
    ) -> [String: Any] {
        var row: [String: Any] = [
            "id": teamId,
            "owner": alice,
            "stdName": "The Team",
            "consensusId": "did:consensus",
            "members": members,
            "memberNum": memberNum ?? Int64(members.count),
            "birthTime": 1_700_000_000,
            "lastHeight": lastHeight,
            "onChain": true,
        ]
        if let invitees { row["invitees"] = invitees }
        if let active { row["active"] = active }
        return row
    }

    private func squareRow(
        members: [String], memberNum: Int64? = nil, lastHeight: Int64 = 4_100_000
    ) -> [String: Any] {
        [
            "id": squareId,
            "name": "The Square",
            "namers": [alice],
            "members": members,
            "memberNum": memberNum ?? Int64(members.count),
            "birthTime": 1_700_000_000,
            "lastHeight": lastHeight,
            "onChain": true,
        ]
    }

    /// One page of `base.search` results, then nothing.
    private func stageSearch(rows: [[String: Any]]) {
        var served = false
        mock.responder = { call in
            guard call.api == "base.search" else { return try makeResponse(code: 0) }
            defer { served = true }
            if served || rows.isEmpty { return try makeResponse(code: 404) }
            return try makeResponse(code: 0, data: rows)
        }
    }

    /// A funded wallet and a broadcast sink, so a carve can run end to
    /// end without a network.
    private func stageFundedWallet(
        funds: Int64 = 10_000_000,
        onBroadcast: @escaping @Sendable (String) -> Void
    ) {
        let owner = session.mainFid
        mock.responder = { call in
            switch call.api {
            case "base.cashValid":
                let h160 = try FchAddress(fid: owner).hash160
                let txid = String(repeating: "ab", count: 32)
                return try makeResponse(
                    data: [[
                        "id": try Cash.makeId(birthTxId: txid, birthIndex: 0),
                        "owner": owner,
                        "value": funds,
                        "type": "P2PKH",
                        "birthTxId": txid,
                        "birthIndex": 0,
                        "lockScript": Cash.canonicalP2PKHLockScript(hash160: h160),
                    ]],
                    // Below CDD_CHECK_HEIGHT → no CoinDays requirement.
                    bestHeight: 3_500_000
                )
            case "base.broadcastTx":
                let params = try JSONSerialization.jsonObject(with: call.params!) as? [String: Any]
                onBroadcast((params?["rawTx"] as? String) ?? "")
                return try makeResponse(data: "group-txid-001")
            default:
                return try makeResponse(code: 404)
            }
        }
    }
}

/// A box for a value a `@Sendable` closure writes.
private final class Captured: @unchecked Sendable {
    var value: String?
}

private extension String {
    func ranges(of needle: String) -> [Range<String.Index>] {
        var found: [Range<String.Index>] = []
        var start = startIndex
        while let range = self[start...].range(of: needle) {
            found.append(range)
            start = range.upperBound
        }
        return found
    }
}
