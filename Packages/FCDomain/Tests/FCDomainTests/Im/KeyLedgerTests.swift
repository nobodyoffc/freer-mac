import XCTest
import FCCore
import FCStorage
@testable import FCDomain

/// ``KeyLedger``: the record FIMP §9.7 requires, and the three questions
/// only it can answer — who holds which version, what left this device
/// unexpectedly, and whose copy of a conversation we are reading.
final class KeyLedgerTests: XCTestCase {

    private var baseDir: URL!
    private var manager: ConfigureManager!
    private var configure: ConfigureSession!
    private var session: ActiveSession!

    private let room = "room_b4c9a1f2e8d73065b4c9"
    private let team = "0f0e0d0c0b0a09080706050403020100"
    private let bob = "F-bob"
    private let carol = "F-carol"

    private let t0 = Date(timeIntervalSince1970: 1_789_813_689)
    private func at(_ seconds: TimeInterval) -> Date { t0.addingTimeInterval(seconds) }

    override func setUpWithError() throws {
        baseDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("KeyLedgerTests-\(UUID().uuidString)")
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

    private var ledger: KeyLedger { session.keyLedger }

    // MARK: - writing

    func testARowKeepsEverythingSectionNinePointSevenAsksFor() throws {
        let row = try ledger.record(
            entityId: room, version: 6, counterparty: bob,
            direction: .sent, outcome: .shared, solicited: true,
            requestId: "r-1", now: t0
        )
        XCTAssertEqual(row.entityId, room)
        XCTAssertEqual(row.version, 6)
        XCTAssertEqual(row.counterparty, bob)
        XCTAssertEqual(row.direction, .sent)
        XCTAssertEqual(row.outcome, .shared)
        XCTAssertTrue(row.solicited)
        XCTAssertEqual(row.requestId, "r-1")
        XCTAssertEqual(row.at, Int64(t0.timeIntervalSince1970 * 1000))
        XCTAssertEqual(row.repeats, 1)
        XCTAssertEqual(try ledger.entries(for: room), [row])
    }

    func testRowsComeBackNewestFirst() throws {
        try ledger.record(
            entityId: room, version: 6, counterparty: bob,
            direction: .sent, outcome: .shared, solicited: true, now: t0
        )
        try ledger.record(
            entityId: room, version: 7, counterparty: carol,
            direction: .received, outcome: .stored, solicited: false, now: at(60)
        )
        XCTAssertEqual(try ledger.all().map(\.version), [7, 6])
        XCTAssertEqual(try ledger.all(limit: 1).map(\.version), [7])
    }

    func testEntitiesAreSeparate() throws {
        try ledger.record(
            entityId: room, version: 6, counterparty: bob,
            direction: .sent, outcome: .shared, solicited: true, now: t0
        )
        try ledger.record(
            entityId: team, version: 6, counterparty: bob,
            direction: .sent, outcome: .shared, solicited: true, now: t0
        )
        XCTAssertEqual(try ledger.entries(for: room).count, 1)
        XCTAssertEqual(try ledger.entries(for: team).count, 1)
        XCTAssertEqual(try ledger.count(), 2)
    }

    /// Two different events in one millisecond must not collide, or one
    /// of them is lost.
    func testDifferentEventsAtOneInstantAreDistinctRows() throws {
        try ledger.record(
            entityId: room, version: 6, counterparty: bob,
            direction: .sent, outcome: .shared, solicited: true, now: t0
        )
        try ledger.record(
            entityId: room, version: 6, counterparty: carol,
            direction: .sent, outcome: .shared, solicited: true, now: t0
        )
        try ledger.record(
            entityId: room, version: 6, counterparty: bob,
            direction: .received, outcome: .stored, solicited: true, now: t0
        )
        XCTAssertEqual(try ledger.count(), 3)
    }

    // MARK: - coalescing

    /// **What keeps an unbounded record safe.** An admitted key costs its
    /// sender ownership or a request we made (FIMP §4.2), so those rows
    /// are bounded by honest activity — but a *refusal* costs an attacker
    /// only the sending. Folding repeats keeps the signal a person needs
    /// ("Carol keeps pushing keys at me") at one row an hour.
    func testRepeatsOfOneEventFoldIntoOneRow() throws {
        for second in [0.0, 1.0, 30.0, 600.0] {
            try ledger.record(
                entityId: room, version: 6, counterparty: carol,
                direction: .received, outcome: .refused, solicited: false, now: at(second)
            )
        }
        let rows = try ledger.entries(for: room)
        XCTAssertEqual(rows.count, 1)
        XCTAssertEqual(rows.first?.repeats, 4)
        XCTAssertEqual(rows.first?.at, Int64(t0.timeIntervalSince1970 * 1000), "first occurrence")
        XCTAssertEqual(rows.first?.lastAt, Int64(at(600).timeIntervalSince1970 * 1000), "and the last")
    }

    /// Past the window it is a new row, so a pattern that resumes days
    /// later reads as two episodes rather than one.
    func testAnEventPastTheWindowIsANewRow() throws {
        try ledger.record(
            entityId: room, version: 6, counterparty: carol,
            direction: .received, outcome: .refused, solicited: false, now: t0
        )
        try ledger.record(
            entityId: room, version: 6, counterparty: carol,
            direction: .received, outcome: .refused, solicited: false,
            now: at(KeyLedger.coalesceWindow + 1)
        )
        XCTAssertEqual(try ledger.entries(for: room).count, 2)
    }

    /// A refusal and a share are not the same event, however close
    /// together: folding them would erase the thing worth reading.
    func testOutcomesAreNotFoldedTogether() throws {
        try ledger.record(
            entityId: room, version: 6, counterparty: carol,
            direction: .received, outcome: .refused, solicited: false, now: t0
        )
        try ledger.record(
            entityId: room, version: 6, counterparty: carol,
            direction: .received, outcome: .stored, solicited: true, now: at(1)
        )
        XCTAssertEqual(Set(try ledger.entries(for: room).map(\.outcome)), [.refused, .stored])
    }

    // MARK: - leak radius

    /// FIMP §9.6 tells an owner to rotate when a key may have leaked, and
    /// deciding who to re-key means knowing who holds what. **The chain
    /// cannot answer it**: membership is public, delivery is not, and the
    /// two differ whenever a push was skipped or a member answered for
    /// the owner.
    func testHoldersAreEveryoneWeGaveAKeyToOrTookOneFrom() throws {
        try ledger.record(
            entityId: room, version: 6, counterparty: bob,
            direction: .sent, outcome: .shared, solicited: false, now: t0
        )
        try ledger.record(
            entityId: room, version: 6, counterparty: carol,
            direction: .received, outcome: .stored, solicited: true, now: at(10)
        )
        // Nothing reached this one, so they hold nothing.
        try ledger.record(
            entityId: room, version: 6, counterparty: "F-dave",
            direction: .sent, outcome: .noPubkey, solicited: false, now: at(20)
        )
        // And this one asked for a version nobody has.
        try ledger.record(
            entityId: room, version: 9, counterparty: "F-erin",
            direction: .sent, outcome: .notHeld, solicited: true, now: at(30)
        )

        XCTAssertEqual(Set(try ledger.holders(of: room)), [bob, carol])
        XCTAssertEqual(Set(try ledger.holders(of: room, version: 6)), [bob, carol])
        XCTAssertTrue(try ledger.holders(of: room, version: 9).isEmpty)
    }

    func testVersionsGivenToOnePerson() throws {
        for version: Int64 in [6, 7] {
            try ledger.record(
                entityId: room, version: version, counterparty: bob,
                direction: .sent, outcome: .shared, solicited: false, now: at(Double(version))
            )
        }
        try ledger.record(
            entityId: room, version: 8, counterparty: bob,
            direction: .received, outcome: .stored, solicited: false, now: at(8)
        )
        XCTAssertEqual(
            try ledger.versionsGiven(to: bob, of: room), [6, 7],
            "what we handed over, not what they handed us"
        )
    }

    // MARK: - the end-to-end path

    /// Answering a request writes a `sent` row without anybody being
    /// asked — which is the entire reason §9.7 exists.
    func testAnsweringARequestIsRecordedWithoutAPrompt() throws {
        try session.rooms.upsert(
            Room(owner: session.liveFid, members: [session.liveFid, bob], id: room)
        )
        let key = try session.symkeys.mint(for: room, now: t0)

        var request = ImMessage.request(
            type: .p2p, from: bob, to: session.liveFid, requestType: .symkey,
            data: SymkeyShare.request(entityId: room, version: key.version), now: t0
        )
        request.id = "0000000000009002"

        let outcome = try router().route(request, as: session.liveFid, now: at(5))
        XCTAssertFalse(outcome.outbound.isEmpty, "the key went out")

        let rows = try ledger.entries(for: room)
        XCTAssertEqual(rows.count, 1)
        XCTAssertEqual(rows.first?.direction, .sent)
        XCTAssertEqual(rows.first?.outcome, .shared)
        XCTAssertEqual(rows.first?.counterparty, bob)
        XCTAssertEqual(rows.first?.version, key.version)
        XCTAssertTrue(try XCTUnwrap(rows.first).solicited)
        XCTAssertEqual(rows.first?.requestId, "0000000000009002")
    }

    /// A member asking for a version nobody holds is the most actionable
    /// row a user has, so a refusal is recorded as carefully as a share.
    func testARefusalIsRecorded() throws {
        try session.rooms.upsert(
            Room(owner: session.liveFid, members: [session.liveFid, bob], id: room)
        )
        var request = ImMessage.request(
            type: .p2p, from: bob, to: session.liveFid, requestType: .symkey,
            data: SymkeyShare.request(entityId: room, version: 42), now: t0
        )
        request.id = "0000000000009003"

        _ = try router().route(request, as: session.liveFid, now: at(5))
        let rows = try ledger.entries(for: room)
        XCTAssertEqual(rows.first?.outcome, .notHeld)
        XCTAssertEqual(rows.first?.version, 42)
    }

    // MARK: - it never leaves

    /// **The record is more sensitive than the membership it derives
    /// from**, which is already on the chain. It must not appear in a
    /// `HISTORY` response, an export, or anything else put on a DOCK.
    ///
    /// An export is built from ``MessagesStore`` rows and nothing else,
    /// so this holds by construction — the assertion is here to fail
    /// loudly if anybody ever folds a second source into it.
    func testTheLedgerIsNotInAHistoryExport() throws {
        try ledger.record(
            entityId: room, version: 6, counterparty: bob,
            direction: .sent, outcome: .shared, solicited: false, now: t0
        )
        let key = try session.symkeys.mint(for: room, now: t0)
        var message = ImMessage.text(type: .room, from: session.liveFid, to: room, "in the room")
        message.id = "0000000000000001"
        message.symkeyVersion = key.version
        try session.messages.put(message, in: Conversation.id(type: .room, targetId: room))

        let conversationId = Conversation.id(type: .room, targetId: room)
        let rows = try session.messages.page(in: conversationId).messages
        let json = HistoryFile.export(
            rows,
            meta: HistoryExportMeta(
                fid: session.liveFid,
                exportTime: Int64(t0.timeIntervalSince1970 * 1000),
                imType: ImType.room.rawValue,
                targetId: room,
                sinceTs: 0,
                beforeTs: Int64(at(3600).timeIntervalSince1970 * 1000),
                sharedTo: bob
            )
        )

        XCTAssertTrue(json.contains("in the room"), "the messages are there")
        for absent in [KeyLedger.namespace, "counterparty", "solicited", "keyledger", bob] {
            XCTAssertFalse(
                json.replacingOccurrences(of: "\"sharedTo\":\"\(bob)\"", with: "")
                    .contains(absent),
                "\(absent) must not travel"
            )
        }
    }

    /// Deleting a room outright takes the record with it: a map of who
    /// could read a conversation the user has erased is its own
    /// disclosure.
    func testForgettingARoomTakesItsLedgerRows() throws {
        try session.rooms.upsert(Room(owner: session.liveFid, members: [session.liveFid], id: room))
        try ledger.record(
            entityId: room, version: 6, counterparty: bob,
            direction: .sent, outcome: .shared, solicited: false, now: t0
        )
        try ledger.record(
            entityId: team, version: 6, counterparty: bob,
            direction: .sent, outcome: .shared, solicited: false, now: t0
        )

        _ = try RoomService(
            rooms: session.rooms, symkeys: session.symkeys, keyLedger: ledger
        ).forget(room)

        XCTAssertTrue(try ledger.entries(for: room).isEmpty)
        XCTAssertEqual(try ledger.entries(for: team).count, 1, "another group is untouched")
    }

    // MARK: - helpers

    private func router() throws -> SignalRouter {
        SignalRouter(
            rooms: session.rooms,
            teams: session.teams,
            symkeys: session.symkeys,
            invites: session.roomInvites,
            roomService: try session.roomService,
            roomConversations: session.roomConversations,
            privkey: Data(repeating: 0xA1, count: 32),
            pubkeys: { fid in
                fid == self.bob
                    ? try Secp256k1.publicKey(fromPrivateKey: Data(repeating: 0xB2, count: 32))
                    : nil
            },
            keyAsks: session.keyAsks,
            keyLedger: session.keyLedger
        )
    }
}
