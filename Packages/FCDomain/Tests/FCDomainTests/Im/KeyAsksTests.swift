import XCTest
import FCCore
import FCStorage
@testable import FCDomain

/// ``KeyAsksStore``: the record that makes a member's answer admissible
/// (FIMP §4.2), paces re-asking (§7.4), and tells a person who they are
/// waiting on.
final class KeyAsksTests: XCTestCase {

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
            .appendingPathComponent("KeyAsksTests-\(UUID().uuidString)")
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

    private var store: KeyAsksStore { session.keyAsks }

    // MARK: - recording

    func testAnAskRemembersWhoWasAskedAndWhen() throws {
        let ask = try store.record(
            entityId: room, version: 6, kind: .symkey,
            sent: [(fid: bob, requestId: "r-1"), (fid: carol, requestId: "r-2")], now: t0
        )
        XCTAssertEqual(ask.askedFids, [bob, carol], "in the order they were asked")
        XCTAssertEqual(ask.requestIds, ["r-1", "r-2"])
        XCTAssertEqual(ask.attempts, 2)
        XCTAssertEqual(ask.version, 6)
        XCTAssertEqual(ask.kind, .symkey)
        XCTAssertEqual(try store.ask(entityId: room, version: 6), ask, "and it survives the round trip")
    }

    /// Asking again merges rather than replacing: the earlier request ids
    /// still have to be recognised, because the member who has not
    /// answered yet may still answer.
    func testAskingAgainKeepsTheEarlierRequestIds() throws {
        try store.record(
            entityId: room, version: 6, kind: .symkey,
            sent: [(fid: bob, requestId: "r-1")], now: t0
        )
        let merged = try store.record(
            entityId: room, version: 6, kind: .symkey,
            sent: [(fid: bob, requestId: "r-2"), (fid: carol, requestId: "r-3")], now: at(300)
        )
        XCTAssertEqual(merged.requestIds, ["r-1", "r-2", "r-3"])
        XCTAssertEqual(merged.askedFids, [bob, carol])
        XCTAssertEqual(merged.attempts, 3)
        XCTAssertEqual(merged.firstAskedAt, Int64(t0.timeIntervalSince1970 * 1000))
        XCTAssertEqual(merged.lastAskedAt, Int64(at(300).timeIntervalSince1970 * 1000))
    }

    func testAsksAreSeparatePerEntityAndVersion() throws {
        try store.record(entityId: room, version: 6, kind: .symkey, sent: [(bob, "r-1")], now: t0)
        try store.record(entityId: room, version: 7, kind: .symkey, sent: [(bob, "r-2")], now: t0)
        try store.record(entityId: team, version: 6, kind: .symkey, sent: [(bob, "r-3")], now: t0)

        XCTAssertEqual(try store.asks(for: room).map(\.version), [6, 7])
        XCTAssertEqual(try store.asks(for: team).map(\.version), [6])
        XCTAssertEqual(try store.all().count, 3)
    }

    // MARK: - the cooldown

    /// FIMP §7.4. Without it, a backlog of a hundred locked rows under
    /// one version is a hundred requests, paid for by us and delivered to
    /// someone who may hold none of them.
    func testTheSamePersonIsNotAskedTwiceInsideTheCooldown() throws {
        try store.record(entityId: room, version: 6, kind: .symkey, sent: [(bob, "r-1")], now: t0)

        let soon = try store.askable([bob], entityId: room, version: 6, now: at(30))
        XCTAssertTrue(soon.allowed.isEmpty)
        XCTAssertEqual(soon.waiting.map(\.fid), [bob])
        XCTAssertEqual(
            soon.waiting.first?.until,
            Date(timeIntervalSince1970: t0.timeIntervalSince1970 + KeyAsksStore.cooldown)
        )

        let later = try store.askable([bob], entityId: room, version: 6, now: at(121))
        XCTAssertEqual(later.allowed, [bob])
        XCTAssertTrue(later.waiting.isEmpty)
    }

    /// **The cooldown is per person, not per question.** A user who asked
    /// one member and got nothing has not repeated anything by asking a
    /// second member, and it costs the first member nothing — so
    /// throttling it would throttle recovery rather than the traffic the
    /// limit exists to bound.
    func testANewPersonMayBeAskedImmediately() throws {
        try store.record(entityId: room, version: 6, kind: .symkey, sent: [(bob, "r-1")], now: t0)

        let both = try store.askable([bob, carol], entityId: room, version: 6, now: at(5))
        XCTAssertEqual(both.allowed, [carol])
        XCTAssertEqual(both.waiting.map(\.fid), [bob])
    }

    /// The same version of a *different* entity is a different question.
    func testTheCooldownIsPerVersion() throws {
        try store.record(entityId: room, version: 6, kind: .symkey, sent: [(bob, "r-1")], now: t0)
        XCTAssertEqual(try store.askable([bob], entityId: room, version: 7, now: at(5)).allowed, [bob])
        XCTAssertEqual(try store.askable([bob], entityId: team, version: 6, now: at(5)).allowed, [bob])
    }

    func testAskableDropsBlanksAndDuplicates() throws {
        let result = try store.askable([bob, bob, "", carol], entityId: room, version: 6, now: t0)
        XCTAssertEqual(result.allowed, [bob, carol])
    }

    // MARK: - admitting an answer

    func testOnlyAMatchingRequestIdIsSolicited() throws {
        try store.record(entityId: room, version: 6, kind: .symkey, sent: [(bob, "r-1")], now: t0)

        XCTAssertTrue(try store.isSolicited(entityId: room, version: 6, requestId: "r-1"))
        XCTAssertFalse(
            try store.isSolicited(entityId: room, version: 6, requestId: "r-9"),
            "an id we never sent"
        )
        XCTAssertFalse(
            try store.isSolicited(entityId: room, version: 6, requestId: nil),
            "solicitation is never inferred from the absence of an id either"
        )
        XCTAssertFalse(try store.isSolicited(entityId: room, version: 6, requestId: ""))
        XCTAssertFalse(
            try store.isSolicited(entityId: team, version: 6, requestId: "r-1"),
            "the right id for the wrong entity"
        )
    }

    /// A responder substituting its current key for the version asked for
    /// is what FIMP §5.1 forbids, and admitting it would store a key that
    /// opens nothing while blocking the one that does.
    func testAnAnswerForAnotherVersionIsNotSolicited() throws {
        try store.record(entityId: room, version: 6, kind: .symkey, sent: [(bob, "r-1")], now: t0)
        XCTAssertFalse(try store.isSolicited(entityId: room, version: 9, requestId: "r-1"))
    }

    /// An ask for "whatever you hold" cannot object to what it is given.
    func testAnAskForTheCurrentKeyIsAnsweredByAnyVersion() throws {
        try store.record(
            entityId: room, version: KeyAsksStore.currentVersion, kind: .symkey,
            sent: [(bob, "r-1")], now: t0
        )
        XCTAssertTrue(try store.isSolicited(entityId: room, version: 1, requestId: "r-1"))
        XCTAssertTrue(try store.isSolicited(entityId: room, version: 1_789_813_689, requestId: "r-1"))
    }

    // MARK: - finishing

    /// A key for one version also settles the "send me your current key"
    /// ask, which it satisfies.
    func testResolvingClearsTheVersionAskedForAndTheCurrentOne() throws {
        try store.record(entityId: room, version: 6, kind: .symkey, sent: [(bob, "r-1")], now: t0)
        try store.record(
            entityId: room, version: KeyAsksStore.currentVersion, kind: .symkey,
            sent: [(carol, "r-2")], now: t0
        )
        try store.record(entityId: room, version: 7, kind: .symkey, sent: [(bob, "r-3")], now: t0)

        XCTAssertEqual(try store.resolve(entityId: room, version: 6), 2)
        XCTAssertEqual(try store.asks(for: room).map(\.version), [7], "the other question stands")
        XCTAssertEqual(try store.resolve(entityId: room, version: 6), 0, "idempotent")
    }

    /// For a delivery that does not say which request it answers — a
    /// room's `ROOM_INFO`, whose key rides along with the membership —
    /// the only honest test is what we now hold.
    func testResolvingByWhatIsHeld() throws {
        try store.record(entityId: room, version: 6, kind: .roomInfo, sent: [(bob, "r-1")], now: t0)
        try store.record(entityId: room, version: 7, kind: .symkey, sent: [(bob, "r-2")], now: t0)

        XCTAssertEqual(try store.resolve(entityId: room, heldVersions: [6]), 1)
        XCTAssertEqual(try store.asks(for: room).map(\.version), [7])
    }

    func testGivingUpRemovesOneAsk() throws {
        try store.record(entityId: room, version: 6, kind: .symkey, sent: [(bob, "r-1")], now: t0)
        XCTAssertTrue(try store.remove(entityId: room, version: 6))
        XCTAssertFalse(try store.remove(entityId: room, version: 6))
        XCTAssertTrue(try store.all().isEmpty)
    }

    /// An ask nobody answered stops being shown, so an abandoned recovery
    /// does not nag forever.
    func testAsksExpire() throws {
        try store.record(entityId: room, version: 6, kind: .symkey, sent: [(bob, "r-1")], now: t0)
        XCTAssertEqual(try store.prune(now: at(KeyAsksStore.expiry - 60)), 0)
        XCTAssertEqual(try store.prune(now: at(KeyAsksStore.expiry + 60)), 1)
        XCTAssertTrue(try store.all().isEmpty)
    }
}
