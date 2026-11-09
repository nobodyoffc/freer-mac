import XCTest
import FCCore
import FCTransport
@testable import FCDomain

/// The owner's "members left, rotate the key" prompt — FIMP4V3 §3.3.
/// Raised from the chain by the team sync, never by a message.
final class KeyRotationRemindersTests: XCTestCase {

    private var baseDir: URL!
    private var manager: ConfigureManager!
    private var session: ActiveSession!

    private let teamId = "3f9c1a2b0000000000000000000000000000000000000000000000000000tid2"

    override func setUpWithError() throws {
        baseDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("KeyRotationRemindersTests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: baseDir, withIntermediateDirectories: true)
        manager = try ConfigureManager(baseDirectory: baseDir)
        let configure = try manager.createConfigure(password: Data("pwd".utf8), kdfKind: .legacySha256)
        let info = try configure.addMain(privkey: Data(repeating: 0xB3, count: 32), label: "A")
        session = try configure.unlockMain(fid: info.fid, fapi: MockFapiClient())
    }

    override func tearDownWithError() throws {
        session = nil
        manager = nil
        if let baseDir { try? FileManager.default.removeItem(at: baseDir) }
    }

    private var me: String { session.liveFid }
    private var store: KeyRotationRemindersStore { session.keyRotations }

    private func team(owner: String? = nil, members: [String], active: Bool = true) -> Team {
        Team(owner: owner ?? me, stdName: "Core", members: members, active: active, id: teamId)
    }

    private let noon = Date(timeIntervalSince1970: 1_800_000_000)

    func testARemovalRaisesAReminderNamingWhoLeft() throws {
        let cached = team(members: [me, "F-a", "F-b"])
        let fresh = team(members: [me, "F-b"])
        let row = try XCTUnwrap(store.reconcile(
            team: fresh, cached: cached, as: me, currentVersion: 0, now: noon
        ))
        XCTAssertEqual(row.removedFids, ["F-a"])
        XCTAssertEqual(row.teamName, "Core")
        XCTAssertEqual(try store.outstanding().count, 1)
    }

    /// Nothing to compare against on a first sight of the team.
    func testAFirstSightRaisesNothing() throws {
        XCTAssertNil(try store.reconcile(
            team: team(members: [me]), cached: nil, as: me, currentVersion: 0, now: noon
        ))
    }

    /// Only the owner can mint, so only the owner is prompted.
    func testAMemberWhoIsNotTheOwnerIsNotPrompted() throws {
        let cached = team(owner: "F-owner", members: ["F-owner", me, "F-a"])
        let fresh = team(owner: "F-owner", members: ["F-owner", me])
        XCTAssertNil(try store.reconcile(
            team: fresh, cached: cached, as: me, currentVersion: 0, now: noon
        ))
    }

    /// Three dismissals in three carves are one prompt, and a further
    /// removal brings back a postponed one.
    func testFurtherRemovalsGatherAndUnpostpone() throws {
        _ = try store.reconcile(
            team: team(members: [me, "F-b"]), cached: team(members: [me, "F-a", "F-b"]),
            as: me, currentVersion: 0, now: noon
        )
        XCTAssertTrue(try store.postpone(teamId: teamId))
        XCTAssertTrue(try store.outstanding().isEmpty)

        let row = try XCTUnwrap(store.reconcile(
            team: team(members: [me]), cached: team(members: [me, "F-b"]),
            as: me, currentVersion: 0, now: noon.addingTimeInterval(60)
        ))
        XCTAssertEqual(row.removedFids, ["F-a", "F-b"])
        XCTAssertFalse(row.isPostponed)
    }

    /// An unrelated later sync keeps a postponed reminder postponed.
    func testAnUnrelatedSyncKeepsThePostponement() throws {
        let fresh = team(members: [me])
        _ = try store.reconcile(
            team: fresh, cached: team(members: [me, "F-a"]), as: me, currentVersion: 0, now: noon
        )
        _ = try store.postpone(teamId: teamId)
        let row = try XCTUnwrap(store.reconcile(
            team: fresh, cached: fresh, as: me, currentVersion: 0, now: noon
        ))
        XCTAssertTrue(row.isPostponed)
    }

    /// A key minted after the reminder — on this Mac or another of the
    /// owner's devices — is the rotation it asked for.
    func testANewerKeyClearsIt() throws {
        let fresh = team(members: [me])
        _ = try store.reconcile(
            team: fresh, cached: team(members: [me, "F-a"]), as: me, currentVersion: 0, now: noon
        )
        let after = Int64(noon.timeIntervalSince1970) + 5
        XCTAssertNil(try store.reconcile(
            team: fresh, cached: fresh, as: me, currentVersion: after, now: noon
        ))
        XCTAssertTrue(try store.all().isEmpty)
    }

    /// A key minted before the removal went to a list that still had the
    /// removed member in it, so it does not count.
    func testAnOlderKeyDoesNotClearIt() throws {
        let before = Int64(noon.timeIntervalSince1970) - 3600
        XCTAssertNotNil(try store.reconcile(
            team: team(members: [me]), cached: team(members: [me, "F-a"]),
            as: me, currentVersion: before, now: noon
        ))
        XCTAssertNotNil(try store.reconcile(
            team: team(members: [me]), cached: team(members: [me]),
            as: me, currentVersion: before, now: noon
        ))
    }

    /// Taken over, or disbanded: no longer ours to rotate.
    func testLosingOwnershipOrDisbandingDropsIt() throws {
        _ = try store.reconcile(
            team: team(members: [me]), cached: team(members: [me, "F-a"]),
            as: me, currentVersion: 0, now: noon
        )
        XCTAssertNil(try store.reconcile(
            team: team(members: [me], active: false), cached: team(members: [me]),
            as: me, currentVersion: 0, now: noon
        ))
        XCTAssertTrue(try store.all().isEmpty)
    }
}
