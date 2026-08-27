import XCTest
import FCCore
import FCStorage
@testable import FCDomain

/// Team keys: who may mint one, who gets given it, and what happens to
/// the people we cannot reach.
///
/// A team's *membership* needs no defending — it is on the chain, and a
/// peer cannot lie about it because a peer is not asked. The one thing
/// that does need defending is who mints the key, which is what these
/// tests are about.
final class TeamKeyServiceTests: XCTestCase {

    private var baseDir: URL!
    private var kv: EncryptedKVStore!
    private var teams: TeamsStore!
    private var symkeys: SymkeyStore!
    private var service: TeamKeyService!

    private let alicePriv = Data(repeating: 0xA1, count: 32)
    private let bobPriv = Data(repeating: 0xB2, count: 32)
    private let carolPriv = Data(repeating: 0xD4, count: 32)
    private let alice = "F-alice"
    private let bob = "F-bob"
    private let carol = "F-carol"
    private let dave = "F-dave"
    private let teamId = "team-1"

    private let t0 = Date(timeIntervalSince1970: 1_755_100_000)

    override func setUpWithError() throws {
        baseDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("TeamKeyServiceTests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: baseDir, withIntermediateDirectories: true)
        kv = try EncryptedKVStore(
            databasePath: baseDir.appendingPathComponent("store.sqlite").path,
            vaultKey: Data(repeating: 0x5C, count: 32)
        )
        teams = TeamsStore(kv: kv)
        symkeys = SymkeyStore(kv: kv)
        service = TeamKeyService(teams: teams, symkeys: symkeys)

        try teams.upsert(
            Team(owner: alice, stdName: "The Team", members: [alice, bob, carol], active: true, id: teamId)
        )
    }

    override func tearDownWithError() throws {
        service = nil
        symkeys = nil
        teams = nil
        kv = nil
        if let baseDir { try? FileManager.default.removeItem(at: baseDir) }
    }

    private func pubkeys(_ fid: String) throws -> Data? {
        switch fid {
        case bob: return try Secp256k1.publicKey(fromPrivateKey: bobPriv)
        case carol: return try Secp256k1.publicKey(fromPrivateKey: carolPriv)
        default: return nil
        }
    }

    // MARK: - minting

    func testEnsureMintsVersionOneAndSharesItWithEveryMember() throws {
        let keyed = try service.ensureSymkey(
            for: teamId, as: alice, pubkeys: pubkeys, now: t0
        )
        XCTAssertTrue(keyed.created)
        XCTAssertEqual(keyed.version, 1)
        XCTAssertEqual(try symkeys.currentVersion(for: teamId), 1)

        XCTAssertEqual(Set(keyed.outbound.compactMap(\.targetId)), [bob, carol])
        for message in keyed.outbound {
            XCTAssertEqual(message.contentType, .symkey)
            // Never on the team's own channel: the whole reason someone
            // needs the key is that they cannot read that channel yet.
            XCTAssertEqual(message.type, .p2p)
            XCTAssertEqual(message.symkeyVersion, 1)
            let payload = SymkeyShare.parse(try XCTUnwrap(message.content))
            XCTAssertEqual(payload?.entityId, teamId)
            XCTAssertNotNil(message.id, "queueable — the outbox refuses a message with no id")
        }
    }

    /// This runs on every group sync, so a team that already has a key
    /// must not get a second one. A rotation stays a deliberate act.
    func testEnsureIsIdempotent() throws {
        _ = try service.ensureSymkey(for: teamId, as: alice, pubkeys: pubkeys, now: t0)
        let again = try service.ensureSymkey(for: teamId, as: alice, pubkeys: pubkeys, now: t0)

        XCTAssertFalse(again.created)
        XCTAssertEqual(again.version, 1)
        XCTAssertTrue(again.outbound.isEmpty)
        XCTAssertEqual(try symkeys.versions(for: teamId), [1])
    }

    /// The one rule this type exists to enforce. If any member could
    /// mint a key and push it out, a member could split the team in two
    /// and nothing on the chain would say which half was real.
    func testOnlyTheOwnerMintsOrRotates() throws {
        XCTAssertThrowsError(
            try service.ensureSymkey(for: teamId, as: bob, pubkeys: pubkeys, now: t0)
        ) { XCTAssertEqual($0 as? TeamKeyService.Failure, .notTheOwner(teamId: teamId)) }

        XCTAssertThrowsError(
            try service.resetSymkey(for: teamId, as: bob, pubkeys: pubkeys, now: t0)
        ) { XCTAssertEqual($0 as? TeamKeyService.Failure, .notTheOwner(teamId: teamId)) }

        XCTAssertThrowsError(
            try service.ensureSymkey(for: "team-nope", as: alice, pubkeys: pubkeys, now: t0)
        ) { XCTAssertEqual($0 as? TeamKeyService.Failure, .noSuchTeam("team-nope")) }

        XCTAssertEqual(try symkeys.currentVersion(for: teamId), 0, "nothing was minted")
    }

    // MARK: - rotating

    /// Rotating is additive everywhere in this codebase: the old version
    /// stays, because it is the only thing that can still open what was
    /// said under it.
    func testResetAddsAVersionAndKeepsTheOldOne() throws {
        _ = try service.ensureSymkey(for: teamId, as: alice, pubkeys: pubkeys, now: t0)
        let first = try XCTUnwrap(try symkeys.key(for: teamId, version: 1))

        let rotated = try service.resetSymkey(for: teamId, as: alice, pubkeys: pubkeys, now: t0)
        XCTAssertEqual(rotated.version, 2)
        XCTAssertEqual(try symkeys.versions(for: teamId), [1, 2])
        XCTAssertEqual(try symkeys.key(for: teamId, version: 1), first, "v1 still opens the past")
        XCTAssertNotEqual(try symkeys.key(for: teamId, version: 2), first)
        XCTAssertEqual(Set(rotated.outbound.compactMap(\.targetId)), [bob, carol])
    }

    /// An owner whose device holds no key for a team it owns rotates
    /// rather than generating: `rotate` takes the next version up, so a
    /// version number a different key may already be sealing under is
    /// never reused.
    func testResetOnATeamWithNoKeyStartsAtVersionOne() throws {
        let keyed = try service.resetSymkey(for: teamId, as: alice, pubkeys: pubkeys, now: t0)
        XCTAssertEqual(keyed.version, 1)
    }

    // MARK: - who gets skipped

    /// A member we cannot seal to or cannot reach is skipped, not thrown
    /// over: a rotation that failed because one of three members has no
    /// published key would leave the other two unable to read anything
    /// said afterwards.
    func testMembersWithNoPubkeyOrNoDockAreSkippedRatherThanFatal() throws {
        try teams.upsert(
            Team(owner: alice, members: [alice, bob, carol, dave], active: true, id: teamId)
        )
        let bobFid = bob
        let homes: (String) -> [String: String]? = { fid in
            fid == bobFid ? [ServiceName.dock: "https://dock.example"] : nil
        }
        let keyed = try service.ensureSymkey(
            for: teamId, as: alice, pubkeys: pubkeys, homes: homes, now: t0
        )
        XCTAssertTrue(keyed.created, "the key is still minted")
        XCTAssertEqual(keyed.outbound.compactMap(\.targetId), [bob])
        XCTAssertEqual(Set(keyed.skipped), [carol, dave])
    }

    // MARK: - sharing without rotating

    func testShareCurrentOnlyGoesToPeopleTheChainSaysAreMembers() throws {
        _ = try service.ensureSymkey(for: teamId, as: alice, pubkeys: pubkeys, now: t0)

        let shared = try service.shareCurrent(
            of: teamId, to: [bob, dave], as: alice, pubkeys: pubkeys, now: t0
        )
        XCTAssertFalse(shared.created, "no rotation")
        XCTAssertEqual(shared.version, 1)
        XCTAssertEqual(shared.outbound.compactMap(\.targetId), [bob], "dave is not in the team")
        XCTAssertEqual(try symkeys.versions(for: teamId), [1])
    }

    func testShareCurrentWithNoKeyHeldIsAnError() throws {
        XCTAssertThrowsError(
            try service.shareCurrent(of: teamId, to: [bob], as: alice, pubkeys: pubkeys, now: t0)
        ) { XCTAssertEqual($0 as? TeamKeyService.Failure, .noKey(teamId: teamId)) }
    }
}
