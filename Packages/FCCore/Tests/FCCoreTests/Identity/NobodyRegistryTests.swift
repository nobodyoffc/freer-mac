import XCTest
@testable import FCCore

/// The registry is what every nobody mark and confirmation reads, so these
/// pin its rules: a published key is remembered for good, a "not a nobody"
/// answer only for a while, and a failed check never pretends to be one.
/// The same rules are pinned on Android by `NobodyRegistryTest`.
final class NobodyRegistryTests: XCTestCase {

    private let alice = "FEk41Kqjar45fLDriztUDTUkdki7mmcjWK"
    private let bob = "FTqiqAyXHnK7uDTXzMap3acvqADK4ZGzts"

    private final class Clock: @unchecked Sendable {
        var now = Date(timeIntervalSince1970: 1_000_000)
    }

    private var clock: Clock!
    private var store: MemoryNobodyStore!
    private var registry: NobodyRegistry!

    override func setUp() {
        clock = Clock()
        store = MemoryNobodyStore()
        let clock = clock!
        registry = NobodyRegistry(store: store, now: { clock.now })
    }

    func testDefaultBoardIsAlwaysANobody() {
        XCTAssertTrue(registry.isNobody(NobodyRegistry.defaultNobodyFid))
    }

    func testPositivesArePersistedAndNeverExpire() {
        registry.markNobodies([alice])
        clock.now += 365 * 24 * 60 * 60
        XCTAssertTrue(registry.isNobody(alice))

        let reloaded = NobodyRegistry(store: store)
        XCTAssertTrue(reloaded.isNobody(alice))
    }

    func testNegativesExpire() {
        registry.markNotNobodies([bob])
        XCTAssertTrue(registry.isKnownNotNobody(bob))
        XCTAssertEqual(registry.unknown(among: [bob]), [])

        clock.now += NobodyRegistry.negativeTtl + 1
        XCTAssertFalse(registry.isKnownNotNobody(bob))
        XCTAssertEqual(registry.unknown(among: [bob]), [bob])
    }

    func testAPublishedKeyOverridesAnEarlierNegative() {
        registry.markNotNobodies([alice])
        registry.markNobodies([alice])
        XCTAssertTrue(registry.isNobody(alice))
        XCTAssertFalse(registry.isKnownNotNobody(alice))

        registry.markNotNobodies([alice])
        XCTAssertTrue(registry.isNobody(alice))
    }

    func testNobodiesAmongKeepsOrderAndDropsDuplicates() {
        registry.markNobodies([bob, alice])
        XCTAssertEqual(registry.nobodies(among: [bob, "x", alice, bob, ""]), [bob, alice])
    }

    func testResolveMarksFoundAndAbsentFids() async {
        let ok = await registry.resolve([alice, bob], retryFailed: false) { _ in [self.alice] }
        XCTAssertTrue(ok)
        XCTAssertTrue(registry.isNobody(alice))
        XCTAssertTrue(registry.isKnownNotNobody(bob))
    }

    func testAFailedCheckIsNotAnAnswer() async {
        let ok = await registry.resolve([alice], retryFailed: false) { _ in nil }
        XCTAssertFalse(ok)
        XCTAssertFalse(registry.isNobody(alice))
        XCTAssertFalse(registry.isKnownNotNobody(alice))
    }

    func testAThrowingCheckIsNotAnAnswer() async {
        struct Offline: Error {}
        let ok = await registry.resolve([alice], retryFailed: false) { _ in throw Offline() }
        XCTAssertFalse(ok)
        XCTAssertFalse(registry.isKnownNotNobody(alice))
    }

    func testAFailedCheckBacksOffForListsButNotForConfirmations() async {
        await registry.resolve([alice], retryFailed: false) { _ in nil }

        var calls = 0
        let quiet = await registry.resolve([alice], retryFailed: false) { _ in calls += 1; return [] }
        XCTAssertTrue(quiet)
        XCTAssertEqual(calls, 0)

        let retried = await registry.resolve([alice], retryFailed: true) { _ in calls += 1; return [] }
        XCTAssertTrue(retried)
        XCTAssertEqual(calls, 1)
        XCTAssertTrue(registry.isKnownNotNobody(alice))
    }

    func testKnownFidsAreNotCheckedAgain() async {
        registry.markNobodies([alice])
        registry.markNotNobodies([bob])
        var asked: [String] = []
        await registry.resolve([alice, bob], retryFailed: true) { fids in asked += fids; return [] }
        XCTAssertEqual(asked, [])
    }

    func testPubkeyMapsToItsFid() throws {
        // The board's published key, the same vector Android pins.
        let prikey = try Hex.decode("d710ff828229c8fd9923407a5ebfb4a27a42504a1d69ae7ec95b9cc2c7073226")
        let pubkey = try Secp256k1.publicKey(fromPrivateKey: prikey)
        XCTAssertEqual(NobodyRegistry.fid(ofPubkeyHex: Hex.encode(pubkey)), NobodyRegistry.defaultNobodyFid)
        XCTAssertTrue(registry.isNobody(pubkeyHex: Hex.encode(pubkey)))
        XCTAssertNil(NobodyRegistry.fid(ofPubkeyHex: "not a pubkey"))
    }

    func testOwnKeyAlertIsClaimedOnce() {
        XCTAssertFalse(registry.claimOwnKeyAlert(alice))
        registry.markNobodies([alice])
        XCTAssertTrue(registry.claimOwnKeyAlert(alice))
        XCTAssertFalse(registry.claimOwnKeyAlert(alice))
        XCTAssertFalse(NobodyRegistry(store: store).claimOwnKeyAlert(alice))
    }

    func testFileStoreRoundTrips() throws {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
            .appendingPathComponent("nobodies.json")
        defer { try? FileManager.default.removeItem(at: url.deletingLastPathComponent()) }

        let first = NobodyRegistry(store: FileNobodyStore(url: url))
        first.markNobodies([alice])
        _ = first.claimOwnKeyAlert(alice)

        let second = NobodyRegistry(store: FileNobodyStore(url: url))
        XCTAssertTrue(second.isNobody(alice))
        XCTAssertFalse(second.claimOwnKeyAlert(alice))
    }
}
