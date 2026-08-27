import XCTest
import FCCore
import FCTransport
@testable import FCDomain

/// The FID bar's data layer: ``LiveFidInfo`` merge semantics, the
/// ``ActiveSession/refreshLiveFidInfo()`` fetch-and-cache round trip,
/// and ``ActiveSession/setLabel(_:forFid:)`` writing the label to both
/// places the main FID's name lives.
final class LiveFidInfoTests: XCTestCase {

    private var baseDir: URL!

    override func setUpWithError() throws {
        baseDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("LiveFidInfoTests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: baseDir, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        if let baseDir { try? FileManager.default.removeItem(at: baseDir) }
    }

    private func makeSession() throws -> (ActiveSession, ConfigureSession, MockFapiClient) {
        let mgr = try ConfigureManager(baseDirectory: baseDir)
        let cs = try mgr.createConfigure(
            password: Data("live-fid-info".utf8), kdfKind: .legacySha256
        )
        let priv = Data(fromHex: "a048f6c843f92bfe036057f7fc2bf2c27353c624cf7ad97e98ed41432f700575")
        let main = try cs.addMain(privkey: priv, label: "main")
        let mock = MockFapiClient()
        return (try cs.unlockMain(fid: main.fid, fapi: mock), cs, mock)
    }

    // MARK: - merging

    func testMergingOverwritesPresentFieldsAndKeepsAbsentOnes() {
        var info = LiveFidInfo(fid: "FTestFid111")
        info.balance = 5_000
        info.cash = 3
        info.weight = 42

        var freer = Freer()
        freer.balance = 9_000
        freer.reputation = 7
        // cash and weight deliberately absent

        let merged = info.merging(freer)

        XCTAssertEqual(merged.balance, 9_000, "present field must win")
        XCTAssertEqual(merged.reputation, 7, "newly present field must land")
        XCTAssertEqual(merged.cash, 3, "absent field must keep its old value")
        XCTAssertEqual(merged.weight, 42, "absent field must keep its old value")
        XCTAssertEqual(merged.fid, "FTestFid111")
    }

    func testMergingAcceptsAnExplicitZero() {
        var info = LiveFidInfo(fid: "FTestFid111")
        info.balance = 5_000

        var freer = Freer()
        freer.balance = 0

        // The index reports a spent-down FID as an explicit 0 rather than
        // by omission, so a drained wallet must not keep showing its old
        // balance.
        XCTAssertEqual(info.merging(freer).balance, 0)
    }

    func testMergingStampsFetchedAt() {
        let then = Date(timeIntervalSince1970: 1_000)
        var info = LiveFidInfo(fid: "FTestFid111", fetchedAt: then)
        info.balance = 1

        let now = Date(timeIntervalSince1970: 2_000)
        XCTAssertEqual(info.merging(Freer(), fetchedAt: now).fetchedAt, now)
    }

    // MARK: - display

    func testDisplayNameUsesCidWhenPresent() {
        var info = LiveFidInfo(fid: "FTestFid111")
        XCTAssertEqual(info.displayName, "FTestFid111")
        XCTAssertFalse(info.hasCid)

        info.cid = "alice"
        XCTAssertEqual(info.displayName, "alice")
        XCTAssertTrue(info.hasCid)
    }

    func testBlankCidIsNotACid() {
        var info = LiveFidInfo(fid: "FTestFid111")
        info.cid = "   "
        XCTAssertEqual(info.displayName, "FTestFid111")
        XCTAssertFalse(info.hasCid)
    }

    func testHasMetricsIgnoresNilAndZero() {
        var info = LiveFidInfo(fid: "FTestFid111")
        XCTAssertFalse(info.hasMetrics)

        info.weight = 0
        info.reputation = 0
        info.hot = 0
        XCTAssertFalse(info.hasMetrics, "all-zero must hide the row, as Android does")

        info.hot = 5
        XCTAssertTrue(info.hasMetrics)
    }

    // MARK: - refresh

    func testRefreshFetchesFreerAndCachesIt() async throws {
        let (session, _, mock) = try makeSession()
        let fid = session.liveFid
        mock.responder = { call in
            XCTAssertEqual(call.api, "base.freerByIds")
            return try makeResponse(data: [
                fid: [
                    "id": fid, "cid": "alice", "balance": 12_345,
                    "cash": 4, "cd": 900, "weight": 5_000,
                    "reputation": 12, "hot": 340, "isNobody": false
                ]
            ])
        }

        let info = try await session.refreshLiveFidInfo()

        XCTAssertEqual(info.cid, "alice")
        XCTAssertEqual(info.balance, 12_345)
        XCTAssertEqual(info.cash, 4)
        XCTAssertEqual(info.cd, 900)
        XCTAssertEqual(info.weight, 5_000)
        XCTAssertEqual(info.reputation, 12)
        XCTAssertEqual(info.hot, 340)
        XCTAssertEqual(info.isNobody, false)

        // Survives into the cache, so the next launch renders before
        // the network answers.
        XCTAssertEqual(session.cachedLiveFidInfo().balance, 12_345)
        XCTAssertEqual(session.cachedLiveFidInfo().cid, "alice")
    }

    func testRefreshWithNoOnChainRecordStillStampsTheCache() async throws {
        let (session, _, mock) = try makeSession()
        mock.responder = { _ in try makeResponse(data: [String: Any]()) }

        let before = Date()
        let info = try await session.refreshLiveFidInfo()

        // A FID nobody has ever sent to is absent from the reply. That is
        // a normal answer, not a failure — and the bar needs the stamp so
        // it stops looking like it is still loading.
        XCTAssertNil(info.balance)
        XCTAssertGreaterThanOrEqual(info.fetchedAt, before)
        XCTAssertNotNil(try session.liveFidInfoCache.get(fid: session.liveFid))
    }

    func testCachedLiveFidInfoIsPerFid() async throws {
        let (session, _, mock) = try makeSession()
        let mainFid = session.liveFid
        let watched = "FTestWatchedFid1111111111111111111"
        try session.addWatchedFid(watched)

        mock.responder = { call in
            let fcdsl = try XCTUnwrap(call.fcdsl)
            let dict = try XCTUnwrap(
                JSONSerialization.jsonObject(with: fcdsl) as? [String: Any]
            )
            let ids = try XCTUnwrap(dict["ids"] as? [String])
            let id = try XCTUnwrap(ids.first)
            return try makeResponse(data: [id: ["id": id, "balance": id == mainFid ? 111 : 222]])
        }

        _ = try await session.refreshLiveFidInfo()
        try session.switchLive(fid: watched)
        _ = try await session.refreshLiveFidInfo()

        // Switching back must show the main's own numbers, not the ones
        // the watched FID last fetched.
        XCTAssertEqual(session.cachedLiveFidInfo().balance, 222)
        try session.switchLive(fid: mainFid)
        XCTAssertEqual(session.cachedLiveFidInfo().balance, 111)
    }

    // MARK: - cid write-back

    func testRefreshPersistsCidIntoKeyInfoAndConfigure() async throws {
        let (session, cs, mock) = try makeSession()
        let fid = session.liveFid
        mock.responder = { _ in
            try makeResponse(data: [fid: ["id": fid, "cid": "alice.f"]])
        }

        _ = try await session.refreshLiveFidInfo()

        XCTAssertEqual(session.liveKeyInfo.cid, "alice.f")
        XCTAssertEqual(session.liveKeyInfo.activeCid, "alice.f")
        // The identity chooser reads the Configure body, before any
        // Setting has been decrypted — the CID has to reach there too or
        // the chooser can never show it.
        XCTAssertEqual(cs.mainKeyInfo(fid: fid)?.cid, "alice.f")
    }

    func testRefreshLeavesLabelAloneWhenWritingCid() async throws {
        let (session, cs, mock) = try makeSession()
        let fid = session.liveFid
        mock.responder = { _ in
            try makeResponse(data: [fid: ["id": fid, "cid": "alice.f"]])
        }

        _ = try await session.refreshLiveFidInfo()

        // Both show in the chooser row, so a CID arriving must not
        // overwrite what the user named this identity.
        XCTAssertEqual(session.liveKeyInfo.label, "main")
        XCTAssertEqual(cs.mainKeyInfo(fid: fid)?.label, "main")
    }

    func testRefreshWithoutCidLeavesTheStoredOneAlone() async throws {
        let (session, _, mock) = try makeSession()
        let fid = session.liveFid
        mock.responder = { _ in
            try makeResponse(data: [fid: ["id": fid, "cid": "alice.f"]])
        }
        _ = try await session.refreshLiveFidInfo()

        // A reply that simply omits the cid means "the server said
        // nothing", not "the name is gone".
        mock.responder = { _ in try makeResponse(data: [fid: ["id": fid, "balance": 5]]) }
        _ = try await session.refreshLiveFidInfo()

        XCTAssertEqual(session.liveKeyInfo.cid, "alice.f")
    }

    func testBlankCidFromServerReadsAsNoCid() async throws {
        let (session, _, mock) = try makeSession()
        let fid = session.liveFid
        mock.responder = { _ in
            try makeResponse(data: [fid: ["id": fid, "cid": "   "]])
        }

        _ = try await session.refreshLiveFidInfo()

        XCTAssertNil(session.liveKeyInfo.activeCid)
        XCTAssertNil(session.liveKeyInfo.cid, "whitespace is normalised away, not stored")
    }

    func testKeyInfoDecodesWithoutACidField() throws {
        // Every Configure written before the cid field existed must
        // still open — a vault that fails to decode is a vault the user
        // cannot get into.
        let json = Data("""
        {"fid":"FTestFid111","label":"old","kind":"main",
         "savedAt":0}
        """.utf8)
        let decoded = try JSONDecoder().decode(KeyInfo.self, from: json)
        XCTAssertEqual(decoded.fid, "FTestFid111")
        XCTAssertEqual(decoded.label, "old")
        XCTAssertNil(decoded.cid)
        XCTAssertNil(decoded.activeCid)
    }

    // MARK: - label

    func testSetLabelWritesSettingAndConfigure() throws {
        let (session, cs, _) = try makeSession()
        let fid = session.mainFid

        try session.setLabel("daily spending", forFid: fid)

        XCTAssertEqual(session.liveKeyInfo.label, "daily spending")
        // The identity chooser runs before any Setting is decrypted, so
        // the Configure body has to carry the label too.
        XCTAssertEqual(cs.mainKeyInfo(fid: fid)?.label, "daily spending")
    }

    func testSetLabelTrimsAndCanClear() throws {
        let (session, cs, _) = try makeSession()
        let fid = session.mainFid

        try session.setLabel("  spaced  ", forFid: fid)
        XCTAssertEqual(session.liveKeyInfo.label, "spaced")

        try session.setLabel("   ", forFid: fid)
        XCTAssertEqual(session.liveKeyInfo.label, "", "whitespace-only clears the label")
        XCTAssertEqual(cs.mainKeyInfo(fid: fid)?.label, "")
    }

    func testSetLabelOnSubIdentityLeavesConfigureAlone() throws {
        let (session, cs, _) = try makeSession()
        let watched = "FTestWatchedFid1111111111111111111"
        try session.addWatchedFid(watched, label: "old")

        try session.setLabel("watched wallet", forFid: watched)

        XCTAssertEqual(session.setting.keyInfoMap[watched]?.label, "watched wallet")
        XCTAssertEqual(cs.mainKeyInfo(fid: session.mainFid)?.label, "main")
        XCTAssertNil(cs.mainKeyInfo(fid: watched))
    }

    func testSetLabelForUnknownFidThrows() throws {
        let (session, _, _) = try makeSession()
        XCTAssertThrowsError(try session.setLabel("x", forFid: "FNotRegistered111"))
    }
}
