import XCTest
import FCCore
@testable import FCDomain

/// Phase 7.8 (person menu): sub-identity registration on
/// ``ActiveSession`` and the ``KeyInfo/from(freer:kind:)`` factory
/// used when a master / watched FID is discovered via the directory.
final class SubIdentityTests: XCTestCase {

    private var baseDir: URL!

    override func setUpWithError() throws {
        baseDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("SubIdentityTests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: baseDir, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        if let baseDir { try? FileManager.default.removeItem(at: baseDir) }
    }

    private func makeActiveSession() throws -> ActiveSession {
        let mgr = try ConfigureManager(baseDirectory: baseDir)
        let cs = try mgr.createConfigure(
            password: Data("sub-identity".utf8), kdfKind: .legacySha256
        )
        let priv = Data(fromHex: "a048f6c843f92bfe036057f7fc2bf2c27353c624cf7ad97e98ed41432f700575")
        let main = try cs.addMain(privkey: priv, label: "main")
        return try cs.unlockMain(fid: main.fid, fapi: MockFapiClient())
    }

    // MARK: - KeyInfo.from(freer:)

    func testKeyInfoFromFreerDecodesPubkeyAndLabel() {
        var freer = Freer()
        freer.id = "FEk41Kqjar45fLDriztUDTUkdki7mmcjWK"
        freer.cid = "Alice"
        freer.pubkey = "02" + String(repeating: "ab", count: 32)
        freer.master = "FMasterFid111111111111111111111111"

        let info = KeyInfo.from(freer: freer)
        XCTAssertNotNil(info)
        XCTAssertEqual(info?.fid, freer.id)
        XCTAssertEqual(info?.label, "Alice")
        XCTAssertEqual(info?.kind, .watched)
        XCTAssertEqual(info?.pubkey?.count, 33)
        XCTAssertEqual(info?.pubkey?.first, 0x02)
        XCTAssertEqual(info?.master, freer.master)
        XCTAssertNil(info?.prikeyCipher)
        XCTAssertEqual(info?.hasPrivkey, false)
    }

    func testKeyInfoFromFreerWithoutIdIsNil() {
        var freer = Freer()
        freer.cid = "NoId"
        XCTAssertNil(KeyInfo.from(freer: freer))
    }

    func testKeyInfoFromFreerIgnoresMalformedPubkey() {
        var freer = Freer()
        freer.id = "FEk41Kqjar45fLDriztUDTUkdki7mmcjWK"
        freer.pubkey = "04deadbeef"   // wrong length + uncompressed prefix
        let info = KeyInfo.from(freer: freer)
        XCTAssertNotNil(info)
        XCTAssertNil(info?.pubkey)
    }

    // MARK: - addSubIdentity / addWatchedFid

    func testAddWatchedFidRegistersAndSwitches() throws {
        let session = try makeActiveSession()
        let watched = "FMasterFid111111111111111111111111"

        let info = try session.addWatchedFid(
            watched, label: "cold",
            pubkey: Data(repeating: 0x02, count: 33)
        )
        XCTAssertEqual(info.kind, .watched)
        XCTAssertEqual(info.pubkey?.count, 33)
        XCTAssertEqual(session.setting.keyInfoMap[watched]?.label, "cold")

        try session.switchLive(fid: watched)
        XCTAssertEqual(session.liveFid, watched)
        XCTAssertFalse(session.canSign)
        XCTAssertThrowsError(try session.livePrikey())
    }

    func testAddSubIdentityRefusesMainFid() throws {
        let session = try makeActiveSession()
        let impostor = KeyInfo(fid: session.mainFid, kind: .watched)
        XCTAssertThrowsError(try session.addSubIdentity(impostor)) { error in
            guard case ActiveSession.Failure.cannotReplaceMain = error else {
                XCTFail("expected cannotReplaceMain, got \(error)"); return
            }
        }
        // Main entry untouched — still signs.
        XCTAssertTrue(session.canSign)
    }

    func testRemoveSubIdentityFallsBackToMain() throws {
        let session = try makeActiveSession()
        let watched = "FMasterFid111111111111111111111111"
        _ = try session.addWatchedFid(watched)
        try session.switchLive(fid: watched)

        XCTAssertTrue(try session.removeSubIdentity(fid: watched))
        XCTAssertEqual(session.liveFid, session.mainFid)
        XCTAssertNil(session.setting.keyInfoMap[watched])
    }
}
