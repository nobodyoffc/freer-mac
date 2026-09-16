import XCTest
import FCTransport
@testable import FCDomain

/// FEIP3 CID and FEIP9 Home: the payloads, the parser's suffix rule run
/// client-side, and the home merge that keeps a `register` from erasing
/// entries it did not mean to touch.
final class IdentityFeipTests: XCTestCase {

    /// FEIP3's own example FID. Its examples call the CID `Alice_VkUV`, but
    /// this FID ends in `vkUV`; the suffix is the FID's characters as they are.
    private let fid = "FPL44YJRwPdd2ipziFvqq6y2tw4VnVvkUV"

    private func data(_ json: String) throws -> [String: Any] {
        let object = try JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String: Any]
        XCTAssertEqual(object?["type"] as? String, "FEIP")
        return try XCTUnwrap(object?["data"] as? [String: Any])
    }

    // MARK: - CID

    func testRegisterPayloadMatchesTheSpec() throws {
        let json = try CidFeip.register(name: "Alice")
        let envelope = try JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String: Any]
        XCTAssertEqual(envelope?["sn"] as? String, "3")
        XCTAssertEqual(envelope?["ver"] as? String, "4")
        XCTAssertEqual(envelope?["name"] as? String, "CID")
        let d = try data(json)
        XCTAssertEqual(d["op"] as? String, "register")
        XCTAssertEqual(d["name"] as? String, "Alice", "the suffix is the parser's to add, never ours")
    }

    func testBadNamesAreRefusedBeforeAnythingIsBuilt() {
        for bad in ["", "Al ice", "a@b", "a#b", "a/b", "tab\tname"] {
            XCTAssertFalse(CidFeip.isGoodName(bad), bad)
            XCTAssertThrowsError(try CidFeip.register(name: bad), bad)
        }
        XCTAssertTrue(CidFeip.isGoodName("Alice_1"))
    }

    func testPreviewTakesTheLastFourCharacters() async throws {
        let preview = try await CidFeip.preview(name: "Alice", fid: fid, ownUsedCids: []) { _ in nil }
        XCTAssertEqual(preview, .new(cid: "Alice_vkUV"))
    }

    func testPreviewExtendsTheSuffixPastOtherFidsCollisions() async throws {
        let taken = ["Alice_vkUV": "FSomebodyElse", "Alice_VvkUV": "FAnotherOne"]
        let preview = try await CidFeip.preview(name: "Alice", fid: fid, ownUsedCids: []) { taken[$0] }
        XCTAssertEqual(preview, .new(cid: "Alice_nVvkUV"))
    }

    func testOwnEarlierCidReactivatesEvenAtTheLimit() async throws {
        let used = ["Alice_vkUV", "Bob_vkUV", "Carol_vkUV", "Dave_vkUV"]
        let again = try await CidFeip.preview(name: "Bob", fid: fid, ownUsedCids: used) { _ in nil }
        XCTAssertEqual(again, .reactivate(cid: "Bob_vkUV"))

        let fifth = try await CidFeip.preview(name: "Eve", fid: fid, ownUsedCids: used) { _ in nil }
        XCTAssertEqual(fifth, .limitReached(cid: "Eve_vkUV"))
    }

    func testFidUsingCidSearchesUsedCidsAndPicksTheExactHolder() async throws {
        let mock = MockFapiClient()
        mock.responder = { call in
            XCTAssertEqual(call.api, "base.search")
            let body = try JSONSerialization.jsonObject(with: call.fcdsl ?? Data()) as? [String: Any]
            XCTAssertEqual(body?["entity"] as? String, "freer")
            let terms = (body?["filter"] as? [String: Any])?["terms"] as? [String: Any]
            XCTAssertEqual(terms?["fields"] as? [String], ["usedCids"])
            return try makeResponse(data: [
                ["id": "FNear", "usedCids": ["Alice_VkUVx"]],
                ["id": "FExact", "usedCids": ["Old_1", "Alice_VkUV"]],
            ])
        }
        let owner = try await DirectoryService(fapi: mock).fidUsingCid("Alice_VkUV")
        XCTAssertEqual(owner, "FExact")

        mock.responder = { _ in try makeResponse(code: 404) }
        let none = try await DirectoryService(fapi: mock).fidUsingCid("Nobody_VkUV")
        XCTAssertNil(none)
    }

    // MARK: - Home

    func testHomePayloadMatchesTheSpec() throws {
        let json = try HomeFeip.register(home: [ServiceName.dock: "(sid)abc"])
        let envelope = try JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String: Any]
        XCTAssertEqual(envelope?["sn"] as? String, "9")
        XCTAssertEqual(envelope?["name"] as? String, "Home")
        let d = try data(json)
        XCTAssertEqual(d["op"] as? String, "register")
        XCTAssertEqual(d["home"] as? [String: String], [ServiceName.dock: "(sid)abc"])
    }

    func testMergeKeepsEntriesItDidNotMeanToTouch() {
        let sid = String(repeating: "a", count: 64)
        let merged = HomeFeip.merged(
            over: ["blog": "https://me.example", ServiceName.dock: "(sid)old"],
            dock: sid, disk: nil
        )
        XCTAssertEqual(merged, [
            "blog": "https://me.example",
            ServiceName.dock: "(sid)" + sid,
        ], "register replaces the whole map, so everything else has to be carried")
    }

    func testMergeThatChangesNothingIsNil() {
        let sid = String(repeating: "b", count: 64)
        XCTAssertNil(HomeFeip.merged(over: [ServiceName.disk: "(sid)" + sid], dock: "", disk: sid))
    }

    func testDeclaresMatchesByPrefixAndIgnoresBlankValues() {
        XCTAssertTrue(HomeFeip.declares("DOCK", in: [ServiceName.dock: "x"]))
        XCTAssertTrue(HomeFeip.declares("DOCK", in: ["dock": "x"]))
        XCTAssertFalse(HomeFeip.declares("DOCK", in: [ServiceName.dock: "  "]))
        XCTAssertFalse(HomeFeip.declares("DISK", in: [ServiceName.dock: "x"]))
        XCTAssertFalse(HomeFeip.declares("DISK", in: nil))
    }
}

/// The record that stops a CID or home carve being offered twice while it
/// confirms.
final class PendingIdentityCarvesTests: XCTestCase {

    private let fid = "FPL44YJRwPdd2ipziFvqq6y2tw4VnVvkUV"

    private func info(cid: String? = nil, home: [String: String]? = nil) -> LiveFidInfo {
        var info = LiveFidInfo(fid: fid)
        info.cid = cid
        info.home = home
        return info
    }

    func testCidLandsOnlyAsTheCarvedNameWithAFidSuffix() {
        let pending = PendingIdentityCarve(fid: fid, kind: .cid, name: "Al", txid: "t", broadcastAt: 0)
        XCTAssertTrue(pending.isLanded(on: info(cid: "Al_vkUV")))
        XCTAssertTrue(pending.isLanded(on: info(cid: "Al_VvkUV")), "a collision lengthens the suffix")
        XCTAssertFalse(pending.isLanded(on: info(cid: "Al_x_vkUV")), "another name that starts the same")
        XCTAssertFalse(pending.isLanded(on: info(cid: "Al_kUV")), "shorter than any suffix the parser makes")
        XCTAssertFalse(pending.isLanded(on: info(cid: nil)))
    }

    func testHomeLandsWhenEveryCarvedEntryIsOnTheChain() {
        let carved = [ServiceName.dock: "(sid)a", ServiceName.disk: "(sid)b"]
        let pending = PendingIdentityCarve(fid: fid, kind: .home, home: carved, txid: "t", broadcastAt: 0)
        XCTAssertFalse(pending.isLanded(on: info(home: [ServiceName.dock: "(sid)a"])))
        XCTAssertTrue(pending.isLanded(on: info(home: carved.merging(["blog": "x"]) { a, _ in a })))
    }

    func testMasterLandsOnAnyMasterBecauseItIsWriteOnce() {
        let pending = PendingIdentityCarve(fid: fid, kind: .master, master: "FMine", txid: "t", broadcastAt: 0)
        var landed = info()
        XCTAssertFalse(pending.isLanded(on: landed))
        landed.master = "FSomebodyElse"
        XCTAssertTrue(pending.isLanded(on: landed), "nothing more can come of this carve once the chain has a master")
    }

    func testOverdueAfterADay() {
        let pending = PendingIdentityCarve(fid: fid, kind: .cid, name: "Al", txid: "t", broadcastAt: 0)
        let day = TimeInterval(PendingGroupsStore.overdueMs / 1000)
        XCTAssertFalse(pending.isOverdue(now: Date(timeIntervalSince1970: day - 1)))
        XCTAssertTrue(pending.isOverdue(now: Date(timeIntervalSince1970: day)))
    }

    func testRefreshClearsWhatTheChainShows() async throws {
        let baseDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("PendingIdentityCarves-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: baseDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: baseDir) }
        let mgr = try ConfigureManager(baseDirectory: baseDir)
        let cs = try mgr.createConfigure(password: Data("pending".utf8), kdfKind: .legacySha256)
        let priv = Data(fromHex: "a048f6c843f92bfe036057f7fc2bf2c27353c624cf7ad97e98ed41432f700575")
        let main = try cs.addMain(privkey: priv, label: "main")
        let mock = MockFapiClient()
        let session = try cs.unlockMain(fid: main.fid, fapi: mock)
        let me = session.liveFid

        try session.pendingIdentityCarves.record(PendingIdentityCarve(
            fid: me, kind: .cid, name: "Al", txid: "t1", broadcastAt: 0
        ))
        try session.pendingIdentityCarves.record(PendingIdentityCarve(
            fid: me, kind: .home, home: [ServiceName.dock: "(sid)a"], txid: "t2", broadcastAt: 0
        ))
        let cid = "Al_" + me.suffix(4)
        mock.responder = { _ in try makeResponse(data: [me: ["id": me, "cid": cid]]) }

        try await session.refreshLiveFidInfo()

        XCTAssertNil(try session.pendingIdentityCarves.get(fid: me, kind: .cid), "landed, so cleared")
        XCTAssertNotNil(try session.pendingIdentityCarves.get(fid: me, kind: .home), "not on the chain yet")
    }
}
