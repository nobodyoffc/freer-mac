import XCTest
import FCCore
import FCTransport
@testable import FCDomain

/// What a sync is allowed to overwrite.
///
/// The cash cache holds two kinds of fact: what the chain says, which
/// the server owns, and what this device did, which only this device
/// knows. A sync that treats the server's answer as the whole truth
/// erases the second kind — and because the index is built from
/// confirmed blocks, it does so at exactly the wrong moment: in the
/// minutes after a broadcast, when the server still reports a cash we
/// just spent as perfectly spendable.
final class CashSyncAnnotationTests: XCTestCase {

    private var baseDir: URL!

    override func setUpWithError() throws {
        baseDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("CashSyncTests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: baseDir, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        if let baseDir { try? FileManager.default.removeItem(at: baseDir) }
    }

    private func makeSessions(passwords pwds: [String], fapi: any FapiCalling) throws -> [ActiveSession] {
        let mgr = try ConfigureManager(baseDirectory: baseDir)
        let configure = try mgr.createConfigure(
            password: Data("cash-sync-tests".utf8), kdfKind: .legacySha256
        )
        var sessions: [ActiveSession] = []
        for (i, pwd) in pwds.enumerated() {
            let priv = Hash.sha256(Data(pwd.utf8))
            let info = try configure.addMain(privkey: priv, label: "L\(i)")
            sessions.append(try configure.unlockMain(fid: info.fid, fapi: fapi))
        }
        return sessions
    }

    private func txid(_ byte: UInt8) -> String {
        String(repeating: String(format: "%02x", byte), count: 32)
    }

    private func cash(owner: String, txidByte: UInt8, index: Int, value: Int64) throws -> Cash {
        let h160 = try FchAddress(fid: owner).hash160
        return Cash(
            id: try Cash.makeId(birthTxId: txid(txidByte), birthIndex: index),
            owner: owner, value: value, type: "P2PKH",
            birthTxId: txid(txidByte), birthIndex: index,
            lockScript: Cash.canonicalP2PKHLockScript(hash160: h160),
            birthHeight: 900
        )
    }

    /// The wire shape of one still-spendable cash, as the index emits
    /// it: `valid: true`, with a block height, because that index only
    /// knows about confirmed blocks.
    private func wireRow(_ cash: Cash, owner: String, lastHeight: Int64 = 900) throws -> [String: Any] {
        let h160 = try FchAddress(fid: owner).hash160
        return [
            "id": cash.id!,
            "owner": owner,
            "value": cash.value,
            "type": "P2PKH",
            "birthTxId": cash.birthTxId,
            "birthIndex": cash.birthIndex,
            "valid": true,
            "birthHeight": 900,
            "lastHeight": lastHeight,
            "lockScript": Cash.canonicalP2PKHLockScript(hash160: h160)
        ]
    }

    // MARK: - the reported bug

    /// Send, then refresh. The input must still be marked: the server
    /// says it is spendable because it hasn't seen our transaction,
    /// and believing it would offer the same cash for spending twice.
    func testRefreshAfterSendKeepsTheSpentInputMarked() async throws {
        let mock = MockFapiClient()
        let sessions = try makeSessions(passwords: ["bug-a", "bug-b"], fapi: mock)
        let alice = sessions[0]
        let bob = sessions[1]

        let input = try cash(owner: alice.mainFid, txidByte: 0xA1, index: 0, value: 1_000_000)
        try alice.cashes.save(CashSnapshot(
            addr: alice.mainFid, cashes: [input],
            bestHeight: 1_000, watermarkHeight: 1_000
        ))

        var searched = false
        mock.responder = { call in
            switch call.api {
            case "base.broadcastTx":
                return try makeResponse(data: self.txid(0xB2))
            case "base.search":
                // The index hasn't seen the broadcast: the spent cash
                // still comes back valid.
                defer { searched = true }
                if searched { return try makeResponse(data: [], bestHeight: 1_000) }
                return try makeResponse(
                    data: [try self.wireRow(input, owner: alice.mainFid, lastHeight: 995)],
                    bestHeight: 1_000
                )
            default:
                XCTFail("unexpected api: \(call.api)"); return FapiResponse(code: 1)
            }
        }

        let result = try await alice.sendFromLive(
            to: bob.mainFid, amount: 100_000, using: [input]
        )

        // Straight after the broadcast: marked.
        let afterSend = try XCTUnwrap(try alice.cashes.snapshot(forAddress: alice.mainFid))
        XCTAssertTrue(try XCTUnwrap(afterSend.cashes.first { $0.id == input.id }).pendingSpend)

        // After a refresh that still shows it spendable: *still* marked.
        let refreshed = try await alice.wallet.refreshCashes(forFid: alice.mainFid)
        let row = try XCTUnwrap(refreshed.cashes.first { $0.id == input.id })
        XCTAssertTrue(row.pendingSpend, "sync must not un-flag a cash whose spend hasn't confirmed")

        // And the change we minted is still there and still spendable.
        let changeId = try Cash.makeId(birthTxId: result.remoteTxid, birthIndex: 1)
        let change = try XCTUnwrap(refreshed.cashes.first { $0.id == changeId })
        XCTAssertFalse(change.pendingSpend)
        XCTAssertEqual(change.unconfirmedDepth, 1)
    }

    /// The flag is not permanent: when the index finally reports the
    /// cash as spent, the row goes for good.
    func testConfirmedSpendRemovesTheRowEntirely() async throws {
        let mock = MockFapiClient()
        let alice = try makeSessions(passwords: ["confirmed-spend"], fapi: mock)[0]

        var spent = try cash(owner: alice.mainFid, txidByte: 0xC3, index: 0, value: 500_000)
        spent.pendingSpend = true
        try alice.cashes.save(CashSnapshot(
            addr: alice.mainFid, cashes: [spent],
            bestHeight: 1_000, watermarkHeight: 1_000
        ))

        var served = false
        mock.responder = { call in
            guard call.api == "base.search" else {
                XCTFail("unexpected api: \(call.api)"); return FapiResponse(code: 1)
            }
            if served { return try makeResponse(data: [], bestHeight: 1_010) }
            served = true
            var row = try self.wireRow(spent, owner: alice.mainFid, lastHeight: 1_005)
            row["valid"] = false
            row["spendTxId"] = self.txid(0xD4)
            return try makeResponse(data: [row], bestHeight: 1_010)
        }

        let refreshed = try await alice.wallet.refreshCashes(forFid: alice.mainFid)
        XCTAssertNil(refreshed.cashes.first { $0.id == spent.id })
    }

    // MARK: - bootstrap fallback

    /// Incremental sync failing is routine — a timeout, a server whose
    /// `base.search` contract drifts — and the fallback must not be a
    /// data-loss event.
    func testBootstrapFallbackKeepsFlagsAndLocallyMintedCash() async throws {
        let mock = MockFapiClient()
        let alice = try makeSessions(passwords: ["bootstrap-merge"], fapi: mock)[0]

        var flagged = try cash(owner: alice.mainFid, txidByte: 0xE5, index: 0, value: 700_000)
        flagged.pendingSpend = true

        var minted = try cash(owner: alice.mainFid, txidByte: 0xF6, index: 1, value: 300_000)
        minted.localState = .unknown
        minted.unconfirmedDepth = 2
        minted.birthHeight = nil

        try alice.cashes.save(CashSnapshot(
            addr: alice.mainFid, cashes: [flagged, minted],
            bestHeight: 1_000, watermarkHeight: 1_000
        ))

        mock.responder = { call in
            switch call.api {
            case "base.search":
                // Incremental fails, forcing the bootstrap fallback.
                return FapiResponse(code: 1, message: "search unavailable")
            case "base.cashValid":
                // A full listing that knows nothing about either local
                // fact: the spend is unconfirmed and the minted cash
                // is not indexed.
                return try makeResponse(
                    data: [try self.wireRow(flagged, owner: alice.mainFid)],
                    bestHeight: 1_000
                )
            default:
                XCTFail("unexpected api: \(call.api)"); return FapiResponse(code: 1)
            }
        }

        let snap = try await alice.wallet.refreshCashes(forFid: alice.mainFid)

        let flaggedRow = try XCTUnwrap(snap.cashes.first { $0.id == flagged.id })
        XCTAssertTrue(flaggedRow.pendingSpend, "a full re-listing must not resurrect a spent input")

        let mintedRow = try XCTUnwrap(
            snap.cashes.first { $0.id == minted.id },
            "cash our own broadcast minted must survive a re-listing that predates it"
        )
        XCTAssertEqual(mintedRow.unconfirmedDepth, 2)
        XCTAssertEqual(mintedRow.localState, .unknown)
    }

    /// Purge is still the clean slate — that is its whole job, and
    /// merging must not quietly make it a no-op.
    func testPurgeThenBootstrapReallyStartsFromNothing() async throws {
        let mock = MockFapiClient()
        let alice = try makeSessions(passwords: ["purge-clean"], fapi: mock)[0]

        var flagged = try cash(owner: alice.mainFid, txidByte: 0x17, index: 0, value: 100_000)
        flagged.pendingSpend = true
        var minted = try cash(owner: alice.mainFid, txidByte: 0x28, index: 0, value: 200_000)
        minted.localState = .unknown
        try alice.cashes.save(CashSnapshot(addr: alice.mainFid, cashes: [flagged, minted]))

        mock.responder = { call in
            guard call.api == "base.cashValid" else {
                XCTFail("unexpected api: \(call.api)"); return FapiResponse(code: 1)
            }
            return try makeResponse(
                data: [try self.wireRow(flagged, owner: alice.mainFid)],
                bestHeight: 1_000
            )
        }

        try alice.wallet.purgeCashes(forFid: alice.mainFid)
        let snap = try await alice.wallet.refreshCashes(forFid: alice.mainFid)

        XCTAssertEqual(snap.cashes.count, 1)
        XCTAssertFalse(try XCTUnwrap(snap.cashes.first).pendingSpend)
        XCTAssertNil(snap.cashes.first { $0.id == minted.id })
    }

    // MARK: - depth

    /// A row the index returns without any height is not evidence of a
    /// block, so the unconfirmed ancestry stands.
    func testDepthSurvivesAHeightlessServerRow() async throws {
        let mock = MockFapiClient()
        let alice = try makeSessions(passwords: ["depth-keep"], fapi: mock)[0]

        var minted = try cash(owner: alice.mainFid, txidByte: 0x39, index: 0, value: 400_000)
        minted.localState = .unknown
        minted.unconfirmedDepth = 4
        minted.birthHeight = nil
        try alice.cashes.save(CashSnapshot(
            addr: alice.mainFid, cashes: [minted],
            bestHeight: 1_000, watermarkHeight: 1_000
        ))

        var served = false
        mock.responder = { call in
            guard call.api == "base.search" else {
                XCTFail("unexpected api: \(call.api)"); return FapiResponse(code: 1)
            }
            if served { return try makeResponse(data: [], bestHeight: 1_000) }
            served = true
            let h160 = try FchAddress(fid: alice.mainFid).hash160
            return try makeResponse(data: [[
                "id": minted.id!,
                "owner": alice.mainFid,
                "value": minted.value,
                "type": "P2PKH",
                "birthTxId": minted.birthTxId,
                "birthIndex": minted.birthIndex,
                "valid": true,
                "lockScript": Cash.canonicalP2PKHLockScript(hash160: h160)
            ]], bestHeight: 1_000)
        }

        let snap = try await alice.wallet.refreshCashes(forFid: alice.mainFid)
        XCTAssertEqual(try XCTUnwrap(snap.cashes.first { $0.id == minted.id }).unconfirmedDepth, 4)
    }
}
