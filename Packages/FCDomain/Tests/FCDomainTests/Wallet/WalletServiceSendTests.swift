import XCTest
import FCCore
import FCTransport
@testable import FCDomain

/// End-to-end exercise of the send pipeline: refresh → coin-select →
/// build → sign → broadcast. The mock FAPI client serves the cash
/// listing on `base.cashValid` and accepts the broadcast on
/// `base.broadcastTx`. Signing runs for real through ``FCCore.TxHandler``,
/// so this test also catches regressions in the FCCore tx layer.
final class WalletServiceSendTests: XCTestCase {

    private var baseDir: URL!

    override func setUpWithError() throws {
        baseDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("WalletServiceSendTests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: baseDir, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        if let baseDir { try? FileManager.default.removeItem(at: baseDir) }
    }

    /// Spin up a brand-new Configure under our temp baseDir, mint
    /// `count` main FIDs from fixed-pattern privkeys (so each test
    /// gets stable, predictable FIDs), and return their unlocked
    /// ActiveSessions.
    private func makeSessions(passwords pwds: [String], fapi: any FapiCalling) throws -> [ActiveSession] {
        let mgr = try ConfigureManager(baseDirectory: baseDir)
        let configure = try mgr.createConfigure(
            password: Data("send-tests".utf8), kdfKind: .legacySha256
        )
        var sessions: [ActiveSession] = []
        for (i, pwd) in pwds.enumerated() {
            // Deterministic: hash the password into 32 bytes for a stable privkey-per-test.
            let priv = Hash.sha256(Data(pwd.utf8))
            let info = try configure.addMain(privkey: priv, label: "L\(i)")
            sessions.append(try configure.unlockMain(fid: info.fid, fapi: fapi))
        }
        return sessions
    }

    /// Build a single P2PKH cash JSON object — the wire shape that
    /// `base.cashValid` emits for a Cash entity. Includes a canonical
    /// `lockScript` paying to `owner`'s hash160, because
    /// `WalletService.send` filters by lockScript (not `type`) before
    /// signing. Also includes `id` (the protocol-level cash identifier
    /// computed from `(birthTxId, birthIndex)`) so the optimistic
    /// post-send update can later look the row up by id.
    private func cashDict(owner: String, txid: String, index: Int, value: Int64) throws -> [String: Any] {
        let h160 = try FchAddress(fid: owner).hash160
        return [
            "id": try Cash.makeId(birthTxId: txid, birthIndex: index),
            "owner": owner,
            "value": value,
            "type": "P2PKH",
            "birthTxId": txid,
            "birthIndex": index,
            "lockScript": Cash.canonicalP2PKHLockScript(hash160: h160)
        ]
    }

    // MARK: - happy path

    func testSendFullPipeline() async throws {
        let mock = MockFapiClient()
        let sessions = try makeSessions(passwords: ["alice-secret", "bob-secret"], fapi: mock)
        let alice = sessions[0]
        let bob = sessions[1]

        // Now wire the mock with the live FIDs.
        mock.responder = { call in
            switch call.api {
            case "base.cashValid":
                return try makeResponse(data: [try self.cashDict(
                    owner: alice.mainFid,
                    txid: String(repeating: "ab", count: 32),
                    index: 0,
                    value: 1_000_000
                )])
            case "base.broadcastTx":
                let params = try JSONSerialization.jsonObject(with: call.params!) as? [String: Any]
                let rawHex = params?["rawTx"] as? String ?? ""
                return try makeResponse(data: "echo-\(rawHex.prefix(16))")
            default:
                XCTFail("unexpected api: \(call.api)")
                return FapiResponse(code: 1, message: "unexpected")
            }
        }

        let result = try await alice.sendFromLive(
            to: bob.mainFid, amount: 100_000, feePerByte: 1
        )

        // 1 input, 2 outputs (recipient + change to alice).
        // Fee math (Schnorr P2PKH input = 141 B, P2PKH output = 34 B,
        // tx overhead = 10 B): 10 + 141 + 34*2 = 219 B at 1 sat/B = 219.
        XCTAssertEqual(result.transaction.inputs.count, 1)
        XCTAssertEqual(result.transaction.outputs.count, 2)
        XCTAssertEqual(result.transaction.outputs[0].value, 100_000)
        // Change = 1_000_000 - 100_000 - 219 = 899_781.
        XCTAssertEqual(result.transaction.outputs[1].value, 899_781)
        XCTAssertEqual(result.plan.fee, 219)

        // Input is signed: scriptSig non-empty.
        XCTAssertGreaterThan(result.transaction.inputs[0].scriptSig.bytes.count, 0)

        // remoteTxid was returned by the mock broadcaster.
        XCTAssertTrue(result.remoteTxid.hasPrefix("echo-"))

        // Mock saw exactly two FAPI calls in the right order.
        XCTAssertEqual(mock.recorded.map { $0.api }, ["base.cashValid", "base.broadcastTx"])

        // Signed tx verifies as a BCH-Schnorr signature against the
        // recomputed sighash. (FCH mainnet rejects ECDSA on P2PKH;
        // see TxHandler.swift for the network rule.)
        let signed = result.transaction
        let pub = try Secp256k1.publicKey(fromPrivateKey: try alice.mainPrikey())
        let pubHash = Hash.hash160(pub)
        let scriptCode = try ScriptBuilder.p2pkhOutput(hash160: pubHash).bytes
        let sighash = try BchSighash.sighash(
            tx: signed, inputIndex: 0,
            scriptCode: scriptCode, prevValueSats: 1_000_000
        )
        let scriptBytes = [UInt8](signed.inputs[0].scriptSig.bytes)
        XCTAssertEqual(scriptBytes[0], 65, "Schnorr+sighash push opcode")
        let schnorrSig = Data(scriptBytes[1..<65])
        XCTAssertTrue(try BchSchnorr.verify(
            message: sighash, publicKey: pub, signature: schnorrSig
        ))
    }

    // MARK: - rawTx wire format ground truth

    func testRawTxIsExactlyTheSerializedBytes() async throws {
        let mock = MockFapiClient()
        let sessions = try makeSessions(passwords: ["rawtx-a", "rawtx-b"], fapi: mock)
        let alice = sessions[0]
        let bob = sessions[1]

        mock.responder = { call in
            switch call.api {
            case "base.cashValid":
                return try makeResponse(data: [try self.cashDict(
                    owner: alice.mainFid,
                    txid: String(repeating: "ab", count: 32),
                    index: 0,
                    value: 500_000
                )])
            case "base.broadcastTx":
                let params = try JSONSerialization.jsonObject(with: call.params!) as? [String: Any]
                let rawHex = params?["rawTx"] as? String ?? ""
                return try makeResponse(data: "echo-\(rawHex.prefix(16))")
            default:
                XCTFail("unexpected api: \(call.api)"); return FapiResponse(code: 1)
            }
        }

        let result = try await alice.sendFromLive(to: bob.mainFid, amount: 50_000)

        let bcastCall = mock.recorded.last { $0.api == "base.broadcastTx" }!
        let bcastParams = try JSONSerialization.jsonObject(with: bcastCall.params!) as? [String: Any]
        let rawTxHex = bcastParams?["rawTx"] as? String ?? ""
        let expected = result.transaction.serialized.map { String(format: "%02x", $0) }.joined()
        XCTAssertEqual(rawTxHex, expected)
    }

    // MARK: - error surfacing

    func testSendThrowsOnInsufficientFunds() async throws {
        let mock = MockFapiClient()
        let sessions = try makeSessions(passwords: ["broke", "broke-b"], fapi: mock)
        let alice = sessions[0]
        let bob = sessions[1]

        mock.responder = { call in
            switch call.api {
            case "base.cashValid":
                return try makeResponse(data: [try self.cashDict(
                    owner: alice.mainFid,
                    txid: String(repeating: "ab", count: 32),
                    index: 0,
                    value: 100      // way too small
                )])
            default:
                XCTFail("unexpected api: \(call.api)"); return FapiResponse(code: 1)
            }
        }

        do {
            _ = try await alice.sendFromLive(to: bob.mainFid, amount: 1_000_000)
            XCTFail("expected throw")
        } catch CoinSelector.Failure.insufficientFunds {
            // expected
        } catch {
            XCTFail("wrong error: \(error)")
        }
    }

    func testSendUsesCacheWhenRequested() async throws {
        let mock = MockFapiClient()
        let sessions = try makeSessions(passwords: ["cache-a", "cache-b"], fapi: mock)
        let alice = sessions[0]
        let bob = sessions[1]

        // Pre-populate cache so refresh is unnecessary. The cached
        // Cash needs a real lockScript — WalletService.send filters
        // by lockScript, not the (unreliable) `type` label.
        let aliceH160 = try FchAddress(fid: alice.mainFid).hash160
        try alice.cashes.save(CashSnapshot(addr: alice.mainFid, cashes: [
            Cash(
                owner: alice.mainFid,
                value: 500_000,
                type: "P2PKH",
                birthTxId: String(repeating: "cd", count: 32),
                birthIndex: 0,
                lockScript: Cash.canonicalP2PKHLockScript(hash160: aliceH160)
            )
        ]))

        // The mock will fail on base.cashValid because we only mock
        // base.broadcastTx — proving cache short-circuits the refresh.
        mock.responder = { call in
            if call.api == "base.broadcastTx" {
                return try makeResponse(data: "ok-cached")
            }
            XCTFail("unexpected api when useCache=true: \(call.api)")
            return FapiResponse(code: 1)
        }
        let result = try await alice.sendFromLive(
            to: bob.mainFid, amount: 50_000, useCache: true
        )
        XCTAssertEqual(result.remoteTxid, "ok-cached")
        XCTAssertEqual(mock.recorded.count, 1)  // only the broadcast
    }

    func testSendThrowsOnBroadcastError() async throws {
        let mock = MockFapiClient()
        let sessions = try makeSessions(passwords: ["bcast-err-a", "bcast-err-b"], fapi: mock)
        let alice = sessions[0]
        let bob = sessions[1]

        mock.responder = { call in
            switch call.api {
            case "base.cashValid":
                return try makeResponse(data: [try self.cashDict(
                    owner: alice.mainFid,
                    txid: String(repeating: "ee", count: 32),
                    index: 0,
                    value: 1_000_000
                )])
            case "base.broadcastTx":
                return FapiResponse(code: 500, message: "node down")
            default:
                return FapiResponse(code: 1)
            }
        }

        do {
            _ = try await alice.sendFromLive(to: bob.mainFid, amount: 100_000)
            XCTFail("expected throw")
        } catch let WalletService.Failure.fapiNonZeroCode(api, code, message) {
            XCTAssertEqual(api, "base.broadcastTx")
            XCTAssertEqual(code, 500)
            XCTAssertEqual(message, "node down")
        }
    }

    // MARK: - non-standard cash types are rejected

    func testSendRejectsNonStandardCashTypes() async throws {
        let mock = MockFapiClient()
        let sessions = try makeSessions(passwords: ["cltv-a", "cltv-b"], fapi: mock)
        let alice = sessions[0]
        let bob = sessions[1]

        // Server returns a single P2SH-CLTV cash. The send path should
        // refuse rather than try to sign with the P2PKH path.
        mock.responder = { call in
            if call.api == "base.cashValid" {
                return try makeResponse(data: [[
                    "owner": alice.mainFid,
                    "value": 1_000_000,
                    "type": "P2SH_CLTV",
                    "birthTxId": String(repeating: "ab", count: 32),
                    "birthIndex": 0,
                    "redeemScript": "0011",
                    "lockTime": 800_000
                ]])
            }
            XCTFail("unexpected api: \(call.api)"); return FapiResponse(code: 1)
        }

        do {
            _ = try await alice.sendFromLive(to: bob.mainFid, amount: 1_000)
            XCTFail("expected throw")
        } catch WalletService.Failure.unsupportedCashType {
            // expected
        } catch {
            XCTFail("wrong error: \(error)")
        }
    }

    /// Regression for the live-server bug where the FAPI
    /// `base.cashValid` mode-2 path returned a cash whose `type` was
    /// nil (Java `Cash.fromUtxo` doesn't set type) but whose actual
    /// `lockScript` was a P2SH-multisig template. The earlier
    /// `type ?? "P2PKH"` filter let it through and the broadcast
    /// failed with `mandatory-script-verify-flag-failed
    /// (Signature cannot be 65 bytes in CHECKMULTISIG)`. Now we
    /// validate against the lockScript and reject up-front.
    func testSendRejectsNullTypeButMultisigLockScript() async throws {
        let mock = MockFapiClient()
        let sessions = try makeSessions(passwords: ["null-type-a", "null-type-b"], fapi: mock)
        let alice = sessions[0]
        let bob = sessions[1]

        mock.responder = { call in
            if call.api == "base.cashValid" {
                // No `type` field. lockScript starts with OP_2 / OP_3
                // and contains OP_CHECKMULTISIG (0xae) — a 2-of-3
                // multisig template. Old filter would pass this
                // through; new filter rejects it because the
                // lockScript ≠ canonical P2PKH-to-alice-hash160.
                return try makeResponse(data: [[
                    "owner": alice.mainFid,
                    "value": 1_000_000,
                    "birthTxId": String(repeating: "ab", count: 32),
                    "birthIndex": 0,
                    "lockScript": "5221" + String(repeating: "00", count: 33)
                                + "21" + String(repeating: "11", count: 33)
                                + "21" + String(repeating: "22", count: 33)
                                + "53ae"
                ]])
            }
            XCTFail("unexpected api: \(call.api)"); return FapiResponse(code: 1)
        }

        do {
            _ = try await alice.sendFromLive(to: bob.mainFid, amount: 1_000)
            XCTFail("expected throw")
        } catch WalletService.Failure.unsupportedCashType {
            // expected — broadcast never happens
        } catch {
            XCTFail("wrong error: \(error)")
        }
        // Critically: only ONE FAPI call, the cashValid; no broadcast.
        XCTAssertEqual(mock.recorded.map { $0.api }, ["base.cashValid"])
    }

    // MARK: - post-send optimistic cache update

    /// After a successful broadcast, the on-disk cache must reflect:
    ///   1. each spent input is marked `pendingSpend = true` (kept in
    ///      the cache so manual recovery can restore it)
    ///   2. each change output appears as a new `.unknown` cash that
    ///      is spendable (no `pendingSpend`) and has a pre-computed id
    ///      matching `Cash.makeId(birthTxId: remoteTxid, birthIndex: i)`
    ///
    /// This is what makes the live Send pipeline feel instant: the
    /// next refresh will reconcile via the server delta, but until
    /// then the wallet correctly shows the new balance and won't
    /// double-spend.
    func testSendOptimisticallyUpdatesCache() async throws {
        let mock = MockFapiClient()
        let sessions = try makeSessions(passwords: ["opt-a", "opt-b"], fapi: mock)
        let alice = sessions[0]
        let bob = sessions[1]
        let inputTxid = String(repeating: "ab", count: 32)

        mock.responder = { call in
            switch call.api {
            case "base.cashValid":
                return try makeResponse(data: [try self.cashDict(
                    owner: alice.mainFid, txid: inputTxid, index: 0,
                    value: 1_000_000
                )])
            case "base.broadcastTx":
                return try makeResponse(data: "echo-ok")
            default:
                XCTFail("unexpected api: \(call.api)")
                return FapiResponse(code: 1)
            }
        }

        let result = try await alice.sendFromLive(
            to: bob.mainFid, amount: 100_000, feePerByte: 1
        )

        let cached = try alice.cashes.snapshot(forAddress: alice.mainFid)
        XCTAssertNotNil(cached)
        // The original input should still be in the cache, but flagged.
        let original = cached?.cashes.first(where: { $0.birthTxId == inputTxid && $0.birthIndex == 0 })
        XCTAssertNotNil(original)
        XCTAssertTrue(original?.pendingSpend ?? false,
                      "spent input must be marked pendingSpend, not removed")

        // The change output (output[1] of the signed tx, paying back
        // to alice) should appear as a fresh `.unknown` row with the
        // pre-computed cash id.
        let txidDisplay = result.transaction.txidDisplay
        let changeCashId = try Cash.makeId(birthTxId: txidDisplay, birthIndex: 1)
        let change = cached?.cashes.first { $0.id == changeCashId }
        XCTAssertNotNil(change, "change cash must be cached with pre-computed id")
        XCTAssertEqual(change?.localState, .unknown)
        XCTAssertFalse(change?.pendingSpend ?? true,
                       "change cash is spendable, not pending-spent")
        XCTAssertEqual(change?.value, 899_781,
                       "change == 1_000_000 - 100_000 - 219 fee")
    }

    // MARK: - manual recover

    /// `recoverPendingSpend(cashId:forFid:)` un-marks a previously
    /// pendingSpend row, making the cash spendable again. Used when
    /// a Send tx never confirms (mempool eviction, network drop).
    func testRecoverPendingSpendUnmarksRow() async throws {
        let mock = MockFapiClient()
        let sessions = try makeSessions(passwords: ["rec-a", "rec-b"], fapi: mock)
        let alice = sessions[0]
        let bob = sessions[1]
        let inputTxid = String(repeating: "ab", count: 32)

        mock.responder = { call in
            switch call.api {
            case "base.cashValid":
                return try makeResponse(data: [try self.cashDict(
                    owner: alice.mainFid, txid: inputTxid, index: 0,
                    value: 1_000_000
                )])
            case "base.broadcastTx":
                return try makeResponse(data: "echo-rec")
            default:
                XCTFail("unexpected api: \(call.api)")
                return FapiResponse(code: 1)
            }
        }

        // Send to flag the input.
        _ = try await alice.sendFromLive(
            to: bob.mainFid, amount: 100_000, feePerByte: 1
        )
        var cached = try alice.cashes.snapshot(forAddress: alice.mainFid)
        let inputId = try Cash.makeId(birthTxId: inputTxid, birthIndex: 0)
        XCTAssertTrue(cached?.cashes.first(where: { $0.id == inputId })?.pendingSpend ?? false)

        // Recover.
        let didChange = try alice.wallet.recoverPendingSpend(
            cashId: inputId, forFid: alice.mainFid
        )
        XCTAssertTrue(didChange)

        cached = try alice.cashes.snapshot(forAddress: alice.mainFid)
        XCTAssertFalse(cached?.cashes.first(where: { $0.id == inputId })?.pendingSpend ?? true)

        // Idempotent: second call returns false (no change).
        XCTAssertFalse(try alice.wallet.recoverPendingSpend(
            cashId: inputId, forFid: alice.mainFid
        ))
    }

    // MARK: - watch-only refusal

    func testWatchOnlyLiveFidCannotSend() async throws {
        let mock = MockFapiClient()
        let sessions = try makeSessions(passwords: ["watch-test"], fapi: mock)
        let alice = sessions[0]

        // Add a watch-only sub-identity, switch to it, expect refusal.
        let priv = Data(repeating: 0x55, count: 32)
        let pub = try Secp256k1.publicKey(fromPrivateKey: priv)
        let watchedFid = try FchAddress(publicKey: pub).fid
        _ = try alice.addWatchedFid(watchedFid, label: "watch-only friend")
        try alice.switchLive(fid: watchedFid)
        XCTAssertFalse(alice.canSign)

        do {
            _ = try await alice.sendFromLive(to: alice.mainFid, amount: 1_000)
            XCTFail("expected throw")
        } catch ActiveSession.Failure.watchOnlyCannotSign {
            // expected
        } catch {
            XCTFail("wrong error: \(error)")
        }
    }
}
