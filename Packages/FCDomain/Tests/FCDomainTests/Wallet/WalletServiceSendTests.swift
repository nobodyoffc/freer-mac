import XCTest
import FCCore
import FCTransport
@testable import FCDomain

/// End-to-end exercise of the send pipeline: refresh → coin-select →
/// build → sign → broadcast. The mock FAPI client serves the UTXO
/// listing on `base.getUtxo` and accepts the broadcast on
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

    /// Mock that serves `base.getUtxo` (one UTXO worth `value`) for
    /// `addr` and echoes back `base.broadcastTx`.
    private func mockReturning(utxo addr: String, value: Int64) -> MockFapiClient {
        let mock = MockFapiClient()
        mock.responder = { call in
            switch call.api {
            case "base.getUtxo":
                return try makeResponse(data: [[
                    "addr": addr,
                    "txId": String(repeating: "ab", count: 32),
                    "index": 0,
                    "amount": Double(value) / Double(Utxo.satoshisPerBch)
                ]])
            case "base.broadcastTx":
                let params = try JSONSerialization.jsonObject(with: call.params!) as? [String: Any]
                let rawHex = params?["rawTx"] as? String ?? ""
                return try makeResponse(data: "echo-\(rawHex.prefix(16))")
            default:
                XCTFail("unexpected api: \(call.api)")
                return FapiResponse(code: 1, message: "unexpected")
            }
        }
        return mock
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
            case "base.getUtxo":
                return try makeResponse(data: [[
                    "addr": alice.mainFid,
                    "txId": String(repeating: "ab", count: 32),
                    "index": 0,
                    "amount": Double(1_000_000) / Double(Utxo.satoshisPerBch)
                ]])
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
        XCTAssertEqual(result.transaction.inputs.count, 1)
        XCTAssertEqual(result.transaction.outputs.count, 2)
        XCTAssertEqual(result.transaction.outputs[0].value, 100_000)
        // Change = 1_000_000 - 100_000 - 226 (fee) = 899_774.
        XCTAssertEqual(result.transaction.outputs[1].value, 899_774)
        XCTAssertEqual(result.plan.fee, 226)

        // Input is signed: scriptSig non-empty.
        XCTAssertGreaterThan(result.transaction.inputs[0].scriptSig.bytes.count, 0)

        // remoteTxid was returned by the mock broadcaster.
        XCTAssertTrue(result.remoteTxid.hasPrefix("echo-"))

        // Mock saw exactly two FAPI calls in the right order.
        XCTAssertEqual(mock.recorded.map { $0.api }, ["base.getUtxo", "base.broadcastTx"])

        // Signed tx verifies via FCCore's secp256k1 wrapper.
        let signed = result.transaction
        let pub = try Secp256k1.publicKey(fromPrivateKey: try alice.mainPrikey())
        let pubHash = Hash.hash160(pub)
        let scriptCode = try ScriptBuilder.p2pkhOutput(hash160: pubHash).bytes
        let sighash = try BchSighash.sighash(
            tx: signed, inputIndex: 0,
            scriptCode: scriptCode, prevValueSats: 1_000_000
        )
        let scriptBytes = [UInt8](signed.inputs[0].scriptSig.bytes)
        let sigLen = Int(scriptBytes[0])
        let derSig = Data(scriptBytes[1..<(1 + sigLen - 1)])
        XCTAssertTrue(try Secp256k1.verifySighashSig(
            publicKey: pub, sighash: sighash, signatureDER: derSig
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
            case "base.getUtxo":
                return try makeResponse(data: [[
                    "addr": alice.mainFid,
                    "txId": String(repeating: "ab", count: 32),
                    "index": 0,
                    "amount": Double(500_000) / Double(Utxo.satoshisPerBch)
                ]])
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
            case "base.getUtxo":
                return try makeResponse(data: [[
                    "addr": alice.mainFid,
                    "txId": String(repeating: "ab", count: 32),
                    "index": 0,
                    "amount": Double(100) / Double(Utxo.satoshisPerBch)  // way too small
                ]])
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

        // Pre-populate cache so refresh is unnecessary.
        try alice.utxos.save(UtxoSnapshot(addr: alice.mainFid, utxos: [
            Utxo(addr: alice.mainFid,
                 txid: String(repeating: "cd", count: 32),
                 index: 0,
                 value: 500_000)
        ]))

        // The mock will fail on base.getUtxo because we only mock
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
            case "base.getUtxo":
                return try makeResponse(data: [[
                    "addr": alice.mainFid,
                    "txId": String(repeating: "ee", count: 32),
                    "index": 0,
                    "amount": 0.01
                ]])
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
