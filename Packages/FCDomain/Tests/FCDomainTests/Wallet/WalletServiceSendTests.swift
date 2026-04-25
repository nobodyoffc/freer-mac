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

    private func makeIdentity(passphrase: String) throws -> Identity {
        let vault = try IdentityVault(baseDirectory: baseDir)
        return try vault.register(
            passphrase: passphrase,
            displayName: "T",
            scheme: .legacySha256
        )
    }

    /// Wires the mock so `base.getUtxo` returns a single UTXO worth
    /// `value` sat for `addr`, and `base.broadcastTx` echoes back
    /// the txid of whatever was submitted.
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
                // Decode rawTx back into a Transaction, return its txid
                // so the test can assert remote/local agreement.
                let params = try JSONSerialization.jsonObject(with: call.params!) as? [String: Any]
                let rawHex = params?["rawTx"] as? String ?? ""
                // Just hand back a synthetic confirmation txid here —
                // we only verify shape, not chain validity.
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
        let alice = try makeIdentity(passphrase: "alice-secret")
        let bob = try makeIdentity(passphrase: "bob-secret")

        let mock = mockReturning(utxo: alice.fid, value: 1_000_000)
        let svc = WalletService(fapi: mock)

        let result = try await svc.send(
            from: alice, to: bob.fid, amount: 100_000, feePerByte: 1
        )

        // Expect 1 input, 2 outputs (recipient + change to alice).
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

        // The mock saw exactly two FAPI calls in the right order.
        XCTAssertEqual(mock.recorded.map { $0.api }, ["base.getUtxo", "base.broadcastTx"])

        // Signed tx verifies via FCCore's secp256k1 wrapper.
        let signed = result.transaction
        let pub = try Secp256k1.publicKey(fromPrivateKey: try alice.privateKey())
        let pubHash = Hash.hash160(pub)
        let scriptCode = try ScriptBuilder.p2pkhOutput(hash160: pubHash).bytes
        let sighash = try BchSighash.sighash(
            tx: signed, inputIndex: 0,
            scriptCode: scriptCode, prevValueSats: 1_000_000
        )
        // Pull the DER signature out of the scriptSig: first push.
        let scriptBytes = [UInt8](signed.inputs[0].scriptSig.bytes)
        let sigLen = Int(scriptBytes[0])
        // DER sig + 1B sighash flag.
        let derSig = Data(scriptBytes[1..<(1 + sigLen - 1)])
        XCTAssertTrue(try Secp256k1.verifySighashSig(
            publicKey: pub, sighash: sighash, signatureDER: derSig
        ))
    }

    // MARK: - rawTx wire format ground truth

    func testRawTxIsExactlyTheSerializedBytes() async throws {
        // What the server gets in `params.rawTx` MUST equal
        // `transaction.serialized.hex` byte-for-byte. The mock
        // captures the params; we compare.
        let alice = try makeIdentity(passphrase: "rawtx")
        let bob = try makeIdentity(passphrase: "rawtx-bob")

        let mock = mockReturning(utxo: alice.fid, value: 500_000)
        let svc = WalletService(fapi: mock)

        let result = try await svc.send(from: alice, to: bob.fid, amount: 50_000)

        let bcastCall = mock.recorded.last { $0.api == "base.broadcastTx" }!
        let bcastParams = try JSONSerialization.jsonObject(with: bcastCall.params!) as? [String: Any]
        let rawTxHex = bcastParams?["rawTx"] as? String ?? ""
        let expected = result.transaction.serialized.map { String(format: "%02x", $0) }.joined()
        XCTAssertEqual(rawTxHex, expected)
    }

    // MARK: - error surfacing

    func testSendThrowsOnInsufficientFunds() async throws {
        let alice = try makeIdentity(passphrase: "broke")
        let bob = try makeIdentity(passphrase: "broke-bob")

        let mock = mockReturning(utxo: alice.fid, value: 100)  // way too small
        let svc = WalletService(fapi: mock)

        do {
            _ = try await svc.send(from: alice, to: bob.fid, amount: 1_000_000)
            XCTFail("expected throw")
        } catch CoinSelector.Failure.insufficientFunds {
            // expected
        } catch {
            XCTFail("wrong error: \(error)")
        }
    }

    func testSendUsesCacheWhenRequested() async throws {
        let alice = try makeIdentity(passphrase: "cache-test")
        let bob = try makeIdentity(passphrase: "cache-test-bob")

        let utxosStore = try UtxosStore(alice)
        try utxosStore.save(UtxoSnapshot(addr: alice.fid, utxos: [
            Utxo(addr: alice.fid,
                 txid: String(repeating: "cd", count: 32),
                 index: 0,
                 value: 500_000)
        ]))

        // The mock will fail on base.getUtxo because we only mock
        // base.broadcastTx — proving cache short-circuits the refresh.
        let mock = MockFapiClient()
        mock.responder = { call in
            if call.api == "base.broadcastTx" {
                return try makeResponse(data: "ok-cached")
            }
            XCTFail("unexpected api when useCache=true: \(call.api)")
            return FapiResponse(code: 1)
        }
        let svc = WalletService(fapi: mock, utxos: utxosStore)
        let result = try await svc.send(
            from: alice, to: bob.fid, amount: 50_000,
            useCache: true
        )
        XCTAssertEqual(result.remoteTxid, "ok-cached")
        XCTAssertEqual(mock.recorded.count, 1)  // only the broadcast
    }

    func testSendThrowsOnBroadcastError() async throws {
        let alice = try makeIdentity(passphrase: "broadcast-err")
        let bob = try makeIdentity(passphrase: "broadcast-err-bob")

        let mock = MockFapiClient()
        mock.responder = { call in
            switch call.api {
            case "base.getUtxo":
                return try makeResponse(data: [[
                    "addr": alice.fid,
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
        let svc = WalletService(fapi: mock)

        do {
            _ = try await svc.send(from: alice, to: bob.fid, amount: 100_000)
            XCTFail("expected throw")
        } catch let WalletService.Failure.fapiNonZeroCode(api, code, message) {
            XCTAssertEqual(api, "base.broadcastTx")
            XCTAssertEqual(code, 500)
            XCTAssertEqual(message, "node down")
        }
    }
}
