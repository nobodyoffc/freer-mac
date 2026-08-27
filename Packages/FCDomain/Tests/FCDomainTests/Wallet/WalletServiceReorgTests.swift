import XCTest
import FCCore
import FCTransport
@testable import FCDomain

/// End-to-end exercise of the reorg pipeline — the Cash pane's
/// Merge / Split, and the explicit-inputs Send it shares machinery
/// with: plan → build → sign every input → broadcast → optimistic
/// cache update. Signing runs for real through ``FCCore.TxHandler``.
///
/// Unlike the ordinary send tests there is deliberately **no**
/// `base.cashValid` round-trip staged: naming the inputs is the whole
/// point, so a snapshot fetch here would mean the code ignored them.
final class WalletServiceReorgTests: XCTestCase {

    private var baseDir: URL!

    override func setUpWithError() throws {
        baseDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("WalletServiceReorgTests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: baseDir, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        if let baseDir { try? FileManager.default.removeItem(at: baseDir) }
    }

    private func makeSessions(passwords pwds: [String], fapi: any FapiCalling) throws -> [ActiveSession] {
        let mgr = try ConfigureManager(baseDirectory: baseDir)
        let configure = try mgr.createConfigure(
            password: Data("reorg-tests".utf8), kdfKind: .legacySha256
        )
        var sessions: [ActiveSession] = []
        for (i, pwd) in pwds.enumerated() {
            let priv = Hash.sha256(Data(pwd.utf8))
            let info = try configure.addMain(privkey: priv, label: "L\(i)")
            sessions.append(try configure.unlockMain(fid: info.fid, fapi: fapi))
        }
        return sessions
    }

    /// A spendable cash for `owner`: canonical P2PKH lockScript and
    /// the protocol-level id, which is what the optimistic post-spend
    /// update matches rows on.
    private func cash(owner: String, txidByte: UInt8, index: Int, value: Int64) throws -> Cash {
        let txid = String(repeating: String(format: "%02x", txidByte), count: 32)
        let h160 = try FchAddress(fid: owner).hash160
        return Cash(
            id: try Cash.makeId(birthTxId: txid, birthIndex: index),
            owner: owner,
            value: value,
            type: "P2PKH",
            birthTxId: txid,
            birthIndex: index,
            lockScript: Cash.canonicalP2PKHLockScript(hash160: h160)
        )
    }

    private func broadcastOnly(_ mock: MockFapiClient) {
        mock.responder = { call in
            switch call.api {
            case "base.broadcastTx":
                return try makeResponse(data: String(repeating: "cd", count: 32))
            default:
                XCTFail("unexpected api: \(call.api)")
                return FapiResponse(code: 1, message: "unexpected")
            }
        }
    }

    // MARK: - consolidate

    func testConsolidateSignsEveryInputAndBroadcastsOnce() async throws {
        let mock = MockFapiClient()
        let alice = try makeSessions(passwords: ["reorg-alice"], fapi: mock)[0]
        broadcastOnly(mock)

        let inputs = try (0..<3).map {
            try cash(owner: alice.mainFid, txidByte: UInt8(0xA0 + $0), index: $0, value: 100_000)
        }
        let result = try await alice.reorganizeFromLive(inputs: inputs, shape: .consolidate)

        // Three inputs in, one bill out, all of it back to alice.
        XCTAssertEqual(result.transaction.inputs.count, 3)
        XCTAssertEqual(result.transaction.outputs.count, 1)
        let expectedSize = CoinSelector.sizeFor(nIn: 3, nOut: 1)
        XCTAssertEqual(result.plan.fee, Int64(expectedSize))
        XCTAssertEqual(result.transaction.outputs[0].value, UInt64(300_000 - Int64(expectedSize)))

        // Output pays alice's own hash160 — a reorg moves no money.
        let h160 = try FchAddress(fid: alice.mainFid).hash160
        let scriptHex = result.transaction.outputs[0].scriptPubKey.bytes
            .map { String(format: "%02x", $0) }.joined()
        XCTAssertEqual(scriptHex, Cash.canonicalP2PKHLockScript(hash160: h160))

        // Every input carries a signature, not just the first.
        for input in result.transaction.inputs {
            XCTAssertGreaterThan(input.scriptSig.bytes.count, 0)
        }

        // No snapshot fetch: the inputs were named.
        XCTAssertEqual(mock.recorded.map(\.api), ["base.broadcastTx"])

        // The broadcast body is exactly the serialized tx.
        let params = try JSONSerialization.jsonObject(
            with: mock.recorded[0].params!
        ) as? [String: Any]
        let expectedHex = result.transaction.serialized
            .map { String(format: "%02x", $0) }.joined()
        XCTAssertEqual(params?["rawTx"] as? String, expectedHex)
    }

    /// Each input's signature must commit to *that* input's value —
    /// BIP-143 puts the previous output's amount in the preimage, so
    /// a loop that reused the first cash's value would produce a tx
    /// every node rejects.
    func testEachInputIsSignedAgainstItsOwnValue() async throws {
        let mock = MockFapiClient()
        let alice = try makeSessions(passwords: ["reorg-sigs"], fapi: mock)[0]
        broadcastOnly(mock)

        let values: [Int64] = [120_000, 45_000, 900_000]
        let inputs = try values.enumerated().map {
            try cash(owner: alice.mainFid, txidByte: UInt8(0xB0 + $0.offset),
                     index: $0.offset, value: $0.element)
        }
        let result = try await alice.reorganizeFromLive(inputs: inputs, shape: .byCount(2))

        let pub = try Secp256k1.publicKey(fromPrivateKey: try alice.mainPrikey())
        let scriptCode = try ScriptBuilder.p2pkhOutput(hash160: Hash.hash160(pub)).bytes
        for (idx, value) in values.enumerated() {
            let sighash = try BchSighash.sighash(
                tx: result.transaction, inputIndex: idx,
                scriptCode: scriptCode, prevValueSats: UInt64(value)
            )
            let bytes = [UInt8](result.transaction.inputs[idx].scriptSig.bytes)
            XCTAssertEqual(bytes[0], 65, "Schnorr+sighash push opcode")
            XCTAssertTrue(try BchSchnorr.verify(
                message: sighash, publicKey: pub, signature: Data(bytes[1..<65])
            ), "input \(idx) signature doesn't verify against its own value")
        }
    }

    // MARK: - split

    func testSplitProducesTheRequestedBills() async throws {
        let mock = MockFapiClient()
        let alice = try makeSessions(passwords: ["reorg-split"], fapi: mock)[0]
        broadcastOnly(mock)

        let inputs = [try cash(owner: alice.mainFid, txidByte: 0xC1, index: 0, value: 1_000_000)]
        let result = try await alice.reorganizeFromLive(
            inputs: inputs, shape: .exact(count: 3, amount: 200_000)
        )

        XCTAssertEqual(result.transaction.outputs.count, 4)  // 3 bills + change
        XCTAssertEqual(result.transaction.outputs.prefix(3).map(\.value),
                       [200_000, 200_000, 200_000])
        // Value is conserved apart from the fee.
        let out = result.transaction.outputs.reduce(UInt64(0)) { $0 + $1.value }
        XCTAssertEqual(Int64(out) + result.plan.fee, 1_000_000)
    }

    // MARK: - optimistic cache update

    func testReorgMarksInputsPendingAndInsertsNewBills() async throws {
        let mock = MockFapiClient()
        let alice = try makeSessions(passwords: ["reorg-cache"], fapi: mock)[0]
        broadcastOnly(mock)

        // Seed the cache with the two cashes we're about to merge, so
        // the optimistic update has rows to flip.
        let inputs = try (0..<2).map {
            try cash(owner: alice.mainFid, txidByte: UInt8(0xD0 + $0), index: $0, value: 250_000)
        }
        try alice.cashes.save(CashSnapshot(addr: alice.mainFid, cashes: inputs))

        let result = try await alice.reorganizeFromLive(inputs: inputs, shape: .consolidate)

        let snap = try XCTUnwrap(try alice.cashes.snapshot(forAddress: alice.mainFid))
        for input in inputs {
            let row = snap.cashes.first { $0.id == input.id }
            XCTAssertTrue(row?.pendingSpend ?? false, "input should be held back from selection")
        }
        // The new bill is there, unconfirmed, keyed by the id the
        // server will independently compute for it.
        let newId = try Cash.makeId(birthTxId: result.remoteTxid, birthIndex: 0)
        let issued = try XCTUnwrap(snap.cashes.first { $0.id == newId })
        XCTAssertEqual(issued.localState, .unknown)
        XCTAssertFalse(issued.pendingSpend)
        XCTAssertEqual(issued.value, result.plan.outputs[0])
    }

    // MARK: - input validation

    func testRefusesACashThatIsAlreadyPendingSpend() async throws {
        let mock = MockFapiClient()
        let alice = try makeSessions(passwords: ["reorg-pending"], fapi: mock)[0]
        broadcastOnly(mock)

        var stuck = try cash(owner: alice.mainFid, txidByte: 0xE1, index: 0, value: 500_000)
        stuck.pendingSpend = true

        do {
            _ = try await alice.reorganizeFromLive(inputs: [stuck], shape: .consolidate)
            XCTFail("expected throw")
        } catch WalletService.Failure.unspendableInput {
            // expected — and nothing was broadcast.
            XCTAssertTrue(mock.recorded.isEmpty)
        }
    }

    /// A cash that doesn't lock to us can't be signed by us. Rejecting
    /// it beats silently dropping it: the plan the user previewed was
    /// priced with that cash in it.
    func testRefusesACashThatDoesNotLockToUs() async throws {
        let mock = MockFapiClient()
        let sessions = try makeSessions(passwords: ["reorg-mine", "reorg-theirs"], fapi: mock)
        let alice = sessions[0]
        let bob = sessions[1]
        broadcastOnly(mock)

        let theirs = try cash(owner: bob.mainFid, txidByte: 0xE2, index: 0, value: 500_000)
        do {
            _ = try await alice.reorganizeFromLive(inputs: [theirs], shape: .consolidate)
            XCTFail("expected throw")
        } catch WalletService.Failure.unspendableInput {
            XCTAssertTrue(mock.recorded.isEmpty)
        }
    }

    // MARK: - explicit-input send

    func testSendWithChosenInputsSpendsExactlyThose() async throws {
        let mock = MockFapiClient()
        let sessions = try makeSessions(passwords: ["fixed-send-a", "fixed-send-b"], fapi: mock)
        let alice = sessions[0]
        let bob = sessions[1]
        broadcastOnly(mock)

        // Two small cashes where coin selection would have taken one:
        // proof that the caller's list wins.
        let inputs = try (0..<2).map {
            try cash(owner: alice.mainFid, txidByte: UInt8(0xF0 + $0), index: $0, value: 300_000)
        }
        let result = try await alice.sendFromLive(
            to: bob.mainFid, amount: 100_000, using: inputs
        )

        XCTAssertEqual(result.transaction.inputs.count, 2)
        XCTAssertEqual(result.plan.selected.map(\.id), inputs.map(\.id))
        XCTAssertEqual(result.transaction.outputs[0].value, 100_000)
        XCTAssertEqual(mock.recorded.map(\.api), ["base.broadcastTx"])
    }

    /// The cold-sign half: a watch-only identity can still say "spend
    /// these", it just can't sign the result.
    func testUnsignedReorgExportsEveryOutputExplicitly() throws {
        let mock = MockFapiClient()
        let alice = try makeSessions(passwords: ["reorg-cold"], fapi: mock)[0]

        let inputs = [try cash(owner: alice.mainFid, txidByte: 0xC9, index: 0, value: 1_000_000)]
        let unsigned = try alice.buildUnsignedReorgFromLive(
            inputs: inputs, shape: .exact(count: 2, amount: 300_000)
        )

        XCTAssertEqual(unsigned.info.sender, alice.mainFid)
        XCTAssertEqual(unsigned.info.changeTo, alice.mainFid)
        XCTAssertEqual(unsigned.info.inputs?.count, 1)
        // Change is written out as an output of its own rather than
        // left for the signer to invent — the previewed shape is the
        // shape that gets signed.
        XCTAssertEqual(unsigned.info.outputs?.count, 3)
        XCTAssertEqual(unsigned.info.outputs?.prefix(2).map(\.value), [300_000, 300_000])
        XCTAssertEqual(unsigned.info.outputs?.allSatisfy { $0.owner == alice.mainFid }, true)
        // Nothing was broadcast, so nothing may be held back.
        XCTAssertTrue(mock.recorded.isEmpty)
    }
}
