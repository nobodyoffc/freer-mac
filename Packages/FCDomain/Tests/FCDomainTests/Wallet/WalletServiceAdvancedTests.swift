import XCTest
import FCCore
import FCTransport
@testable import FCDomain

/// The composed-transaction path end to end — the Compose pane's
/// engine: price → build → sign → broadcast → optimistic cache update,
/// with signing running for real through ``FCCore/TxHandler``.
///
/// Nothing is selected here. The inputs in the document are the
/// instruction, so a snapshot fetch would mean the code ignored them —
/// which is why the recorded API calls are asserted, not just the
/// result.
final class WalletServiceAdvancedTests: XCTestCase {

    private var baseDir: URL!

    override func setUpWithError() throws {
        baseDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("WalletServiceAdvancedTests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: baseDir, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        if let baseDir { try? FileManager.default.removeItem(at: baseDir) }
    }

    private func makeSession(_ password: String, fapi: any FapiCalling) throws -> ActiveSession {
        let mgr = try ConfigureManager(baseDirectory: baseDir)
        let configure = try mgr.createConfigure(
            password: Data("advanced-tests".utf8), kdfKind: .legacySha256
        )
        let info = try configure.addMain(privkey: Hash.sha256(Data(password.utf8)), label: "L")
        return try configure.unlockMain(fid: info.fid, fapi: fapi)
    }

    private func cash(owner: String, txidByte: UInt8, index: Int, value: Int64) throws -> Cash {
        let txid = String(repeating: String(format: "%02x", txidByte), count: 32)
        return Cash(
            id: try Cash.makeId(birthTxId: txid, birthIndex: index),
            owner: owner,
            value: value,
            type: "P2PKH",
            birthTxId: txid,
            birthIndex: index,
            lockScript: Cash.canonicalP2PKHLockScript(hash160: try FchAddress(fid: owner).hash160)
        )
    }

    private func broadcastOnly(_ mock: MockFapiClient) {
        mock.responder = { call in
            switch call.api {
            case "base.broadcastTx":
                return try makeResponse(data: String(repeating: "ef", count: 32))
            default:
                XCTFail("unexpected api: \(call.api)")
                return FapiResponse(code: 1, message: "unexpected")
            }
        }
    }

    private let payee = "FUqvgtMU7YT2TbVXH3G39heb4C7QvpgJag"

    private func document(
        from session: ActiveSession, inputs: [Cash], outputs: [RawTxInfo.Slot],
        opReturn: String? = nil
    ) -> RawTxInfo {
        RawTxInfo(
            sender: session.liveFid,
            feeRate: TxFee.defaultFeeRate,
            inputs: inputs.map(RawTxInfo.Slot.input(from:)),
            outputs: outputs,
            opReturn: opReturn,
            changeTo: session.liveFid
        )
    }

    // MARK: - send

    func testComposedSendSpendsExactlyTheNamedInputs() async throws {
        let mock = MockFapiClient()
        let alice = try makeSession("compose-a", fapi: mock)
        broadcastOnly(mock)

        let inputs = try (0..<2).map {
            try cash(owner: alice.liveFid, txidByte: UInt8(0xA0 + $0), index: $0, value: 500_000)
        }
        let info = document(
            from: alice, inputs: inputs,
            outputs: [.output(to: payee, amount: 100_000), .output(to: payee, amount: 200_000)]
        )

        let result = try await alice.sendAdvancedFromLive(info: info, inputCashes: inputs)

        XCTAssertEqual(result.transaction.inputs.count, 2)
        // Two payments plus change.
        XCTAssertEqual(result.transaction.outputs.count, 3)
        XCTAssertEqual(result.transaction.outputs[0].value, 100_000)
        XCTAssertEqual(result.transaction.outputs[1].value, 200_000)
        for input in result.transaction.inputs {
            XCTAssertFalse(input.scriptSig.bytes.isEmpty, "every input must be signed")
        }
        // No snapshot fetch — the inputs were named.
        XCTAssertEqual(mock.recorded.map(\.api), ["base.broadcastTx"])
    }

    func testComposedSendCarvesTheMessageAsWell() async throws {
        let mock = MockFapiClient()
        let alice = try makeSession("compose-msg", fapi: mock)
        broadcastOnly(mock)

        let inputs = [try cash(owner: alice.liveFid, txidByte: 0xB1, index: 0, value: 1_000_000)]
        let info = document(
            from: alice, inputs: inputs,
            outputs: [.output(to: payee, amount: 100_000)],
            opReturn: "paid in full"
        )
        let result = try await alice.sendAdvancedFromLive(info: info, inputCashes: inputs)

        let opReturn = try XCTUnwrap(result.transaction.outputs.last)
        XCTAssertEqual(opReturn.value, 0)
        XCTAssertEqual(opReturn.scriptPubKey.bytes.first, 0x6A)
        XCTAssertTrue(
            String(decoding: opReturn.scriptPubKey.bytes, as: UTF8.self).contains("paid in full")
        )
    }

    /// A time-locked payment: the coins land at a P2SH address the
    /// payee cannot touch yet, and the redeem script goes on chain in
    /// the same transaction so they can reconstruct it when the lock
    /// expires.
    func testTimeLockedPaymentPublishesItsRedeemScript() async throws {
        let mock = MockFapiClient()
        let alice = try makeSession("compose-lock", fapi: mock)
        broadcastOnly(mock)

        let inputs = [try cash(owner: alice.liveFid, txidByte: 0xC1, index: 0, value: 1_000_000)]
        let locked = try RawTxInfo.Slot.lockedOutput(
            to: payee, amount: 100_000, lockTime: 900_000
        )
        let info = document(from: alice, inputs: inputs, outputs: [locked])
        let result = try await alice.sendAdvancedFromLive(info: info, inputCashes: inputs)

        let p2sh = try P2sh(redeemScriptHex: XCTUnwrap(locked.redeemScript))
        XCTAssertEqual(result.transaction.outputs[0].scriptPubKey, p2sh.outputScript)

        let manifest = String(
            decoding: try XCTUnwrap(result.transaction.outputs.last).scriptPubKey.bytes,
            as: UTF8.self
        )
        XCTAssertTrue(manifest.contains(p2sh.redeemScriptHex))

        // Creating a lock does not lock the transaction itself — only
        // *spending* one does.
        XCTAssertEqual(result.transaction.locktime, 0)
    }

    func testStillLockedInputIsRefusedBeforeAnythingIsBroadcast() async throws {
        let mock = MockFapiClient()
        let alice = try makeSession("compose-locked-in", fapi: mock)
        broadcastOnly(mock)

        let p2sh = try P2sh(fid: alice.liveFid, lockTime: 900_000)
        var input = try cash(owner: alice.liveFid, txidByte: 0xD1, index: 0, value: 1_000_000)
        input.lockTime = 900_000
        input.redeemScript = p2sh.redeemScriptHex
        let info = document(
            from: alice, inputs: [input], outputs: [.output(to: payee, amount: 100_000)]
        )

        do {
            _ = try await alice.sendAdvancedFromLive(
                info: info, inputCashes: [input], bestHeight: 899_999
            )
            XCTFail("a locked input must not be spendable")
        } catch {
            guard case AdvancedTxBuilder.Failure.lockedInput = error else {
                return XCTFail("expected lockedInput, got \(error)")
            }
        }
        XCTAssertTrue(mock.recorded.isEmpty, "nothing should have been broadcast")
    }

    /// A refused or failed send must give the cashes back. Otherwise a
    /// declined confirmation costs the user the use of their money
    /// until the next sync.
    func testAFailedSendReleasesTheClaimedInputs() async throws {
        let mock = MockFapiClient()
        let alice = try makeSession("compose-release", fapi: mock)
        mock.responder = { _ in FapiResponse(code: 1, message: "nope") }

        let inputs = [try cash(owner: alice.liveFid, txidByte: 0xE1, index: 0, value: 1_000_000)]
        try alice.cashes.save(CashSnapshot(addr: alice.liveFid, cashes: inputs))
        let info = document(
            from: alice, inputs: inputs, outputs: [.output(to: payee, amount: 100_000)]
        )

        do {
            _ = try await alice.sendAdvancedFromLive(info: info, inputCashes: inputs)
            XCTFail("the broadcast was rejected")
        } catch {}

        let snap = try XCTUnwrap(try alice.cashes.snapshot(forAddress: alice.liveFid))
        XCTAssertEqual(snap.cashes.filter(\.pendingSpend).count, 0)
    }

    func testSuccessfulSendMarksInputsPendingAndMintsChange() async throws {
        let mock = MockFapiClient()
        let alice = try makeSession("compose-cache", fapi: mock)
        broadcastOnly(mock)

        let inputs = [try cash(owner: alice.liveFid, txidByte: 0xF1, index: 0, value: 1_000_000)]
        try alice.cashes.save(CashSnapshot(addr: alice.liveFid, cashes: inputs))
        let info = document(
            from: alice, inputs: inputs, outputs: [.output(to: payee, amount: 100_000)]
        )
        _ = try await alice.sendAdvancedFromLive(info: info, inputCashes: inputs)

        let snap = try XCTUnwrap(try alice.cashes.snapshot(forAddress: alice.liveFid))
        XCTAssertEqual(snap.cashes.filter(\.pendingSpend).count, 1)
        // The change cash is ours, unconfirmed, and one step deep.
        let minted = snap.cashes.filter { !$0.pendingSpend }
        XCTAssertEqual(minted.count, 1)
        XCTAssertEqual(minted[0].localState, .unknown)
        XCTAssertEqual(minted[0].unconfirmedDepth, 1)
    }

    /// The document names whoever composed it. Signing with *our* key
    /// on their `sender` would send our change to a stranger.
    func testTheSenderIsForcedToTheLiveFid() async throws {
        let mock = MockFapiClient()
        let alice = try makeSession("compose-sender", fapi: mock)
        broadcastOnly(mock)

        let inputs = [try cash(owner: alice.liveFid, txidByte: 0xA9, index: 0, value: 1_000_000)]
        var info = document(
            from: alice, inputs: inputs, outputs: [.output(to: payee, amount: 100_000)]
        )
        info.sender = payee          // as an imported document would say
        info.changeTo = nil

        let result = try await alice.sendAdvancedFromLive(info: info, inputCashes: inputs)
        let expected = Cash.canonicalP2PKHLockScript(
            hash160: try FchAddress(fid: alice.liveFid).hash160
        )
        let changeScript = result.transaction.outputs[1].scriptPubKey.bytes
            .map { String(format: "%02x", $0) }.joined()
        XCTAssertEqual(changeScript, expected)
    }

    // MARK: - quote

    /// `rest` is the plain remainder, and a shortfall shows as a
    /// negative one. Android rounds a rest of exactly −34 up to zero,
    /// which against its own fee calculator only happens when the
    /// inputs really are 34 satoshis short — a transaction it then
    /// refuses to build. Reporting the truth is the point of the line.
    func testShortfallShowsAsNegativeRestRatherThanZero() async throws {
        let mock = MockFapiClient()
        let alice = try makeSession("compose-rest", fapi: mock)

        let inputs = [try cash(owner: alice.liveFid, txidByte: 0xB9, index: 0, value: 1_000_000)]
        // Size without change is 10 + 141 + 34 = 185, so paying
        // 1_000_000 − 151 leaves the fee 34 satoshis short.
        let info = document(
            from: alice, inputs: inputs,
            outputs: [.output(to: payee, amount: 1_000_000 - 151)]
        )
        let quote = alice.wallet.quoteAdvanced(info)
        XCTAssertEqual(quote.fee, 185)
        XCTAssertEqual(quote.rest, -34)
        XCTAssertFalse(quote.willHaveChange)

        // And the builder agrees, rather than the pane saying "0" and
        // Send failing a moment later.
        XCTAssertThrowsError(try AdvancedTxBuilder.build(info, inputCashes: inputs))
    }

    /// "Rest…" — the amount that makes the transaction balance with no
    /// change at all. Feeding it straight back in must land on rest 0.
    func testMaxValueForOutputBalancesTheTransaction() async throws {
        let mock = MockFapiClient()
        let alice = try makeSession("compose-max", fapi: mock)

        let inputs = [try cash(owner: alice.liveFid, txidByte: 0xC9, index: 0, value: 1_000_000)]
        let info = document(from: alice, inputs: inputs, outputs: [])

        let value = try XCTUnwrap(alice.wallet.maxValueForOutput(
            in: info, adding: .output(to: payee, amount: 0)
        ))
        var filled = info
        filled.outputs = [.output(to: payee, amount: value)]

        let quote = alice.wallet.quoteAdvanced(filled)
        XCTAssertEqual(quote.rest, 0)
        XCTAssertFalse(quote.willHaveChange)
        XCTAssertEqual(quote.totalIn, quote.totalOut + (quote.fee ?? -1))
    }

    /// The same question for a time-locked output, where the answer is
    /// smaller: the redeem-script manifest in the OP_RETURN is paid for
    /// out of the same money.
    func testMaxValueIsSmallerForATimeLockedOutput() async throws {
        let mock = MockFapiClient()
        let alice = try makeSession("compose-max-lock", fapi: mock)

        let inputs = [try cash(owner: alice.liveFid, txidByte: 0xD9, index: 0, value: 1_000_000)]
        let info = document(from: alice, inputs: inputs, outputs: [])

        let plain = try XCTUnwrap(alice.wallet.maxValueForOutput(
            in: info, adding: .output(to: payee, amount: 0)
        ))
        let locked = try XCTUnwrap(alice.wallet.maxValueForOutput(
            in: info,
            adding: try RawTxInfo.Slot.lockedOutput(to: payee, amount: 0, lockTime: 900_000)
        ))
        XCTAssertLessThan(locked, plain)

        var filled = info
        filled.outputs = [try RawTxInfo.Slot.lockedOutput(
            to: payee, amount: locked, lockTime: 900_000
        )]
        XCTAssertEqual(alice.wallet.quoteAdvanced(filled).rest, 0)
    }

    func testMaxValueIsNilWhenNothingIsLeft() async throws {
        let mock = MockFapiClient()
        let alice = try makeSession("compose-max-empty", fapi: mock)
        let inputs = [try cash(owner: alice.liveFid, txidByte: 0xE9, index: 0, value: 100)]
        let info = document(from: alice, inputs: inputs, outputs: [])
        XCTAssertNil(alice.wallet.maxValueForOutput(
            in: info, adding: .output(to: payee, amount: 0)
        ))
    }

    // MARK: - what the approval dialog is handed

    /// The payload is the only part of a transaction that is both
    /// irreversible and public, so the preview has to carry it —
    /// everything the confirm sheet can show is what arrives here.
    func testTheApproverSeesTheMessageThatWillBeCarved() async throws {
        let mock = MockFapiClient()
        let alice = try makeSession("compose-preview-msg", fapi: mock)
        broadcastOnly(mock)

        let seen = SeenPreview()
        alice.txApprover = { preview in await seen.record(preview); return true }

        let inputs = [try cash(owner: alice.liveFid, txidByte: 0xAA, index: 0, value: 1_000_000)]
        let message = "你好 — paid in full ✓"
        _ = try await alice.sendAdvancedFromLive(
            info: document(
                from: alice, inputs: inputs,
                outputs: [.output(to: payee, amount: 100_000)], opReturn: message
            ),
            inputCashes: inputs
        )

        let captured = await seen.value
        let preview = try XCTUnwrap(captured)
        XCTAssertEqual(preview.opReturn, message)
        // Counted in bytes, which is what the chain charges for and
        // caps: this message is 21 characters and 27 bytes.
        XCTAssertEqual(preview.opReturnByteCount, message.utf8.count)
        XCTAssertNotEqual(preview.opReturnByteCount, message.count)
        // A message is not a manifest.
        XCTAssertTrue(preview.payloadRedeemScripts.isEmpty)
    }

    /// A time-locked payment's payload is a list of redeem scripts.
    /// Shown raw it is a wall of hex, so the preview exposes it
    /// parsed — the address each one pays and the block it frees.
    func testTheApproverSeesTheRedeemScriptsBehindATimeLock() async throws {
        let mock = MockFapiClient()
        let alice = try makeSession("compose-preview-lock", fapi: mock)
        broadcastOnly(mock)

        let seen = SeenPreview()
        alice.txApprover = { preview in await seen.record(preview); return true }

        let inputs = [try cash(owner: alice.liveFid, txidByte: 0xBB, index: 0, value: 1_000_000)]
        let locked = try RawTxInfo.Slot.lockedOutput(
            to: payee, amount: 100_000, lockTime: 900_000
        )
        _ = try await alice.sendAdvancedFromLive(
            info: document(from: alice, inputs: inputs, outputs: [locked]),
            inputCashes: inputs
        )

        let captured = await seen.value
        let preview = try XCTUnwrap(captured)
        let scripts = preview.payloadRedeemScripts
        XCTAssertEqual(scripts.count, 1)
        XCTAssertEqual(scripts[0].lockTime, 900_000)
        XCTAssertEqual(scripts[0].fid, payee)
        // And the output the dialog lists pays that script's address,
        // so the two halves of the story agree.
        XCTAssertTrue(preview.outputs.contains { $0.fid == scripts[0].address })
    }

    /// A message that merely happens to be a JSON array must not be
    /// dressed up as a redeem-script manifest.
    func testAnOrdinaryJsonMessageIsNotMistakenForAManifest() async throws {
        let mock = MockFapiClient()
        let alice = try makeSession("compose-preview-json", fapi: mock)
        broadcastOnly(mock)

        let seen = SeenPreview()
        alice.txApprover = { preview in await seen.record(preview); return true }

        let inputs = [try cash(owner: alice.liveFid, txidByte: 0xCC, index: 0, value: 1_000_000)]
        _ = try await alice.sendAdvancedFromLive(
            info: document(
                from: alice, inputs: inputs,
                outputs: [.output(to: payee, amount: 100_000)],
                opReturn: #"["not", "a", "manifest"]"#
            ),
            inputCashes: inputs
        )

        let captured = await seen.value
        let preview = try XCTUnwrap(captured)
        XCTAssertTrue(preview.payloadRedeemScripts.isEmpty)
    }

    // MARK: - unsigned export

    func testUnsignedExportPricesTheDocumentAndClaimsNothing() async throws {
        let mock = MockFapiClient()
        let alice = try makeSession("compose-unsigned", fapi: mock)

        let inputs = [try cash(owner: alice.liveFid, txidByte: 0xF9, index: 0, value: 1_000_000)]
        try alice.cashes.save(CashSnapshot(addr: alice.liveFid, cashes: inputs))
        let info = document(
            from: alice, inputs: inputs, outputs: [.output(to: payee, amount: 100_000)]
        )

        let result = try alice.buildUnsignedAdvancedFromLive(info: info)
        XCTAssertEqual(result.plan.fee, 219)
        XCTAssertEqual(result.info.sender, alice.liveFid)
        XCTAssertEqual(result.info.changeTo, alice.liveFid)
        XCTAssertNil(result.info.senderMultisig)

        // Nothing broadcast, nothing claimed.
        XCTAssertTrue(mock.recorded.isEmpty)
        let snap = try XCTUnwrap(try alice.cashes.snapshot(forAddress: alice.liveFid))
        XCTAssertEqual(snap.cashes.filter(\.pendingSpend).count, 0)
    }

    /// The exported document must survive the trip to a signer and
    /// back — it is the only thing that crosses.
    func testExportedDocumentRoundTrips() async throws {
        let mock = MockFapiClient()
        let alice = try makeSession("compose-roundtrip", fapi: mock)

        let inputs = [try cash(owner: alice.liveFid, txidByte: 0xAB, index: 3, value: 1_000_000)]
        let locked = try RawTxInfo.Slot.lockedOutput(
            to: payee, amount: 100_000, lockTime: 900_000
        )
        let info = document(from: alice, inputs: inputs, outputs: [locked])
        let exported = try alice.buildUnsignedAdvancedFromLive(info: info).info

        let decoded = try RawTxInfo.fromJson(try exported.exportJson())
        XCTAssertEqual(decoded.inputs, exported.inputs)
        XCTAssertEqual(decoded.outputs, exported.outputs)
        XCTAssertEqual(decoded.outputs?.first?.redeemScript, locked.redeemScript)
        XCTAssertEqual(decoded.outputs?.first?.lockTime, 900_000)
    }
}

/// Captures the preview the approver was handed, so a test can assert
/// on what the dialog would have shown.
private actor SeenPreview {
    private(set) var value: TxPreview?
    func record(_ preview: TxPreview) { value = preview }
}
