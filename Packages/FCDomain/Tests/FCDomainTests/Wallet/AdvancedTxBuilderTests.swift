import XCTest
import FCCore
@testable import FCDomain

/// ``AdvancedTxBuilder`` — the composed-transaction assembler.
///
/// Most of what is checked here is invisible in a diff and fatal on
/// chain: which order the outputs go in, whether a CLTV input's
/// sequence is non-final, whether the transaction's own locktime
/// clears the lock it is trying to spend.
final class AdvancedTxBuilderTests: XCTestCase {

    private let fid = "FEk41Kqjar45fLDriztUDTUkdki7mmcjWK"
    /// A real second address — derived from the second key of the
    /// vector generator's 2-of-3 group, so it survives a checksum.
    private let other = "FUqvgtMU7YT2TbVXH3G39heb4C7QvpgJag"
    private let txid = "6ff4e2c4d2b9c9c53d69b0b3e2b6a94b6f5d1e0f8a7c6b5a4d3e2f1a0b9c8d7e"
    private let privkey = try! Hex.decode(
        "a048f6c843f92bfe036057f7fc2bf2c27353c624cf7ad97e98ed41432f700575"
    )

    private func input(_ value: Int64, index: Int = 0, lockTime: Int64? = nil,
                       redeemScript: String? = nil) -> RawTxInfo.Slot {
        RawTxInfo.Slot(
            owner: fid, value: value, birthTxId: txid, birthIndex: index,
            redeemScript: redeemScript, lockTime: lockTime
        )
    }

    private func base(_ inputs: [RawTxInfo.Slot], _ outputs: [RawTxInfo.Slot],
                      opReturn: String? = nil) -> RawTxInfo {
        RawTxInfo(
            sender: fid,
            feeRate: TxFee.defaultFeeRate,
            inputs: inputs,
            outputs: outputs,
            opReturn: opReturn,
            changeTo: fid
        )
    }

    // MARK: - shape

    func testOutputOrderIsPaymentsThenChangeThenOpReturn() throws {
        let info = base(
            [input(1_000_000)],
            [.output(to: other, amount: 100_000)],
            opReturn: "hello"
        )
        let built = try AdvancedTxBuilder.build(info, inputCashes: [])
        XCTAssertEqual(built.transaction.outputs.count, 3)

        // 0: the payment.
        XCTAssertEqual(built.transaction.outputs[0].value, 100_000)
        // 1: change back to us.
        XCTAssertEqual(Int64(built.transaction.outputs[1].value), built.change)
        XCTAssertTrue(built.hasChange)
        // 2: the OP_RETURN, always last and always worth nothing.
        XCTAssertEqual(built.transaction.outputs[2].value, 0)
        XCTAssertEqual(built.transaction.outputs[2].scriptPubKey.bytes.first, 0x6A)
    }

    func testChangeBelowDustIsLeftToTheMiner() throws {
        // 1 000 000 in, 998 800 out: what is left cannot pay for its
        // own output, so there is no change and the fee absorbs it.
        let info = base([input(1_000_000)], [.output(to: other, amount: 998_800)])
        let built = try AdvancedTxBuilder.build(info, inputCashes: [])
        XCTAssertFalse(built.hasChange)
        XCTAssertEqual(built.transaction.outputs.count, 1)
        XCTAssertNil(built.changeTo)
    }

    func testInsufficientInputsAreRefusedRatherThanUnderfunded() {
        let info = base([input(1_000)], [.output(to: other, amount: 100_000)])
        XCTAssertThrowsError(try AdvancedTxBuilder.build(info, inputCashes: [])) { error in
            guard case AdvancedTxBuilder.Failure.insufficientFunds = error else {
                return XCTFail("expected insufficientFunds, got \(error)")
            }
        }
    }

    func testNoInputsIsRefused() {
        XCTAssertThrowsError(
            try AdvancedTxBuilder.build(base([], [.output(to: other, amount: 1)]), inputCashes: [])
        )
    }

    // MARK: - P2SH outputs

    func testTimeLockedOutputPaysTheScriptHashNotTheAddress() throws {
        let slot = try RawTxInfo.Slot.lockedOutput(to: other, amount: 100_000, lockTime: 900_000)
        let info = base([input(1_000_000)], [slot])
        let built = try AdvancedTxBuilder.build(info, inputCashes: [])

        let p2sh = try P2sh(redeemScriptHex: XCTUnwrap(slot.redeemScript))
        // OP_HASH160 <20> OP_EQUAL, over the hash of the redeem script.
        XCTAssertEqual(built.transaction.outputs[0].scriptPubKey, p2sh.outputScript)
        // The slot still names the human payee, not the script address.
        XCTAssertEqual(slot.owner, other)
        XCTAssertNotEqual(p2sh.address, other)

        // The manifest is published so the payee can spend it later.
        let manifest = String(decoding: built.opReturn, as: UTF8.self)
        XCTAssertTrue(manifest.contains(p2sh.redeemScriptHex))
    }

    /// The lock applies to the *payee's* output. Change comes straight
    /// back unlocked — locking it would freeze the rest of the wallet
    /// alongside the gift.
    func testChangeIsNeverTimeLocked() throws {
        let slot = try RawTxInfo.Slot.lockedOutput(to: other, amount: 100_000, lockTime: 900_000)
        let info = base([input(1_000_000)], [slot])
        let built = try AdvancedTxBuilder.build(info, inputCashes: [])

        let change = built.transaction.outputs[1]
        let expected = try ScriptBuilder.p2pkhOutput(hash160: FchAddress(fid: fid).hash160)
        XCTAssertEqual(change.scriptPubKey, expected)
    }

    // MARK: - CLTV inputs

    /// Two settings, both required, and each useless without the
    /// other: the transaction's locktime has to reach the lock, and
    /// the input's sequence has to be non-final so the locktime is
    /// consulted at all.
    func testSpendingALockedInputSetsLocktimeAndANonFinalSequence() throws {
        let p2sh = try P2sh(fid: fid, lockTime: 900_000)
        let info = base(
            [input(1_000_000, lockTime: 900_000, redeemScript: p2sh.redeemScriptHex)],
            [.output(to: other, amount: 100_000)]
        )
        let built = try AdvancedTxBuilder.build(info, inputCashes: [])

        XCTAssertEqual(built.transaction.locktime, 900_000)
        XCTAssertEqual(built.transaction.inputs[0].sequence, 0xFFFF_FFFE)
    }

    func testPlainInputsKeepTheFinalSequenceAndNoLocktime() throws {
        let info = base([input(1_000_000)], [.output(to: other, amount: 100_000)])
        let built = try AdvancedTxBuilder.build(info, inputCashes: [])
        XCTAssertEqual(built.transaction.locktime, 0)
        XCTAssertEqual(built.transaction.inputs[0].sequence, 0xFFFF_FFFF)
    }

    func testLocktimeTakesTheDeepestLockAmongTheInputs() throws {
        let a = try P2sh(fid: fid, lockTime: 900_000)
        let b = try P2sh(fid: fid, lockTime: 950_000)
        let info = base(
            [
                input(1_000_000, index: 0, lockTime: 900_000, redeemScript: a.redeemScriptHex),
                input(1_000_000, index: 1, lockTime: 950_000, redeemScript: b.redeemScriptHex),
            ],
            [.output(to: other, amount: 100_000)]
        )
        let built = try AdvancedTxBuilder.build(info, inputCashes: [])
        XCTAssertEqual(built.transaction.locktime, 950_000)
    }

    func testStillLockedInputsAreRefusedBeforeTheChainRefusesThem() throws {
        let p2sh = try P2sh(fid: fid, lockTime: 900_000)
        let slots = [input(1_000_000, lockTime: 900_000, redeemScript: p2sh.redeemScriptHex)]

        XCTAssertThrowsError(
            try AdvancedTxBuilder.requireUnlocked(slots, bestHeight: 899_999)
        )
        XCTAssertNoThrow(try AdvancedTxBuilder.requireUnlocked(slots, bestHeight: 900_000))
        // Height 0 means "we don't know" — not "everything is locked".
        XCTAssertNoThrow(try AdvancedTxBuilder.requireUnlocked(slots, bestHeight: 0))
    }

    /// An imported document may carry the lock without the script.
    /// A single-sig CLTV script is a function of the owner and the
    /// lock, so it is rebuilt rather than refused.
    func testMissingRedeemScriptsAreRebuiltFromOwnerAndLock() throws {
        let repaired = AdvancedTxBuilder.fillMissingRedeemScripts([
            input(1_000_000, lockTime: 900_000),
            input(1_000_000, index: 1),               // no lock: left alone
        ])
        let expected = try P2sh(fid: fid, lockTime: 900_000).redeemScriptHex
        XCTAssertEqual(repaired[0].redeemScript, expected)
        XCTAssertNil(repaired[1].redeemScript)
    }

    // MARK: - signing

    func testPlainInputsSignAsP2pkhAndLockedOnesAsP2sh() throws {
        let p2sh = try P2sh(fid: fid, lockTime: 900_000)
        let slots = [
            input(1_000_000, index: 0),
            input(1_000_000, index: 1, lockTime: 900_000, redeemScript: p2sh.redeemScriptHex),
        ]
        let info = base(slots, [.output(to: other, amount: 100_000)])
        let built = try AdvancedTxBuilder.build(info, inputCashes: [])
        let signed = try AdvancedTxBuilder.signAll(
            built.transaction, slots: slots, privkey: privkey
        )

        // P2PKH: <sig+flag> <pubkey> — two pushes.
        let p2pkhChunks = try ScriptParser.chunks(signed.inputs[0].scriptSig.bytes)
        XCTAssertEqual(p2pkhChunks.count, 2)
        XCTAssertEqual(p2pkhChunks[0].data?.count, 65)   // 64-byte Schnorr + sighash
        XCTAssertEqual(p2pkhChunks[1].data?.count, 33)

        // P2SH: <sig+flag> <pubkey> <redeemScript> — three, and the
        // third must be the script whose hash the output committed to.
        let p2shChunks = try ScriptParser.chunks(signed.inputs[1].scriptSig.bytes)
        XCTAssertEqual(p2shChunks.count, 3)
        XCTAssertEqual(p2shChunks[0].data?.count, 65)
        XCTAssertEqual(p2shChunks[2].data, p2sh.redeemScript)
    }

    /// A multisig input needs every member's signature and a merge
    /// step. Signing it with one key would produce a transaction the
    /// chain rejects, so it is refused where the mistake is visible.
    func testMultisigInputsAreRefusedRatherThanHalfSigned() throws {
        let group = try P2sh(
            pubkeys: [
                "030be1d7e633feb2338a74a860e76d893bac525f35a5813cb7b21e27ba1bc8312a",
                "034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa",
                "02466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f27",
            ],
            m: 2, n: 3, lockTime: nil
        )
        let slots = [input(1_000_000, lockTime: 900_000, redeemScript: group.redeemScriptHex)]
        let tx = Transaction(
            version: 2,
            inputs: [TxInput(outpoint: try OutPoint(
                prevTxHash: try TxBuilder.decodeTxid(txid), outIndex: 0
            ))],
            outputs: [],
            locktime: 0
        )
        XCTAssertThrowsError(
            try AdvancedTxBuilder.signAll(tx, slots: slots, privkey: privkey)
        )
    }

    // MARK: - the wire document

    /// The multisig group is local knowledge. An exported document
    /// that carried it would hand the group's membership to anyone who
    /// scanned the QR code.
    func testSenderMultisigNeverReachesTheWire() throws {
        var group = Multisig()
        group.m = 2
        group.n = 3
        var info = base([input(1_000_000)], [.output(to: other, amount: 100_000)])
        info.senderMultisig = group

        let json = try info.exportJson()
        XCTAssertFalse(json.contains("senderMultisig"))
        XCTAssertNil(try RawTxInfo.fromJson(json).senderMultisig)
        // Everything else survives the round trip.
        XCTAssertEqual(try RawTxInfo.fromJson(json).inputs, info.inputs)
        XCTAssertEqual(try RawTxInfo.fromJson(json).outputs, info.outputs)
    }

    func testSlotsRebuildIntoSpendableCash() throws {
        let slot = input(1_000_000, lockTime: 900_000)
        let cash = try XCTUnwrap(Cash(slot: slot))
        XCTAssertEqual(cash.value, 1_000_000)
        XCTAssertEqual(cash.birthTxId, txid)
        XCTAssertEqual(cash.lockTime, 900_000)
        // Not `.onchain`: we have not seen it confirmed ourselves.
        XCTAssertEqual(cash.localState, .unknown)
        XCTAssertNil(Cash(slot: RawTxInfo.Slot(owner: fid, value: 1)))
    }
}
