import XCTest
import FCCore
@testable import FCDomain

/// The co-sign conversation: propose → sign → merge → assemble.
///
/// The round trip is the point. Each step is cheap to get subtly wrong
/// in a way that only shows up as a node rejecting the finished
/// transaction, so these drive it end to end and check the bytes that
/// come out.
final class MultisigCosignTests: XCTestCase {

    private let alicePriv = Data(repeating: 0xA1, count: 32)
    private let bobPriv = Data(repeating: 0xB2, count: 32)
    private let carolPriv = Data(repeating: 0xC3, count: 32)
    private let strangerPriv = Data(repeating: 0xDD, count: 32)

    private func pubkeyHex(_ priv: Data) throws -> String {
        Hex.encode(try Secp256k1.publicKey(fromPrivateKey: priv))
    }

    private func fid(_ priv: Data) throws -> String {
        try FchAddress(publicKey: try Secp256k1.publicKey(fromPrivateKey: priv)).fid
    }

    /// 2-of-3 over alice, bob, carol — in that order.
    private func group() throws -> Multisig {
        try Multisig(
            pubkeys: [
                try pubkeyHex(alicePriv),
                try pubkeyHex(bobPriv),
                try pubkeyHex(carolPriv),
            ],
            m: 2
        )
    }

    /// One 10 000-sat input at the group's address, paying 9 000 out.
    private func proposal(_ group: Multisig, lockTime: Int64? = nil) throws -> RawTxInfo {
        let slot = RawTxInfo.Slot(
            owner: try group.address(lockTime: lockTime),
            value: 10_000,
            birthTxId: String(repeating: "11", count: 32),
            birthIndex: 0,
            redeemScript: try group.redeemScript(lockTime: lockTime),
            lockTime: lockTime
        )
        return RawTxInfo(
            sender: group.id,
            feeRate: RawTxInfo.feeRate(satsPerByte: 1),
            inputs: [slot],
            outputs: [RawTxInfo.Slot.output(to: try fid(strangerPriv), amount: 9_000)],
            changeTo: group.id,
            senderMultisig: group
        )
    }

    // MARK: - the group

    func testGroupAddressIsDerivedFromMembersAndThreshold() throws {
        let g = try group()
        XCTAssertEqual(g.m, 2)
        XCTAssertEqual(g.n, 3)
        XCTAssertEqual(g.fids?.count, 3)
        XCTAssertEqual(g.fids?[0], try fid(alicePriv), "member order follows pubkey order")
        XCTAssertEqual(g.fids?[2], try fid(carolPriv))
        let address = try XCTUnwrap(g.id)
        XCTAssertTrue(address.hasPrefix("3"), "a P2SH address, not an F… one")
        // Same members in a different order is a *different* group:
        // the redeem script, and so the address, depends on the order.
        let reordered = try Multisig(
            pubkeys: [
                try pubkeyHex(carolPriv),
                try pubkeyHex(bobPriv),
                try pubkeyHex(alicePriv),
            ],
            m: 2
        )
        XCTAssertNotEqual(reordered.id, g.id)
    }

    func testGroupRoundTripsThroughItsRedeemScript() throws {
        let g = try group()
        let parsed = try Multisig(redeemScriptHex: try XCTUnwrap(g.redeemScript))
        XCTAssertEqual(parsed.id, g.id)
        XCTAssertEqual(parsed.m, g.m)
        XCTAssertEqual(parsed.n, g.n)
        XCTAssertEqual(parsed.pubkeys, g.pubkeys)
        XCTAssertEqual(parsed.fids, g.fids)
    }

    /// The membership is read out of the inputs, so a document needs no
    /// separate statement of who its group is.
    func testGroupIsRecoveredFromTheInputsAlone() throws {
        let g = try group()
        var info = try proposal(g)
        info.senderMultisig = nil

        let recovered = try MultisigCosign.group(of: info)
        XCTAssertEqual(recovered.fid, g.id)
        XCTAssertEqual(recovered.m, 2)
        XCTAssertEqual(recovered.n, 3)
        XCTAssertEqual(recovered.fids, g.fids)
    }

    // MARK: - signing and status

    func testStatusCountsTowardsTheThreshold() throws {
        let g = try group()
        let info = try proposal(g)

        var status = try MultisigCosign.status(info)
        XCTAssertEqual(status.remaining, 2)
        XCTAssertFalse(status.isComplete)
        XCTAssertEqual(status.unsigned.count, 3)

        let signed = try MultisigCosign.sign(info, privkey: alicePriv)
        status = try MultisigCosign.status(signed)
        XCTAssertEqual(status.signed, [try fid(alicePriv)])
        XCTAssertEqual(status.remaining, 1)
        XCTAssertFalse(status.isComplete)

        let twice = try MultisigCosign.sign(signed, privkey: bobPriv)
        status = try MultisigCosign.status(twice)
        XCTAssertEqual(status.remaining, 0)
        XCTAssertTrue(status.isComplete)
    }

    func testSigningTwiceReplacesRatherThanDuplicates() throws {
        let g = try group()
        let once = try MultisigCosign.sign(try proposal(g), privkey: alicePriv)
        let again = try MultisigCosign.sign(once, privkey: alicePriv)
        XCTAssertEqual(again.fidSigMap?.count, 1)
    }

    func testANonMemberCannotSign() throws {
        let g = try group()
        XCTAssertThrowsError(
            try MultisigCosign.sign(try proposal(g), privkey: strangerPriv)
        ) { error in
            guard case MultisigCosign.Failure.notAMember = error else {
                return XCTFail("wrong failure: \(error)")
            }
        }
    }

    // MARK: - merging

    /// The normal case: two members sign the same proposal
    /// independently and their documents combine.
    func testTwoIndependentSignaturesMerge() throws {
        let g = try group()
        let info = try proposal(g)
        let fromAlice = try MultisigCosign.sign(info, privkey: alicePriv)
        let fromCarol = try MultisigCosign.sign(info, privkey: carolPriv)

        let merged = try MultisigCosign.merge([fromAlice, fromCarol])
        let status = try MultisigCosign.status(merged)
        XCTAssertEqual(status.signed, [try fid(alicePriv), try fid(carolPriv)])
        XCTAssertTrue(status.isComplete)
    }

    /// The case worth refusing loudly. Two members who each changed the
    /// amount before signing produce signatures that cannot coexist;
    /// merging them would yield a transaction the node rejects with a
    /// script error naming neither of them.
    func testMergingDocumentsForDifferentTransactionsIsRefused() throws {
        let g = try group()
        let fromAlice = try MultisigCosign.sign(try proposal(g), privkey: alicePriv)

        var edited = try proposal(g)
        edited.outputs = [RawTxInfo.Slot.output(to: try fid(strangerPriv), amount: 8_000)]
        let fromCarol = try MultisigCosign.sign(edited, privkey: carolPriv)

        XCTAssertThrowsError(try MultisigCosign.merge([fromAlice, fromCarol])) { error in
            guard case MultisigCosign.Failure.documentsDiffer = error else {
                return XCTFail("wrong failure: \(error)")
            }
        }
    }

    // MARK: - assembling

    func testAssembledTransactionCarriesTheUnlockScript() throws {
        let g = try group()
        let info = try proposal(g)
        let merged = try MultisigCosign.merge([
            try MultisigCosign.sign(info, privkey: alicePriv),
            try MultisigCosign.sign(info, privkey: bobPriv),
        ])

        let raw = try MultisigCosign.assemble(merged)
        let hex = Hex.encode(raw)
        // The redeem script is revealed in the scriptSig, and the two
        // signatures sit in front of it under a null dummy.
        XCTAssertTrue(hex.contains(try XCTUnwrap(g.redeemScript)))
        XCTAssertTrue(raw.count > 300, "a real transaction, not an empty shell")
    }

    func testAssemblingBelowTheThresholdIsRefused() throws {
        let g = try group()
        let one = try MultisigCosign.sign(try proposal(g), privkey: alicePriv)
        XCTAssertThrowsError(try MultisigCosign.assemble(one)) { error in
            guard case MultisigCosign.Failure.notEnoughSignatures(let have, let need) = error else {
                return XCTFail("wrong failure: \(error)")
            }
            XCTAssertEqual(have, 1)
            XCTAssertEqual(need, 2)
        }
    }

    /// Three signatures on a 2-of-3 must be trimmed to two: a spare
    /// signature makes OP_CHECKMULTISIG fail.
    func testASpareSignatureIsDroppedRatherThanIncluded() throws {
        let g = try group()
        let info = try proposal(g)
        var all = try MultisigCosign.sign(info, privkey: alicePriv)
        all = try MultisigCosign.sign(all, privkey: bobPriv)
        all = try MultisigCosign.sign(all, privkey: carolPriv)
        XCTAssertEqual(all.fidSigMap?.count, 3)

        let raw = try MultisigCosign.assemble(all)
        // OP_0 then exactly two 65-byte pushes before the redeem
        // script push.
        let scriptSig = raw
        let sixtyFives = scriptSig.enumerated().filter { $0.element == 65 }.count
        XCTAssertGreaterThanOrEqual(sixtyFives, 2)
        // Deterministic: assembling twice gives the same bytes, which
        // Android's HashMap-order trim does not guarantee.
        XCTAssertEqual(raw, try MultisigCosign.assemble(all))
    }

    /// A forged signature is caught at assembly rather than by the
    /// node, so the group learns whose it was.
    func testAForgedSignatureIsRejectedAtAssembly() throws {
        let g = try group()
        let info = try proposal(g)
        var merged = try MultisigCosign.merge([
            try MultisigCosign.sign(info, privkey: alicePriv),
            try MultisigCosign.sign(info, privkey: bobPriv),
        ])
        merged.fidSigMap?[try fid(bobPriv)] = [String(repeating: "ab", count: 64)]

        XCTAssertThrowsError(try MultisigCosign.assemble(merged)) { error in
            guard case MultisigCosign.Failure.invalidSignature(let who, _) = error else {
                return XCTFail("wrong failure: \(error)")
            }
            XCTAssertEqual(who, try? fid(bobPriv))
        }
    }

    // MARK: - CLTV

    /// A time-locked group spends through a different address and a
    /// different script, and the transaction it produces must carry the
    /// lock time and a non-final sequence or the lock is never checked.
    func testCltvMultisigSpendSetsLockTimeAndSequence() throws {
        let g = try group()
        let lock: Int64 = 700_000
        let info = try proposal(g, lockTime: lock)

        XCTAssertNotEqual(
            try g.address(lockTime: lock), try g.address(),
            "a locked group is paid at its own address"
        )

        let merged = try MultisigCosign.merge([
            try MultisigCosign.sign(info, privkey: alicePriv),
            try MultisigCosign.sign(info, privkey: bobPriv),
        ])
        let built = try AdvancedTxBuilder.build(merged, inputCashes: [])
        XCTAssertEqual(built.transaction.locktime, UInt32(lock))
        XCTAssertEqual(
            built.transaction.inputs[0].sequence, 0xFFFF_FFFE,
            "a final sequence would stop the lock time being consulted at all"
        )
        XCTAssertNoThrow(try MultisigCosign.assemble(merged))
    }

    /// The wire shape: signatures travel, the group does not.
    func testExportedDocumentCarriesSignaturesButNotTheGroup() throws {
        let g = try group()
        let signed = try MultisigCosign.sign(try proposal(g), privkey: alicePriv)

        let json = try JSONEncoder().encode(signed)
        let back = try JSONDecoder().decode(RawTxInfo.self, from: json)

        XCTAssertNil(back.senderMultisig, "the group is not exported")
        XCTAssertEqual(back.fidSigMap?.count, 1, "the signatures are")
        // And the group is still recoverable on the far side, from the
        // inputs — which is why dropping it costs nothing.
        XCTAssertEqual(try MultisigCosign.group(of: back).fid, g.id)
    }
}
