import XCTest
@testable import FCCore

/// Multisig P2SH signing: the script shape FCH accepts, and a
/// sign → assemble → verify round trip.
///
/// The shape assertions are pinned against the worked example in
/// `Multisig.parseMultisign`'s own comment, byte layout and all,
/// because an unlock script that is subtly wrong does not fail
/// loudly — it produces a transaction the network drops.
final class MultisigTxTests: XCTestCase {

    private let alicePriv = Data(repeating: 0xA1, count: 32)
    private let bobPriv = Data(repeating: 0xB2, count: 32)
    private let carolPriv = Data(repeating: 0xC3, count: 32)

    private func pubkeyHex(_ priv: Data) throws -> String {
        Hex.encode(try Secp256k1.publicKey(fromPrivateKey: priv))
    }

    /// A 2-of-3 over the three keys, in that order.
    private func group() throws -> P2sh {
        try P2sh(
            pubkeys: [
                try pubkeyHex(alicePriv),
                try pubkeyHex(bobPriv),
                try pubkeyHex(carolPriv),
            ],
            m: 2, n: 3, lockTime: nil
        )
    }

    /// One input spending `p2sh`, one output paying it back minus a fee.
    private func makeTx(_ p2sh: P2sh) throws -> Transaction {
        let outpoint = try OutPoint(
            prevTxHash: Data(repeating: 0x11, count: 32), outIndex: 0
        )
        return Transaction(
            version: 2,
            inputs: [TxInput(
                outpoint: outpoint, scriptSig: Script(Data()), sequence: 0xFFFF_FFFF
            )],
            outputs: [TxOutput(value: 9_000, scriptPubKey: p2sh.outputScript)],
            locktime: 0
        )
    }

    // MARK: - script shape

    /// The layout from `Multisig.parseMultisign`'s comment:
    /// `00` then each `41`-length signature then the pushed redeem
    /// script, which itself ends in `ae` (OP_CHECKMULTISIG).
    func testUnlockScriptHasNullDummyAnd65ByteSignatures() throws {
        let p2sh = try group()
        let sigs = [Data(repeating: 0x01, count: 64), Data(repeating: 0x02, count: 64)]

        let script = try TxHandler.multisigInputScript(
            signatures: sigs, redeemScript: p2sh.redeemScript
        )
        let bytes = script.bytes

        // The null dummy — a bare OP_0, not a checkbits bitfield.
        XCTAssertEqual(bytes[0], 0x00)
        // Then two pushes of 65 = 64-byte Schnorr sig + the 0x41 flag.
        XCTAssertEqual(bytes[1], 65)
        XCTAssertEqual(bytes[1 + 65], 0x41, "sighash flag closes the first signature")
        XCTAssertEqual(bytes[2 + 65], 65)
        XCTAssertEqual(bytes[2 + 65 + 65], 0x41, "and the second")
        // And the script ends with the redeem script, which ends in
        // OP_CHECKMULTISIG.
        XCTAssertEqual(bytes.last, 0xAE)
        XCTAssertTrue(
            bytes.suffix(p2sh.redeemScript.count) == p2sh.redeemScript,
            "the redeem script is the last push"
        )
    }

    func testMoreThanFifteenSignaturesIsRefused() throws {
        let p2sh = try group()
        let sigs = Array(repeating: Data(repeating: 0x01, count: 64), count: 16)
        XCTAssertThrowsError(
            try TxHandler.multisigInputScript(
                signatures: sigs, redeemScript: p2sh.redeemScript
            )
        )
    }

    // MARK: - signing

    /// A partial signature is 64 bytes and carries no sighash flag —
    /// that is what makes it safe to hand between signers.
    func testAPartialSignatureIsSixtyFourBaresBytes() throws {
        let p2sh = try group()
        let tx = try makeTx(p2sh)
        let sig = try TxHandler.signMultisigInput(
            tx: tx, inputIndex: 0, privateKey: alicePriv,
            prevValueSats: 10_000, redeemScript: p2sh.redeemScript
        )
        XCTAssertEqual(sig.count, 64)
        XCTAssertNotEqual(sig.last, 0x41, "the flag is added at assembly, not here")
    }

    func testEachMembersSignatureVerifiesUnderTheirOwnKey() throws {
        let p2sh = try group()
        let tx = try makeTx(p2sh)

        for priv in [alicePriv, bobPriv, carolPriv] {
            let sig = try TxHandler.signMultisigInput(
                tx: tx, inputIndex: 0, privateKey: priv,
                prevValueSats: 10_000, redeemScript: p2sh.redeemScript
            )
            let pubkey = try Secp256k1.publicKey(fromPrivateKey: priv)
            XCTAssertTrue(try TxHandler.verifyMultisigInput(
                tx: tx, inputIndex: 0, publicKey: pubkey, signature: sig,
                prevValueSats: 10_000, redeemScript: p2sh.redeemScript
            ))
        }
    }

    /// The check that makes a merge safe: a signature made by one
    /// member does not verify under another's key.
    func testASignatureDoesNotVerifyUnderTheWrongKey() throws {
        let p2sh = try group()
        let tx = try makeTx(p2sh)
        let aliceSig = try TxHandler.signMultisigInput(
            tx: tx, inputIndex: 0, privateKey: alicePriv,
            prevValueSats: 10_000, redeemScript: p2sh.redeemScript
        )
        let bobPubkey = try Secp256k1.publicKey(fromPrivateKey: bobPriv)
        XCTAssertFalse(try TxHandler.verifyMultisigInput(
            tx: tx, inputIndex: 0, publicKey: bobPubkey, signature: aliceSig,
            prevValueSats: 10_000, redeemScript: p2sh.redeemScript
        ))
    }

    /// A signature commits to the whole transaction. Change an output
    /// and every signature already collected is waste paper — which is
    /// why the co-sign document must travel with the exact tx it was
    /// signed against.
    func testChangingAnOutputInvalidatesASignature() throws {
        let p2sh = try group()
        let tx = try makeTx(p2sh)
        let sig = try TxHandler.signMultisigInput(
            tx: tx, inputIndex: 0, privateKey: alicePriv,
            prevValueSats: 10_000, redeemScript: p2sh.redeemScript
        )
        let tampered = Transaction(
            version: tx.version, inputs: tx.inputs,
            outputs: [TxOutput(value: 8_000, scriptPubKey: p2sh.outputScript)],
            locktime: tx.locktime
        )
        let pubkey = try Secp256k1.publicKey(fromPrivateKey: alicePriv)
        XCTAssertFalse(try TxHandler.verifyMultisigInput(
            tx: tampered, inputIndex: 0, publicKey: pubkey, signature: sig,
            prevValueSats: 10_000, redeemScript: p2sh.redeemScript
        ))
    }

    /// A CLTV multisig must be signed over the *full* time-locked
    /// script. Signing the bare multisig body produces a signature that
    /// verifies against nothing, which is the quiet way to lock a
    /// group's coins up.
    func testCltvMultisigSignsOverTheTimeLockedScript() throws {
        let keys = [
            try pubkeyHex(alicePriv), try pubkeyHex(bobPriv), try pubkeyHex(carolPriv),
        ]
        let plain = try P2sh(pubkeys: keys, m: 2, n: 3, lockTime: nil)
        let locked = try P2sh(pubkeys: keys, m: 2, n: 3, lockTime: 800_000)
        XCTAssertEqual(locked.kind, .multisigCltv)
        XCTAssertNotEqual(locked.redeemScript, plain.redeemScript)
        // Both name the same group, but they are paid to different
        // addresses — see P2sh's note on fid vs address.
        XCTAssertEqual(locked.fid, plain.fid)
        XCTAssertNotEqual(locked.address, plain.address)

        let tx = try makeTx(locked)
        let sig = try TxHandler.signMultisigInput(
            tx: tx, inputIndex: 0, privateKey: alicePriv,
            prevValueSats: 10_000, redeemScript: locked.redeemScript
        )
        let pubkey = try Secp256k1.publicKey(fromPrivateKey: alicePriv)
        XCTAssertTrue(try TxHandler.verifyMultisigInput(
            tx: tx, inputIndex: 0, publicKey: pubkey, signature: sig,
            prevValueSats: 10_000, redeemScript: locked.redeemScript
        ))
        XCTAssertFalse(
            try TxHandler.verifyMultisigInput(
                tx: tx, inputIndex: 0, publicKey: pubkey, signature: sig,
                prevValueSats: 10_000, redeemScript: plain.redeemScript
            ),
            "signing the bare body would not verify against the locked script"
        )
    }
}
