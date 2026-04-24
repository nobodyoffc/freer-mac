import XCTest
@testable import FCCore

final class TxHandlerTests: XCTestCase {

    /// With Java's DER signature plugged into our scriptSig builder, the
    /// full signed tx hex and txid must match Java byte-exactly. This
    /// tests the *script + tx serialization* paths without depending on
    /// libsecp256k1 and bitcoinj producing identical RFC 6979 sigs (they
    /// don't — see phase 1.5a commit note).
    func testSignedTxWithJavaDerSigMatchesJavaBytes() throws {
        let vectors = try TestVectors.load()
        let unsigned = try buildSampleTransaction(from: vectors)
        let signedVec = vectors.bchSignedTx[0]
        let pubkey = Data(fromHex: vectors.sampleKey.pubkeyHex)

        let scriptSig = try ScriptBuilder.p2pkhInput(
            signatureDER: Data(fromHex: signedVec.derSigHex),
            sighashFlag: UInt8(signedVec.hashType & 0xFF),
            pubkey: pubkey
        )
        XCTAssertEqual(scriptSig.bytes.hex, signedVec.scriptSigHex, "scriptSig parity")

        var inputs = unsigned.inputs
        inputs[0] = TxInput(
            outpoint: inputs[0].outpoint,
            scriptSig: scriptSig,
            sequence: inputs[0].sequence
        )
        let signed = Transaction(
            version: unsigned.version,
            inputs: inputs,
            outputs: unsigned.outputs,
            locktime: unsigned.locktime
        )

        XCTAssertEqual(signed.serialized.hex, signedVec.signedTxHex,
                       "signed tx serialization")
        XCTAssertEqual(signed.txid.hex, signedVec.signedTxidNaturalHex,
                       "signed txid natural")
        XCTAssertEqual(signed.txidDisplay, signedVec.signedTxidDisplayHex,
                       "signed txid display")
    }

    /// Java's ECDSA DER signature must verify under our libsecp256k1-based
    /// verifier — confirms sighash computation and DER parsing line up.
    func testJavaDerSigVerifiesAgainstSighash() throws {
        let vectors = try TestVectors.load()
        let signedVec = vectors.bchSignedTx[0]
        let pubkey = Data(fromHex: vectors.sampleKey.pubkeyHex)
        let sighash = Data(fromHex: vectors.bchSighash[0].sighashHex)
        let derSig = Data(fromHex: signedVec.derSigHex)

        let valid = try Secp256k1.verifySighashSig(
            publicKey: pubkey, sighash: sighash, signatureDER: derSig
        )
        XCTAssertTrue(valid)
    }

    /// Swift's TxHandler.signP2pkhInput produces a signed tx whose
    /// scriptSig parses back into a valid signature for the same sighash.
    /// (Byte-exact parity with Java isn't asserted here because the two
    /// libraries' RFC 6979 internals differ and produce different
    /// signatures for the same privkey+hash.)
    func testSwiftSignedInputProducesVerifiableSignature() throws {
        let vectors = try TestVectors.load()
        let unsigned = try buildSampleTransaction(from: vectors)
        let privkey = Data(fromHex: vectors.sampleKey.privkeyHex)
        let pubkey = Data(fromHex: vectors.sampleKey.pubkeyHex)
        let prevValueSats = vectors.bchSighash[0].prevValueSats

        let signed = try TxHandler.signP2pkhInput(
            tx: unsigned,
            inputIndex: 0,
            privateKey: privkey,
            prevValueSats: prevValueSats
        )
        XCTAssertFalse(signed.inputs[0].scriptSig.bytes.isEmpty)

        // Recompute the sighash from the original unsigned tx and
        // independently obtain the Swift-side DER sig. It must verify.
        let pubkeyHash = Hash.hash160(pubkey)
        let scriptCode = try ScriptBuilder.p2pkhOutput(hash160: pubkeyHash).bytes
        let sighash = try BchSighash.sighash(
            tx: unsigned, inputIndex: 0,
            scriptCode: scriptCode, prevValueSats: prevValueSats
        )
        let derSig = try Secp256k1.signSighash(privateKey: privkey, sighash: sighash)
        XCTAssertTrue(
            try Secp256k1.verifySighashSig(
                publicKey: pubkey, sighash: sighash, signatureDER: derSig
            )
        )

        // And the Swift-signed scriptSig should match the scriptSig we'd
        // build from that same DER sig — proves TxHandler.signP2pkhInput
        // composes the two correctly.
        let expectedScriptSig = try ScriptBuilder.p2pkhInput(
            signatureDER: derSig, sighashFlag: 0x41, pubkey: pubkey
        )
        XCTAssertEqual(signed.inputs[0].scriptSig, expectedScriptSig)
    }

    func testSignP2pkhInputIsDeterministic() throws {
        let vectors = try TestVectors.load()
        let unsigned = try buildSampleTransaction(from: vectors)
        let privkey = Data(fromHex: vectors.sampleKey.privkeyHex)
        let prevValueSats = vectors.bchSighash[0].prevValueSats

        let first = try TxHandler.signP2pkhInput(
            tx: unsigned, inputIndex: 0,
            privateKey: privkey, prevValueSats: prevValueSats
        )
        let second = try TxHandler.signP2pkhInput(
            tx: unsigned, inputIndex: 0,
            privateKey: privkey, prevValueSats: prevValueSats
        )
        XCTAssertEqual(first.serialized, second.serialized)
    }

    func testRejectsBadInputIndex() throws {
        let vectors = try TestVectors.load()
        let unsigned = try buildSampleTransaction(from: vectors)
        let privkey = Data(fromHex: vectors.sampleKey.privkeyHex)
        XCTAssertThrowsError(try TxHandler.signP2pkhInput(
            tx: unsigned, inputIndex: 99,
            privateKey: privkey, prevValueSats: 1
        )) { e in
            guard case TxHandler.Failure.inputIndexOutOfRange = e else {
                XCTFail("wrong error: \(e)"); return
            }
        }
    }

    // MARK: - helper

    private func buildSampleTransaction(from vectors: TestVectors.Root) throws -> Transaction {
        let vector = vectors.transaction[0]
        let inputs: [TxInput] = try vector.inputs.map { ic in
            let outpoint = try OutPoint(
                prevTxHash: Data(fromHex: ic.prevTxHashHex),
                outIndex: ic.prevOutputIndex
            )
            return TxInput(
                outpoint: outpoint,
                scriptSig: Script(Data(fromHex: ic.scriptSigHex)),
                sequence: ic.sequence
            )
        }
        let outputs: [TxOutput] = vector.outputs.map { oc in
            TxOutput(
                value: oc.valueSats,
                scriptPubKey: Script(Data(fromHex: oc.scriptPubkeyHex))
            )
        }
        return Transaction(
            version: vector.version,
            inputs: inputs,
            outputs: outputs,
            locktime: vector.locktime
        )
    }
}
