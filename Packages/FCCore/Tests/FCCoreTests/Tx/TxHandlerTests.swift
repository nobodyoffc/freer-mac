import XCTest
@testable import FCCore

final class TxHandlerTests: XCTestCase {

    /// With Java's DER signature plugged into our scriptSig builder, the
    /// full signed tx hex and txid must match Java byte-exactly. This
    /// tests the *script + tx serialization* paths without depending on
    /// libsecp256k1 and bitcoinj producing identical RFC 6979 sigs (they
    /// don't — see phase 1.5a commit note). Note: `signedTxHex` here is
    /// a legacy ECDSA-signed fixture; mainnet FCH now requires Schnorr,
    /// but the wire-format parity check this test asserts is still valid.
    func testSignedTxWithJavaDerSigMatchesJavaBytes() throws {
        let vectors = try TestVectors.load()
        let unsigned = try buildSampleTransaction(from: vectors)
        let signedVec = vectors.bchSignedTx[0]
        let pubkey = Data(fromHex: vectors.sampleKey.pubkeyHex)

        let scriptSig = try ScriptBuilder.p2pkhInput(
            signature: Data(fromHex: signedVec.derSigHex),
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
    /// scriptSig parses back into a valid BCH-Schnorr signature for the
    /// same sighash. The signature is BCH 2019 Schnorr (64 bytes),
    /// because that's the only form FCH mainnet accepts on P2PKH spends.
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

        // Pull the signature out of scriptSig: layout is
        //   [push65 sig+sighash] [push33 pubkey]
        // First byte is the 65 push opcode; next 64 bytes are the
        // Schnorr sig and the 65th byte is the sighash flag (0x41).
        let scriptBytes = [UInt8](signed.inputs[0].scriptSig.bytes)
        XCTAssertEqual(scriptBytes[0], 65, "Schnorr+sighash push len")
        let schnorrSig = Data(scriptBytes[1..<65])
        XCTAssertEqual(scriptBytes[65], 0x41, "BCH sighash flag (ALL|FORKID)")

        // Recompute the sighash from the original unsigned tx and
        // verify the Schnorr signature.
        let pubkeyHash = Hash.hash160(pubkey)
        let scriptCode = try ScriptBuilder.p2pkhOutput(hash160: pubkeyHash).bytes
        let sighash = try BchSighash.sighash(
            tx: unsigned, inputIndex: 0,
            scriptCode: scriptCode, prevValueSats: prevValueSats
        )
        XCTAssertTrue(
            try BchSchnorr.verify(
                message: sighash, publicKey: pubkey, signature: schnorrSig
            )
        )

        // And the Swift-signed scriptSig should match the scriptSig we'd
        // build from a freshly-computed Schnorr sig — proves
        // TxHandler.signP2pkhInput composes signing + scripting correctly
        // (Schnorr is deterministic via SHA256(privkey || msg) nonce).
        let freshSig = try BchSchnorr.sign(message: sighash, privateKey: privkey)
        let expectedScriptSig = try ScriptBuilder.p2pkhInput(
            signature: freshSig, sighashFlag: 0x41, pubkey: pubkey
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
