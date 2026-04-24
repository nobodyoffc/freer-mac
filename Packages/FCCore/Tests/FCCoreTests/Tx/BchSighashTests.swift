import XCTest
@testable import FCCore

final class BchSighashTests: XCTestCase {

    func testPreimageMatchesFreecashjVector() throws {
        let vectors = try TestVectors.load()
        let tx = try buildSampleTransaction(from: vectors)
        let sighashVector = vectors.bchSighash[0]

        let preimage = try BchSighash.preimage(
            tx: tx,
            inputIndex: sighashVector.inputIndex,
            scriptCode: Data(fromHex: sighashVector.scriptCodeHex),
            prevValueSats: sighashVector.prevValueSats,
            hashType: sighashVector.hashType
        )
        XCTAssertEqual(preimage.hex, sighashVector.preimageHex,
                       "preimage '\(sighashVector.label)'")
    }

    func testSighashMatchesFreecashjVector() throws {
        let vectors = try TestVectors.load()
        let tx = try buildSampleTransaction(from: vectors)
        let sighashVector = vectors.bchSighash[0]

        let sighash = try BchSighash.sighash(
            tx: tx,
            inputIndex: sighashVector.inputIndex,
            scriptCode: Data(fromHex: sighashVector.scriptCodeHex),
            prevValueSats: sighashVector.prevValueSats,
            hashType: sighashVector.hashType
        )
        XCTAssertEqual(sighash.hex, sighashVector.sighashHex,
                       "sighash '\(sighashVector.label)'")
    }

    /// The hashType field in the preimage has FORKID (0x40) set. The
    /// all-but-forkid value 0x01 must be rejected — accepting it silently
    /// would produce a legacy-Bitcoin sighash that an FCH node rejects.
    func testRejectsUnsupportedHashType() throws {
        let vectors = try TestVectors.load()
        let tx = try buildSampleTransaction(from: vectors)
        XCTAssertThrowsError(try BchSighash.sighash(
            tx: tx, inputIndex: 0,
            scriptCode: Data([0x00]),
            prevValueSats: 1,
            hashType: 0x01
        )) { error in
            guard case BchSighash.Failure.unsupportedHashType = error else {
                XCTFail("wrong error: \(error)"); return
            }
        }
    }

    func testRejectsBadInputIndex() throws {
        let vectors = try TestVectors.load()
        let tx = try buildSampleTransaction(from: vectors)
        XCTAssertThrowsError(try BchSighash.sighash(
            tx: tx, inputIndex: 5,
            scriptCode: Data([0x00]),
            prevValueSats: 1
        )) { error in
            guard case BchSighash.Failure.inputIndexOutOfRange = error else {
                XCTFail("wrong error: \(error)"); return
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
