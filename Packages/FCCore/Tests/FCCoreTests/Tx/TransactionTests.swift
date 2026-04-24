import XCTest
@testable import FCCore

final class TransactionTests: XCTestCase {

    func testSerializationMatchesVectors() throws {
        let vectors = try TestVectors.load()
        XCTAssertFalse(vectors.transaction.isEmpty)
        for vector in vectors.transaction {
            let tx = try buildTransaction(from: vector)
            XCTAssertEqual(tx.serialized.hex, vector.serializedHex,
                           "serialized '\(vector.label)'")
        }
    }

    func testTxidMatchesVectors() throws {
        let vectors = try TestVectors.load()
        for vector in vectors.transaction {
            let tx = try buildTransaction(from: vector)
            XCTAssertEqual(tx.txid.hex, vector.txidNaturalHex,
                           "txid natural '\(vector.label)'")
            XCTAssertEqual(tx.txidDisplay, vector.txidDisplayHex,
                           "txid display '\(vector.label)'")
        }
    }

    /// Sanity check of the field wiring — serialization begins with the
    /// little-endian version and ends with the little-endian locktime.
    /// If either end is off by a byte, every other test silently shifts.
    func testVersionAndLocktimeFraming() throws {
        let tx = Transaction(
            version: 2,
            inputs: [],
            outputs: [],
            locktime: 0x11223344
        )
        let bytes = tx.serialized
        XCTAssertEqual(bytes.prefix(4).hex, "02000000")
        XCTAssertEqual(bytes.suffix(4).hex, "44332211")
    }

    func testOutPointRejectsBadHashLength() {
        XCTAssertThrowsError(try OutPoint(prevTxHash: Data(repeating: 0, count: 31), outIndex: 0))
    }

    // MARK: - helper

    private func buildTransaction(from vector: TestVectors.TransactionCase) throws -> Transaction {
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
