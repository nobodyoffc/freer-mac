import XCTest
import FCCore
@testable import FCDomain

final class TxBuilderTests: XCTestCase {

    // Two distinct legitimate FIDs derived from raw privkeys, so we
    // can assert recipient/change scripts by hash without needing the
    // FAPI server.
    private let aPrivkey = Data(repeating: 0x11, count: 32)
    private let bPrivkey = Data(repeating: 0x22, count: 32)

    private func fid(for privkey: Data) throws -> String {
        try FchAddress(publicKey: try Secp256k1.publicKey(fromPrivateKey: privkey)).fid
    }

    // MARK: - decodeTxid

    func testDecodeTxidReversesBytes() throws {
        // Display order: 01 02 03 ... 1F 20  (32 bytes)
        // Natural order: 20 1F 1E ... 03 02 01
        let display = (1...32).map { String(format: "%02x", $0) }.joined()
        let natural = try TxBuilder.decodeTxid(display)
        XCTAssertEqual(natural.count, 32)
        XCTAssertEqual(natural[0], 0x20)
        XCTAssertEqual(natural[31], 0x01)
    }

    func testDecodeTxidRejectsWrongLength() {
        XCTAssertThrowsError(try TxBuilder.decodeTxid("00"))
        XCTAssertThrowsError(try TxBuilder.decodeTxid(String(repeating: "0", count: 63)))
    }

    func testDecodeTxidRejectsNonHex() {
        XCTAssertThrowsError(try TxBuilder.decodeTxid(String(repeating: "z", count: 64)))
    }

    // MARK: - buildUnsigned

    func testBuildUnsignedShapeWithChange() throws {
        let aFid = try fid(for: aPrivkey)
        let bFid = try fid(for: bPrivkey)

        let utxoTxid = String(repeating: "ab", count: 32)
        let plan = CoinSelector.Plan(
            selected: [Utxo(addr: aFid, txid: utxoTxid, index: 1, value: 10_000)],
            change: 8_774,
            fee: 226,
            estimatedSize: 226
        )
        let tx = try TxBuilder.buildUnsigned(
            plan: plan, toFid: bFid, amount: 1_000, changeFid: aFid
        )

        XCTAssertEqual(tx.version, 2)
        XCTAssertEqual(tx.locktime, 0)
        XCTAssertEqual(tx.inputs.count, 1)
        XCTAssertEqual(tx.outputs.count, 2)

        // Input outpoint round-trips back to the same display txid.
        XCTAssertEqual(tx.inputs[0].outpoint.outIndex, 1)
        let restored = Data(tx.inputs[0].outpoint.prevTxHash.reversed())
            .map { String(format: "%02x", $0) }.joined()
        XCTAssertEqual(restored, utxoTxid)

        // scriptSig is empty pre-signing.
        XCTAssertEqual(tx.inputs[0].scriptSig.bytes.count, 0)

        // Output values match: amount, change.
        XCTAssertEqual(tx.outputs[0].value, 1_000)
        XCTAssertEqual(tx.outputs[1].value, 8_774)
    }

    func testBuildUnsignedNoChangeOutputWhenPlanHasNoChange() throws {
        let aFid = try fid(for: aPrivkey)
        let bFid = try fid(for: bPrivkey)

        let plan = CoinSelector.Plan(
            selected: [Utxo(addr: aFid, txid: String(repeating: "cc", count: 32), index: 0, value: 1_500)],
            change: 0,
            fee: 500,
            estimatedSize: 192
        )
        let tx = try TxBuilder.buildUnsigned(
            plan: plan, toFid: bFid, amount: 1_000, changeFid: aFid
        )
        XCTAssertEqual(tx.outputs.count, 1)
        XCTAssertEqual(tx.outputs[0].value, 1_000)
    }

    func testBuildUnsignedRejectsBadFid() {
        let plan = CoinSelector.Plan(
            selected: [Utxo(addr: "FAddr", txid: String(repeating: "11", count: 32), index: 0, value: 1)],
            change: 0,
            fee: 0,
            estimatedSize: 0
        )
        XCTAssertThrowsError(try TxBuilder.buildUnsigned(
            plan: plan, toFid: "not-a-fid", amount: 1, changeFid: "also-not"
        )) { error in
            guard case TxBuilder.Failure.invalidFid = error else {
                XCTFail("wrong error: \(error)"); return
            }
        }
    }
}
