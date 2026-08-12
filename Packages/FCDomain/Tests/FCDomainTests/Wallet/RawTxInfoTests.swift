import XCTest
@testable import FCDomain

/// Phase 7.8.3: the unsigned-tx export document. The JSON must stay
/// in Android's `RawTxInfo` dialect (ver "2") so `CreateTxActivity`
/// can import and sign it.
final class RawTxInfoTests: XCTestCase {

    private func sampleCash(value: Int64 = 5_000_000) -> Cash {
        Cash(
            id: "cash-id-is-local-only",
            owner: "FEk41Kqjar45fLDriztUDTUkdki7mmcjWK",
            value: value,
            birthTxId: String(repeating: "ab", count: 32),
            birthIndex: 1,
            lockScript: "76a914000000000000000000000000000000000000000088ac",
            cd: 42,
            localState: .unknown,
            pendingSpend: true
        )
    }

    func testInputSlotKeepsOnlyAndroidPayFields() throws {
        let slot = RawTxInfo.Slot.input(from: sampleCash())

        XCTAssertEqual(slot.owner, "FEk41Kqjar45fLDriztUDTUkdki7mmcjWK")
        XCTAssertEqual(slot.value, 5_000_000)
        XCTAssertEqual(slot.birthTxId, String(repeating: "ab", count: 32))
        XCTAssertEqual(slot.birthIndex, 1)
        XCTAssertEqual(slot.cd, 42)
        XCTAssertNil(slot.redeemScript)
        XCTAssertNil(slot.lockTime)

        // Mac-local bookkeeping must not survive into the wire JSON.
        let json = String(
            decoding: try JSONEncoder().encode(slot), as: UTF8.self
        )
        XCTAssertFalse(json.contains("localState"))
        XCTAssertFalse(json.contains("pendingSpend"))
        XCTAssertFalse(json.contains("lockScript"))
        XCTAssertFalse(json.contains("cash-id-is-local-only"))
    }

    func testExportJsonRoundTripsAndCarriesVersion2() throws {
        let info = RawTxInfo(
            sender: "FEk41Kqjar45fLDriztUDTUkdki7mmcjWK",
            feeRate: RawTxInfo.feeRate(satsPerByte: 1),
            inputs: [.input(from: sampleCash())],
            outputs: [.output(to: "FUmo2eez6VK2sfGWjek9i9aK5ZZAxbtcXF", amount: 1_000_000)],
            changeTo: "FEk41Kqjar45fLDriztUDTUkdki7mmcjWK"
        )

        let json = try info.exportJson()
        XCTAssertTrue(json.contains("\"ver\" : \"2\""))

        let decoded = try RawTxInfo.fromJson(json)
        XCTAssertEqual(decoded, info)

        // Deterministic export — same tx, same bytes, same QR codes.
        XCTAssertEqual(try info.exportJson(), json)
    }

    func testFeeRateMatchesAndroidCalcFeeInverse() {
        // Android: feeRateLong = feeRate / 1000 * 1e8 (sat/byte).
        // 1 sat/byte → 0.00001 (TxHandler.DEFAULT_FEE_RATE).
        XCTAssertEqual(RawTxInfo.feeRate(satsPerByte: 1), 0.00001, accuracy: 1e-12)
        let roundTripped = RawTxInfo.feeRate(satsPerByte: 5) / 1000 * 100_000_000
        XCTAssertEqual(Int64(roundTripped), 5)
    }

    func testDecodesAndroidShapedJson() throws {
        // Hand-written in the Android field layout (Gson output).
        let android = """
        {
          "sender": "FEk41Kqjar45fLDriztUDTUkdki7mmcjWK",
          "feeRate": 0.00001,
          "inputs": [
            {"birthTxId": "\(String(repeating: "cd", count: 32))",
             "birthIndex": 0, "value": 200000,
             "owner": "FEk41Kqjar45fLDriztUDTUkdki7mmcjWK", "cd": 7}
          ],
          "outputs": [
            {"owner": "FUmo2eez6VK2sfGWjek9i9aK5ZZAxbtcXF", "value": 100000}
          ],
          "changeTo": "FEk41Kqjar45fLDriztUDTUkdki7mmcjWK",
          "cd": 0,
          "ver": "2"
        }
        """
        let decoded = try RawTxInfo.fromJson(android)
        XCTAssertEqual(decoded.ver, "2")
        XCTAssertEqual(decoded.inputs?.count, 1)
        XCTAssertEqual(decoded.inputs?.first?.birthIndex, 0)
        XCTAssertEqual(decoded.outputs?.first?.value, 100_000)
    }
}
