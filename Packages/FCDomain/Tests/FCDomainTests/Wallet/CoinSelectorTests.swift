import XCTest
@testable import FCDomain

final class CoinSelectorTests: XCTestCase {

    // MARK: - helpers

    private func utxo(_ value: Int64, txidByte: UInt8 = 0xAA) -> Utxo {
        // 64 hex chars = 32 bytes; varied by `txidByte` so equality
        // distinguishes utxos in tests.
        let txid = String(repeating: String(format: "%02x", txidByte), count: 32)
        return Utxo(addr: "FAddr", txid: txid, index: 0, value: value)
    }

    // MARK: - happy paths

    func testSelectPicksLargestFirst() throws {
        let plan = try CoinSelector.select(
            utxos: [utxo(100, txidByte: 1), utxo(500, txidByte: 2), utxo(50, txidByte: 3)],
            amount: 200
        )
        // Largest UTXO (500) covers 200 + fee comfortably; only 1 input needed.
        XCTAssertEqual(plan.selected.count, 1)
        XCTAssertEqual(plan.selected[0].value, 500)
    }

    func testSelectAddsChangeOutputWhenSurplusAboveDust() throws {
        let plan = try CoinSelector.select(
            utxos: [utxo(10_000)],
            amount: 1_000,
            feePerByte: 1
        )
        // size = 10 + 148 + 34*2 = 226 bytes → fee = 226 sat
        // change = 10_000 - 1_000 - 226 = 8_774 sat → above 546 dust → has change
        XCTAssertTrue(plan.hasChange)
        XCTAssertEqual(plan.fee, 226)
        XCTAssertEqual(plan.change, 8_774)
        XCTAssertEqual(plan.estimatedSize, 226)
    }

    func testSelectDropsChangeWhenChangeWouldBeDust() throws {
        // Build a UTXO whose surplus over (amount + 2-output fee) is
        // below dust but covers (amount + 1-output fee).
        // 1-output size = 192 → fee 192. amount 1000 + fee 192 = 1192.
        // 2-output size = 226 → would-be change at sum=1500: 1500-1000-226=274 (dust).
        // → fall through to 1-output path; actualFee = 1500-1000 = 500.
        let plan = try CoinSelector.select(
            utxos: [utxo(1_500)], amount: 1_000, feePerByte: 1
        )
        XCTAssertFalse(plan.hasChange)
        XCTAssertEqual(plan.change, 0)
        // No change output → leftover (1500 - 1000) all goes to fee.
        XCTAssertEqual(plan.fee, 500)
        XCTAssertEqual(plan.estimatedSize, 192)
    }

    func testSelectAggregatesMultipleInputsWhenSingleNotEnough() throws {
        let plan = try CoinSelector.select(
            utxos: [utxo(700, txidByte: 1), utxo(800, txidByte: 2), utxo(50, txidByte: 3)],
            amount: 1_000
        )
        // Largest first: 800 alone — 800 - 1000 - fee < 0 — skip.
        // Add 700: sum 1500, 2-output fee = 226 + 148 = 374 → 1500-1000-374=126 (dust).
        // 1-output fee = 192 + 148 = 340 → 1500 >= 1340 → no-change branch.
        // actualFee = 1500 - 1000 = 500.
        XCTAssertEqual(plan.selected.count, 2)
        XCTAssertEqual(plan.selected.map { $0.value }, [800, 700])
        XCTAssertEqual(plan.totalIn, 1500)
        XCTAssertFalse(plan.hasChange)
    }

    // MARK: - error cases

    func testSelectThrowsOnInsufficientFunds() {
        XCTAssertThrowsError(try CoinSelector.select(
            utxos: [utxo(100)], amount: 1000
        )) { error in
            guard case CoinSelector.Failure.insufficientFunds = error else {
                XCTFail("wrong error: \(error)"); return
            }
        }
    }

    func testSelectThrowsOnNonPositiveAmount() {
        XCTAssertThrowsError(try CoinSelector.select(utxos: [], amount: 0))
        XCTAssertThrowsError(try CoinSelector.select(utxos: [], amount: -1))
    }

    func testSelectThrowsOnNonPositiveFeeRate() {
        XCTAssertThrowsError(try CoinSelector.select(
            utxos: [utxo(1_000)], amount: 100, feePerByte: 0
        ))
    }

    // MARK: - size formula

    func testSizeFormulaMatchesBitcoinjConvention() {
        // 10 + 148*nIn + 34*nOut
        XCTAssertEqual(CoinSelector.sizeFor(nIn: 1, nOut: 1), 192)
        XCTAssertEqual(CoinSelector.sizeFor(nIn: 1, nOut: 2), 226)
        XCTAssertEqual(CoinSelector.sizeFor(nIn: 3, nOut: 2), 522)
    }
}
