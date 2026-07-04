import XCTest
@testable import FCDomain

final class CoinSelectorTests: XCTestCase {

    // MARK: - helpers

    private func cash(_ value: Int64, txidByte: UInt8 = 0xAA) -> Cash {
        // 64 hex chars = 32 bytes; varied by `txidByte` so equality
        // distinguishes cashes in tests.
        let txid = String(repeating: String(format: "%02x", txidByte), count: 32)
        return Cash(
            owner: "FAddr",
            value: value,
            type: "P2PKH",
            birthTxId: txid,
            birthIndex: 0
        )
    }

    // MARK: - happy paths

    func testSelectPicksLargestFirst() throws {
        let plan = try CoinSelector.select(
            cashes: [cash(100, txidByte: 1), cash(500, txidByte: 2), cash(50, txidByte: 3)],
            amount: 200
        )
        // Largest cash (500) covers 200 + fee comfortably; only 1 input needed.
        XCTAssertEqual(plan.selected.count, 1)
        XCTAssertEqual(plan.selected[0].value, 500)
    }

    func testSelectAddsChangeOutputWhenSurplusAboveDust() throws {
        let plan = try CoinSelector.select(
            cashes: [cash(10_000)],
            amount: 1_000,
            feePerByte: 1
        )
        // size = 10 + 141 + 34*2 = 219 bytes → fee = 219 sat
        // change = 10_000 - 1_000 - 219 = 8_781 sat → above 546 dust → has change
        XCTAssertTrue(plan.hasChange)
        XCTAssertEqual(plan.fee, 219)
        XCTAssertEqual(plan.change, 8_781)
        XCTAssertEqual(plan.estimatedSize, 219)
    }

    func testSelectDropsChangeWhenChangeWouldBeDust() throws {
        // Build a cash whose surplus over (amount + 2-output fee) is
        // below dust but covers (amount + 1-output fee).
        // 1-output size = 185 → fee 185. amount 1000 + fee 185 = 1185.
        // 2-output size = 219 → would-be change at sum=1500: 1500-1000-219=281 (dust).
        // → fall through to 1-output path; actualFee = 1500-1000 = 500.
        let plan = try CoinSelector.select(
            cashes: [cash(1_500)], amount: 1_000, feePerByte: 1
        )
        XCTAssertFalse(plan.hasChange)
        XCTAssertEqual(plan.change, 0)
        // No change output → leftover (1500 - 1000) all goes to fee.
        XCTAssertEqual(plan.fee, 500)
        XCTAssertEqual(plan.estimatedSize, 185)
    }

    func testSelectAggregatesMultipleInputsWhenSingleNotEnough() throws {
        let plan = try CoinSelector.select(
            cashes: [cash(700, txidByte: 1), cash(800, txidByte: 2), cash(50, txidByte: 3)],
            amount: 1_000
        )
        // Largest first: 800 alone — 800 - 1000 - fee < 0 — skip.
        // Add 700: sum 1500. 2-output fee for 2 inputs = 219 + 141 = 360
        // → 1500-1000-360=140 (dust). 1-output fee = 185 + 141 = 326
        // → 1500 >= 1326 → no-change branch. actualFee = 1500 - 1000 = 500.
        XCTAssertEqual(plan.selected.count, 2)
        XCTAssertEqual(plan.selected.map { $0.value }, [800, 700])
        XCTAssertEqual(plan.totalIn, 1500)
        XCTAssertFalse(plan.hasChange)
    }

    // MARK: - error cases

    func testSelectThrowsOnInsufficientFunds() {
        XCTAssertThrowsError(try CoinSelector.select(
            cashes: [cash(100)], amount: 1000
        )) { error in
            guard case CoinSelector.Failure.insufficientFunds = error else {
                XCTFail("wrong error: \(error)"); return
            }
        }
    }

    func testSelectThrowsOnNonPositiveAmount() {
        XCTAssertThrowsError(try CoinSelector.select(cashes: [], amount: 0))
        XCTAssertThrowsError(try CoinSelector.select(cashes: [], amount: -1))
    }

    func testSelectThrowsOnNonPositiveFeeRate() {
        XCTAssertThrowsError(try CoinSelector.select(
            cashes: [cash(1_000)], amount: 100, feePerByte: 0
        ))
    }

    // MARK: - size formula

    func testSizeFormulaMatchesBitcoinjConvention() {
        // 10 + 141*nIn + 34*nOut  (Schnorr P2PKH input is 141 B)
        XCTAssertEqual(CoinSelector.sizeFor(nIn: 1, nOut: 1), 185)
        XCTAssertEqual(CoinSelector.sizeFor(nIn: 1, nOut: 2), 219)
        XCTAssertEqual(CoinSelector.sizeFor(nIn: 3, nOut: 2), 501)
    }

    // MARK: - carve selection

    private func cdCash(_ value: Int64, cd: Int64?, txidByte: UInt8) -> Cash {
        let txid = String(repeating: String(format: "%02x", txidByte), count: 32)
        return Cash(
            owner: "FAddr", value: value, type: "P2PKH",
            birthTxId: txid, birthIndex: 0, cd: cd
        )
    }

    /// Android `calcOpReturnLen`: value(8) + scriptLen varint +
    /// (OP_RETURN(1) + pushdata prefix + data).
    func testOpReturnOutputBytesMatchesJavaFormula() {
        XCTAssertEqual(CoinSelector.opReturnOutputBytes(50), 8 + 1 + 52)    // direct push
        XCTAssertEqual(CoinSelector.opReturnOutputBytes(100), 8 + 1 + 103)  // PUSHDATA1
        XCTAssertEqual(CoinSelector.opReturnOutputBytes(300), 8 + 3 + 304)  // PUSHDATA2; scriptLen 304 ≥ 0xFD → 3-byte varint
    }

    func testCarveSelectWithChange() throws {
        let plan = try CoinSelector.selectForCarve(
            cashes: [cash(10_000)], opReturnByteCount: 100, feePerByte: 1
        )
        // size = sizeFor(1 in, 1 change out)=185 + opReturn 112 = 297
        XCTAssertEqual(plan.fee, 297)
        XCTAssertEqual(plan.change, 10_000 - 297)
        XCTAssertTrue(plan.hasChange)
    }

    func testCarveSelectBurnsDustAsFee() throws {
        // sum 700: with change the remainder (700-297=403) is dust →
        // no-change branch (size 151+112=263) → the whole 700 burns.
        let plan = try CoinSelector.selectForCarve(
            cashes: [cash(700)], opReturnByteCount: 100, feePerByte: 1
        )
        XCTAssertFalse(plan.hasChange)
        XCTAssertEqual(plan.fee, 700)
    }

    func testCarveSelectKeepsAddingInputsUntilCdCovered() throws {
        // Largest-first grabs the 10k cash, but it has no CoinDays —
        // the small aged cash must join before the plan can close.
        let plan = try CoinSelector.selectForCarve(
            cashes: [
                cdCash(10_000, cd: 0, txidByte: 1),
                cdCash(600, cd: 5, txidByte: 2)
            ],
            opReturnByteCount: 100,
            feePerByte: 1,
            requiredCd: 1
        )
        XCTAssertEqual(plan.selected.count, 2)
        XCTAssertEqual(plan.totalIn, 10_600)
        XCTAssertTrue(plan.hasChange)
    }

    func testCarveSelectThrowsWhenCoinDaysInsufficient() {
        XCTAssertThrowsError(try CoinSelector.selectForCarve(
            cashes: [cdCash(50_000, cd: 0, txidByte: 1)],
            opReturnByteCount: 100,
            feePerByte: 1,
            requiredCd: 1
        )) { error in
            guard case CoinSelector.Failure.insufficientCoinDays(1, 0) = error else {
                XCTFail("wrong error: \(error)"); return
            }
        }
    }

    func testCarveSelectThrowsOnInsufficientFunds() {
        XCTAssertThrowsError(try CoinSelector.selectForCarve(
            cashes: [cash(100)], opReturnByteCount: 300, feePerByte: 1
        )) { error in
            guard case CoinSelector.Failure.insufficientFunds = error else {
                XCTFail("wrong error: \(error)"); return
            }
        }
    }
}
