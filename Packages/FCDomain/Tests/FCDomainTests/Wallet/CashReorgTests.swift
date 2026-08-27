import XCTest
import FCCore
@testable import FCDomain

/// The reorg planner — Android's four `ReorgCashActivity` strategies.
/// Fee arithmetic is asserted against the same size formula the send
/// path uses (`10 + 141*nIn + 34*nOut`), because a reorg that
/// mis-prices its own fee either burns money or produces a tx no node
/// will relay.
final class CashReorgTests: XCTestCase {

    private let owner = "FEbYaZFVKMBGCJfsMvVLnbQaKfBjPHtsWo"
    private let other = "FHfz2i4KLxCoKJEBAmDgFVJyekcaXQ9j9Y"

    private func cash(_ value: Int64, index: Int = 0, cd: Int64? = nil, owner: String? = nil) -> Cash {
        Cash(
            id: "id-\(index)-\(value)",
            owner: owner ?? self.owner,
            value: value,
            type: "P2PKH",
            birthTxId: String(repeating: "ab", count: 32),
            birthIndex: index,
            cd: cd
        )
    }

    private func size(_ nIn: Int, _ nOut: Int) -> Int {
        CoinSelector.sizeFor(nIn: nIn, nOut: nOut)
    }

    // MARK: - consolidate

    func testConsolidateFoldsEverythingIntoOneBill() throws {
        let inputs = (0..<5).map { cash(100_000, index: $0) }
        let plan = try CashReorg.plan(inputs: inputs, shape: .consolidate)

        let expectedSize = size(5, 1)                 // 10 + 705 + 34 = 749
        XCTAssertEqual(plan.estimatedSize, expectedSize)
        XCTAssertEqual(plan.fee, Int64(expectedSize))
        XCTAssertEqual(plan.outputs, [500_000 - Int64(expectedSize)])
        XCTAssertFalse(plan.hasChange)
        // Nothing is created or destroyed but the fee.
        XCTAssertEqual(plan.totalIn - plan.totalOut, plan.fee)
    }

    func testConsolidateHonoursFeeRate() throws {
        let inputs = [cash(100_000)]
        let plan = try CashReorg.plan(inputs: inputs, shape: .consolidate, feePerByte: 3)
        XCTAssertEqual(plan.fee, Int64(size(1, 1)) * 3)
        XCTAssertEqual(plan.outputs, [100_000 - plan.fee])
    }

    func testConsolidateRejectsDustResult() {
        // Two tiny cashes can't pay for the tx that would merge them.
        let inputs = [cash(400, index: 0), cash(400, index: 1)]
        XCTAssertThrowsError(try CashReorg.plan(inputs: inputs, shape: .consolidate)) { err in
            guard case CashReorg.Failure.insufficientFunds = err else {
                return XCTFail("wrong error: \(err)")
            }
        }
    }

    // MARK: - by count

    func testByCountSplitsIntoEqualBillsPlusRemainder() throws {
        let inputs = [cash(1_000_000)]
        let plan = try CashReorg.plan(inputs: inputs, shape: .byCount(4))

        let expectedSize = size(1, 4)                 // 10 + 141 + 136 = 287
        let available = 1_000_000 - Int64(expectedSize)
        let denomination = available / 4

        XCTAssertEqual(plan.outputs.count, 4)
        XCTAssertEqual(Array(plan.outputs.prefix(3)), Array(repeating: denomination, count: 3))
        XCTAssertEqual(plan.outputs.last, available - denomination * 3)
        XCTAssertTrue(plan.hasChange)
        XCTAssertEqual(plan.totalOut, available)
        XCTAssertEqual(plan.fee, Int64(expectedSize))
    }

    /// A count of one is a consolidation by another name — Android
    /// routes it the same way rather than emitting zero bills plus a
    /// change bill.
    func testByCountOfOneIsConsolidate() throws {
        let inputs = [cash(500_000, index: 0), cash(500_000, index: 1)]
        let byCount = try CashReorg.plan(inputs: inputs, shape: .byCount(1))
        let consolidated = try CashReorg.plan(inputs: inputs, shape: .consolidate)
        XCTAssertEqual(byCount, consolidated)
    }

    func testByCountRejectsPastTheOutputCap() {
        let inputs = [cash(100_000_000)]
        XCTAssertThrowsError(
            try CashReorg.plan(inputs: inputs, shape: .byCount(CashReorg.maxOutputs + 1))
        ) { err in
            guard case CashReorg.Failure.tooManyOutputs = err else {
                return XCTFail("wrong error: \(err)")
            }
        }
    }

    func testByCountRejectsWhenBillsWouldBeDust() {
        let inputs = [cash(3_000)]
        XCTAssertThrowsError(try CashReorg.plan(inputs: inputs, shape: .byCount(10))) { err in
            guard case CashReorg.Failure.insufficientFunds = err else {
                return XCTFail("wrong error: \(err)")
            }
        }
    }

    // MARK: - by amount

    func testByAmountIssuesAsManyBillsAsFit() throws {
        // 1 000 000 sat at 200 000 per bill = 5 bills, and 5 + change
        // is inside the 20-output cap, so all five are issued.
        let inputs = [cash(1_000_000)]
        let plan = try CashReorg.plan(inputs: inputs, shape: .byAmount(200_000))

        XCTAssertEqual(plan.outputs.count, 5)
        XCTAssertEqual(Array(plan.outputs.prefix(4)), Array(repeating: 200_000, count: 4))
        // Five bills would leave nothing for the fee, so the fifth
        // "bill" is the remainder: 4 × 200 000 + change.
        XCTAssertEqual(plan.totalOut, plan.totalIn - plan.fee)
    }

    /// The cap is on cashes *issued*, change included, so the most
    /// denomination bills a reorg can produce is 19.
    func testByAmountStopsAtNineteenBillsPlusChange() throws {
        let inputs = [cash(100_000_000)]
        let plan = try CashReorg.plan(inputs: inputs, shape: .byAmount(1_000_000))
        XCTAssertEqual(plan.outputs.count, CashReorg.maxOutputs)
        XCTAssertEqual(Array(plan.outputs.prefix(19)), Array(repeating: 1_000_000, count: 19))
        XCTAssertTrue(plan.hasChange)
    }

    /// When the requested denomination doesn't quite fit, the planner
    /// issues one bill fewer rather than failing — Android's shrink
    /// loop.
    func testByAmountShrinksUntilTheFeeFits() throws {
        // Two bills of 500 000 would need 1 000 000 + fee; the inputs
        // hold exactly 1 000 000, so only one bill can be issued.
        let inputs = [cash(1_000_000)]
        let plan = try CashReorg.plan(inputs: inputs, shape: .byAmount(500_000))
        XCTAssertEqual(plan.outputs.first, 500_000)
        XCTAssertEqual(plan.outputs.count, 2)         // 1 bill + change
        XCTAssertEqual(plan.totalOut + plan.fee, 1_000_000)
    }

    func testByAmountThrowsWhenEvenOneBillIsTooBig() {
        let inputs = [cash(10_000)]
        XCTAssertThrowsError(try CashReorg.plan(inputs: inputs, shape: .byAmount(50_000))) { err in
            guard case CashReorg.Failure.insufficientFunds = err else {
                return XCTFail("wrong error: \(err)")
            }
        }
    }

    // MARK: - exact

    func testExactIssuesExactlyWhatWasAsked() throws {
        let inputs = [cash(1_000_000)]
        let plan = try CashReorg.plan(inputs: inputs, shape: .exact(count: 3, amount: 100_000))

        let expectedSize = size(1, 4)                 // 3 bills + change
        XCTAssertEqual(plan.estimatedSize, expectedSize)
        XCTAssertEqual(Array(plan.outputs.prefix(3)), Array(repeating: 100_000, count: 3))
        XCTAssertEqual(plan.outputs.count, 4)
        XCTAssertEqual(plan.outputs.last, 1_000_000 - 300_000 - Int64(expectedSize))
        XCTAssertTrue(plan.hasChange)
    }

    /// A remainder too small to pay for its own 34 bytes goes to the
    /// miner instead of becoming a dust output no wallet wants.
    func testExactBurnsADustRemainderAsFee() throws {
        let noChangeSize = size(1, 2)
        // Leave 100 sat over the no-change fee: below the dust floor.
        let total = 200_000 * 2 + Int64(noChangeSize) + 100
        let inputs = [cash(total)]
        let plan = try CashReorg.plan(inputs: inputs, shape: .exact(count: 2, amount: 200_000))

        XCTAssertEqual(plan.outputs, [200_000, 200_000])
        XCTAssertFalse(plan.hasChange)
        XCTAssertEqual(plan.fee, Int64(noChangeSize) + 100)
        XCTAssertEqual(plan.totalIn - plan.totalOut, plan.fee)
    }

    func testExactThrowsWhenTheBillsDontFit() {
        let inputs = [cash(150_000)]
        XCTAssertThrowsError(
            try CashReorg.plan(inputs: inputs, shape: .exact(count: 2, amount: 100_000))
        ) { err in
            guard case CashReorg.Failure.insufficientFunds = err else {
                return XCTFail("wrong error: \(err)")
            }
        }
    }

    func testExactRejectsPastTheOutputCapCountingChange() {
        let inputs = [cash(100_000_000)]
        // 19 bills + change = 20 is fine; 20 bills + change is not.
        XCTAssertNoThrow(
            try CashReorg.plan(inputs: inputs, shape: .exact(count: 19, amount: 100_000))
        )
        XCTAssertThrowsError(
            try CashReorg.plan(inputs: inputs, shape: .exact(count: 20, amount: 100_000))
        ) { err in
            guard case CashReorg.Failure.tooManyOutputs = err else {
                return XCTFail("wrong error: \(err)")
            }
        }
    }

    // MARK: - guards

    func testRejectsEmptyInputs() {
        XCTAssertThrowsError(try CashReorg.plan(inputs: [], shape: .consolidate)) { err in
            guard case CashReorg.Failure.noInputs = err else {
                return XCTFail("wrong error: \(err)")
            }
        }
    }

    func testRejectsTooManyInputs() {
        let inputs = (0...CashReorg.maxInputs).map { cash(10_000, index: $0) }
        XCTAssertThrowsError(try CashReorg.plan(inputs: inputs, shape: .consolidate)) { err in
            guard case CashReorg.Failure.tooManyInputs = err else {
                return XCTFail("wrong error: \(err)")
            }
        }
    }

    /// Two owners means two keys, which is a different transaction
    /// entirely — better to say so than to build something only half
    /// of which can be signed.
    func testRejectsMixedOwners() {
        let inputs = [cash(100_000, index: 0), cash(100_000, index: 1, owner: other)]
        XCTAssertThrowsError(try CashReorg.plan(inputs: inputs, shape: .consolidate)) { err in
            guard case CashReorg.Failure.mixedOwners = err else {
                return XCTFail("wrong error: \(err)")
            }
        }
    }

    func testRejectsNonPositiveInputs() {
        let inputs = [cash(1_000_000)]
        XCTAssertThrowsError(try CashReorg.plan(inputs: inputs, shape: .byCount(0)))
        XCTAssertThrowsError(try CashReorg.plan(inputs: inputs, shape: .byAmount(0)))
        XCTAssertThrowsError(try CashReorg.plan(inputs: inputs, shape: .exact(count: 2, amount: 0)))
        XCTAssertThrowsError(try CashReorg.plan(inputs: inputs, shape: .consolidate, feePerByte: 0))
    }

    // MARK: - totals

    func testTotalCdSumsTheInputs() throws {
        let inputs = [
            cash(100_000, index: 0, cd: 3),
            cash(100_000, index: 1, cd: 4),
            cash(100_000, index: 2)          // nil cd counts as zero
        ]
        let plan = try CashReorg.plan(inputs: inputs, shape: .consolidate)
        XCTAssertEqual(plan.totalCd, 7)
    }
}
