import XCTest
@testable import FCDomain

/// CoinDays are counted locally with the parser's formula, because the
/// server's `cd` is only as fresh as the last time it indexed a cash.
final class CoinDaysTests: XCTestCase {

    private let coin = Cash.satoshisPerBch

    private func cash(value: Int64, birthHeight: Int64?, cd: Int64? = nil) -> Cash {
        Cash(
            owner: "FAddr", value: value, type: "P2PKH",
            birthTxId: String(repeating: "ab", count: 32), birthIndex: 0,
            birthHeight: birthHeight, cd: cd
        )
    }

    func testWholeDaysTimesCoins() {
        // 5 days and 100 blocks of age: the partial day doesn't count.
        let height: Int64 = 1_000 + 5 * Cash.blocksPerCoinDay + 100
        XCTAssertEqual(Cash.coinDays(value: 3 * coin, birthHeight: 1_000, atHeight: height), 15)
    }

    func testAgeUnderADayIsZero() {
        XCTAssertEqual(Cash.coinDays(value: 1_000 * coin, birthHeight: 1_000, atHeight: 1_000 + 1_439), 0)
    }

    func testFractionalCoinsRoundDown() {
        // 1.5 coins × 3 days = 4.5 → 4, as `Math.floorDiv` gives in Java.
        let height: Int64 = 1_000 + 3 * Cash.blocksPerCoinDay
        XCTAssertEqual(Cash.coinDays(value: 3 * coin / 2, birthHeight: 1_000, atHeight: height), 4)
    }

    func testHeightAtOrBeforeBirthIsZero() {
        XCTAssertEqual(Cash.coinDays(value: coin, birthHeight: 5_000, atHeight: 5_000), 0)
        XCTAssertEqual(Cash.coinDays(value: coin, birthHeight: 5_000, atHeight: 4_000), 0)
    }

    /// value × days overflows Int64 for a large enough cash; the result
    /// must still be exact.
    func testLargeCashDoesNotOverflow() {
        let value: Int64 = 21_000_000 * coin
        let days: Int64 = 100_000
        let height = days * Cash.blocksPerCoinDay
        XCTAssertEqual(Cash.coinDays(value: value, birthHeight: 0, atHeight: height), 21_000_000 * days)
    }

    func testWithCdReplacesTheServerFigure() {
        let stale = cash(value: 10 * coin, birthHeight: 1_000, cd: 0)
        let height: Int64 = 1_000 + 2 * Cash.blocksPerCoinDay
        XCTAssertEqual(stale.withCd(atHeight: height).cd, 20)
    }

    func testWithCdLeavesACashWithoutAnAgeAlone() {
        let unconfirmed = cash(value: 10 * coin, birthHeight: nil, cd: nil)
        XCTAssertNil(unconfirmed.withCd(atHeight: 900_000).cd)

        let noHeight = cash(value: 10 * coin, birthHeight: 1_000, cd: 7)
        XCTAssertEqual(noHeight.withCd(atHeight: nil).cd, 7)
    }

    func testSnapshotCountsAtTheLaterOfItsHeightAndTheOneGiven() {
        var snapshot = CashSnapshot(
            addr: "FAddr",
            cashes: [cash(value: coin, birthHeight: 1_000, cd: 0)],
            bestHeight: 1_000 + Cash.blocksPerCoinDay
        )
        snapshot.refreshCd()
        XCTAssertEqual(snapshot.cashes[0].cd, 1)

        snapshot.refreshCd(atHeight: 1_000 + 4 * Cash.blocksPerCoinDay)
        XCTAssertEqual(snapshot.cashes[0].cd, 4)

        // An older height never winds the count back.
        snapshot.bestHeight = 1_000 + 4 * Cash.blocksPerCoinDay
        snapshot.refreshCd(atHeight: 1_000)
        XCTAssertEqual(snapshot.cashes[0].cd, 4)
    }
}
