import XCTest
@testable import FCDomain

/// The notice-fee policy: unit conversion at the chain boundary, the
/// spending cap, and the reply pay-back rule.
final class NoticeFeeTests: XCTestCase {

    // MARK: - units

    /// `Freer.noticeFee` is a decimal string in coins. Everything past
    /// this function is satoshis.
    func testCoinStringToSatoshis() {
        XCTAssertEqual(NoticeFee.satoshis(coinString: "1"), 100_000_000)
        XCTAssertEqual(NoticeFee.satoshis(coinString: "0.0001"), 10_000)
        XCTAssertEqual(NoticeFee.satoshis(coinString: "0.00000001"), 1)
        XCTAssertEqual(NoticeFee.satoshis(coinString: "0"), 0)
        XCTAssertEqual(NoticeFee.satoshis(coinString: " 0.5 "), 50_000_000)
        XCTAssertEqual(NoticeFee.satoshis(coinString: "100"), 10_000_000_000)
    }

    /// 0.0001 has no exact binary representation, so a `Double` route
    /// can land a satoshi short. Decimal does not.
    func testSmallFeesAreExactNotFloatRounded() {
        for (coins, sats) in [("0.0001", 10_000), ("0.0003", 30_000),
                              ("0.07", 7_000_000), ("0.29", 29_000_000)] {
            XCTAssertEqual(NoticeFee.satoshis(coinString: coins), Int64(sats), coins)
        }
    }

    /// Anything unusable reads as "published nothing", which the caller
    /// turns into the default fee — the shape of Android's null check,
    /// widened to cover what `Double.parseDouble` would throw on.
    func testUnusableStringsAreNil() {
        for bad in [nil, "", "   ", "abc", "-1", "+1", ".", "0x10", "1,5",
                    "NaN", "1e999999", "1.2.3", "1 000", "0.0001F"] {
            XCTAssertNil(NoticeFee.satoshis(coinString: bad), String(describing: bad))
        }
    }

    /// `Decimal(string:)` stops at the first character it cannot read
    /// and reports success on the prefix, so "1,5" would parse as 1 —
    /// a third of what the record meant. These must be rejected, not
    /// truncated.
    func testPrefixParsingTrapsAreRejectedRatherThanTruncated() {
        XCTAssertNil(NoticeFee.satoshis(coinString: "1,5"))
        XCTAssertNil(NoticeFee.satoshis(coinString: "0.5abc"))
        XCTAssertEqual(NoticeFee.satoshis(coinString: "1.5"), 150_000_000)
    }

    func testSatoshisBackToCoinString() {
        XCTAssertEqual(NoticeFee.coinString(satoshis: 10_000), "0.0001")
        XCTAssertEqual(NoticeFee.coinString(satoshis: 100_000_000), "1")
        XCTAssertEqual(NoticeFee.coinString(satoshis: 0), "0")
        XCTAssertEqual(NoticeFee.coinString(satoshis: 1), "0.00000001")
        XCTAssertEqual(NoticeFee.coinString(satoshis: 150_000_000), "1.5")
    }

    func testUnitRoundTrip() {
        for sats: Int64 in [1, 546, 10_000, 12_345_678, 100_000_000, 10_000_000_000] {
            XCTAssertEqual(
                NoticeFee.satoshis(coinString: NoticeFee.coinString(satoshis: sats)),
                sats
            )
        }
    }

    // MARK: - policy

    func testUnpublishedFeeFallsBackToTheDefault() {
        XCTAssertEqual(NoticeFee.decide(recipientNoticeFee: nil), .pay(10_000))
        XCTAssertEqual(NoticeFee.decide(recipientNoticeFee: "garbage"), .pay(10_000))
    }

    func testPublishedFeeIsHonoured() {
        XCTAssertEqual(NoticeFee.decide(recipientNoticeFee: "0.5"), .pay(50_000_000))
    }

    func testFeeOverTheLimitIsRefusedWithBothNumbers() {
        let decision = NoticeFee.decide(
            recipientNoticeFee: "200", maxPayingSats: 100 * NoticeFee.satsPerCoin
        )
        XCTAssertEqual(
            decision,
            .refuse(requested: 200 * NoticeFee.satsPerCoin, limit: 100 * NoticeFee.satsPerCoin)
        )
        XCTAssertNil(decision.satoshis, "a refusal has nothing to spend")
    }

    func testLimitIsInclusive() {
        XCTAssertEqual(
            NoticeFee.decide(recipientNoticeFee: "1", maxPayingSats: NoticeFee.satsPerCoin),
            .pay(NoticeFee.satsPerCoin)
        )
    }

    /// The payment is the addressing, so it cannot vanish. A FID that
    /// charges nothing still gets a dust output, or the mail would have
    /// no recipient at all.
    func testAZeroFeeStillPaysTheMinimum() {
        XCTAssertEqual(
            NoticeFee.decide(recipientNoticeFee: "0"),
            .pay(NoticeFee.minimumPayableSats)
        )
        XCTAssertEqual(
            NoticeFee.decide(recipientNoticeFee: "0.000001"),
            .pay(NoticeFee.minimumPayableSats)
        )
    }

    // MARK: - pay-back on reply

    func testReplyMatchesALargerFeeTheyPaidUs() {
        XCTAssertEqual(
            NoticeFee.decide(recipientNoticeFee: "0.0001", receivedNoticeFeeSats: 5_000_000),
            .pay(5_000_000)
        )
    }

    func testReplyDoesNotUndercutTheirPublishedFee() {
        // They paid us less than they charge — we still pay what they ask.
        XCTAssertEqual(
            NoticeFee.decide(recipientNoticeFee: "0.5", receivedNoticeFeeSats: 10_000),
            .pay(50_000_000)
        )
    }

    func testPayBackCanBeTurnedOff() {
        XCTAssertEqual(
            NoticeFee.decide(
                recipientNoticeFee: "0.0001", payBack: false, receivedNoticeFeeSats: 5_000_000
            ),
            .pay(10_000)
        )
    }

    /// Our deliberate divergence from Android, which applies the cap
    /// *before* the pay-back bump and so lets a reply pay any amount at
    /// all. A limit a correspondent can step around by attaching a
    /// large fee to their mail is not a limit.
    func testPayBackIsStillSubjectToTheLimit() {
        let decision = NoticeFee.decide(
            recipientNoticeFee: "0.0001",
            maxPayingSats: 1 * NoticeFee.satsPerCoin,
            receivedNoticeFeeSats: 500 * NoticeFee.satsPerCoin
        )
        XCTAssertEqual(
            decision,
            .refuse(requested: 500 * NoticeFee.satsPerCoin, limit: NoticeFee.satsPerCoin)
        )
    }

    /// A fresh mail has nothing to pay back.
    func testNoReplyContextMeansNoBump() {
        XCTAssertEqual(
            NoticeFee.decide(recipientNoticeFee: "0.0001", receivedNoticeFeeSats: nil),
            .pay(10_000)
        )
    }
}
