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

/// The `NoticeFee` FEIP (sn 10 ver 1) — publishing what you charge to
/// receive mail.
final class NoticeFeeFeipTests: XCTestCase {

    private func data(_ carve: String) throws -> [String: Any] {
        let root = try XCTUnwrap(
            JSONSerialization.jsonObject(with: Data(carve.utf8)) as? [String: Any]
        )
        XCTAssertEqual(root["type"] as? String, "FEIP")
        XCTAssertEqual(root["sn"] as? String, "10")
        XCTAssertEqual(root["ver"] as? String, "1")
        XCTAssertEqual(root["name"] as? String, "NoticeFee")
        return try XCTUnwrap(root["data"] as? [String: Any])
    }

    /// The value goes on the wire as a **coin-denominated string** — the
    /// one place a fee leaves satoshis, because that is how it lands on
    /// `Freer.noticeFee` and how every sender reads it back.
    func testCarveCarriesCoinsAsAString() throws {
        let payload = try data(try NoticeFeeFeip.carve(satoshis: 10_000))
        XCTAssertEqual(payload["noticeFee"] as? String, "0.0001")
        XCTAssertEqual(Set(payload.keys), ["noticeFee"], "the protocol has no op field")
    }

    func testCarveNormalisesTheAmount() throws {
        XCTAssertEqual(
            try data(try NoticeFeeFeip.carve(satoshis: 100_000_000))["noticeFee"] as? String,
            "1"
        )
        XCTAssertEqual(
            try data(try NoticeFeeFeip.carve(satoshis: 150_000_000))["noticeFee"] as? String,
            "1.5"
        )
    }

    /// Publishing zero is a real statement — "I don't charge" — and is
    /// how you stop charging, since the protocol has no delete.
    func testZeroIsPublishable() throws {
        XCTAssertEqual(try data(try NoticeFeeFeip.carve(satoshis: 0))["noticeFee"] as? String, "0")
    }

    /// A published fee can only be changed by another carve, so one
    /// typo'd zero would make the FID unreachable. The ceiling is ours,
    /// not the protocol's.
    func testAbsurdlyHighFeesAreRefused() {
        XCTAssertThrowsError(
            try NoticeFeeFeip.carve(satoshis: NoticeFee.maxPublishableSats + 1)
        ) { error in
            guard case NoticeFeeFeip.Failure.tooLarge = error else {
                return XCTFail("expected tooLarge, got \(error)")
            }
        }
        XCTAssertNoThrow(try NoticeFeeFeip.carve(satoshis: NoticeFee.maxPublishableSats))
    }

    func testNegativeFeesAreRefused() {
        XCTAssertThrowsError(try NoticeFeeFeip.carve(satoshis: -1)) { error in
            guard case NoticeFeeFeip.Failure.negative = error else {
                return XCTFail("expected negative, got \(error)")
            }
        }
    }

    /// What we publish must be what a sender's `decide` reads back.
    func testPublishedFeeRoundTripsThroughThePolicy() throws {
        for sats: Int64 in [0, 546, 10_000, 50_000_000, 100_000_000] {
            let payload = try data(try NoticeFeeFeip.carve(satoshis: sats))
            let published = try XCTUnwrap(payload["noticeFee"] as? String)
            let decision = NoticeFee.decide(recipientNoticeFee: published)
            XCTAssertEqual(decision, .pay(max(sats, NoticeFee.minimumPayableSats)), published)
        }
    }
}
