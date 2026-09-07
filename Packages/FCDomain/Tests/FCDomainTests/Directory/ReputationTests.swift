import XCTest
import FCCore
import FCTransport
@testable import FCDomain

/// FEIP16 (`Reputation`): the carve's wire shape, the rating-history
/// query, and the two rules that are easy to get wrong — the ratee is
/// `data.fid` (not the envelope's `did`, and not an output), and only
/// `good`/`bad` carry a score.
final class ReputationTests: XCTestCase {

    /// A real FCH address — the builder validates the ratee, so a
    /// placeholder string would fail every carve in this file.
    private static let ratee = try! FchAddress(
        publicKey: Secp256k1.publicKey(fromPrivateKey: Data(repeating: 0xC3, count: 32))
    ).fid

    // MARK: - the carve

    func testCarveShapeMatchesTheProtocol() throws {
        let json = try ReputationFeip.carve(
            ratee: Self.ratee, rate: .good, cause: "Helpful contributor"
        )
        let obj = try XCTUnwrap(
            JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String: Any]
        )
        XCTAssertEqual(obj["type"] as? String, "FEIP")
        XCTAssertEqual(obj["sn"] as? String, "16")
        XCTAssertEqual(obj["ver"] as? String, "1")
        XCTAssertEqual(obj["name"] as? String, "Reputation")

        let data = try XCTUnwrap(obj["data"] as? [String: Any])
        XCTAssertEqual(data["fid"] as? String, Self.ratee)
        XCTAssertEqual(data["rate"] as? String, "good")
        XCTAssertEqual(data["cause"] as? String, "Helpful contributor")
    }

    /// The ratee belongs in `data.fid` and nowhere else. The envelope's
    /// `did` is FEIP0's *document* id — Android puts the ratee there,
    /// which is why its ratings land on nobody — so this asserts we
    /// emit no such field, and that a minimal carve is exactly the two
    /// fields the protocol needs.
    func testRateeIsInDataAndNotInDid() throws {
        let json = try ReputationFeip.carve(ratee: Self.ratee, rate: .bad, cause: nil)
        let obj = try XCTUnwrap(
            JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String: Any]
        )
        XCTAssertNil(obj["did"])
        XCTAssertNil(obj["pid"])
        let data = try XCTUnwrap(obj["data"] as? [String: Any])
        XCTAssertEqual(data.keys.sorted(), ["fid", "rate"])
        XCTAssertEqual(data["fid"] as? String, Self.ratee)
    }

    /// A ratee that is not an FCH address is refused before anything is
    /// built: the carve would confirm, cost the fee and the CoinDays,
    /// and match no `Freer`.
    func testMalformedRateeIsRefused() {
        for bad in ["", "   ", "not-an-address", "FZZZ"] {
            XCTAssertThrowsError(
                try ReputationFeip.carve(ratee: bad, rate: .good), "accepted \(bad)"
            ) { error in
                guard case ReputationFeip.Failure.rateeNotAnFid = error else {
                    return XCTFail("expected .rateeNotAnFid for \(bad), got \(error)")
                }
            }
        }
    }

    func testRateeIsTrimmed() throws {
        let json = try ReputationFeip.carve(ratee: "  \(Self.ratee)\n", rate: .good)
        let data = try XCTUnwrap(
            (JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String: Any])?["data"]
                as? [String: Any]
        )
        XCTAssertEqual(data["fid"] as? String, Self.ratee)
    }

    /// A blank cause is omitted, not carved as `""` — Gson drops the
    /// null on the Android side and an empty string would be a shape no
    /// other client writes.
    func testBlankCauseIsOmittedAndWhitespaceTrimmed() throws {
        let blank = try ReputationFeip.carve(ratee: Self.ratee, rate: .good, cause: "   \n ")
        let blankData = try XCTUnwrap(
            (JSONSerialization.jsonObject(with: Data(blank.utf8)) as? [String: Any])?["data"]
                as? [String: Any]
        )
        XCTAssertNil(blankData["cause"])

        let padded = try ReputationFeip.carve(ratee: Self.ratee, rate: .good, cause: "  well met  ")
        let paddedData = try XCTUnwrap(
            (JSONSerialization.jsonObject(with: Data(padded.utf8)) as? [String: Any])?["data"]
                as? [String: Any]
        )
        XCTAssertEqual(paddedData["cause"] as? String, "well met")
    }

    func testOversizedCauseIsRefusedRatherThanTruncated() {
        let huge = String(repeating: "x", count: ReputationFeip.maxOpReturnSize + 1)
        XCTAssertThrowsError(try ReputationFeip.carve(ratee: Self.ratee, rate: .good, cause: huge)) { error in
            guard case ReputationFeip.Failure.tooLarge = error else {
                return XCTFail("expected .tooLarge, got \(error)")
            }
        }
    }

    func testMaxCauseBytesActuallyFits() throws {
        let budget = ReputationFeip.maxCauseBytes(ratee: Self.ratee, rate: .good)
        XCTAssertGreaterThan(budget, 0)
        let cause = String(repeating: "y", count: budget)
        let json = try ReputationFeip.carve(ratee: Self.ratee, rate: .good, cause: cause)
        XCTAssertLessThanOrEqual(json.utf8.count, ReputationFeip.maxOpReturnSize)
    }

    func testRateSignMatchesTheDelta() {
        XCTAssertEqual(Rate.good.sign, 1)
        XCTAssertEqual(Rate.bad.sign, -1)
    }

    func testWeightFormulaMatchesTheReferenceRatios() {
        // 40 % CD + 10 % CDD + 50 % reputation, integer-divided.
        XCTAssertEqual(WeightMethod.weight(cd: 100, cdd: 100, reputation: 100), 100)
        XCTAssertEqual(WeightMethod.weight(cd: 0, cdd: 0, reputation: 0), 0)
        // A bad-rated FID can weigh less than its coin-days alone.
        XCTAssertEqual(WeightMethod.weight(cd: 100, cdd: 0, reputation: -100), -10)
    }

    // MARK: - the history

    func testReceivedSendsTermsQueryOnRateeAndDecodesRows() async throws {
        let mock = MockFapiClient()
        mock.responder = { call in
            XCTAssertEqual(call.api, "base.search")
            var resp = try makeResponse(data: [
                [
                    "id": "txid-1", "height": 900_100, "index": 3, "time": 1_770_000_000,
                    "ratee": "FRatee", "rater": "FRaterA",
                    "reputation": 250, "hot": 250, "rate": "good", "cause": "paid on time"
                ],
                [
                    "id": "txid-2", "height": 900_000,
                    "ratee": "FRatee", "rater": "FRaterB",
                    "reputation": -40, "hot": 40, "rate": "bad"
                ]
            ])
            resp.total = 2
            resp.last = ["900000", "txid-2"]
            return resp
        }

        let page = try await ReputationService(fapi: mock).received(by: "FRatee", size: 25)

        XCTAssertEqual(page.ratings.count, 2)
        XCTAssertEqual(page.total, 2)
        XCTAssertEqual(page.ratings.first?.kind, .good)
        XCTAssertEqual(page.ratings.first?.hot, 250)
        XCTAssertEqual(page.ratings.first?.cause, "paid on time")
        // A bad rating still raises hot; only reputation goes negative.
        XCTAssertEqual(page.ratings.last?.kind, .bad)
        XCTAssertEqual(page.ratings.last?.hot, 40)
        XCTAssertEqual(page.ratings.last?.reputation, -40)
        XCTAssertEqual(page.ratings.last?.cursor, ["900000", "txid-2"])

        let call = try XCTUnwrap(mock.recorded.first)
        let dict = try XCTUnwrap(
            JSONSerialization.jsonObject(with: try XCTUnwrap(call.fcdsl)) as? [String: Any]
        )
        XCTAssertEqual(dict["entity"] as? String, "reputation_history")
        XCTAssertEqual(dict["size"] as? String, "25")
        XCTAssertNil(dict["after"])
        let terms = try XCTUnwrap(
            (dict["query"] as? [String: Any])?["terms"] as? [String: Any]
        )
        XCTAssertEqual(terms["fields"] as? [String], ["ratee"])
        XCTAssertEqual(terms["values"] as? [String], ["FRatee"])
        let sort = try XCTUnwrap(dict["sort"] as? [[String: String]])
        XCTAssertEqual(sort.map { $0["field"] }, ["height", "id"])
        XCTAssertEqual(sort.map { $0["order"] }, ["desc", "desc"])
    }

    func testGivenQueriesTheRaterSide() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in try makeResponse(data: [[String: Any]]()) }

        _ = try await ReputationService(fapi: mock).given(by: "FRaterA")

        let dict = try XCTUnwrap(
            JSONSerialization.jsonObject(
                with: try XCTUnwrap(mock.recorded.first?.fcdsl)
            ) as? [String: Any]
        )
        let terms = try XCTUnwrap(
            (dict["query"] as? [String: Any])?["terms"] as? [String: Any]
        )
        XCTAssertEqual(terms["fields"] as? [String], ["rater"])
    }

    /// "Have I rated them" is narrowed server-side, so the answer does
    /// not depend on how many pages we happened to pull.
    func testRatingsByOfNarrowsWithAFilter() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in try makeResponse(data: [[String: Any]]()) }

        _ = try await ReputationService(fapi: mock).ratings(by: "FMine", of: "FTheirs")

        let dict = try XCTUnwrap(
            JSONSerialization.jsonObject(
                with: try XCTUnwrap(mock.recorded.first?.fcdsl)
            ) as? [String: Any]
        )
        let query = try XCTUnwrap((dict["query"] as? [String: Any])?["terms"] as? [String: Any])
        XCTAssertEqual(query["values"] as? [String], ["FTheirs"])
        let filter = try XCTUnwrap((dict["filter"] as? [String: Any])?["terms"] as? [String: Any])
        XCTAssertEqual(filter["fields"] as? [String], ["rater"])
        XCTAssertEqual(filter["values"] as? [String], ["FMine"])
    }

    func testAfterCursorIsPassedThrough() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in try makeResponse(data: [[String: Any]]()) }

        _ = try await ReputationService(fapi: mock)
            .received(by: "FRatee", after: ["900000", "txid-2"])

        let dict = try XCTUnwrap(
            JSONSerialization.jsonObject(
                with: try XCTUnwrap(mock.recorded.first?.fcdsl)
            ) as? [String: Any]
        )
        XCTAssertEqual(dict["after"] as? [String], ["900000", "txid-2"])
    }

    /// Most FIDs have never been rated, and the index answers that with
    /// a 404. An empty page, not a thrown error — otherwise every
    /// details sheet in the app would show a failure line.
    func testNotFoundIsAnEmptyPage() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in FapiResponse(code: 404, message: "NOT_FOUND") }

        let page = try await ReputationService(fapi: mock).received(by: "FUnrated")
        XCTAssertTrue(page.ratings.isEmpty)
        XCTAssertEqual(page.total, 0)
        XCTAssertNil(page.last)
    }

    func testEmptyFidMakesNoCall() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in XCTFail("should not call"); return FapiResponse(code: 0) }

        let page = try await ReputationService(fapi: mock).received(by: "")
        XCTAssertTrue(page.ratings.isEmpty)
        XCTAssertTrue(mock.recorded.isEmpty)
    }

    /// A `rate` the protocol does not define is kept verbatim and
    /// resolves to no case: the row exists on chain and moved no score,
    /// and a UI that rendered it as "good" would be lying.
    func testUnknownRateStringHasNoKind() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in
            try makeResponse(data: [
                ["id": "txid-3", "ratee": "FRatee", "rater": "FR", "rate": "excellent", "hot": 5]
            ])
        }

        let page = try await ReputationService(fapi: mock).received(by: "FRatee")
        XCTAssertEqual(page.ratings.first?.rate, "excellent")
        XCTAssertNil(page.ratings.first?.kind)
    }

    /// A row missing either half of the sort key has no cursor, so the
    /// walk restarts from the top rather than paging into nonsense.
    func testCursorNeedsBothHalves() {
        var row = RepuHist()
        row.id = "txid"
        XCTAssertNil(row.cursor)
        row.height = 900_000
        XCTAssertEqual(row.cursor, ["900000", "txid"])
    }
}
