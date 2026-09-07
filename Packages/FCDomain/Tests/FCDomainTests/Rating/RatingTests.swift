import XCTest
import FCCore
import FCTransport
@testable import FCDomain

/// The rating layer shared by the ten protocols that define a `rate`
/// op: the per-kind spellings, the carve dispatch, and the history
/// query.
final class RatingTests: XCTestCase {

    // MARK: - the spellings

    /// The ten subject keys are not interchangeable, and using the
    /// wrong one produces a carve the client accepts, the parser drops
    /// and the chain keeps the fee for. They are asserted literally
    /// rather than derived, so a "tidy-up" that makes them uniform
    /// fails here instead of on chain.
    func testEachKindNamesItsOwnIndexAndSubjectKey() {
        let expected: [RatableKind: (index: String, key: String)] = [
            .protocolSpec: ("protocol", "pid"),
            .code:         ("code",     "codeId"),
            .service:      ("service",  "sid"),
            .app:          ("app",      "aid"),
            .team:         ("team",     "tid"),
            .text:         ("text",     "textId"),
            .remark:       ("remark",   "remarkId"),
            .image:        ("image",    "imageId"),
            .sound:        ("sound",    "soundId"),
            .video:        ("video",    "videoId"),
        ]
        XCTAssertEqual(Set(expected.keys), Set(RatableKind.allCases),
                       "a new ratable kind needs its spellings pinned here")
        for kind in RatableKind.allCases {
            let want = try! XCTUnwrap(expected[kind])
            XCTAssertEqual(kind.index, want.index, "\(kind) index")
            XCTAssertEqual(kind.subjectKey, want.key, "\(kind) subject key")
            XCTAssertEqual(kind.historyIndex, want.index + "_history", "\(kind) history index")
        }
    }

    /// The Construct four and Team bar the `owner`; the Publish five
    /// bar the `publisher`. The specs use the two words for different
    /// roles and the sheets quote them, so they are not synonyms.
    func testOwnerNounFollowsTheSpecs() {
        for kind in [RatableKind.protocolSpec, .code, .service, .app, .team] {
            XCTAssertEqual(kind.ownerNoun, "owner", "\(kind)")
        }
        for kind in [RatableKind.text, .remark, .image, .sound, .video] {
            XCTAssertEqual(kind.ownerNoun, "publisher", "\(kind)")
        }
    }

    func testMediaKindRoundTrips() {
        for media in MediaKind.allCases {
            let kind = RatableKind(mediaKind: media)
            XCTAssertEqual(kind.mediaKind, media)
            XCTAssertEqual(kind.subjectKey, media.subjectKey)
        }
        XCTAssertNil(RatableKind.text.mediaKind)
    }

    // MARK: - the carve dispatch

    /// Every kind carves a complete FEIP envelope naming its own serial
    /// number, its own subject key, the score and the cause. This is
    /// the one test that covers all ten paths at once, which is the
    /// point: the switch that dispatches them is exhaustive, and a new
    /// ratable protocol should not be able to reach the UI without one
    /// of these assertions failing first.
    func testEveryKindCarvesItsOwnEnvelope() throws {
        for kind in RatableKind.allCases {
            let json = try ActiveSession.rateCarve(
                kind: kind, subjectId: "SUBJ1", rate: 4, cause: "  because  "
            )
            let obj = try XCTUnwrap(
                JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String: Any]
            )
            XCTAssertEqual(obj["type"] as? String, "FEIP", "\(kind)")
            XCTAssertEqual(obj["sn"] as? String, kind.feip.sn, "\(kind) serial number")

            let data = try XCTUnwrap(obj["data"] as? [String: Any], "\(kind)")
            XCTAssertEqual(data["op"] as? String, "rate", "\(kind)")
            XCTAssertEqual(data[kind.subjectKey] as? String, "SUBJ1", "\(kind) subject")
            XCTAssertEqual(data["rate"] as? Int, 4, "\(kind) score")
            // Trimmed, not passed through.
            XCTAssertEqual(data["cause"] as? String, "because", "\(kind) cause")
        }
    }

    /// Blank means omit the field, not carve `""`. Android's `makeRate`
    /// passes null for an empty box and Gson drops null fields, so an
    /// empty string here would be a shape no other client writes.
    func testABlankCauseIsOmittedByEveryKind() throws {
        for kind in RatableKind.allCases {
            for blank in [nil, "", "   ", "\n"] as [String?] {
                let json = try ActiveSession.rateCarve(
                    kind: kind, subjectId: "SUBJ1", rate: 3, cause: blank
                )
                XCTAssertFalse(json.contains("cause"),
                               "\(kind) carved a cause for \(String(describing: blank))")
            }
        }
    }

    /// 0 through 5 inclusive, everywhere. The reference parser accepts
    /// `0...MAX_RATE` and Android has always drawn a 0 button; the Mac
    /// builders used to refuse 0, which made 1 the worst verdict this
    /// app could express.
    func testTheRangeIsZeroToFiveForEveryKind() {
        for kind in RatableKind.allCases {
            for good in 0...5 {
                XCTAssertNoThrow(
                    try ActiveSession.rateCarve(kind: kind, subjectId: "S", rate: good, cause: nil),
                    "\(kind) refused \(good)"
                )
            }
            for bad in [-1, 6, 99] {
                XCTAssertThrowsError(
                    try ActiveSession.rateCarve(kind: kind, subjectId: "S", rate: bad, cause: nil),
                    "\(kind) accepted \(bad)"
                )
            }
        }
    }

    /// Nine builders refuse an empty subject themselves; `TeamFeip`
    /// does not, so the dispatch guards all ten at one point. A `rate`
    /// naming an empty id confirms, spends the fee and the coin-days,
    /// and rates nothing.
    func testAnEmptySubjectIsRefusedByEveryKind() {
        for kind in RatableKind.allCases {
            XCTAssertThrowsError(
                try ActiveSession.rateCarve(kind: kind, subjectId: "", rate: 4, cause: nil),
                "\(kind) carved a rating with no subject"
            )
        }
    }

    func testRateScoreCoversTheProtocolRange() {
        XCTAssertEqual(RateScore.allCases.map(\.rawValue), [0, 1, 2, 3, 4, 5])
        XCTAssertNil(RateScore(rawValue: 6))
        XCTAssertNil(RateScore(rawValue: -1))
        XCTAssertLessThan(RateScore.zero, RateScore.five)
    }

    // MARK: - the history

    func testRatingsQueriesTheHistoryIndexAndDecodesRows() async throws {
        let mock = MockFapiClient()
        mock.responder = { call in
            XCTAssertEqual(call.api, "base.search")
            var resp = try makeResponse(data: [
                [
                    "id": "tx-1", "height": 900_100, "index": 2, "time": 1_770_000_000,
                    "signer": "FRaterA", "op": "rate", "rate": 5, "cdd": 1_200,
                    "cause": "builds clean"
                ],
                [
                    "id": "tx-2", "height": 900_000,
                    "signer": "FRaterB", "op": "rate", "rate": 1, "cdd": 40
                ]
            ])
            resp.total = 2
            resp.last = ["900000", "tx-2"]
            return resp
        }

        let page = try await RatingService(fapi: mock)
            .ratings(of: .code, subjectId: "CODE1", size: 25)

        XCTAssertEqual(page.ratings.count, 2)
        XCTAssertEqual(page.total, 2)
        XCTAssertEqual(page.ratings.first?.score, .five)
        XCTAssertEqual(page.ratings.first?.cdd, 1_200)
        XCTAssertEqual(page.ratings.first?.cause, "builds clean")
        // A row carved before `cause` existed simply has none.
        XCTAssertNil(page.ratings.last?.cause)
        XCTAssertEqual(page.ratings.last?.cursor, ["900000", "tx-2"])

        let dict = try XCTUnwrap(
            JSONSerialization.jsonObject(
                with: try XCTUnwrap(mock.recorded.first?.fcdsl)
            ) as? [String: Any]
        )
        XCTAssertEqual(dict["entity"] as? String, "code_history")
        XCTAssertEqual(dict["size"] as? String, "25")
        let terms = try XCTUnwrap((dict["query"] as? [String: Any])?["terms"] as? [String: Any])
        XCTAssertEqual(terms["fields"] as? [String], ["codeId"])
        XCTAssertEqual(terms["values"] as? [String], ["CODE1"])
        let sort = try XCTUnwrap(dict["sort"] as? [[String: String]])
        XCTAssertEqual(sort.map { $0["field"] }, ["height", "id"])
    }

    /// These indices hold every operation on the record, so `op` is
    /// narrowed server-side — a publish row carries no rate at all, and
    /// sieving client-side would spend the page budget on rows that can
    /// never be ratings.
    func testTheOpIsNarrowedServerSide() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in try makeResponse(data: [[String: Any]]()) }

        _ = try await RatingService(fapi: mock).ratings(of: .text, subjectId: "T1")

        let dict = try XCTUnwrap(
            JSONSerialization.jsonObject(
                with: try XCTUnwrap(mock.recorded.first?.fcdsl)
            ) as? [String: Any]
        )
        let filter = try XCTUnwrap(dict["filter"] as? [String: Any])
        let equals = try XCTUnwrap(filter["equals"] as? [String: Any])
        XCTAssertEqual(equals["fields"] as? [String], ["op"])
        XCTAssertEqual(equals["values"] as? [String], ["rate"])
    }

    /// "Have I rated this" adds the signer beside the op — and under a
    /// *different* clause key on purpose. An FCDSL `filter` is one
    /// object whose keys are clause types, so two `terms` clauses
    /// cannot coexist: the second would replace the first and the
    /// narrowing would vanish without an error.
    func testRatingsByNarrowsOnSignerWithoutDisplacingTheOpClause() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in try makeResponse(data: [[String: Any]]()) }

        _ = try await RatingService(fapi: mock)
            .ratings(by: "FMine", of: .app, subjectId: "APP1")

        let dict = try XCTUnwrap(
            JSONSerialization.jsonObject(
                with: try XCTUnwrap(mock.recorded.first?.fcdsl)
            ) as? [String: Any]
        )
        XCTAssertEqual(dict["entity"] as? String, "app_history")
        let filter = try XCTUnwrap(dict["filter"] as? [String: Any])

        let equals = try XCTUnwrap(filter["equals"] as? [String: Any],
                                   "the op clause was displaced")
        XCTAssertEqual(equals["values"] as? [String], ["rate"])

        let terms = try XCTUnwrap(filter["terms"] as? [String: Any])
        XCTAssertEqual(terms["fields"] as? [String], ["signer"])
        XCTAssertEqual(terms["values"] as? [String], ["FMine"])
    }

    /// An empty subject asks nothing rather than asking for everything:
    /// a blank id would otherwise match no `terms` clause and return
    /// the index's first page as if it were one record's ratings.
    func testAnEmptySubjectQueriesNothing() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in XCTFail("should not have called"); return try makeResponse(data: [[String: Any]]()) }

        let page = try await RatingService(fapi: mock).ratings(of: .app, subjectId: "")
        XCTAssertTrue(page.ratings.isEmpty)
        XCTAssertEqual(page.total, 0)
        XCTAssertTrue(mock.recorded.isEmpty)
    }

    /// Nobody has ever rated most records, and the server says so with
    /// a 404. That is the normal state, not a failure.
    func testNotFoundIsAnEmptyPage() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in
            var resp = try makeResponse(data: [[String: Any]]())
            resp.code = 404
            return resp
        }
        let page = try await RatingService(fapi: mock).ratings(of: .video, subjectId: "V1")
        XCTAssertTrue(page.ratings.isEmpty)
        XCTAssertEqual(page.total, 0)
    }

    /// A row outside 0–5 still decodes and still renders. Those can
    /// exist: the five Publish parsers bounded `rate` only recently,
    /// and a 9 indexed before that is still on chain.
    func testAnOutOfRangeRowDecodesWithoutAScore() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in
            try makeResponse(data: [
                ["id": "tx-9", "signer": "FOdd", "op": "rate", "rate": 9, "cdd": 10]
            ])
        }
        let page = try await RatingService(fapi: mock).ratings(of: .image, subjectId: "I1")
        XCTAssertEqual(page.ratings.first?.rate, 9)
        XCTAssertNil(page.ratings.first?.score)
    }
}
