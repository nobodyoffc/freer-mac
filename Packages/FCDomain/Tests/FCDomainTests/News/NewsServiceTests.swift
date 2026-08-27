import XCTest
import FCCore
import FCTransport
@testable import FCDomain

/// `NewsService` against a staged `base.search`: the FCDSL wire shape
/// for each walk direction and for search, page decoding, the
/// 404-is-empty rule, and the new-item watermark.
final class NewsServiceTests: XCTestCase {

    // MARK: - helpers

    private func fcdsl(_ mock: MockFapiClient, at index: Int = 0) throws -> [String: Any] {
        let call = try XCTUnwrap(mock.recorded[safe: index])
        let body = try XCTUnwrap(call.fcdsl)
        return try XCTUnwrap(JSONSerialization.jsonObject(with: body) as? [String: Any])
    }

    private func sorts(_ dict: [String: Any]) throws -> [[String: String]] {
        try XCTUnwrap(dict["sort"] as? [[String: String]])
    }

    // MARK: - browse

    func testFetchNewestSendsTimeDescAndNoCursor() async throws {
        let mock = MockFapiClient()
        mock.responder = { call in
            XCTAssertEqual(call.api, "base.search")
            var resp = try makeResponse(data: [
                [
                    "id": "news-1", "doer": "FTestDoer1", "act": "register",
                    "objectType": "1", "objectName": "alice",
                    "objectBrief": "a new cid", "height": 900_100, "time": 1_770_000_000
                ]
            ])
            resp.total = 4_242
            resp.bestHeight = 900_150
            resp.last = ["1770000000", "news-1"]
            return resp
        }

        let page = try await NewsService(fapi: mock).fetch(.newest, size: 25)

        XCTAssertEqual(page.news.count, 1)
        XCTAssertEqual(page.news.first?.doer, "FTestDoer1")
        XCTAssertEqual(page.news.first?.act, "register")
        XCTAssertEqual(page.news.first?.objectBrief, "a new cid")
        XCTAssertEqual(page.news.first?.height, 900_100)
        XCTAssertEqual(page.total, 4_242)
        XCTAssertEqual(page.bestHeight, 900_150)
        XCTAssertEqual(page.last, ["1770000000", "news-1"])

        let dict = try fcdsl(mock)
        XCTAssertEqual(dict["entity"] as? String, "news")
        XCTAssertEqual(dict["size"] as? String, "25")
        XCTAssertNil(dict["after"])
        XCTAssertNil(dict["query"])
        XCTAssertEqual(try sorts(dict), [
            ["field": "time", "order": "desc"],
            ["field": "id", "order": "desc"]
        ])
    }

    func testFetchOlderPagesDescendingFromTheReferenceRow() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in try makeResponse(data: [[String: Any]]()) }

        let earliest = News(height: 900_000, time: 1_769_000_000, id: "news-9")
        _ = try await NewsService(fapi: mock).fetch(.older, reference: earliest)

        let dict = try fcdsl(mock)
        XCTAssertEqual(dict["after"] as? [String], ["1769000000", "news-9"])
        XCTAssertEqual(try sorts(dict).first?["order"], "desc")
    }

    /// The refresh path reads *forwards* from the newest row held —
    /// so the page comes back oldest-first and the caller reverses it.
    func testFetchNewerFlipsTheSortToAscending() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in try makeResponse(data: [[String: Any]]()) }

        let latest = News(height: 900_100, time: 1_770_000_000, id: "news-1")
        _ = try await NewsService(fapi: mock).fetch(.newer, reference: latest)

        let dict = try fcdsl(mock)
        XCTAssertEqual(dict["after"] as? [String], ["1770000000", "news-1"])
        XCTAssertEqual(try sorts(dict), [
            ["field": "time", "order": "asc"],
            ["field": "id", "order": "asc"]
        ])
    }

    /// A row the index handed us without a `time`/`id` pair cannot
    /// produce a cursor. Starting from the tip beats throwing: the
    /// pane still shows a feed.
    func testFetchWithUncursorableReferenceOmitsAfter() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in try makeResponse(data: [[String: Any]]()) }

        _ = try await NewsService(fapi: mock).fetch(.older, reference: News(doer: "FTest"))

        XCTAssertNil(try fcdsl(mock)["after"])
    }

    // MARK: - search

    func testSearchWithoutFieldMatchesEverySearchableField() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in try makeResponse(data: [[String: Any]]()) }

        _ = try await NewsService(fapi: mock).search(query: "alice")

        let dict = try fcdsl(mock)
        let query = try XCTUnwrap(dict["query"] as? [String: Any])
        let match = try XCTUnwrap(query["match"] as? [String: Any])
        XCTAssertEqual(
            match["fields"] as? [String],
            ["doer", "objectType", "act", "objectName", "objectBrief", "id"]
        )
        XCTAssertEqual(match["value"] as? String, "alice")
        // No sort field given → time, newest first.
        XCTAssertEqual(try sorts(dict), [
            ["field": "time", "order": "desc"],
            ["field": "id", "order": "desc"]
        ])
    }

    func testSearchInOneFieldSendsOnlyThatField() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in try makeResponse(data: [[String: Any]]()) }

        _ = try await NewsService(fapi: mock).search(
            query: "FTestDoer1", inField: News.doerField
        )

        let query = try XCTUnwrap(try fcdsl(mock)["query"] as? [String: Any])
        let match = try XCTUnwrap(query["match"] as? [String: Any])
        XCTAssertEqual(match["fields"] as? [String], ["doer"])
    }

    func testSearchSortAddsIdTiebreakerInTheSameOrder() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in try makeResponse(data: [[String: Any]]()) }

        _ = try await NewsService(fapi: mock).search(
            query: "alice", sortField: News.objectNameField, ascending: true
        )

        XCTAssertEqual(try sorts(try fcdsl(mock)), [
            ["field": "objectName", "order": "asc"],
            ["field": "id", "order": "asc"]
        ])
    }

    /// Sorting by `id` already gives a total order — a second `id` sort
    /// would be a duplicate key in the request.
    func testSearchSortedByIdDoesNotRepeatTheTiebreaker() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in try makeResponse(data: [[String: Any]]()) }

        _ = try await NewsService(fapi: mock).search(query: "x", sortField: News.idField)

        XCTAssertEqual(try sorts(try fcdsl(mock)), [["field": "id", "order": "desc"]])
    }

    func testSearchPassesServerCursorForTheNextPage() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in try makeResponse(data: [[String: Any]]()) }

        _ = try await NewsService(fapi: mock).search(
            query: "alice", after: ["cursor-a", "cursor-b"]
        )

        XCTAssertEqual(try fcdsl(mock)["after"] as? [String], ["cursor-a", "cursor-b"])
    }

    // MARK: - failure shapes

    func testNotFoundIsAnEmptyPageNotAnError() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in FapiResponse(code: 404, message: "NOT_FOUND") }

        let page = try await NewsService(fapi: mock).fetch(.newest)

        XCTAssertTrue(page.news.isEmpty)
        XCTAssertNil(page.last)
        XCTAssertEqual(page.total, 0)
    }

    func testOtherNonZeroCodesThrow() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in FapiResponse(code: 500, message: "boom") }

        do {
            _ = try await NewsService(fapi: mock).fetch(.newest)
            XCTFail("expected a throw")
        } catch let e as NewsService.Failure {
            guard case let .fapiNonZeroCode(api, code, _) = e else {
                return XCTFail("wrong case: \(e)")
            }
            XCTAssertEqual(api, "base.search")
            XCTAssertEqual(code, 500)
        }
    }

    // MARK: - the new-item watermark

    func testNoWatermarkMarksNothingNew() {
        let items = [News(height: 900_100, id: "a"), News(height: 800_000, id: "b")]

        let marked = NewsService.markingNew(items, sinceHeight: nil)

        XCTAssertTrue(marked.allSatisfy { $0.isNew == nil })
    }

    func testOnlyRowsAboveTheWatermarkAreMarked() {
        let items = [
            News(height: 900_101, id: "a"),
            News(height: 900_100, id: "b"),
            News(height: 899_999, id: "c"),
            News(height: nil, id: "d")
        ]

        let marked = NewsService.markingNew(items, sinceHeight: 900_100)

        XCTAssertEqual(marked[0].isNew, true)
        XCTAssertNil(marked[1].isNew)   // equal to the watermark: already seen
        XCTAssertNil(marked[2].isNew)
        XCTAssertNil(marked[3].isNew)   // no height: nothing to compare
    }

    // MARK: - local filtering

    func testMatchesScansEveryVisibleField() {
        let item = News(
            doer: "FTestDoer1", act: "register", objectType: "1",
            objectName: "alice", objectBrief: "a new cid",
            objectId: "obj-7", id: "news-1"
        )

        XCTAssertTrue(item.matches(query: "ALICE"))
        XCTAssertTrue(item.matches(query: "regis"))
        XCTAssertTrue(item.matches(query: "obj-7"))
        XCTAssertTrue(item.matches(query: "  "))       // empty query matches all
        XCTAssertFalse(item.matches(query: "bob"))
    }
}

private extension Array {
    subscript(safe index: Int) -> Element? {
        indices.contains(index) ? self[index] : nil
    }
}

/// The `sn` → protocol-name table the feed reads every row through.
final class FeipProtocolTests: XCTestCase {

    func testSerialNumbersAreUniqueAndCoverOneThroughTwentyFive() {
        let sns = FeipProtocol.allCases.map(\.sn)
        XCTAssertEqual(Set(sns).count, sns.count)
        XCTAssertEqual(Set(sns), Set((1...25).map(String.init)))
    }

    func testKnownSerialNumbersResolveToTheAndroidNames() {
        XCTAssertEqual(FeipProtocol.bySn("12"), .contact)
        XCTAssertEqual(FeipProtocol.displayName(forSn: "12"), "Contact")
        XCTAssertEqual(FeipProtocol.displayName(forSn: "3"), "CID")
        XCTAssertEqual(FeipProtocol.displayName(forSn: " 7 "), "Mail")
    }

    /// The versions the carve builders in this package already write
    /// must agree with the table, or one of the two is wrong.
    func testVersionsMatchTheShippedCarveBuilders() {
        XCTAssertEqual(FeipProtocol.mail.ver, "4")
        XCTAssertEqual(FeipProtocol.contact.ver, "3")
        XCTAssertEqual(FeipProtocol.secret.ver, "3")
        XCTAssertEqual(FeipProtocol.team.ver, "1")
        XCTAssertEqual(FeipProtocol.noticeFee.ver, "1")
    }

    /// An indexer that writes something other than a serial number
    /// still gets its value shown.
    func testUnknownSerialNumberFallsBackToTheRawValue() {
        XCTAssertEqual(FeipProtocol.displayName(forSn: "99"), "99")
        XCTAssertEqual(FeipProtocol.displayName(forSn: "Freer"), "Freer")
        XCTAssertNil(FeipProtocol.displayName(forSn: ""))
        XCTAssertNil(FeipProtocol.displayName(forSn: nil))
    }
}
