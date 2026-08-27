import XCTest
import FCCore
import FCTransport
@testable import FCDomain

/// The publish read path: the fcdsl each query emits, the cursor it
/// pages with, and how a page becomes rows.
///
/// One service serves two indices, so most of what is checked here is
/// that the *right* index and the *right* field set went out — the
/// failure mode of sharing a client is a remark query that quietly
/// searches texts.
final class PublishServiceTests: XCTestCase {

    private func body(_ call: MockFapiClient.Recorded) throws -> [String: Any] {
        try XCTUnwrap(
            JSONSerialization.jsonObject(with: try XCTUnwrap(call.fcdsl)) as? [String: Any]
        )
    }

    private func textRow(
        id: String, title: String = "t", publisher: String = "ME", lastHeight: Int64 = 100
    ) -> [String: Any] {
        ["id": id, "title": title, "publisher": publisher,
         "lastHeight": lastHeight, "ver": "1", "deleted": false]
    }

    // MARK: - browse

    /// A shelf is one publisher's; discovery is nobody's. The same
    /// method does both, and the difference is whether the `equals`
    /// clause is there at all — a stray empty clause would return
    /// nothing rather than everything.
    func testBrowseScopesToAPublisherOnlyWhenGivenOne() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in try makeResponse(data: [] as [Any]) }
        let service = PublishService(fapi: mock)

        _ = try await service.fetchTexts(publisher: "ME")
        var sent = try body(mock.recorded[0])
        XCTAssertEqual(sent["entity"] as? String, "text")
        var query = try XCTUnwrap(sent["query"] as? [String: Any])
        let equals = try XCTUnwrap(query["equals"] as? [String: Any])
        XCTAssertEqual(equals["fields"] as? [String], ["publisher"])
        XCTAssertEqual(equals["values"] as? [String], ["ME"])

        // Unscoped and unfiltered, there is no query object at all —
        // an empty `equals` would ask for records belonging to nobody
        // and return nothing rather than everything.
        _ = try await service.fetchTexts(publisher: nil, deleted: nil)
        sent = try body(mock.recorded[1])
        XCTAssertNil(sent["query"], "discovery is not scoped to anybody")
    }

    /// `deleted` and `publisher` are both exact-value clauses and one
    /// filter holds one clause of each kind, so the second one has to
    /// take the other slot — the slot conflict `ServiceRegistry`
    /// documents. Dropping either silently widens the result.
    func testBothTheDeletedFlagAndThePublisherSurviveOneRequest() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in try makeResponse(data: [] as [Any]) }
        let service = PublishService(fapi: mock)

        _ = try await service.fetchTexts(publisher: "ME", deleted: false)
        let query = try XCTUnwrap(try body(mock.recorded[0])["query"] as? [String: Any])
        let equals = try XCTUnwrap(query["equals"] as? [String: Any])
        let terms = try XCTUnwrap(query["terms"] as? [String: Any])
        XCTAssertEqual(equals["fields"] as? [String], ["publisher"])
        XCTAssertEqual(terms["fields"] as? [String], ["deleted"])
        XCTAssertEqual(terms["values"] as? [String], ["false"])

        // With no publisher, the flag takes the `equals` slot itself.
        _ = try await service.fetchTexts(publisher: nil, deleted: true)
        let solo = try XCTUnwrap(try body(mock.recorded[1])["query"] as? [String: Any])
        XCTAssertEqual((solo["equals"] as? [String: Any])?["values"] as? [String], ["true"])
        XCTAssertNil(solo["terms"])

        // nil asks for both, which means no flag at all.
        _ = try await service.fetchTexts(publisher: "ME", deleted: nil)
        let none = try XCTUnwrap(try body(mock.recorded[2])["query"] as? [String: Any])
        XCTAssertNil(none["terms"])
    }

    func testBrowseSortsByHeightWithAnIdTiebreaker() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in try makeResponse(data: [] as [Any]) }
        _ = try await PublishService(fapi: mock).fetchTexts()

        let sort = try XCTUnwrap(try body(mock.recorded[0])["sort"] as? [[String: String]])
        XCTAssertEqual(sort, [
            ["field": "lastHeight", "order": "desc"],
            ["field": "id", "order": "desc"]
        ])
    }

    // MARK: - search

    /// `title` and `summary` are analysed text and `did` is a keyword:
    /// the searchable set is not the sortable set, and Elasticsearch
    /// refuses to sort on an analysed field.
    func testSearchableAndSortableFieldsDoNotOverlapWhereTheyMustNot() {
        XCTAssertTrue(PublishService.Field.searchable.contains(.title))
        XCTAssertFalse(PublishService.Field.sortable.contains(.title))
        XCTAssertFalse(PublishService.Field.sortable.contains(.summary))
        XCTAssertTrue(PublishService.Field.sortable.contains(.lastHeight))
        // A remark has no `type` — searching one would ask the index
        // for a field that is not in its mapping.
        XCTAssertTrue(PublishService.Field.searchable.contains(.type))
        XCTAssertFalse(PublishService.Field.searchableForRemark.contains(.type))
    }

    func testSearchMatchesEveryTextFieldUnlessNarrowed() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in try makeResponse(data: [] as [Any]) }
        let service = PublishService(fapi: mock)

        _ = try await service.searchTexts(query: "freecash")
        var query = try XCTUnwrap(try body(mock.recorded[0])["query"] as? [String: Any])
        var match = try XCTUnwrap(query["match"] as? [String: Any])
        XCTAssertEqual(match["value"] as? String, "freecash")
        XCTAssertEqual(
            match["fields"] as? [String],
            PublishService.Field.searchable.map(\.name)
        )

        _ = try await service.searchTexts(query: "freecash", inField: .title)
        query = try XCTUnwrap(try body(mock.recorded[1])["query"] as? [String: Any])
        match = try XCTUnwrap(query["match"] as? [String: Any])
        XCTAssertEqual(match["fields"] as? [String], ["title"])
    }

    /// Sorting by a field other than height still needs the id
    /// tiebreaker, and `search_after` compares positionally against the
    /// sort keys actually used — which is why the cursor comes from the
    /// server rather than being rebuilt (**Android issue C17**).
    func testASortedSearchKeepsTheIdTiebreakerAndPagesFromTheServerCursor() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in
            var resp = try makeResponse(data: [self.textRow(id: "T1")])
            resp.last = ["100", "T1"]
            return resp
        }
        let service = PublishService(fapi: mock)

        let page = try await service.searchTexts(query: "q", sortField: .tRate)
        let sort = try XCTUnwrap(try body(mock.recorded[0])["sort"] as? [[String: String]])
        XCTAssertEqual(sort, [
            ["field": "tRate", "order": "desc"],
            ["field": "id", "order": "desc"]
        ])
        XCTAssertEqual(page.last, ["100", "T1"])

        _ = try await service.searchTexts(query: "q", sortField: .tRate, after: page.last)
        XCTAssertEqual(try body(mock.recorded[1])["after"] as? [String], ["100", "T1"])
    }

    // MARK: - remarks

    /// The thread under a work is `onDid` matched against the target's
    /// **record id**, and it reads oldest-first — the opposite of every
    /// other list in the family.
    func testTheThreadQueryMatchesOnDidAgainstTheTargetIdAndReadsForward() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in try makeResponse(data: [] as [Any]) }
        _ = try await PublishService(fapi: mock).fetchRemarks(on: "text-txid-001")

        let sent = try body(mock.recorded[0])
        XCTAssertEqual(sent["entity"] as? String, "remark")
        let query = try XCTUnwrap(sent["query"] as? [String: Any])
        let terms = try XCTUnwrap(query["terms"] as? [String: Any])
        XCTAssertEqual(terms["fields"] as? [String], ["onDid"])
        XCTAssertEqual(terms["values"] as? [String], ["text-txid-001"])

        let sort = try XCTUnwrap(sent["sort"] as? [[String: String]])
        XCTAssertEqual(sort.first?["order"], "asc")
    }

    // MARK: - rows

    /// Chain rows are on-chain by definition; the `text` mapping has no
    /// such field, and the pane's whole layout keys off it.
    func testChainRowsAreStampedOnChain() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in try makeResponse(data: [self.textRow(id: "T1")]) }
        let page = try await PublishService(fapi: mock).fetchTexts()
        XCTAssertEqual(page.rows.count, 1)
        XCTAssertEqual(page.rows[0].onChain, true)
    }

    /// A row with no id would key the store under "" and collide with
    /// the next such row.
    func testRowsWithoutAnIdAreDropped() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in
            try makeResponse(data: [["title": "orphan"], self.textRow(id: "T1")])
        }
        let page = try await PublishService(fapi: mock).fetchTexts()
        XCTAssertEqual(page.rows.map(\.id), ["T1"])
    }

    /// 404 is the server's "nothing matched" — for a FID that has never
    /// published, the normal reply, and not an error to show anybody.
    func testAMissingIndexReadsAsAnEmptyPage() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in FapiResponse(code: 404, message: "not found") }
        let page = try await PublishService(fapi: mock).fetchTexts(publisher: "NOBODY")
        XCTAssertTrue(page.rows.isEmpty)
        XCTAssertEqual(page.total, 0)
    }

    /// By-ids answers with a **map** from id to record, not an array —
    /// the shape mismatch that once made every SID unresolvable. The
    /// map key is authoritative for a body that omits its own id.
    func testByIdsDecodesAMapAndTakesTheKeyAsTheId() async throws {
        let mock = MockFapiClient()
        mock.responder = { call in
            XCTAssertEqual(call.api, "base.getByIds")
            return try makeResponse(data: ["T1": ["title": "keyed only"]])
        }
        let found = try await PublishService(fapi: mock).textsByIds(["T1"])
        XCTAssertEqual(found["T1"]?.id, "T1")
        XCTAssertEqual(found["T1"]?.onChain, true)
    }

    func testByIdsSendsTheRightIndexForEachKind() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in try makeResponse(data: [:] as [String: Any]) }
        let service = PublishService(fapi: mock)

        _ = try await service.textsByIds(["T1"])
        XCTAssertEqual(try body(mock.recorded[0])["entity"] as? String, "text")
        _ = try await service.remarksByIds(["R1"])
        XCTAssertEqual(try body(mock.recorded[1])["entity"] as? String, "remark")
    }

    func testByIdsWithNoIdsAsksNothing() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in
            XCTFail("should not be called")
            return FapiResponse(code: 0, message: "ok")
        }
        let found = try await PublishService(fapi: mock).textsByIds([])
        XCTAssertTrue(found.isEmpty)
        XCTAssertTrue(mock.recorded.isEmpty)
    }

    // MARK: - images

    /// One service, three indices — and the failure mode of sharing a
    /// client is a query that quietly goes to the wrong one.
    func testEachKindGoesToItsOwnIndex() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in try makeResponse(data: [] as [Any]) }
        let service = PublishService(fapi: mock)

        _ = try await service.fetchTexts()
        _ = try await service.fetchMedia(kind: .image)
        _ = try await service.fetchRemarks(on: "T1")
        _ = try await service.searchMedia(kind: .image, query: "cover")

        XCTAssertEqual(try body(mock.recorded[0])["entity"] as? String, "text")
        XCTAssertEqual(try body(mock.recorded[1])["entity"] as? String, "image")
        XCTAssertEqual(try body(mock.recorded[2])["entity"] as? String, "remark")
        XCTAssertEqual(try body(mock.recorded[3])["entity"] as? String, "image")
    }

    /// The `image` mapping has no `type`, so searching one would ask
    /// the index for a field it does not have.
    func testAnImageSearchDoesNotAskForType() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in try makeResponse(data: [] as [Any]) }
        _ = try await PublishService(fapi: mock).searchMedia(kind: .image, query: "cover")

        let query = try XCTUnwrap(try body(mock.recorded[0])["query"] as? [String: Any])
        let match = try XCTUnwrap(query["match"] as? [String: Any])
        let fields = try XCTUnwrap(match["fields"] as? [String])
        XCTAssertFalse(fields.contains("type"))
        XCTAssertTrue(fields.contains("title"))
        XCTAssertEqual(fields, PublishService.Field.searchableForMedia.map(\.name))
    }

    /// A media row carries no `kind` on the wire — the index asked is
    /// what knows — so the service stamps it. A row that reached a pane
    /// claiming the wrong medium would be played by the wrong player.
    func testMediaRowsAreStampedWithTheKindOfTheIndexAsked() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in
            try makeResponse(data: [["id": "I1", "title": "Cover", "publisher": "ME", "ver": "1"]])
        }
        let page = try await PublishService(fapi: mock).fetchMedia(kind: .video)
        XCTAssertEqual(page.rows.count, 1)
        XCTAssertEqual(page.rows[0].onChain, true)
        XCTAssertEqual(page.rows[0].title, "Cover")
        XCTAssertEqual(page.rows[0].kind, .video)
    }
}
