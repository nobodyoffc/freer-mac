import XCTest
import FCCore
import FCTransport
@testable import FCDomain

/// The code read path: the fcdsl each query emits, where the state
/// filters land, and how a page is turned into rows.
final class CodeServiceTests: XCTestCase {

    private func body(_ call: MockFapiClient.Recorded) throws -> [String: Any] {
        try XCTUnwrap(
            JSONSerialization.jsonObject(with: try XCTUnwrap(call.fcdsl)) as? [String: Any]
        )
    }

    private func row(
        id: String, lastHeight: Int64 = 100,
        name: String = "C", owner: String = "FID1"
    ) -> [String: Any] {
        ["id": id, "name": name, "owner": owner,
         "lastHeight": lastHeight, "active": true, "closed": false]
    }

    // MARK: - browse

    /// The registry is chain-wide. Unlike a proof query there is no
    /// identity clause by default — the point of a registry is looking
    /// up what other people published.
    func testBrowseIsUnscopedByDefault() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in try makeResponse(data: [] as [Any]) }
        _ = try await CodeService(fapi: mock).fetchCodes()

        let sent = try body(try XCTUnwrap(mock.recorded.first))
        XCTAssertEqual(sent["entity"] as? String, "code")
        XCTAssertNil(sent["query"], "no owner, no state — nothing to say")
        XCTAssertNil(sent["filter"])
        XCTAssertEqual(
            sent["sort"] as? [[String: String]],
            [["field": "lastHeight", "order": "desc"], ["field": "id", "order": "desc"]]
        )
        XCTAssertEqual(sent["size"] as? String, "25")
    }

    func testBrowseScopesToAnOwnerWhenAsked() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in try makeResponse(data: [] as [Any]) }
        _ = try await CodeService(fapi: mock).fetchCodes(owner: "ME")

        let query = try XCTUnwrap(try body(mock.recorded[0])["query"] as? [String: Any])
        let equals = try XCTUnwrap(query["equals"] as? [String: Any])
        XCTAssertEqual(equals["fields"] as? [String], ["owner"])
        XCTAssertEqual(equals["values"] as? [String], ["ME"])
    }

    /// `active` and `closed` cannot share one `terms`: a single clause
    /// naming two fields and two values matches either value in either
    /// field, so `active=true, closed=false` would also return the rows
    /// it is excluding. `closed` therefore goes in the top-level
    /// `filter`, which is a sibling of `query` in the fcdsl — nested
    /// inside it, it would be silently ignored.
    func testTheTwoStateFlagsGoInSeparateClauses() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in try makeResponse(data: [] as [Any]) }
        _ = try await CodeService(fapi: mock).fetchCodes(active: true, closed: false)

        let sent = try body(mock.recorded[0])
        let query = try XCTUnwrap(sent["query"] as? [String: Any])
        let terms = try XCTUnwrap(query["terms"] as? [String: Any])
        XCTAssertEqual(terms["fields"] as? [String], ["active"])
        XCTAssertEqual(terms["values"] as? [String], ["true"])

        XCTAssertNil(query["filter"], "a filter inside the query is ignored by the server")
        let filter = try XCTUnwrap(sent["filter"] as? [String: Any])
        let filterTerms = try XCTUnwrap(filter["terms"] as? [String: Any])
        XCTAssertEqual(filterTerms["fields"] as? [String], ["closed"])
        XCTAssertEqual(filterTerms["values"] as? [String], ["false"])
    }

    /// Nil means "leave the state out of the query", which is how an All
    /// view sees stopped and closed records alongside live ones.
    func testNilStateFlagsEmitNoClause() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in try makeResponse(data: [] as [Any]) }
        _ = try await CodeService(fapi: mock).fetchCodes(owner: "ME")

        let sent = try body(mock.recorded[0])
        let query = try XCTUnwrap(sent["query"] as? [String: Any])
        XCTAssertNil(query["terms"])
        XCTAssertNil(sent["filter"])
    }

    func testAscendingFlipsBothSortKeys() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in try makeResponse(data: [] as [Any]) }
        _ = try await CodeService(fapi: mock).fetchCodes(ascending: true)

        XCTAssertEqual(
            try body(mock.recorded[0])["sort"] as? [[String: String]],
            [["field": "lastHeight", "order": "asc"], ["field": "id", "order": "asc"]]
        )
    }

    // MARK: - search

    /// Java's `getSearchableFields` minus `home` — a map of label→URL a
    /// `match` clause has no sensible way to score — plus `id`.
    func testSearchMatchesEverySearchableFieldByDefault() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in try makeResponse(data: [] as [Any]) }
        _ = try await CodeService(fapi: mock).search(query: "freer")

        let query = try XCTUnwrap(try body(mock.recorded[0])["query"] as? [String: Any])
        let match = try XCTUnwrap(query["match"] as? [String: Any])
        XCTAssertEqual(
            match["fields"] as? [String],
            ["name", "desc", "langs", "protocols", "waiters", "owner", "id"]
        )
        XCTAssertEqual(match["value"] as? String, "freer")
    }

    func testSearchCanBeNarrowedToOneField() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in try makeResponse(data: [] as [Any]) }
        _ = try await CodeService(fapi: mock).search(query: "swift", inField: .langs)

        let query = try XCTUnwrap(try body(mock.recorded[0])["query"] as? [String: Any])
        let match = try XCTUnwrap(query["match"] as? [String: Any])
        XCTAssertEqual(match["fields"] as? [String], ["langs"])
    }

    /// The id tiebreaker is what makes the cursor total, and it must not
    /// be added twice when the sort already *is* the id.
    func testSortingByIdDoesNotAddASecondIdKey() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in try makeResponse(data: [] as [Any]) }
        let service = CodeService(fapi: mock)

        _ = try await service.search(query: "x", sortField: .name)
        XCTAssertEqual(
            try body(mock.recorded[0])["sort"] as? [[String: String]],
            [["field": "name", "order": "desc"], ["field": "id", "order": "desc"]]
        )

        _ = try await service.search(query: "x", sortField: .id)
        XCTAssertEqual(
            try body(mock.recorded[1])["sort"] as? [[String: String]],
            [["field": "id", "order": "desc"]]
        )
    }

    /// Android rebuilds `after` as `[lastHeight, id]` for every search
    /// whatever it sorted by — and its default search sorts on
    /// `lastTime` while building the cursor from `lastHeight`, so even
    /// that one pages against keys it is not sorted on (Android issue
    /// C17). The server's own cursor is correct for every sort.
    func testPagingFeedsTheServersCursorBackVerbatim() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in
            var resp = try makeResponse(data: [self.row(id: "c1")])
            resp.last = ["abc", "c1"]
            return resp
        }
        let service = CodeService(fapi: mock)
        let page = try await service.search(query: "x", sortField: .name)
        XCTAssertEqual(page.last, ["abc", "c1"])

        _ = try await service.search(query: "x", sortField: .name, after: page.last)
        XCTAssertEqual(try body(mock.recorded[1])["after"] as? [String], ["abc", "c1"])
    }

    // MARK: - pages

    /// Chain rows are on-chain by definition; the wire may or may not
    /// carry the flag, and the pane's whole layout keys off it.
    func testChainRowsAreStampedOnChain() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in try makeResponse(data: [self.row(id: "c1")], bestHeight: 900) }
        let page = try await CodeService(fapi: mock).fetchCodes()

        XCTAssertEqual(page.codes.count, 1)
        XCTAssertEqual(page.codes[0].onChain, true)
        XCTAssertEqual(page.codes[0].state, .live)
        XCTAssertEqual(page.bestHeight, 900)
    }

    /// A row with no id cannot be opened, refreshed or carved against.
    /// Dropping it beats failing the page it arrived in.
    func testRowsWithoutAnIdAreDropped() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in
            try makeResponse(data: [self.row(id: "c1"), ["name": "nameless"]])
        }
        let page = try await CodeService(fapi: mock).fetchCodes()
        XCTAssertEqual(page.codes.map(\.id), ["c1"])
    }

    /// 404 is the server's "nothing matched" — an empty page, and for a
    /// filter nothing satisfies, the normal reply.
    func testA404IsAnEmptyPageNotAnError() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in try makeResponse(code: 404) }
        let page = try await CodeService(fapi: mock).fetchCodes()
        XCTAssertTrue(page.codes.isEmpty)
        XCTAssertEqual(page.total, 0)
    }

    func testOtherNonZeroCodesThrow() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in try makeResponse(code: 1) }
        do {
            _ = try await CodeService(fapi: mock).fetchCodes()
            XCTFail("expected a throw")
        } catch {
            guard case CodeService.Failure.fapiNonZeroCode = error else {
                return XCTFail("expected fapiNonZeroCode, got \(error)")
            }
        }
    }

    // MARK: - by ids

    /// By-ids is its own endpoint and its `data` is a map from id to
    /// record, not an array. The map key is authoritative: a record
    /// whose body omits its own id still has one here.
    func testByIdsDecodesAMapAndTrustsTheKey() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in
            try makeResponse(data: ["c1": ["name": "freer-mac"], "c2": self.row(id: "c2")])
        }
        let found = try await CodeService(fapi: mock).fetchCodesByIds(["c1", "c2"])

        XCTAssertEqual(found.count, 2)
        XCTAssertEqual(found["c1"]?.id, "c1")
        XCTAssertEqual(found["c1"]?.onChain, true)
        XCTAssertEqual(mock.recorded[0].api, DirectoryService.getByIdsApi)
    }

    /// Ids absent from the reply have no record yet, which for a
    /// just-broadcast carve is the expected answer, not a failure.
    func testByIdsReturnsNothingFor404() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in try makeResponse(code: 404) }
        let found = try await CodeService(fapi: mock).fetchCodesByIds(["c1"])
        XCTAssertTrue(found.isEmpty)
    }

    func testByIdsPagesLongIdLists() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in try makeResponse(data: [:] as [String: Any]) }
        _ = try await CodeService(fapi: mock).fetchCodesByIds((0..<250).map { "c\($0)" })
        XCTAssertEqual(mock.recorded.count, 3, "100 + 100 + 50")
    }

    func testByIdsSendsNothingForAnEmptyList() async throws {
        let mock = MockFapiClient()
        _ = try await CodeService(fapi: mock).fetchCodesByIds([])
        XCTAssertTrue(mock.recorded.isEmpty)
    }
}
