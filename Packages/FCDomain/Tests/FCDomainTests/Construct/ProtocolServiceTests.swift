import XCTest
import FCCore
import FCTransport
@testable import FCDomain

/// The protocol read path: the fcdsl each query emits, where the state
/// filters land, and how a page is turned into rows.
final class ProtocolServiceTests: XCTestCase {

    private func body(_ call: MockFapiClient.Recorded) throws -> [String: Any] {
        try XCTUnwrap(
            JSONSerialization.jsonObject(with: try XCTUnwrap(call.fcdsl)) as? [String: Any]
        )
    }

    private func row(
        id: String, lastHeight: Int64 = 100,
        name: String = "P", owner: String = "FID1"
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
        _ = try await ProtocolService(fapi: mock).fetchProtocols()

        let sent = try body(try XCTUnwrap(mock.recorded.first))
        XCTAssertEqual(sent["entity"] as? String, "protocol")
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
        _ = try await ProtocolService(fapi: mock).fetchProtocols(owner: "ME")

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
        _ = try await ProtocolService(fapi: mock)
            .fetchProtocols(active: true, closed: false)

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
        _ = try await ProtocolService(fapi: mock).fetchProtocols(owner: "ME")

        let sent = try body(mock.recorded[0])
        let query = try XCTUnwrap(sent["query"] as? [String: Any])
        XCTAssertNil(query["terms"])
        XCTAssertNil(sent["filter"])
    }

    func testAscendingFlipsBothSortKeys() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in try makeResponse(data: [] as [Any]) }
        _ = try await ProtocolService(fapi: mock).fetchProtocols(ascending: true)

        XCTAssertEqual(
            try body(mock.recorded[0])["sort"] as? [[String: String]],
            [["field": "lastHeight", "order": "asc"], ["field": "id", "order": "asc"]]
        )
    }

    // MARK: - search

    func testSearchMatchesEverySearchableFieldByDefault() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in try makeResponse(data: [] as [Any]) }
        _ = try await ProtocolService(fapi: mock).search(query: "cash")

        let query = try XCTUnwrap(try body(mock.recorded[0])["query"] as? [String: Any])
        let match = try XCTUnwrap(query["match"] as? [String: Any])
        XCTAssertEqual(
            match["fields"] as? [String],
            ["name", "type", "sn", "desc", "lang", "owner", "waiters", "id"]
        )
        XCTAssertEqual(match["value"] as? String, "cash")
    }

    func testSearchCanBeNarrowedToOneField() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in try makeResponse(data: [] as [Any]) }
        _ = try await ProtocolService(fapi: mock).search(query: "cash", inField: .desc)

        let query = try XCTUnwrap(try body(mock.recorded[0])["query"] as? [String: Any])
        let match = try XCTUnwrap(query["match"] as? [String: Any])
        XCTAssertEqual(match["fields"] as? [String], ["desc"])
    }

    /// The id tiebreaker is what makes the cursor total, and it must not
    /// be added twice when the sort already *is* the id.
    func testSortingByIdDoesNotAddASecondIdKey() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in try makeResponse(data: [] as [Any]) }
        let service = ProtocolService(fapi: mock)

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
            var resp = try makeResponse(data: [self.row(id: "p1")])
            resp.last = ["abc", "p1"]
            return resp
        }
        let service = ProtocolService(fapi: mock)
        let page = try await service.search(query: "x", sortField: .name)
        XCTAssertEqual(page.last, ["abc", "p1"])

        _ = try await service.search(query: "x", sortField: .name, after: page.last)
        XCTAssertEqual(try body(mock.recorded[1])["after"] as? [String], ["abc", "p1"])
    }

    // MARK: - pages

    /// Chain rows are on-chain by definition; the wire may or may not
    /// carry the flag, and the pane's whole layout keys off it.
    func testChainRowsAreStampedOnChain() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in try makeResponse(data: [self.row(id: "p1")], bestHeight: 900) }
        let page = try await ProtocolService(fapi: mock).fetchProtocols()

        XCTAssertEqual(page.protocols.count, 1)
        XCTAssertEqual(page.protocols[0].onChain, true)
        XCTAssertEqual(page.protocols[0].state, .live)
        XCTAssertEqual(page.bestHeight, 900)
    }

    /// A row with no id cannot be opened, refreshed or carved against.
    /// Dropping it beats failing the page it arrived in.
    func testRowsWithoutAnIdAreDropped() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in
            try makeResponse(data: [self.row(id: "p1"), ["name": "nameless"]])
        }
        let page = try await ProtocolService(fapi: mock).fetchProtocols()
        XCTAssertEqual(page.protocols.map(\.id), ["p1"])
    }

    /// 404 is the server's "nothing matched" — an empty page, and for a
    /// filter nothing satisfies, the normal reply.
    func testA404IsAnEmptyPageNotAnError() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in try makeResponse(code: 404) }
        let page = try await ProtocolService(fapi: mock).fetchProtocols()
        XCTAssertTrue(page.protocols.isEmpty)
        XCTAssertEqual(page.total, 0)
    }

    func testOtherNonZeroCodesThrow() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in try makeResponse(code: 1) }
        do {
            _ = try await ProtocolService(fapi: mock).fetchProtocols()
            XCTFail("expected a throw")
        } catch {
            guard case ProtocolService.Failure.fapiNonZeroCode = error else {
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
            try makeResponse(data: ["p1": ["name": "Contact"], "p2": self.row(id: "p2")])
        }
        let found = try await ProtocolService(fapi: mock).fetchProtocolsByIds(["p1", "p2"])

        XCTAssertEqual(found.count, 2)
        XCTAssertEqual(found["p1"]?.id, "p1")
        XCTAssertEqual(found["p1"]?.onChain, true)
        XCTAssertEqual(mock.recorded[0].api, DirectoryService.getByIdsApi)
    }

    /// Ids absent from the reply have no record yet, which for a
    /// just-broadcast carve is the expected answer, not a failure.
    func testByIdsReturnsNothingFor404() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in try makeResponse(code: 404) }
        let found = try await ProtocolService(fapi: mock).fetchProtocolsByIds(["p1"])
        XCTAssertTrue(found.isEmpty)
    }

    func testByIdsPagesLongIdLists() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in try makeResponse(data: [:] as [String: Any]) }
        _ = try await ProtocolService(fapi: mock)
            .fetchProtocolsByIds((0..<250).map { "p\($0)" })
        XCTAssertEqual(mock.recorded.count, 3, "100 + 100 + 50")
    }

    func testByIdsSendsNothingForAnEmptyList() async throws {
        let mock = MockFapiClient()
        _ = try await ProtocolService(fapi: mock).fetchProtocolsByIds([])
        XCTAssertTrue(mock.recorded.isEmpty)
    }
}
