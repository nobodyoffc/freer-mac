import XCTest
import FCCore
import FCTransport
@testable import FCDomain

/// The proof read path: the fcdsl each query emits, the cursor it pages
/// with, and how a page is turned into rows.
final class ProofServiceTests: XCTestCase {

    private func body(_ call: MockFapiClient.Recorded) throws -> [String: Any] {
        try XCTUnwrap(
            JSONSerialization.jsonObject(with: try XCTUnwrap(call.fcdsl)) as? [String: Any]
        )
    }

    private func row(
        id: String, lastHeight: Int64 = 100,
        title: String = "t", owner: String = "me"
    ) -> [String: Any] {
        ["id": id, "title": title, "owner": owner, "issuer": owner,
         "lastHeight": lastHeight, "destroyed": false]
    }

    // MARK: - browse

    /// The three-role clause is the whole query: a proof can require
    /// something of you as its owner, its issuer, or an invited
    /// cosigner, and one fetch has to bring back all three.
    func testBrowseMatchesOwnerIssuerAndCosigner() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in try makeResponse(data: [] as [Any]) }
        _ = try await ProofService(fapi: mock).fetchProofs(for: "ME")

        let sent = try body(try XCTUnwrap(mock.recorded.first))
        XCTAssertEqual(sent["entity"] as? String, "proof")
        let query = try XCTUnwrap(sent["query"] as? [String: Any])
        let equals = try XCTUnwrap(query["equals"] as? [String: Any])
        XCTAssertEqual(
            equals["fields"] as? [String],
            ["owner", "issuer", "cosignersInvited"]
        )
        XCTAssertEqual(equals["values"] as? [String], ["ME"])
    }

    func testBrowseFiltersDestroyedAndSortsByHeightWithAnIdTiebreaker() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in try makeResponse(data: [] as [Any]) }
        let service = ProofService(fapi: mock)

        _ = try await service.fetchProofs(for: "ME", destroyed: false)
        var query = try XCTUnwrap(try body(mock.recorded[0])["query"] as? [String: Any])
        var terms = try XCTUnwrap(query["terms"] as? [String: Any])
        XCTAssertEqual(terms["fields"] as? [String], ["destroyed"])
        XCTAssertEqual(terms["values"] as? [String], ["false"])

        _ = try await service.fetchProofs(for: "ME", destroyed: true)
        query = try XCTUnwrap(try body(mock.recorded[1])["query"] as? [String: Any])
        terms = try XCTUnwrap(query["terms"] as? [String: Any])
        XCTAssertEqual(terms["values"] as? [String], ["true"])

        // nil asks for both, which means no flag at all.
        _ = try await service.fetchProofs(for: "ME", destroyed: nil)
        query = try XCTUnwrap(try body(mock.recorded[2])["query"] as? [String: Any])
        XCTAssertNil(query["terms"])

        let sort = try XCTUnwrap(try body(mock.recorded[0])["sort"] as? [[String: String]])
        XCTAssertEqual(sort, [
            ["field": "lastHeight", "order": "desc"],
            ["field": "id", "order": "desc"]
        ])
    }

    /// Chain rows are on-chain by definition. The pane's whole layout
    /// keys off the flag, so it is stamped rather than trusted to be
    /// present in the reply.
    func testChainRowsAreStampedOnChain() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in try makeResponse(data: [self.row(id: "p1")]) }
        let page = try await ProofService(fapi: mock).fetchProofs(for: "ME")
        XCTAssertEqual(page.proofs.count, 1)
        XCTAssertEqual(page.proofs[0].onChain, true)
    }

    /// A row with no id cannot be acted on — it would key the store
    /// under "" and collide with the next such row.
    func testRowsWithoutAnIdAreDropped() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in
            try makeResponse(data: [["title": "orphan"], self.row(id: "p1")])
        }
        let page = try await ProofService(fapi: mock).fetchProofs(for: "ME")
        XCTAssertEqual(page.proofs.map(\.id), ["p1"])
    }

    /// 404 is the server's "nothing matched" — for a FID that has never
    /// touched a proof, the normal reply, not a failure.
    func testNotFoundIsAnEmptyPage() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in FapiResponse(code: 404, message: "not found") }
        let page = try await ProofService(fapi: mock).fetchProofs(for: "ME")
        XCTAssertTrue(page.proofs.isEmpty)
        XCTAssertEqual(page.total, 0)
    }

    func testOtherErrorCodesThrow() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in FapiResponse(code: 500, message: "boom") }
        do {
            _ = try await ProofService(fapi: mock).fetchProofs(for: "ME")
            XCTFail("expected a throw")
        } catch let e as ProofService.Failure {
            guard case let .fapiNonZeroCode(_, code, _) = e else {
                return XCTFail("wrong failure: \(e)")
            }
            XCTAssertEqual(code, 500)
        }
    }

    // MARK: - search

    /// Scoped to the same three roles as browse: a box on a pane titled
    /// "your proofs" must not quietly return strangers' documents.
    func testSearchStaysScopedToYourProofs() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in try makeResponse(data: [] as [Any]) }
        _ = try await ProofService(fapi: mock).search(for: "ME", query: "lease")

        let query = try XCTUnwrap(try body(mock.recorded[0])["query"] as? [String: Any])
        XCTAssertNotNil(query["equals"])
        let match = try XCTUnwrap(query["match"] as? [String: Any])
        XCTAssertEqual(match["value"] as? String, "lease")
        XCTAssertEqual(
            match["fields"] as? [String],
            ProofService.Field.searchable.map(\.name)
        )
    }

    func testSearchInOneFieldNarrowsTheMatch() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in try makeResponse(data: [] as [Any]) }
        _ = try await ProofService(fapi: mock)
            .search(for: "ME", query: "lease", inField: .title)
        let query = try XCTUnwrap(try body(mock.recorded[0])["query"] as? [String: Any])
        let match = try XCTUnwrap(query["match"] as? [String: Any])
        XCTAssertEqual(match["fields"] as? [String], ["title"])
    }

    /// The id tiebreaker keeps the sort total, which is what makes the
    /// server's cursor stable — except when id *is* the sort field,
    /// where repeating it is meaningless.
    func testSearchSortCarriesAnIdTiebreakerExceptOnIdItself() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in try makeResponse(data: [] as [Any]) }
        let service = ProofService(fapi: mock)

        _ = try await service.search(for: "ME", query: "q", sortField: .title, ascending: true)
        XCTAssertEqual(
            try XCTUnwrap(try body(mock.recorded[0])["sort"] as? [[String: String]]),
            [["field": "title", "order": "asc"], ["field": "id", "order": "asc"]]
        )

        _ = try await service.search(for: "ME", query: "q", sortField: .id)
        XCTAssertEqual(
            try XCTUnwrap(try body(mock.recorded[1])["sort"] as? [[String: String]]),
            [["field": "id", "order": "desc"]]
        )
    }

    /// Paging passes the server's own cursor back. Android rebuilds
    /// `[lastHeight, id]` regardless of the sort it used, which pages
    /// wrong for every sort but the default (Android issue C17).
    func testPagingSendsTheServerCursorVerbatim() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in
            var resp = try makeResponse(data: [self.row(id: "p1")])
            resp.last = ["Lease", "p1"]
            return resp
        }
        let service = ProofService(fapi: mock)
        let first = try await service.search(for: "ME", query: "q", sortField: .title)
        XCTAssertEqual(first.last, ["Lease", "p1"])

        _ = try await service.search(
            for: "ME", query: "q", sortField: .title, after: first.last
        )
        XCTAssertEqual(try body(mock.recorded[1])["after"] as? [String], ["Lease", "p1"])
    }

    func testNoCursorIsSentOnTheFirstPage() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in try makeResponse(data: [] as [Any]) }
        _ = try await ProofService(fapi: mock).fetchProofs(for: "ME")
        XCTAssertNil(try body(mock.recorded[0])["after"])
    }

    // MARK: - by ids

    /// By-ids is its own endpoint and its data is a *map*, not an array
    /// — sending it to `base.search` would decode to nothing and make
    /// every id silently unresolvable.
    func testByIdsUsesTheByIdsEndpointAndDecodesAMap() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in
            try makeResponse(data: ["p1": self.row(id: "p1"), "p2": self.row(id: "p2")])
        }
        let found = try await ProofService(fapi: mock).fetchProofsByIds(["p1", "p2"])
        XCTAssertEqual(mock.recorded[0].api, DirectoryService.getByIdsApi)
        let sent = try body(mock.recorded[0])
        XCTAssertEqual(sent["entity"] as? String, "proof")
        XCTAssertEqual(sent["ids"] as? [String], ["p1", "p2"])
        XCTAssertEqual(Set(found.keys), ["p1", "p2"])
        XCTAssertEqual(found["p1"]?.onChain, true)
    }

    /// A record whose body omits its own id still has one: the map key.
    func testByIdsTakesTheIdFromTheMapKey() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in try makeResponse(data: ["p9": ["title": "no id inside"]]) }
        let found = try await ProofService(fapi: mock).fetchProofsByIds(["p9"])
        XCTAssertEqual(found["p9"]?.id, "p9")
    }

    /// A just-broadcast carve has no record yet — an empty answer, not
    /// an error.
    func testByIdsTreatsNotFoundAsNoRecord() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in FapiResponse(code: 404, message: "not found") }
        let found = try await ProofService(fapi: mock).fetchProofsByIds(["p1"])
        XCTAssertTrue(found.isEmpty)
    }

    func testByIdsWithNoIdsMakesNoCall() async throws {
        let mock = MockFapiClient()
        let found = try await ProofService(fapi: mock).fetchProofsByIds([])
        XCTAssertTrue(found.isEmpty)
        XCTAssertTrue(mock.recorded.isEmpty)
    }
}
