import XCTest
import FCCore
import FCTransport
@testable import FCDomain

/// The token read path across all three indices: the fcdsl each query
/// emits, the cursor it pages with, and how a page becomes rows.
final class TokenServiceTests: XCTestCase {

    private func body(_ call: MockFapiClient.Recorded) throws -> [String: Any] {
        try XCTUnwrap(
            JSONSerialization.jsonObject(with: try XCTUnwrap(call.fcdsl)) as? [String: Any]
        )
    }

    private func service(_ mock: MockFapiClient) -> TokenService {
        TokenService(fapi: mock)
    }

    // MARK: - tokens

    /// The chain-wide browse has no scoping clause at all, and that is
    /// the feature: you find a token to hold by looking at the ones
    /// that exist.
    func testBrowseTokensIsUnscopedAndSortsByHeight() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in try makeResponse(data: [] as [Any]) }
        _ = try await service(mock).fetchTokens()

        let sent = try body(try XCTUnwrap(mock.recorded.first))
        XCTAssertEqual(sent["entity"] as? String, "token")
        XCTAssertNil(sent["query"])
        XCTAssertEqual(sent["sort"] as? [[String: String]], [
            ["field": "lastHeight", "order": "desc"],
            ["field": "id", "order": "desc"]
        ])
        XCTAssertEqual(sent["size"] as? String, "25")
    }

    func testTokenSearchDefaultsToTheIndexedSearchFields() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in try makeResponse(data: [] as [Any]) }
        _ = try await service(mock).searchTokens(query: "gold")

        let sent = try body(try XCTUnwrap(mock.recorded.first))
        let query = try XCTUnwrap(sent["query"] as? [String: Any])
        let match = try XCTUnwrap(query["match"] as? [String: Any])
        XCTAssertEqual(
            match["fields"] as? [String],
            ["name", "desc", "consensusId", "deployer", "id"]
        )
        XCTAssertEqual(match["value"] as? String, "gold")
    }

    /// Sorting by a non-id field keeps the id tiebreaker; sorting *by*
    /// id must not name it twice.
    func testTokenSearchSortCarriesAnIdTiebreakerExactlyOnce() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in try makeResponse(data: [] as [Any]) }
        let svc = service(mock)

        _ = try await svc.searchTokens(query: "g", sortField: .name, ascending: true)
        XCTAssertEqual(try body(mock.recorded[0])["sort"] as? [[String: String]], [
            ["field": "name", "order": "asc"],
            ["field": "id", "order": "asc"]
        ])

        _ = try await svc.searchTokens(query: "g", sortField: .id)
        XCTAssertEqual(try body(mock.recorded[1])["sort"] as? [[String: String]], [
            ["field": "id", "order": "desc"]
        ])
    }

    /// Paging feeds the server's own cursor straight back — the fix for
    /// Android issue C17, where a locally rebuilt `[lastHeight, id]`
    /// pair pages wrong for every sort that is not by height.
    func testPagingPassesTheServerCursorThrough() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in try makeResponse(data: [] as [Any]) }
        _ = try await service(mock).searchTokens(
            query: "g", sortField: .name, after: ["Gold", "tx1"]
        )
        XCTAssertEqual(try body(mock.recorded[0])["after"] as? [String], ["Gold", "tx1"])

        // An empty cursor is no cursor — sending `[]` asks the server to
        // page after nothing, which is not the same as the first page.
        _ = try await service(mock).searchTokens(query: "g", after: [])
        XCTAssertNil(try body(mock.recorded[1])["after"])
    }

    func testTokenRowsWithoutAnIdAreDropped() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in
            try makeResponse(data: [
                ["id": "tx1", "name": "Gold"],
                ["name": "Nameless row with no id"]
            ])
        }
        let page = try await service(mock).fetchTokens()
        XCTAssertEqual(page.rows.map(\.id), ["tx1"])
    }

    /// 404 is the server's "nothing matched", which for a fresh FID is
    /// the normal reply — not an error to show.
    func testNotFoundIsAnEmptyPageNotAFailure() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in try makeResponse(code: 404) }
        let page = try await service(mock).fetchTokens()
        XCTAssertTrue(page.rows.isEmpty)
        XCTAssertEqual(page.total, 0)
    }

    func testOtherNonZeroCodesThrow() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in try makeResponse(code: 500) }
        do {
            _ = try await service(mock).fetchTokens()
            XCTFail("expected a failure")
        } catch let e as TokenService.Failure {
            guard case .fapiNonZeroCode(_, 500, _) = e else {
                return XCTFail("wrong failure: \(e)")
            }
        }
    }

    // MARK: - holders

    func testHoldingsAreScopedToTheLiveFid() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in try makeResponse(data: [] as [Any]) }
        _ = try await service(mock).fetchHolders(for: "ME")

        let sent = try body(try XCTUnwrap(mock.recorded.first))
        XCTAssertEqual(sent["entity"] as? String, "token_holder")
        let terms = try XCTUnwrap(
            (sent["query"] as? [String: Any])?["terms"] as? [String: Any]
        )
        XCTAssertEqual(terms["fields"] as? [String], ["fid"])
        XCTAssertEqual(terms["values"] as? [String], ["ME"])
    }

    /// A search box on a pane titled "your tokens" must not quietly
    /// return strangers' holdings: the fid clause survives the search.
    func testHolderSearchKeepsTheFidScope() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in try makeResponse(data: [] as [Any]) }
        _ = try await service(mock).searchHolders(for: "ME", query: "T1")

        let query = try XCTUnwrap(try body(mock.recorded[0])["query"] as? [String: Any])
        let terms = try XCTUnwrap(query["terms"] as? [String: Any])
        XCTAssertEqual(terms["values"] as? [String], ["ME"])
        let match = try XCTUnwrap(query["match"] as? [String: Any])
        XCTAssertEqual(match["fields"] as? [String], ["tokenId", "id"])
    }

    /// The deployer's view of where their token went — scoped by token
    /// rather than by holder, biggest stake first.
    func testHoldersOfATokenSortByBalance() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in try makeResponse(data: [] as [Any]) }
        _ = try await service(mock).fetchHolders(ofToken: "T1")

        let sent = try body(try XCTUnwrap(mock.recorded.first))
        let terms = try XCTUnwrap(
            (sent["query"] as? [String: Any])?["terms"] as? [String: Any]
        )
        XCTAssertEqual(terms["fields"] as? [String], ["tokenId"])
        XCTAssertEqual(terms["values"] as? [String], ["T1"])
        XCTAssertEqual((sent["sort"] as? [[String: String]])?.first?["field"], "balance")
    }

    /// A holder row's id is computable, so the freshest possible
    /// balance takes no prior fetch to ask for.
    func testFetchHolderAddressesTheDerivedId() async throws {
        let mock = MockFapiClient()
        let id = TokenHolder.id(fid: "ME", tokenId: "T1")
        mock.responder = { _ in
            try makeResponse(data: [id: ["balance": 42.0]])
        }
        let holder = try await service(mock).fetchHolder(fid: "ME", tokenId: "T1")

        let sent = try body(try XCTUnwrap(mock.recorded.first))
        XCTAssertEqual(mock.recorded.first?.api, DirectoryService.getByIdsApi)
        XCTAssertEqual(sent["entity"] as? String, "token_holder")
        XCTAssertEqual(sent["ids"] as? [String], [id])
        // The map key is authoritative, and the fid/tokenId the caller
        // asked about are filled back in — a bare balance row carries
        // neither, and a Send form needs both.
        XCTAssertEqual(holder?.id, id)
        XCTAssertEqual(holder?.balance, 42)
        XCTAssertEqual(holder?.fid, "ME")
        XCTAssertEqual(holder?.tokenId, "T1")
    }

    func testFetchHolderReturnsNilWhenTheChainHasNeverSeenThePairing() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in try makeResponse(code: 404) }
        let holder = try await service(mock).fetchHolder(fid: "ME", tokenId: "T1")
        XCTAssertNil(holder)
    }

    /// By-ids replies are a *map*, not an array — the shape mismatch
    /// that once made every SID unresolvable.
    func testTokensByIdsDecodesAMapAndTrustsTheKey() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in
            try makeResponse(data: ["tx1": ["name": "Gold"], "tx2": ["id": "tx2", "name": "Ag"]])
        }
        let found = try await service(mock).fetchTokensByIds(["tx1", "tx2"])
        XCTAssertEqual(found["tx1"]?.id, "tx1")
        XCTAssertEqual(found["tx1"]?.name, "Gold")
        XCTAssertEqual(found["tx2"]?.id, "tx2")
    }

    func testByIdsWithNoIdsMakesNoCall() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in try makeResponse(data: [:] as [String: Any]) }
        let found = try await service(mock).fetchTokensByIds([])
        XCTAssertTrue(found.isEmpty)
        XCTAssertTrue(mock.recorded.isEmpty)
    }

    /// The endpoint caps how many ids one call may name, so a long list
    /// is chunked rather than sent whole.
    func testByIdsChunksLongLists() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in try makeResponse(data: [:] as [String: Any]) }
        _ = try await service(mock).fetchTokensByIds((0..<250).map { "id\($0)" })
        XCTAssertEqual(mock.recorded.count, 3)
        XCTAssertEqual((try body(mock.recorded[0])["ids"] as? [String])?.count, 100)
        XCTAssertEqual((try body(mock.recorded[2])["ids"] as? [String])?.count, 50)
    }

    // MARK: - history

    /// History sorts by time, not height: two ops in one block share a
    /// height and are ordered by their index within it.
    func testHistorySortsByTime() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in try makeResponse(data: [] as [Any]) }
        _ = try await service(mock).fetchHistory()

        let sent = try body(try XCTUnwrap(mock.recorded.first))
        XCTAssertEqual(sent["entity"] as? String, "token_history")
        XCTAssertEqual(sent["sort"] as? [[String: String]], [
            ["field": "time", "order": "desc"],
            ["field": "id", "order": "desc"]
        ])
        // No filter at all is the chain's whole token history.
        XCTAssertNil(sent["query"])
    }

    func testHistoryByTokenAndByParty() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in try makeResponse(data: [] as [Any]) }
        let svc = service(mock)

        _ = try await svc.fetchHistory(tokenId: "T1")
        var terms = try XCTUnwrap(
            (try body(mock.recorded[0])["query"] as? [String: Any])?["terms"] as? [String: Any]
        )
        XCTAssertEqual(terms["fields"] as? [String], ["tokenId"])
        XCTAssertEqual(terms["values"] as? [String], ["T1"])

        _ = try await svc.fetchHistory(fid: "ME")
        terms = try XCTUnwrap(
            (try body(mock.recorded[1])["query"] as? [String: Any])?["terms"] as? [String: Any]
        )
        XCTAssertEqual(terms["fields"] as? [String], ["signer", "recipient"])
        XCTAssertEqual(terms["values"] as? [String], ["ME"])
    }

    /// Both filters together apply only the token one. `terms` is a
    /// disjunction, so combining them would *widen* the result — the
    /// opposite of what asking for both means.
    func testHistoryWithBothFiltersNarrowsToTheToken() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in try makeResponse(data: [] as [Any]) }
        _ = try await service(mock).fetchHistory(tokenId: "T1", fid: "ME")

        let terms = try XCTUnwrap(
            (try body(mock.recorded[0])["query"] as? [String: Any])?["terms"] as? [String: Any]
        )
        XCTAssertEqual(terms["fields"] as? [String], ["tokenId"])
    }
}
