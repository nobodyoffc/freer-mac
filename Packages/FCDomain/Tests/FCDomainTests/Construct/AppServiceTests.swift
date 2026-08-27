import XCTest
import FCCore
import FCTransport
@testable import FCDomain

/// The app read path: the fcdsl each query emits, where the state
/// filters and the type narrowing land, and how a page becomes rows.
final class AppServiceTests: XCTestCase {

    private func body(_ call: MockFapiClient.Recorded) throws -> [String: Any] {
        try XCTUnwrap(
            JSONSerialization.jsonObject(with: try XCTUnwrap(call.fcdsl)) as? [String: Any]
        )
    }

    private func row(
        id: String, lastHeight: Int64 = 100,
        stdName: String = "Freer", owner: String = "FID1"
    ) -> [String: Any] {
        ["id": id, "stdName": stdName, "owner": owner,
         "lastHeight": lastHeight, "active": true, "closed": false]
    }

    // MARK: - browse

    func testBrowseIsUnscopedByDefault() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in try makeResponse(data: [] as [Any]) }
        _ = try await AppService(fapi: mock).fetchApps()

        let sent = try body(try XCTUnwrap(mock.recorded.first))
        XCTAssertEqual(sent["entity"] as? String, "app")
        XCTAssertNil(sent["query"], "no owner, no state, no type — nothing to say")
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
        _ = try await AppService(fapi: mock).fetchApps(owner: "ME")

        let query = try XCTUnwrap(try body(mock.recorded[0])["query"] as? [String: Any])
        let equals = try XCTUnwrap(query["equals"] as? [String: Any])
        XCTAssertEqual(equals["fields"] as? [String], ["owner"])
        XCTAssertEqual(equals["values"] as? [String], ["ME"])
    }

    /// `active` and `closed` cannot share one `terms` — a clause naming
    /// two fields and two values matches either value in either field.
    ///
    /// And **not-closed is an `except`**: the indexer never writes
    /// `closed` on an app it publishes, so a `filter closed=false` — a
    /// must — matches nothing at all on this index. `except closed=true`
    /// is a must-not, which a record without the field satisfies.
    func testTheTwoStateFlagsGoInSeparateClauses() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in try makeResponse(data: [] as [Any]) }
        _ = try await AppService(fapi: mock).fetchApps(active: true, closed: false)

        let sent = try body(mock.recorded[0])
        let query = try XCTUnwrap(sent["query"] as? [String: Any])
        let queryTerms = try XCTUnwrap(query["terms"] as? [String: Any])
        XCTAssertEqual(queryTerms["fields"] as? [String], ["active"])
        XCTAssertEqual(queryTerms["values"] as? [String], ["true"])

        // A sibling of `query`, not a member of it.
        let except = try XCTUnwrap(sent["except"] as? [String: Any])
        XCTAssertNil(query["except"])
        let exceptTerms = try XCTUnwrap(except["terms"] as? [String: Any])
        XCTAssertEqual(exceptTerms["fields"] as? [String], ["closed"])
        XCTAssertEqual(exceptTerms["values"] as? [String], ["true"])
        // Nothing asks for `closed=false` — no app record carries it.
        XCTAssertNil(sent["filter"])
    }

    /// Closed is the one state the index can be asked for directly: the
    /// `close` op does write the flag.
    func testClosedIsAskedOfTheIndexAsAFilter() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in try makeResponse(data: [] as [Any]) }
        _ = try await AppService(fapi: mock).fetchApps(active: nil, closed: true)

        let sent = try body(mock.recorded[0])
        XCTAssertNil(sent["except"])
        let filter = try XCTUnwrap(sent["filter"] as? [String: Any])
        let terms = try XCTUnwrap(filter["terms"] as? [String: Any])
        XCTAssertEqual(terms["fields"] as? [String], ["closed"])
        XCTAssertEqual(terms["values"] as? [String], ["true"])
    }

    func testNoStateAskedMeansNoStateClause() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in try makeResponse(data: [] as [Any]) }
        _ = try await AppService(fapi: mock).fetchApps(active: nil, closed: nil)

        let sent = try body(mock.recorded[0])
        XCTAssertNil(sent["query"])
        XCTAssertNil(sent["filter"])
        XCTAssertNil(sent["except"])
    }

    /// `types` is a list, so the narrowing is a `terms` clause against
    /// it rather than an equality on a scalar — an app is often several
    /// kinds at once.
    func testATypeNarrowsAgainstTheTypeList() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in try makeResponse(data: [] as [Any]) }
        _ = try await AppService(fapi: mock).fetchApps(ofType: "wallet")

        let filter = try XCTUnwrap(try body(mock.recorded[0])["filter"] as? [String: Any])
        let terms = try XCTUnwrap(filter["terms"] as? [String: Any])
        XCTAssertEqual(terms["fields"] as? [String], ["types"])
        XCTAssertEqual(terms["values"] as? [String], ["wallet"])
    }

    /// A type and a state ask different things and must both reach the
    /// server — dropping either silently widens the result. They no
    /// longer contend for one filter's `terms`, because not-closed
    /// leaves as an `except`.
    func testATypeAndAStateFlagBothReachTheServer() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in try makeResponse(data: [] as [Any]) }
        _ = try await AppService(fapi: mock)
            .fetchApps(ofType: "im", active: true, closed: false)

        let sent = try body(mock.recorded[0])
        let filter = try XCTUnwrap(sent["filter"] as? [String: Any])
        let terms = try XCTUnwrap(filter["terms"] as? [String: Any])
        XCTAssertEqual(terms["fields"] as? [String], ["types"])
        XCTAssertNil(filter["equals"])

        let except = try XCTUnwrap(sent["except"] as? [String: Any])
        let exceptTerms = try XCTUnwrap(except["terms"] as? [String: Any])
        XCTAssertEqual(exceptTerms["fields"] as? [String], ["closed"])
        XCTAssertEqual(exceptTerms["values"] as? [String], ["true"])
    }

    /// A closed record does carry the flag, so a type and `closed=true`
    /// do share one filter — `terms` goes to the type and `closed`
    /// falls back to `equals`.
    func testATypeAndClosedShareTheOneFilter() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in try makeResponse(data: [] as [Any]) }
        _ = try await AppService(fapi: mock)
            .fetchApps(ofType: "im", closed: true)

        let filter = try XCTUnwrap(try body(mock.recorded[0])["filter"] as? [String: Any])
        let terms = try XCTUnwrap(filter["terms"] as? [String: Any])
        XCTAssertEqual(terms["fields"] as? [String], ["types"])
        let equals = try XCTUnwrap(filter["equals"] as? [String: Any])
        XCTAssertEqual(equals["fields"] as? [String], ["closed"])
        XCTAssertEqual(equals["values"] as? [String], ["true"])
    }

    func testAscendingFlipsBothSortKeys() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in try makeResponse(data: [] as [Any]) }
        _ = try await AppService(fapi: mock).fetchApps(ascending: true)

        XCTAssertEqual(
            try body(mock.recorded[0])["sort"] as? [[String: String]],
            [["field": "lastHeight", "order": "asc"], ["field": "id", "order": "asc"]]
        )
    }

    // MARK: - search

    /// Java's searchable set, minus `home` plus `id`. `downloads` is not
    /// in it — a list of objects is not something `match` can score, and
    /// Java does not list it either.
    func testSearchDefaultsToEverySearchableField() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in try makeResponse(data: [] as [Any]) }
        _ = try await AppService(fapi: mock).search(query: "freer")

        let query = try XCTUnwrap(try body(mock.recorded[0])["query"] as? [String: Any])
        let match = try XCTUnwrap(query["match"] as? [String: Any])
        XCTAssertEqual(
            match["fields"] as? [String],
            ["stdName", "localNames", "types", "desc",
             "waiters", "protocols", "codes", "services", "owner", "id"]
        )
        let fields = match["fields"] as? [String] ?? []
        XCTAssertFalse(fields.contains("downloads"), "a list of objects is not text to score")
        XCTAssertFalse(fields.contains("home"))
    }

    func testSearchNarrowsToOneFieldWhenAsked() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in try makeResponse(data: [] as [Any]) }
        _ = try await AppService(fapi: mock).search(query: "x", inField: .owner)

        let query = try XCTUnwrap(try body(mock.recorded[0])["query"] as? [String: Any])
        let match = try XCTUnwrap(query["match"] as? [String: Any])
        XCTAssertEqual(match["fields"] as? [String], ["owner"])
    }

    func testSortingByIdDoesNotAddADuplicateTiebreak() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in try makeResponse(data: [] as [Any]) }
        _ = try await AppService(fapi: mock).search(query: "x", sortField: .id)

        XCTAssertEqual(
            try body(mock.recorded[0])["sort"] as? [[String: String]],
            [["field": "id", "order": "desc"]]
        )
    }

    /// Android rebuilds `after` as `[lastHeight, id]` whatever it sorted
    /// by (**issue C17**). The server's own cursor is correct for every
    /// sort.
    func testTheServerCursorIsFedBackVerbatim() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in try makeResponse(data: [] as [Any]) }
        _ = try await AppService(fapi: mock)
            .search(query: "x", sortField: .tCdd, after: ["9000", "aid-7"])

        XCTAssertEqual(try body(mock.recorded[0])["after"] as? [String], ["9000", "aid-7"])
    }

    // MARK: - results

    func testChainRowsAreStampedOnChain() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in try makeResponse(data: [self.row(id: "a1")]) }
        let page = try await AppService(fapi: mock).fetchApps()

        XCTAssertEqual(page.apps.count, 1)
        XCTAssertEqual(page.apps[0].onChain, true)
        XCTAssertEqual(page.apps[0].state, .live)
    }

    func testARowWithoutAnIdIsDropped() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in
            try makeResponse(data: [["stdName": "no id"], self.row(id: "a1")])
        }
        let page = try await AppService(fapi: mock).fetchApps()
        XCTAssertEqual(page.apps.map(\.id), ["a1"])
    }

    func testA404IsAnEmptyPageNotAFailure() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in FapiResponse(code: 404, message: "No data found") }
        let page = try await AppService(fapi: mock).fetchApps()
        XCTAssertTrue(page.apps.isEmpty)
        XCTAssertEqual(page.total, 0)
    }

    func testAnyOtherNonZeroCodeThrows() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in FapiResponse(code: 500, message: "boom") }
        do {
            _ = try await AppService(fapi: mock).fetchApps()
            XCTFail("expected a throw")
        } catch let e as AppService.Failure {
            guard case .fapiNonZeroCode(_, let code, _) = e else {
                return XCTFail("wrong case: \(e)")
            }
            XCTAssertEqual(code, 500)
        }
    }

    /// A whole page must survive one row with a broken downloads list.
    func testAPageSurvivesOneRowWithAMalformedDownloadsList() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in
            try makeResponse(data: [
                ["id": "a1", "stdName": "Broken", "downloads": "not-a-list"],
                self.row(id: "a2")
            ])
        }
        let page = try await AppService(fapi: mock).fetchApps()
        XCTAssertEqual(page.apps.map(\.id), ["a1", "a2"])
        XCTAssertNil(page.apps[0].downloads)
    }

    // MARK: - by id

    func testByIdsReadsAMapAndBackfillsTheIdFromTheKey() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in try makeResponse(data: ["a1": ["stdName": "Freer"]]) }
        let found = try await AppService(fapi: mock).fetchAppsByIds(["a1"])
        XCTAssertEqual(found["a1"]?.id, "a1", "the map key is authoritative")
        XCTAssertEqual(found["a1"]?.onChain, true)
    }

    func testByIdsUsesTheByIdsEndpointNotSearch() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in try makeResponse(data: [:] as [String: Any]) }
        _ = try await AppService(fapi: mock).fetchAppsByIds(["a1"])
        XCTAssertEqual(mock.recorded[0].api, DirectoryService.getByIdsApi)
        let sent = try body(mock.recorded[0])
        XCTAssertEqual(sent["entity"] as? String, "app")
        XCTAssertEqual(sent["ids"] as? [String], ["a1"])
    }

    func testByIds404IsAnEmptyResult() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in FapiResponse(code: 404, message: "No data found") }
        let found = try await AppService(fapi: mock).fetchAppsByIds(["a1"])
        XCTAssertTrue(found.isEmpty)
    }

    func testByIdsChunksALongList() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in try makeResponse(data: [:] as [String: Any]) }
        _ = try await AppService(fapi: mock).fetchAppsByIds((0..<250).map { "a\($0)" })
        XCTAssertEqual(mock.recorded.count, 3, "100 + 100 + 50")
    }

    func testByIdsWithNoIdsCallsNothing() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in XCTFail("should not call"); return FapiResponse(code: 1) }
        let found = try await AppService(fapi: mock).fetchAppsByIds([])
        XCTAssertTrue(found.isEmpty)
        XCTAssertTrue(mock.recorded.isEmpty)
    }
}
