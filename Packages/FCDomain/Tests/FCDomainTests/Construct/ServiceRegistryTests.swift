import XCTest
import FCCore
import FCTransport
@testable import FCDomain

/// The service read path: the fcdsl each query emits, where the state
/// filters and the component narrowing land, and how a page becomes
/// rows.
final class ServiceRegistryTests: XCTestCase {

    private func body(_ call: MockFapiClient.Recorded) throws -> [String: Any] {
        try XCTUnwrap(
            JSONSerialization.jsonObject(with: try XCTUnwrap(call.fcdsl)) as? [String: Any]
        )
    }

    private func row(
        id: String, lastHeight: Int64 = 100,
        stdName: String = "DOCK@ME", owner: String = "FID1"
    ) -> [String: Any] {
        ["id": id, "stdName": stdName, "owner": owner,
         "lastHeight": lastHeight, "active": true, "closed": false]
    }

    // MARK: - browse

    func testBrowseIsUnscopedByDefault() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in try makeResponse(data: [] as [Any]) }
        _ = try await ServiceRegistry(fapi: mock).fetchServices()

        let sent = try body(try XCTUnwrap(mock.recorded.first))
        XCTAssertEqual(sent["entity"] as? String, "service")
        XCTAssertNil(sent["query"], "no owner, no state, no component — nothing to say")
        XCTAssertNil(sent["filter"])
        XCTAssertEqual(
            sent["sort"] as? [[String: String]],
            [["field": "lastHeight", "order": "desc"], ["field": "id", "order": "desc"]]
        )
        XCTAssertEqual(sent["size"] as? String, "25")
    }

    /// Same index string the resolver uses. Two readers, one entity —
    /// if these ever drift, SID resolution and the pane are looking at
    /// different things.
    func testTheRegistryAndTheResolverReadTheSameIndex() {
        XCTAssertEqual(ServiceRegistry.index, DirectoryService.serviceIndex)
        XCTAssertEqual(ServiceRegistry.index, "service")
    }

    func testBrowseScopesToAnOwnerWhenAsked() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in try makeResponse(data: [] as [Any]) }
        _ = try await ServiceRegistry(fapi: mock).fetchServices(owner: "ME")

        let query = try XCTUnwrap(try body(mock.recorded[0])["query"] as? [String: Any])
        let equals = try XCTUnwrap(query["equals"] as? [String: Any])
        XCTAssertEqual(equals["fields"] as? [String], ["owner"])
        XCTAssertEqual(equals["values"] as? [String], ["ME"])
    }

    /// `active` and `closed` cannot share one `terms` — a clause naming
    /// two fields and two values matches either value in either field,
    /// so `active=true, closed=false` would also return the rows it is
    /// excluding.
    func testTheTwoStateFlagsGoInSeparateClauses() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in try makeResponse(data: [] as [Any]) }
        _ = try await ServiceRegistry(fapi: mock)
            .fetchServices(active: true, closed: false)

        let sent = try body(mock.recorded[0])
        let query = try XCTUnwrap(sent["query"] as? [String: Any])
        let queryTerms = try XCTUnwrap(query["terms"] as? [String: Any])
        XCTAssertEqual(queryTerms["fields"] as? [String], ["active"])
        XCTAssertEqual(queryTerms["values"] as? [String], ["true"])

        // A sibling of `query`, not a member of it: nested, the server
        // ignores it and the filter silently does nothing.
        let filter = try XCTUnwrap(sent["filter"] as? [String: Any])
        XCTAssertNil(query["filter"])
        let filterTerms = try XCTUnwrap(filter["terms"] as? [String: Any])
        XCTAssertEqual(filterTerms["fields"] as? [String], ["closed"])
        XCTAssertEqual(filterTerms["values"] as? [String], ["false"])
    }

    func testNoStateAskedMeansNoStateClause() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in try makeResponse(data: [] as [Any]) }
        _ = try await ServiceRegistry(fapi: mock).fetchServices(active: nil, closed: nil)

        let sent = try body(mock.recorded[0])
        XCTAssertNil(sent["query"])
        XCTAssertNil(sent["filter"])
    }

    /// The component is a filter, not a query on `type`: one server
    /// publishes one record listing everything it runs, so asking on
    /// `type` matches every FC service on the chain.
    func testAComponentNarrowsByTheComponentListNotTheType() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in try makeResponse(data: [] as [Any]) }
        _ = try await ServiceRegistry(fapi: mock)
            .fetchServices(offering: ServiceName.dock)

        let sent = try body(mock.recorded[0])
        let filter = try XCTUnwrap(sent["filter"] as? [String: Any])
        let terms = try XCTUnwrap(filter["terms"] as? [String: Any])
        XCTAssertEqual(terms["fields"] as? [String], ["components"])
        XCTAssertEqual(terms["values"] as? [String], [ServiceName.dock])
        XCTAssertNil(sent["query"], "the component is not a query clause")
    }

    /// One filter holds one clause of each kind, so a component and a
    /// closed flag cannot both be `terms`. Both must still reach the
    /// server — dropping either silently widens the result.
    func testAComponentAndAClosedFlagBothSurviveTheSameFilter() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in try makeResponse(data: [] as [Any]) }
        _ = try await ServiceRegistry(fapi: mock)
            .fetchServices(offering: ServiceName.disk, active: true, closed: false)

        let filter = try XCTUnwrap(try body(mock.recorded[0])["filter"] as? [String: Any])
        let terms = try XCTUnwrap(filter["terms"] as? [String: Any])
        XCTAssertEqual(terms["fields"] as? [String], ["components"])
        let equals = try XCTUnwrap(filter["equals"] as? [String: Any])
        XCTAssertEqual(equals["fields"] as? [String], ["closed"])
        XCTAssertEqual(equals["values"] as? [String], ["false"])
    }

    func testAscendingFlipsBothSortKeys() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in try makeResponse(data: [] as [Any]) }
        _ = try await ServiceRegistry(fapi: mock).fetchServices(ascending: true)

        XCTAssertEqual(
            try body(mock.recorded[0])["sort"] as? [[String: String]],
            [["field": "lastHeight", "order": "asc"], ["field": "id", "order": "asc"]]
        )
    }

    // MARK: - search

    /// Java's searchable set, minus `home` (a URL map a `match` cannot
    /// score) plus `id`. `localNames` stays — the DOCK picker has
    /// matched on it in production since it shipped.
    func testSearchDefaultsToEverySearchableField() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in try makeResponse(data: [] as [Any]) }
        _ = try await ServiceRegistry(fapi: mock).search(query: "dock")

        let query = try XCTUnwrap(try body(mock.recorded[0])["query"] as? [String: Any])
        let match = try XCTUnwrap(query["match"] as? [String: Any])
        XCTAssertEqual(
            match["fields"] as? [String],
            ["stdName", "localNames", "type", "desc", "components",
             "waiters", "protocols", "codes", "services", "owner", "id"]
        )
        XCTAssertEqual(match["value"] as? String, "dock")
        XCTAssertFalse(
            (match["fields"] as? [String] ?? []).contains("home"),
            "a map of URLs is not something a match clause can score"
        )
    }

    func testSearchNarrowsToOneFieldWhenAsked() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in try makeResponse(data: [] as [Any]) }
        _ = try await ServiceRegistry(fapi: mock).search(query: "x", inField: .owner)

        let query = try XCTUnwrap(try body(mock.recorded[0])["query"] as? [String: Any])
        let match = try XCTUnwrap(query["match"] as? [String: Any])
        XCTAssertEqual(match["fields"] as? [String], ["owner"])
    }

    func testSortingByIdDoesNotAddADuplicateTiebreak() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in try makeResponse(data: [] as [Any]) }
        _ = try await ServiceRegistry(fapi: mock).search(query: "x", sortField: .id)

        XCTAssertEqual(
            try body(mock.recorded[0])["sort"] as? [[String: String]],
            [["field": "id", "order": "desc"]]
        )
    }

    /// Android rebuilds `after` as `[lastHeight, id]` for every search
    /// regardless of what it sorted by, so any other sort pages against
    /// keys it is not sorted on (**issue C17**). The server's own cursor
    /// is correct for every sort.
    func testTheServerCursorIsFedBackVerbatim() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in try makeResponse(data: [] as [Any]) }
        _ = try await ServiceRegistry(fapi: mock)
            .search(query: "x", sortField: .tCdd, after: ["9000", "sid-7"])

        XCTAssertEqual(try body(mock.recorded[0])["after"] as? [String], ["9000", "sid-7"])
    }

    // MARK: - results

    func testChainRowsAreStampedOnChain() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in try makeResponse(data: [self.row(id: "s1")]) }
        let page = try await ServiceRegistry(fapi: mock).fetchServices()

        XCTAssertEqual(page.services.count, 1)
        XCTAssertEqual(page.services[0].onChain, true)
        XCTAssertEqual(page.services[0].state, .live)
    }

    func testARowWithoutAnIdIsDropped() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in
            try makeResponse(data: [["stdName": "no id"], self.row(id: "s1")])
        }
        let page = try await ServiceRegistry(fapi: mock).fetchServices()
        XCTAssertEqual(page.services.map(\.sid), ["s1"])
    }

    func testA404IsAnEmptyPageNotAFailure() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in FapiResponse(code: 404, message: "not found") }
        let page = try await ServiceRegistry(fapi: mock).fetchServices()
        XCTAssertTrue(page.services.isEmpty)
        XCTAssertEqual(page.total, 0)
    }

    func testAnyOtherNonZeroCodeThrows() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in FapiResponse(code: 500, message: "boom") }
        do {
            _ = try await ServiceRegistry(fapi: mock).fetchServices()
            XCTFail("expected a throw")
        } catch let e as ServiceRegistry.Failure {
            guard case .fapiNonZeroCode(_, let code, _) = e else {
                return XCTFail("wrong case: \(e)")
            }
            XCTAssertEqual(code, 500)
        }
    }

    // MARK: - by id

    func testByIdsReadsAMapAndBackfillsTheIdFromTheKey() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in
            try makeResponse(data: ["s1": ["stdName": "DOCK@ME"]])
        }
        let found = try await ServiceRegistry(fapi: mock).fetchServicesByIds(["s1"])
        XCTAssertEqual(found["s1"]?.sid, "s1", "the map key is authoritative")
        XCTAssertEqual(found["s1"]?.onChain, true)
    }

    func testByIdsUsesTheByIdsEndpointNotSearch() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in try makeResponse(data: [:] as [String: Any]) }
        _ = try await ServiceRegistry(fapi: mock).fetchServicesByIds(["s1"])
        XCTAssertEqual(mock.recorded[0].api, DirectoryService.getByIdsApi)
        let sent = try body(mock.recorded[0])
        XCTAssertEqual(sent["entity"] as? String, "service")
        XCTAssertEqual(sent["ids"] as? [String], ["s1"])
    }

    /// A just-broadcast carve is exactly the id the chain does not have
    /// yet, so 404 here is the expected answer, not an error.
    func testByIds404IsAnEmptyResult() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in FapiResponse(code: 404, message: "not found") }
        let found = try await ServiceRegistry(fapi: mock).fetchServicesByIds(["s1"])
        XCTAssertTrue(found.isEmpty)
    }

    func testByIdsChunksALongList() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in try makeResponse(data: [:] as [String: Any]) }
        _ = try await ServiceRegistry(fapi: mock)
            .fetchServicesByIds((0..<250).map { "s\($0)" })
        XCTAssertEqual(mock.recorded.count, 3, "100 + 100 + 50")
    }

    func testByIdsWithNoIdsCallsNothing() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in XCTFail("should not call"); return FapiResponse(code: 1) }
        let found = try await ServiceRegistry(fapi: mock).fetchServicesByIds([])
        XCTAssertTrue(found.isEmpty)
        XCTAssertTrue(mock.recorded.isEmpty)
    }
}
