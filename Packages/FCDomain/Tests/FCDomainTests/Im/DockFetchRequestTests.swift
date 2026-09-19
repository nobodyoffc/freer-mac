import XCTest
@testable import FCDomain
import FCTransport

/// The wire shape of `dock.fetch`.
///
/// **Why this is worth its own file.** FAPI1V1 §4 says a request "MUST
/// NOT have both `fcdsl` and `params` set simultaneously", and that
/// sentence read on its own is an invitation to enforce it in the
/// client — which was done once, and stopped every incoming message in
/// the app while sending, needing only `params`, went on working. The
/// component specs above the core one override it: FAPI13V1 §4.3 gives
/// `dock.fetch` its mailboxes in `params.recipientIds` *and* its paging
/// in `fcdsl`, and the servers and Android both speak it that way.
///
/// So these tests assert the pair travels together. A change that makes
/// them fail is a change that makes the app deaf.
final class DockFetchRequestTests: XCTestCase {

    private func json(_ data: Data?) throws -> [String: Any] {
        let data = try XCTUnwrap(data)
        return try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
    }

    func testFetchSendsRecipientsInParamsAndPagingInFcdsl() async throws {
        let fapi = MockFapiClient()
        fapi.responder = { _ in try makeResponse(code: 0, data: []) }
        let dock = DockService(fapi: fapi)

        _ = try await dock.fetch(
            recipientIds: ["FEk41Kqjar45fLDriztUDTUkdki7mmcjWK", "teamId"],
            after: ["1743033600000", "a1b2"],
            size: 50
        )

        let call = try XCTUnwrap(fapi.recorded.first)
        XCTAssertEqual(call.api, "dock.fetch")

        let params = try json(call.params)
        XCTAssertEqual(
            params["recipientIds"] as? [String],
            ["FEk41Kqjar45fLDriztUDTUkdki7mmcjWK", "teamId"]
        )
        XCTAssertEqual(params["dataType"] as? String, DockService.imDataType)

        let fcdsl = try json(call.fcdsl)
        XCTAssertEqual(fcdsl["size"] as? String, "50")
        XCTAssertEqual(fcdsl["after"] as? [String], ["1743033600000", "a1b2"])
        XCTAssertNotNil(fcdsl["sort"], "the cursor is a position in an order, so the order is sent")
    }

    /// The board read takes the same pair, with its watermark as a
    /// range inside the `fcdsl` and the inbox still in `params`.
    func testFetchNewestAlsoCarriesBoth() async throws {
        let fapi = MockFapiClient()
        fapi.responder = { _ in try makeResponse(code: 0, data: []) }
        let dock = DockService(fapi: fapi)

        _ = try await dock.fetchNewest(recipientIds: ["boardId"], newerThanCreateTime: 1_743_000_000_000)

        let call = try XCTUnwrap(fapi.recorded.first)
        let params = try json(call.params)
        let fcdsl = try json(call.fcdsl)
        XCTAssertEqual(params["recipientIds"] as? [String], ["boardId"])
        XCTAssertNotNil(fcdsl["query"], "the watermark is a server-side range, not a client-side filter")
    }

    /// The counterexample, so the test above is not just asserting that
    /// everything sends both: an operation request carries `params`
    /// alone, exactly as the core protocol describes.
    func testOperationsCarryParamsAlone() async throws {
        let fapi = MockFapiClient()
        fapi.responder = { _ in try makeResponse(code: 0, data: ["id": "d8f3"]) }
        let dock = DockService(fapi: fapi)

        _ = try await dock.delete(id: "d8f3")

        let call = try XCTUnwrap(fapi.recorded.first)
        XCTAssertEqual(call.api, "dock.delete")
        XCTAssertNotNil(call.params)
        XCTAssertNil(call.fcdsl)
    }
}
