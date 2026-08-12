import XCTest
import FCTransport
@testable import FCDomain

/// `DirectoryService.searchFreers` against a staged `base.search`:
/// FCDSL wire shape (entity / part query / size / after cursor),
/// page decoding, and the 404-means-no-matches path.
final class FreerSearchTests: XCTestCase {

    func testSearchSendsPartQueryAndDecodesPage() async throws {
        let mock = MockFapiClient()
        mock.responder = { call in
            XCTAssertEqual(call.api, "base.search")
            var resp = try makeResponse(data: [
                ["id": "FTestFid111", "cid": "alice", "balance": 5_000],
                ["id": "FTestFid222", "cid": "alicia"]
            ])
            resp.total = 12
            resp.last = ["cursor-a", "cursor-b"]
            return resp
        }

        let directory = DirectoryService(fapi: mock)
        let page = try await directory.searchFreers(matching: "ali", size: 10)

        XCTAssertEqual(page.freers.count, 2)
        XCTAssertEqual(page.freers.first?.cid, "alice")
        XCTAssertEqual(page.freers.first?.balance, 5_000)
        XCTAssertEqual(page.total, 12)
        XCTAssertEqual(page.last, ["cursor-a", "cursor-b"])

        let call = try XCTUnwrap(mock.recorded.first)
        let fcdsl = try XCTUnwrap(call.fcdsl)
        let dict = try XCTUnwrap(
            JSONSerialization.jsonObject(with: fcdsl) as? [String: Any]
        )
        XCTAssertEqual(dict["entity"] as? String, "freer")
        XCTAssertEqual(dict["size"] as? String, "10")
        XCTAssertNil(dict["after"])
        let query = try XCTUnwrap(dict["query"] as? [String: Any])
        let part = try XCTUnwrap(query["part"] as? [String: Any])
        XCTAssertEqual(part["fields"] as? [String], ["id", "usedCids"])
        XCTAssertEqual(part["value"] as? String, "ali")
    }

    func testSearchPassesAfterCursorForNextPage() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in try makeResponse(data: [[String: Any]]()) }

        let directory = DirectoryService(fapi: mock)
        _ = try await directory.searchFreers(
            matching: "ali", after: ["cursor-a", "cursor-b"]
        )

        let call = try XCTUnwrap(mock.recorded.first)
        let dict = try XCTUnwrap(
            JSONSerialization.jsonObject(with: try XCTUnwrap(call.fcdsl)) as? [String: Any]
        )
        XCTAssertEqual(dict["after"] as? [String], ["cursor-a", "cursor-b"])
    }

    func testSearch404IsEmptyPageNotError() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in FapiResponse(code: 404, message: "NOT_FOUND") }

        let directory = DirectoryService(fapi: mock)
        let page = try await directory.searchFreers(matching: "nobody")

        XCTAssertTrue(page.freers.isEmpty)
        XCTAssertNil(page.last)
        XCTAssertEqual(page.total, 0)
    }

    func testSearchNonZeroCodeThrows() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in FapiResponse(code: 500, message: "boom") }

        let directory = DirectoryService(fapi: mock)
        do {
            _ = try await directory.searchFreers(matching: "ali")
            XCTFail("expected fapiNonZeroCode")
        } catch let DirectoryService.Failure.fapiNonZeroCode(api, code, message) {
            XCTAssertEqual(api, "base.search")
            XCTAssertEqual(code, 500)
            XCTAssertEqual(message, "boom")
        }
    }
}
