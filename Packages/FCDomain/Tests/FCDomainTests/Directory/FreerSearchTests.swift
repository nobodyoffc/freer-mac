import XCTest
import FCCore
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

    // MARK: - findFreers: the one entry point pickers call

    /// A well-formed FID must never reach `base.search` — it is an
    /// exact identity, and a `part` match on it would return the FID
    /// itself plus anything that merely contains it.
    func testFindWithValidFidFetchesExactlyAndSkipsSearch() async throws {
        let fid = try FchAddress(
            publicKey: Secp256k1.publicKey(fromPrivateKey: Data(repeating: 0x41, count: 32))
        ).fid

        let mock = MockFapiClient()
        mock.responder = { call in
            XCTAssertEqual(call.api, "base.freerByIds")
            return try makeResponse(data: [fid: ["id": fid, "cid": "alice"]])
        }

        let directory = DirectoryService(fapi: mock)
        let page = try await directory.findFreers(matching: "  \(fid) ")

        XCTAssertTrue(page.isExactFid)
        XCTAssertEqual(page.freers.count, 1)
        XCTAssertEqual(page.freers.first?.cid, "alice")
        // Exact fetches are one record: nothing to paginate.
        XCTAssertNil(page.last)
        XCTAssertEqual(page.total, 1)
        XCTAssertEqual(mock.recorded.count, 1)
        XCTAssertEqual(mock.recorded.first?.api, "base.freerByIds")
    }

    /// A valid FID the chain has never seen is an empty page that still
    /// reports `isExactFid` — the picker offers it anyway rather than
    /// claiming there is no such address.
    func testFindWithUnknownFidIsEmptyButStillExact() async throws {
        let fid = try FchAddress(
            publicKey: Secp256k1.publicKey(fromPrivateKey: Data(repeating: 0x42, count: 32))
        ).fid

        let mock = MockFapiClient()
        mock.responder = { _ in FapiResponse(code: 404, message: "NOT_FOUND") }

        let directory = DirectoryService(fapi: mock)
        let page = try await directory.findFreers(matching: fid)

        XCTAssertTrue(page.isExactFid)
        XCTAssertTrue(page.freers.isEmpty)
        XCTAssertEqual(page.total, 0)
    }

    func testFindWithNonFidTermRunsPartSearch() async throws {
        let mock = MockFapiClient()
        mock.responder = { call in
            XCTAssertEqual(call.api, "base.search")
            var resp = try makeResponse(data: [["id": "FTestFid111", "cid": "alice"]])
            resp.total = 3
            resp.last = ["c1"]
            return resp
        }

        let directory = DirectoryService(fapi: mock)
        let page = try await directory.findFreers(matching: "ali", size: 10)

        XCTAssertFalse(page.isExactFid)
        XCTAssertEqual(page.freers.count, 1)
        XCTAssertEqual(page.last, ["c1"])
        XCTAssertEqual(page.total, 3)

        let dict = try XCTUnwrap(
            JSONSerialization.jsonObject(
                with: try XCTUnwrap(mock.recorded.first?.fcdsl)
            ) as? [String: Any]
        )
        let part = try XCTUnwrap((dict["query"] as? [String: Any])?["part"] as? [String: Any])
        XCTAssertEqual(part["value"] as? String, "ali")
    }

    /// An empty box asks nobody anything.
    func testFindWithBlankTermMakesNoCall() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in XCTFail("no call expected"); return FapiResponse(code: 0) }

        let directory = DirectoryService(fapi: mock)
        let page = try await directory.findFreers(matching: "   ")

        XCTAssertTrue(page.freers.isEmpty)
        XCTAssertFalse(page.isExactFid)
        XCTAssertTrue(mock.recorded.isEmpty)
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
