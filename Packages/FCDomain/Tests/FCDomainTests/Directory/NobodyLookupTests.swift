import XCTest
import FCCore
import FCTransport
@testable import FCDomain

/// How directory lookups feed ``NobodyRegistry``: every freer that turns up
/// with its key published is recorded, and only the nobody index is allowed
/// to say "not a nobody". See `NOBODY_SPEC.md`.
final class NobodyLookupTests: XCTestCase {

    private let alice = "FEk41Kqjar45fLDriztUDTUkdki7mmcjWK"
    private let bob = "FTqiqAyXHnK7uDTXzMap3acvqADK4ZGzts"

    func testNobodyByIdsAsksTheNobodyIndexAndRecordsBothAnswers() async throws {
        let mock = MockFapiClient()
        mock.responder = { call in
            XCTAssertEqual(call.api, "base.getByIds")
            return try makeResponse(data: [self.alice: ["id": self.alice, "priKey": "00"]])
        }
        let registry = NobodyRegistry()
        let directory = DirectoryService(fapi: mock, nobodies: registry)

        let found = try await directory.nobodyByIds([alice, bob])

        XCTAssertEqual(Set(found.keys), [alice])
        XCTAssertTrue(registry.isNobody(alice))
        XCTAssertTrue(registry.isKnownNotNobody(bob))

        let dict = try XCTUnwrap(
            JSONSerialization.jsonObject(with: try XCTUnwrap(mock.recorded.first?.fcdsl)) as? [String: Any]
        )
        XCTAssertEqual(dict["entity"] as? String, "nobody")
        XCTAssertEqual(dict["ids"] as? [String], [alice, bob])
    }

    func testNobodyIndex404MeansNoneAreNobodies() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in FapiResponse(code: 404, message: "NOT_FOUND") }
        let registry = NobodyRegistry()
        let found = try await DirectoryService(fapi: mock, nobodies: registry).nobodyByIds([bob])

        XCTAssertTrue(found.isEmpty)
        XCTAssertTrue(registry.isKnownNotNobody(bob))
    }

    func testAFailedNobodyLookupRecordsNothing() async {
        let mock = MockFapiClient()
        mock.responder = { _ in FapiResponse(code: 500, message: "boom") }
        let registry = NobodyRegistry()
        let result = await DirectoryService(fapi: mock, nobodies: registry).nobodyFids(among: [bob])

        XCTAssertNil(result)
        XCTAssertFalse(registry.isKnownNotNobody(bob))
    }

    func testFreerLookupRecordsNobodiesButNeverNegatives() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in
            try makeResponse(data: [
                self.alice: ["id": self.alice, "isNobody": true],
                self.bob: ["id": self.bob, "cid": "bob"]
            ])
        }
        let registry = NobodyRegistry()
        _ = try await DirectoryService(fapi: mock, nobodies: registry).freerByIds([alice, bob])

        XCTAssertTrue(registry.isNobody(alice))
        XCTAssertFalse(registry.isNobody(bob))
        // A freer without the flag proves nothing: bob is still unknown.
        XCTAssertEqual(registry.unknown(among: [bob]), [bob])
    }

    func testAPublishedPrikeyOnAFreerCountsAsNobody() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in
            try makeResponse(data: [["id": self.alice, "prikey": "d710ff"]])
        }
        let registry = NobodyRegistry()
        _ = try await DirectoryService(fapi: mock, nobodies: registry).searchFreers(matching: "x")

        XCTAssertTrue(registry.isNobody(alice))
    }
}
