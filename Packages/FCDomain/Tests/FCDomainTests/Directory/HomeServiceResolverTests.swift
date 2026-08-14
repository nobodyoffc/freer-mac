import XCTest
import FCCore
import FCTransport
@testable import FCDomain

/// ``HomeServiceResolver``: the three shapes a `home` value comes in,
/// the SID lookup that turns two of them into addresses, and the batch
/// that keeps a send to one round trip.
final class HomeServiceResolverTests: XCTestCase {

    private var mock: MockFapiClient!
    private var resolver: HomeServiceResolver!

    private let dockSid = String(repeating: "a1", count: 32)
    private let roadSid = String(repeating: "b2", count: 32)

    override func setUpWithError() throws {
        mock = MockFapiClient()
        resolver = HomeServiceResolver(fapi: mock)
    }

    override func tearDownWithError() throws {
        resolver = nil
        mock = nil
    }

    // MARK: - shapes

    /// `fudp://` counts as a URL. A FUDP endpoint is as much an address
    /// as an HTTP one, and a resolver that only knew the web schemes
    /// would refuse to talk to a peer directly.
    func testUrlShapes() {
        XCTAssertTrue(HomeServiceResolver.isUrl("https://dock.example"))
        XCTAssertTrue(HomeServiceResolver.isUrl("http://dock.example"))
        XCTAssertTrue(HomeServiceResolver.isUrl("fudp://1.2.3.4:9000"))
        XCTAssertFalse(HomeServiceResolver.isUrl("dock.example"))
        XCTAssertFalse(HomeServiceResolver.isUrl(dockSid))
    }

    func testSidShapes() {
        XCTAssertEqual(HomeServiceResolver.extractSid(dockSid), dockSid)
        XCTAssertEqual(HomeServiceResolver.extractSid("(sid)\(dockSid)"), dockSid)
        XCTAssertEqual(HomeServiceResolver.extractSid(dockSid.uppercased()), dockSid.uppercased())

        XCTAssertNil(HomeServiceResolver.extractSid(nil))
        XCTAssertNil(HomeServiceResolver.extractSid(""))
        XCTAssertNil(HomeServiceResolver.extractSid("https://dock.example"))
        XCTAssertNil(HomeServiceResolver.extractSid(String(repeating: "a", count: 63)), "too short")
        XCTAssertNil(HomeServiceResolver.extractSid(String(repeating: "a", count: 65)), "too long")
        XCTAssertNil(
            HomeServiceResolver.extractSid(String(repeating: "z", count: 64)),
            "64 characters, but not hex"
        )
    }

    // MARK: - resolving

    /// A direct URL needs no lookup at all — and must not cost one.
    func testADirectUrlIsReturnedWithoutACall() async {
        let url = await resolver.resolve("https://dock.example")
        XCTAssertEqual(url, "https://dock.example")
        XCTAssertTrue(mock.recorded.isEmpty)
    }

    /// The indirection that makes SIDs worth having: the service record
    /// on the chain says where the server is, so an operator can move
    /// and everyone who wrote down the SID follows.
    func testASidResolvesThroughItsServiceRecord() async throws {
        stageServices([dockSid: "https://dock.moved.example"])
        let url = await resolver.resolve("(sid)\(dockSid)")
        XCTAssertEqual(url, "https://dock.moved.example")

        let dsl = try XCTUnwrap(mock.recorded.last?.fcdsl)
        let body = try XCTUnwrap(try JSONSerialization.jsonObject(with: dsl) as? [String: Any])
        XCTAssertEqual(mock.recorded.last?.api, "base.serviceByIds")
        XCTAssertEqual(body["ids"] as? [String], [dockSid])
    }

    /// Services register the endpoint under `API` or `api` depending on
    /// who published them. Honouring only one spelling would silently
    /// fail to reach half the network.
    func testTheApiKeyIsCaseInsensitive() {
        XCTAssertEqual(Service(home: ["API": "https://a"]).apiUrl, "https://a")
        XCTAssertEqual(Service(home: ["api": "https://b"]).apiUrl, "https://b")
        XCTAssertEqual(Service(home: ["Api": "https://c"]).apiUrl, "https://c")
        XCTAssertNil(Service(home: ["other": "https://d"]).apiUrl)
        XCTAssertNil(Service().apiUrl)
    }

    /// A resolved SID is cached: a service record changes about as often
    /// as a server moves, and a message send is not the moment to
    /// re-litigate it.
    func testAResolvedSidIsCached() async {
        stageServices([dockSid: "https://dock.example"])
        _ = await resolver.resolve(dockSid)
        _ = await resolver.resolve(dockSid)
        _ = await resolver.resolve("(sid)\(dockSid)")
        XCTAssertEqual(mock.recorded.count, 1, "one lookup, three resolutions")

        await resolver.clearCache()
        _ = await resolver.resolve(dockSid)
        XCTAssertEqual(mock.recorded.count, 2, "and the cache can be dropped")
    }

    /// Not resolving is an ordinary outcome — a peer may simply not run
    /// the service being asked about — so it is nil rather than a throw,
    /// and it is not cached as a negative.
    func testUnresolvableValuesAreNilNotErrors() async {
        stageServices([:])
        let unknownSid = await resolver.resolve(dockSid)
        XCTAssertNil(unknownSid)

        let nilValue = await resolver.resolve(nil)
        let emptyValue = await resolver.resolve("")
        let junkValue = await resolver.resolve("not-a-url-or-sid")
        XCTAssertNil(nilValue)
        XCTAssertNil(emptyValue)
        XCTAssertNil(junkValue)
    }

    /// A service record with no `API` in its home is not an address.
    func testAServiceWithNoApiUrlResolvesToNothing() async throws {
        mock.responder = { _ in
            try makeResponse(data: [self.dockSid: ["id": self.dockSid, "home": ["other": "x"]]])
        }
        let resolved = await resolver.resolve(dockSid)
        XCTAssertNil(resolved)
    }

    /// The server's 404 for an unknown SID is a normal answer.
    func testNotFoundIsNotAnError() async {
        mock.responder = { _ in try makeResponse(code: 404) }
        let resolved = await resolver.resolve(dockSid)
        XCTAssertNil(resolved)
    }

    // MARK: - home maps

    func testResolvesTheWellKnownServiceKeys() async {
        stageServices([dockSid: "https://dock.example", roadSid: "https://road.example"])
        let home = [
            ServiceName.dock: "(sid)\(dockSid)",
            ServiceName.road: roadSid,
            ServiceName.disk: "https://disk.example",
        ]
        let dock = await resolver.dockUrl(home: home)
        let road = await resolver.roadUrl(home: home)
        XCTAssertEqual(dock, "https://dock.example")
        XCTAssertEqual(road, "https://road.example")
        let noHome = await resolver.dockUrl(home: nil)
        let emptyHome = await resolver.dockUrl(home: [:])
        XCTAssertNil(noHome)
        XCTAssertNil(emptyHome)
    }

    /// A send resolves a DOCK and a ROAD together, so the batch
    /// collapses their lookups into **one** round trip. Doing them
    /// separately would double the latency of every first message to a
    /// peer.
    func testBatchCollapsesLookupsIntoOneCall() async {
        stageServices([dockSid: "https://dock.example", roadSid: "https://road.example"])
        let resolved = await resolver.resolveBatch([
            ServiceName.dock: "(sid)\(dockSid)",
            ServiceName.road: roadSid,
            ServiceName.disk: "https://disk.example",
        ])

        XCTAssertEqual(resolved[ServiceName.dock], "https://dock.example")
        XCTAssertEqual(resolved[ServiceName.road], "https://road.example")
        XCTAssertEqual(resolved[ServiceName.disk], "https://disk.example")
        XCTAssertEqual(mock.recorded.count, 1)

        let sent = try? JSONSerialization.jsonObject(
            with: mock.recorded[0].fcdsl ?? Data()
        ) as? [String: Any]
        XCTAssertEqual((sent?["ids"] as? [String])?.count, 2, "both SIDs in one request")
    }

    /// What cannot be reached is *absent*, so a caller can read the
    /// result as "what is reachable" rather than sifting nils.
    func testBatchOmitsWhatItCannotResolve() async {
        stageServices([dockSid: "https://dock.example"])
        let resolved = await resolver.resolveBatch([
            ServiceName.dock: dockSid,
            ServiceName.road: roadSid,
            "junk": "not-an-address",
            "empty": "",
        ])
        XCTAssertEqual(resolved, [ServiceName.dock: "https://dock.example"])
    }

    func testBatchUsesTheCacheAndFillsIt() async {
        stageServices([dockSid: "https://dock.example", roadSid: "https://road.example"])
        _ = await resolver.resolve(dockSid)
        XCTAssertEqual(mock.recorded.count, 1)

        let resolved = await resolver.resolveBatch([
            ServiceName.dock: dockSid,
            ServiceName.road: roadSid,
        ])
        XCTAssertEqual(resolved.count, 2)
        XCTAssertEqual(mock.recorded.count, 2, "only the uncached SID was fetched")

        // And what the batch fetched is cached for the next single call.
        _ = await resolver.resolve(roadSid)
        XCTAssertEqual(mock.recorded.count, 2)
        let cached = await resolver.cachedService(sid: roadSid)
        XCTAssertEqual(cached?.apiUrl, "https://road.example")
    }

    func testEmptyBatchMakesNoCall() async {
        let resolved = await resolver.resolveBatch([:])
        XCTAssertTrue(resolved.isEmpty)
        XCTAssertTrue(mock.recorded.isEmpty)
    }

    // MARK: - staging

    /// `base.serviceByIds` answers with the records it knows, keyed by
    /// SID, and omits the rest.
    private func stageServices(_ urlBySid: [String: String]) {
        mock.responder = { call in
            guard call.api == "base.serviceByIds" else { return try makeResponse(code: 0) }
            let requested = (try? JSONSerialization.jsonObject(with: call.fcdsl ?? Data()))
                .flatMap { ($0 as? [String: Any])?["ids"] as? [String] } ?? []
            var data: [String: Any] = [:]
            for sid in requested {
                guard let url = urlBySid[sid] else { continue }
                data[sid] = [
                    "id": sid,
                    "stdName": "DOCK@No1_NrC7",
                    "home": ["API": url],
                    "active": true,
                ]
            }
            if data.isEmpty { return try makeResponse(code: 404) }
            return try makeResponse(data: data)
        }
    }
}
