import XCTest
import FCCore
import FCTransport
@testable import FCDomain

/// The service write path through `ActiveSession`, and the store that
/// holds the results.
///
/// The carve assertions decode the broadcast raw hex rather than
/// trusting the builder: what the chain sees is the only thing that
/// registers a service, and a builder that is right about a payload
/// nobody broadcasts is right about nothing.
final class ServiceCarveTests: XCTestCase {

    private var baseDir: URL!
    private var manager: ConfigureManager!

    override func setUpWithError() throws {
        baseDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("ServiceCarveTests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: baseDir, withIntermediateDirectories: true)
        manager = try ConfigureManager(baseDirectory: baseDir)
    }

    override func tearDownWithError() throws {
        manager = nil
        if let baseDir { try? FileManager.default.removeItem(at: baseDir) }
    }

    // MARK: - fixtures

    private func makeSession(fapi: any FapiCalling) throws -> ActiveSession {
        let configure = try manager.createConfigure(
            password: Data("service-tests".utf8), kdfKind: .legacySha256
        )
        let info = try configure.addMain(
            privkey: Hash.sha256(Data("operator".utf8)), label: "operator"
        )
        return try configure.unlockMain(fid: info.fid, fapi: fapi)
    }

    private func cashDict(owner: String, txid: String, value: Int64) throws -> [String: Any] {
        let h160 = try FchAddress(fid: owner).hash160
        return [
            "id": try Cash.makeId(birthTxId: txid, birthIndex: 0),
            "owner": owner,
            "value": value,
            "type": "P2PKH",
            "birthTxId": txid,
            "birthIndex": 0,
            "lockScript": Cash.canonicalP2PKHLockScript(hash160: h160)
        ]
    }

    private func stage(
        _ mock: MockFapiClient,
        senderFid: String,
        funds: Int64 = 10_000_000,
        txid: String = "svc-txid-001",
        onBroadcast: @escaping @Sendable (String) -> Void = { _ in }
    ) throws {
        mock.responder = { call in
            switch call.api {
            case "base.cashValid":
                return try makeResponse(
                    data: [try self.cashDict(
                        owner: senderFid,
                        txid: String(repeating: "5d", count: 32),
                        value: funds
                    )],
                    bestHeight: 3_500_000
                )
            case "base.search":
                return try makeResponse(data: [] as [Any], bestHeight: 3_500_000)
            case "base.broadcastTx":
                let params = try JSONSerialization.jsonObject(with: call.params!) as? [String: Any]
                onBroadcast((params?["rawTx"] as? String) ?? "")
                return try makeResponse(data: txid)
            default:
                XCTFail("unexpected api: \(call.api)")
                return FapiResponse(code: 1, message: "unexpected")
            }
        }
    }

    // MARK: - publish

    func testPublishCarvesTheFeipAndTakesTheTxidAsItsSid() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        let broadcast = Captured()
        try stage(mock, senderFid: session.mainFid, onBroadcast: { broadcast.value = $0 })

        let service = try await session.carveServicePublishOnChain(
            stdName: "DOCK@No1_NrC7",
            localNames: ["zh": "码头"],
            desc: "store and forward",
            type: "FAPI@No1_NrC7",
            components: ["DOCK@No1_NrC7"],
            ver: "3",
            home: ["API": "https://cid.cash/APIP"],
            waiters: ["FIDW"],
            protocols: ["p1"],
            codes: ["c1"],
            services: ["s1"],
            pricing: .init(pricePerKB: "0.0001", currency: "FCH", maxDataSize: "262144")
        )

        let raw = Data(fromHex: try XCTUnwrap(broadcast.value))
        XCTAssertNotNil(raw.range(of: Data(#""sn":"5","ver":"3""#.utf8)), "envelope")
        XCTAssertNotNil(raw.range(of: Data(#""name":"Service""#.utf8)))
        XCTAssertNotNil(raw.range(of: Data(#""op":"publish""#.utf8)))
        XCTAssertNotNil(raw.range(of: Data(#""stdName":"DOCK@No1_NrC7""#.utf8)))
        XCTAssertNotNil(raw.range(of: Data(#""components":["DOCK@No1_NrC7"]"#.utf8)))
        XCTAssertNotNil(raw.range(of: Data(#""codes":["c1"]"#.utf8)))
        XCTAssertNotNil(raw.range(of: Data(#""services":["s1"]"#.utf8)))
        XCTAssertNotNil(raw.range(of: Data(#""home":{"API":"https://cid.cash/APIP"}"#.utf8)))
        XCTAssertNotNil(raw.range(of: Data(#""pricePerKB":"0.0001""#.utf8)))
        XCTAssertNotNil(raw.range(of: Data(#""maxDataSize":"262144""#.utf8)))

        XCTAssertEqual(service.sid, "svc-txid-001")
        XCTAssertEqual(service.owner, session.liveFid)
        XCTAssertEqual(service.lastTxId, "svc-txid-001")
        XCTAssertEqual(service.maxDataSize, "262144", "the prices are on the row, not just the wire")
        // Broadcast, not confirmed.
        XCTAssertNil(service.onChain)
        XCTAssertEqual(service.state, .broadcast)
        XCTAssertEqual(service.lastHeight, ServicesStore.unconfirmedHeight)
    }

    /// A just-published service must resolve like any other: the row the
    /// carve returns is the one the DOCK picker would read.
    func testAPublishedRowIsImmediatelyResolvable() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        try stage(mock, senderFid: session.mainFid)

        let service = try await session.carveServicePublishOnChain(
            stdName: "DOCK@ME",
            components: ["DOCK@No1_NrC7"],
            home: ["API": "https://me.example/APIP"],
            pricing: .init(maxDataSize: "131072")
        )
        XCTAssertEqual(service.apiUrl, "https://me.example/APIP")
        XCTAssertTrue(service.offers(ServiceName.dock))
        XCTAssertEqual(service.itemSizeLimit, 131_072)
    }

    func testPublishPutsTheBroadcastRowAtTheHeadOfTheWindow() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        try stage(mock, senderFid: session.mainFid)

        _ = try await session.carveServicePublishOnChain(stdName: "DOCK@ME")

        let window = try session.services.window()
        XCTAssertEqual(window.first?.sid, "svc-txid-001")
        XCTAssertEqual(window.first?.stdName, "DOCK@ME")
        XCTAssertNil(window.first?.onChain)
    }

    /// The size guard runs before coin selection, so an oversize
    /// registration costs nothing and broadcasts nothing.
    func testAnOversizeRegistrationIsRefusedBeforeAnyApiCall() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        try stage(mock, senderFid: session.mainFid)

        do {
            _ = try await session.carveServicePublishOnChain(
                stdName: "DOCK@ME",
                desc: String(repeating: "x", count: 5_000)
            )
            XCTFail("expected a throw")
        } catch let e as ServiceFeip.Failure {
            guard case .tooLarge = e else { return XCTFail("wrong case: \(e)") }
        }
        XCTAssertTrue(mock.recorded.isEmpty, "nothing was spent and nothing was asked")
    }

    /// Five id lists is what makes this the tightest of the four
    /// Construct records — the guard has to catch the lists, not just
    /// the prose.
    func testAnOversizeIdListIsRefusedBeforeBroadcast() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        try stage(mock, senderFid: session.mainFid)

        let ids = (0..<40).map { _ in String(repeating: "a", count: 64) }
        do {
            _ = try await session.carveServicePublishOnChain(
                stdName: "DOCK@ME", protocols: ids, codes: ids
            )
            XCTFail("expected a throw")
        } catch let e as ServiceFeip.Failure {
            guard case .tooLarge = e else { return XCTFail("wrong case: \(e)") }
        }
        XCTAssertTrue(mock.recorded.isEmpty)
    }

    func testPublishingADraftPromotesItOutOfTheDraftNamespace() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        try stage(mock, senderFid: session.mainFid)

        let draft = Service.createLocal(
            stdName: "DOCK@ME",
            components: ["DOCK@No1_NrC7"],
            codes: ["c1"],
            pricing: .init(currency: "FCH"),
            owner: session.liveFid
        )
        try session.services.upsertDraft(draft)
        XCTAssertEqual(try session.services.drafts().count, 1)

        let published = try await session.carveServicePublishOnChain(
            stdName: "DOCK@ME",
            components: ["DOCK@No1_NrC7"],
            codes: ["c1"],
            pricing: .init(currency: "FCH"),
            draftId: draft.sid
        )

        XCTAssertEqual(published.sid, "svc-txid-001")
        XCTAssertEqual(published.codes, ["c1"], "the draft's fields came with it")
        XCTAssertEqual(published.currency, "FCH")
        XCTAssertTrue(try session.services.drafts().isEmpty, "no longer a draft")
        XCTAssertEqual(try session.services.window().first?.sid, "svc-txid-001")
    }

    // MARK: - update

    func testUpdateNamesTheRecordBySid() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        let broadcast = Captured()
        try stage(mock, senderFid: session.mainFid, onBroadcast: { broadcast.value = $0 })

        let txid = try await session.carveServiceUpdateOnChain(
            sid: "sid0", stdName: "DOCK@ME", home: ["API": "https://new/APIP"]
        )
        XCTAssertEqual(txid, "svc-txid-001")

        let raw = Data(fromHex: try XCTUnwrap(broadcast.value))
        XCTAssertNotNil(raw.range(of: Data(#""op":"update""#.utf8)))
        XCTAssertNotNil(raw.range(of: Data(#""sid":"sid0""#.utf8)))
        XCTAssertNil(raw.range(of: Data(#""pid""#.utf8)), "Protocol's field name, not this one")
        XCTAssertNil(raw.range(of: Data(#""codeId""#.utf8)), "Code's field name, not this one")
    }

    // MARK: - stop / recover / close

    func testStopCarvesTheIdListAndMarksTheCacheLocally() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        let broadcast = Captured()
        try stage(mock, senderFid: session.mainFid, onBroadcast: { broadcast.value = $0 })

        try session.services.rememberBroadcast(
            Service(owner: session.liveFid, active: true, onChain: true, id: "s1")
        )
        _ = try await session.carveServiceStopOnChain(sids: ["s1", "s2"])

        let raw = Data(fromHex: try XCTUnwrap(broadcast.value))
        XCTAssertNotNil(raw.range(of: Data(#""op":"stop""#.utf8)))
        XCTAssertNotNil(raw.range(of: Data(#""sids":["s1","s2"]"#.utf8)))

        let row = try XCTUnwrap(try session.services.window().first { $0.sid == "s1" })
        XCTAssertEqual(row.active, false)
        XCTAssertEqual(row.state, .stopped)
    }

    func testRecoverPutsTheCachedRowBackInForce() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        let broadcast = Captured()
        try stage(mock, senderFid: session.mainFid, onBroadcast: { broadcast.value = $0 })

        try session.services.rememberBroadcast(
            Service(owner: session.liveFid, active: false, onChain: true, id: "s1")
        )
        _ = try await session.carveServiceRecoverOnChain(sids: ["s1"])

        let raw = Data(fromHex: try XCTUnwrap(broadcast.value))
        XCTAssertNotNil(raw.range(of: Data(#""op":"recover""#.utf8)))
        XCTAssertEqual(try session.services.window().first?.state, .live)
    }

    func testCloseCarvesItsStatementAndIsNotUndoneByRecover() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        let broadcast = Captured()
        try stage(mock, senderFid: session.mainFid, onBroadcast: { broadcast.value = $0 })

        try session.services.rememberBroadcast(
            Service(owner: session.liveFid, active: true, onChain: true, id: "s1")
        )
        _ = try await session.carveServiceCloseOnChain(
            sids: ["s1"], closeStatement: "moved to DOCK@v4"
        )

        let raw = Data(fromHex: try XCTUnwrap(broadcast.value))
        XCTAssertNotNil(raw.range(of: Data(#""op":"close""#.utf8)))
        XCTAssertNotNil(raw.range(of: Data(#""closeStatement":"moved to DOCK@v4""#.utf8)))

        let row = try XCTUnwrap(try session.services.window().first)
        XCTAssertEqual(row.state, .closed)
        XCTAssertEqual(row.closeStatement, "moved to DOCK@v4")
        XCTAssertFalse(row.canRecover(as: session.liveFid))
    }

    /// One carve for the batch is the whole reason these ops take a
    /// list: three services stopped separately is three miner fees.
    func testABatchIsOneBroadcast() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        try stage(mock, senderFid: session.mainFid)

        _ = try await session.carveServiceStopOnChain(sids: ["a", "b", "c"])
        XCTAssertEqual(mock.recorded.filter { $0.api == "base.broadcastTx" }.count, 1)
    }

    func testAnEmptyIdListNeverReachesTheWallet() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        try stage(mock, senderFid: session.mainFid)

        do {
            _ = try await session.carveServiceStopOnChain(sids: [])
            XCTFail("expected a throw")
        } catch let e as ServiceFeip.Failure {
            guard case .noSids = e else { return XCTFail("wrong case: \(e)") }
        }
        XCTAssertTrue(mock.recorded.isEmpty)
    }

    // MARK: - the store

    /// A draft is the only copy of work nobody has paid to publish, so
    /// it must not share a keyspace with a window that is truncated on
    /// every save.
    func testTruncatingTheWindowNeverTouchesADraft() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        let store = session.services

        let draft = Service.createLocal(stdName: "DOCK@ME", owner: session.liveFid)
        try store.upsertDraft(draft)

        let flood = (0..<(ServicesStore.maxCachedServices + 50)).map {
            Service(stdName: "S\($0)", onChain: true, id: "s\($0)")
        }
        try store.saveWindow(flood)

        XCTAssertEqual(try store.window().count, ServicesStore.maxCachedServices)
        XCTAssertEqual(try store.drafts().map(\.sid), [draft.sid])
    }

    /// Three Construct stores over three indices. A shared namespace
    /// would let a service draft show up in the code pane.
    func testTheThreeConstructStoresDoNotShareAKeyspace() {
        let namespaces = [
            ProtocolsStore.draftNamespace, ProtocolsStore.cacheNamespace,
            CodesStore.draftNamespace, CodesStore.cacheNamespace,
            ServicesStore.draftNamespace, ServicesStore.cacheNamespace
        ]
        XCTAssertEqual(Set(namespaces).count, namespaces.count, "\(namespaces)")
    }

    /// The registry cache and the resolver's cache are separate stores.
    /// A browse that evicted the resolver's DOCK would stop messages
    /// moving.
    func testTheRegistryCacheIsNotTheResolverCache() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        try session.services.saveWindow([
            Service(stdName: "DOCK@ME", onChain: true, id: "s1")
        ])
        let resolved = await session.homeServices.cachedService(sid: "s1")
        XCTAssertNil(resolved, "the pane's window is not a resolution answer")
    }

    func testRefreshingTheWindowKeepsWhenARowWasFirstSeen() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        let store = session.services

        let first = Service(stdName: "DOCK@ME", onChain: true, id: "s1")
        try store.saveWindow([first])
        let seen = try XCTUnwrap(try store.window().first?.addedAt)

        try await Task.sleep(nanoseconds: 10_000_000)
        try store.saveWindow([Service(stdName: "DOCK@ME renamed", onChain: true, id: "s1")])

        XCTAssertEqual(try store.window().first?.addedAt, seen)
        XCTAssertEqual(try store.window().first?.stdName, "DOCK@ME renamed")
    }

    func testHidingIsLocalIdempotentAndReversible() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        let store = session.services

        try store.saveWindow([
            Service(stdName: "A", onChain: true, id: "s1"),
            Service(stdName: "B", onChain: true, id: "s2")
        ])
        try store.hide(ids: ["s1"])
        try store.hide(ids: ["s1"])
        XCTAssertEqual(try store.hiddenIds(), ["s1"])
        XCTAssertEqual(try store.visibleWindow().map(\.sid), ["s2"])
        XCTAssertEqual(try store.hidden().map(\.sid), ["s1"])
        // Hiding carves nothing: the record is untouched.
        XCTAssertEqual(try store.window().first?.active, nil)

        try store.unhide(ids: ["s1"])
        XCTAssertEqual(try store.visibleWindow().count, 2)
    }

    /// A hidden row that falls out of the window must stay hidden —
    /// forgetting the decision silently un-hides it on the next refresh.
    func testAHiddenIdSurvivesItsRowLeavingTheWindow() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        let store = session.services

        try store.saveWindow([Service(onChain: true, id: "s1")])
        try store.hide(ids: ["s1"])
        try store.saveWindow([Service(onChain: true, id: "s2")])

        XCTAssertTrue(try store.hidden().isEmpty, "the row is gone")
        XCTAssertEqual(try store.hiddenIds(), ["s1"], "the decision is not")
    }
}

private final class Captured: @unchecked Sendable {
    var value: String?
}
