import XCTest
import FCCore
import FCTransport
@testable import FCDomain

/// The app write path through `ActiveSession`, and the store that holds
/// the results.
///
/// The carve assertions decode the broadcast raw hex rather than
/// trusting the builder: what the chain sees is the only thing that
/// registers an app, and a builder that is right about a payload nobody
/// broadcasts is right about nothing.
final class AppCarveTests: XCTestCase {

    private var baseDir: URL!
    private var manager: ConfigureManager!

    override func setUpWithError() throws {
        baseDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("AppCarveTests-\(UUID().uuidString)")
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
            password: Data("app-tests".utf8), kdfKind: .legacySha256
        )
        let info = try configure.addMain(
            privkey: Hash.sha256(Data("publisher".utf8)), label: "publisher"
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
        txid: String = "app-txid-001",
        onBroadcast: @escaping @Sendable (String) -> Void = { _ in }
    ) throws {
        mock.responder = { call in
            switch call.api {
            case "base.cashValid":
                return try makeResponse(
                    data: [try self.cashDict(
                        owner: senderFid,
                        txid: String(repeating: "ad", count: 32),
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

    func testPublishCarvesTheFeipAndTakesTheTxidAsItsAid() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        let broadcast = Captured()
        try stage(mock, senderFid: session.mainFid, onBroadcast: { broadcast.value = $0 })

        let app = try await session.carveAppPublishOnChain(
            stdName: "Freer",
            localNames: ["zh": "自由"],
            types: ["wallet", "im"],
            desc: "a freecash client",
            ver: "1.4.2",
            home: ["site": "https://freer.cash"],
            downloads: [.init(os: "macos", link: "https://x/Freer.dmg", did: "abc")],
            waiters: ["FIDW"],
            protocols: ["p1"],
            codes: ["c1"],
            services: ["s1"]
        )

        let raw = Data(fromHex: try XCTUnwrap(broadcast.value))
        XCTAssertNotNil(raw.range(of: Data(#""sn":"15","ver":"1""#.utf8)), "envelope")
        XCTAssertNotNil(raw.range(of: Data(#""name":"APP""#.utf8)), "capitals, not \"App\"")
        XCTAssertNotNil(raw.range(of: Data(#""op":"publish""#.utf8)))
        XCTAssertNotNil(raw.range(of: Data(#""stdName":"Freer""#.utf8)))
        XCTAssertNotNil(raw.range(of: Data(#""types":["wallet","im"]"#.utf8)))
        XCTAssertNotNil(raw.range(of: Data(#""codes":["c1"]"#.utf8)))
        XCTAssertNotNil(raw.range(of: Data(#""services":["s1"]"#.utf8)))
        XCTAssertNotNil(raw.range(of: Data(
            #""downloads":[{"did":"abc","link":"https://x/Freer.dmg","os":"macos"}]"#.utf8
        )), "the field Android hardcodes to null")

        XCTAssertEqual(app.id, "app-txid-001")
        XCTAssertEqual(app.owner, session.liveFid)
        XCTAssertEqual(app.lastTxId, "app-txid-001")
        XCTAssertEqual(app.downloads?.count, 1, "the downloads are on the row, not just the wire")
        // Broadcast, not confirmed.
        XCTAssertNil(app.onChain)
        XCTAssertEqual(app.state, .broadcast)
        XCTAssertEqual(app.lastHeight, AppsStore.unconfirmedHeight)
    }

    func testPublishPutsTheBroadcastRowAtTheHeadOfTheWindow() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        try stage(mock, senderFid: session.mainFid)

        _ = try await session.carveAppPublishOnChain(stdName: "Freer")

        let window = try session.apps.window()
        XCTAssertEqual(window.first?.id, "app-txid-001")
        XCTAssertEqual(window.first?.stdName, "Freer")
        XCTAssertNil(window.first?.onChain)
    }

    /// The size guard runs before coin selection, so an oversize
    /// registration costs nothing and broadcasts nothing.
    func testAnOversizeRegistrationIsRefusedBeforeAnyApiCall() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        try stage(mock, senderFid: session.mainFid)

        do {
            _ = try await session.carveAppPublishOnChain(
                stdName: "Freer", desc: String(repeating: "x", count: 5_000)
            )
            XCTFail("expected a throw")
        } catch let e as AppFeip.Failure {
            guard case .tooLarge = e else { return XCTFail("wrong case: \(e)") }
        }
        XCTAssertTrue(mock.recorded.isEmpty, "nothing was spent and nothing was asked")
    }

    /// A download row is the most expensive thing on the form, so the
    /// guard has to catch the list, not just the prose.
    func testAnOversizeDownloadListIsRefusedBeforeBroadcast() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        try stage(mock, senderFid: session.mainFid)

        let downloads = (0..<40).map { i in
            AppRecord.Download(
                os: "os\(i)",
                link: "https://downloads.example.com/build-\(i)/Freer-installer.pkg",
                did: String(repeating: "a", count: 64)
            )
        }
        do {
            _ = try await session.carveAppPublishOnChain(
                stdName: "Freer", downloads: downloads
            )
            XCTFail("expected a throw")
        } catch let e as AppFeip.Failure {
            guard case .tooLarge = e else { return XCTFail("wrong case: \(e)") }
        }
        XCTAssertTrue(mock.recorded.isEmpty)
    }

    func testPublishingADraftPromotesItOutOfTheDraftNamespace() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        try stage(mock, senderFid: session.mainFid)

        let draft = AppRecord.createLocal(
            stdName: "Freer",
            types: ["wallet"],
            downloads: [.init(os: "macos", link: "https://x/Freer.dmg")],
            codes: ["c1"],
            owner: session.liveFid
        )
        try session.apps.upsertDraft(draft)
        XCTAssertEqual(try session.apps.drafts().count, 1)

        let published = try await session.carveAppPublishOnChain(
            stdName: "Freer",
            types: ["wallet"],
            downloads: [.init(os: "macos", link: "https://x/Freer.dmg")],
            codes: ["c1"],
            draftId: draft.id
        )

        XCTAssertEqual(published.id, "app-txid-001")
        XCTAssertEqual(published.codes, ["c1"], "the draft's fields came with it")
        XCTAssertEqual(published.downloads?.first?.link, "https://x/Freer.dmg")
        XCTAssertTrue(try session.apps.drafts().isEmpty, "no longer a draft")
        XCTAssertEqual(try session.apps.window().first?.id, "app-txid-001")
    }

    // MARK: - update

    func testUpdateNamesTheRecordByAid() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        let broadcast = Captured()
        try stage(mock, senderFid: session.mainFid, onBroadcast: { broadcast.value = $0 })

        let txid = try await session.carveAppUpdateOnChain(aid: "aid0", stdName: "Freer")
        XCTAssertEqual(txid, "app-txid-001")

        let raw = Data(fromHex: try XCTUnwrap(broadcast.value))
        XCTAssertNotNil(raw.range(of: Data(#""op":"update""#.utf8)))
        XCTAssertNotNil(raw.range(of: Data(#""aid":"aid0""#.utf8)))
        for foreign in [#""pid""#, #""codeId""#, #""sid""#] {
            XCTAssertNil(raw.range(of: Data(foreign.utf8)), "\(foreign) is another record's")
        }
    }

    /// **Android issue C23.** Its update passes `downloads: null`, so
    /// every amendment silently drops whatever builds the record was
    /// offering. Resending them is the whole fix, and it is worth a
    /// test on the transaction rather than the builder.
    func testAnUpdateResendsTheDownloadsRatherThanClearingThem() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        let broadcast = Captured()
        try stage(mock, senderFid: session.mainFid, onBroadcast: { broadcast.value = $0 })

        _ = try await session.carveAppUpdateOnChain(
            aid: "aid0",
            stdName: "Freer",
            desc: "now with a new icon",
            downloads: [.init(os: "macos", link: "https://x/Freer.dmg", did: "abc")]
        )

        let raw = Data(fromHex: try XCTUnwrap(broadcast.value))
        XCTAssertNotNil(raw.range(of: Data(
            #""downloads":[{"did":"abc","link":"https://x/Freer.dmg","os":"macos"}]"#.utf8
        )), "an update that omits these clears them on chain")
    }

    // MARK: - stop / recover / close

    func testStopCarvesTheIdListAndMarksTheCacheLocally() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        let broadcast = Captured()
        try stage(mock, senderFid: session.mainFid, onBroadcast: { broadcast.value = $0 })

        try session.apps.rememberBroadcast(
            AppRecord(id: "a1", owner: session.liveFid, active: true, onChain: true)
        )
        _ = try await session.carveAppStopOnChain(aids: ["a1", "a2"])

        let raw = Data(fromHex: try XCTUnwrap(broadcast.value))
        XCTAssertNotNil(raw.range(of: Data(#""op":"stop""#.utf8)))
        XCTAssertNotNil(raw.range(of: Data(#""aids":["a1","a2"]"#.utf8)))

        let row = try XCTUnwrap(try session.apps.window().first { $0.id == "a1" })
        XCTAssertEqual(row.active, false)
        XCTAssertEqual(row.state, .stopped)
    }

    func testRecoverPutsTheCachedRowBackInForce() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        let broadcast = Captured()
        try stage(mock, senderFid: session.mainFid, onBroadcast: { broadcast.value = $0 })

        try session.apps.rememberBroadcast(
            AppRecord(id: "a1", owner: session.liveFid, active: false, onChain: true)
        )
        _ = try await session.carveAppRecoverOnChain(aids: ["a1"])

        let raw = Data(fromHex: try XCTUnwrap(broadcast.value))
        XCTAssertNotNil(raw.range(of: Data(#""op":"recover""#.utf8)))
        XCTAssertEqual(try session.apps.window().first?.state, .live)
    }

    func testCloseCarvesItsStatementAndIsNotUndoneByRecover() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        let broadcast = Captured()
        try stage(mock, senderFid: session.mainFid, onBroadcast: { broadcast.value = $0 })

        try session.apps.rememberBroadcast(
            AppRecord(id: "a1", owner: session.liveFid, active: true, onChain: true)
        )
        _ = try await session.carveAppCloseOnChain(
            aids: ["a1"], closeStatement: "use Freer 2"
        )

        let raw = Data(fromHex: try XCTUnwrap(broadcast.value))
        XCTAssertNotNil(raw.range(of: Data(#""op":"close""#.utf8)))
        XCTAssertNotNil(raw.range(of: Data(#""closeStatement":"use Freer 2""#.utf8)))

        let row = try XCTUnwrap(try session.apps.window().first)
        XCTAssertEqual(row.state, .closed)
        XCTAssertEqual(row.closeStatement, "use Freer 2")
        XCTAssertFalse(row.canRecover(as: session.liveFid))
    }

    /// One carve for the batch is the whole reason these ops take a
    /// list: three apps stopped separately is three miner fees.
    func testABatchIsOneBroadcast() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        try stage(mock, senderFid: session.mainFid)

        _ = try await session.carveAppStopOnChain(aids: ["a", "b", "c"])
        XCTAssertEqual(mock.recorded.filter { $0.api == "base.broadcastTx" }.count, 1)
    }

    func testAnEmptyIdListNeverReachesTheWallet() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        try stage(mock, senderFid: session.mainFid)

        do {
            _ = try await session.carveAppStopOnChain(aids: [])
            XCTFail("expected a throw")
        } catch let e as AppFeip.Failure {
            guard case .noAids = e else { return XCTFail("wrong case: \(e)") }
        }
        XCTAssertTrue(mock.recorded.isEmpty)
    }

    // MARK: - the store

    /// A draft is the only copy of work nobody has paid to publish, so
    /// it must not share a keyspace with a window truncated on every
    /// save.
    func testTruncatingTheWindowNeverTouchesADraft() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        let store = session.apps

        let draft = AppRecord.createLocal(stdName: "Freer", owner: session.liveFid)
        try store.upsertDraft(draft)

        let flood = (0..<(AppsStore.maxCachedApps + 50)).map {
            AppRecord(id: "a\($0)", stdName: "A\($0)", onChain: true)
        }
        try store.saveWindow(flood)

        XCTAssertEqual(try store.window().count, AppsStore.maxCachedApps)
        XCTAssertEqual(try store.drafts().map(\.id), [draft.id])
    }

    /// Four Construct stores over four indices. A shared namespace would
    /// let an app draft show up in the code pane.
    func testTheFourConstructStoresDoNotShareAKeyspace() {
        let namespaces = [
            ProtocolsStore.draftNamespace, ProtocolsStore.cacheNamespace,
            CodesStore.draftNamespace, CodesStore.cacheNamespace,
            ServicesStore.draftNamespace, ServicesStore.cacheNamespace,
            AppsStore.draftNamespace, AppsStore.cacheNamespace
        ]
        XCTAssertEqual(Set(namespaces).count, namespaces.count, "\(namespaces)")
    }

    func testRefreshingTheWindowKeepsWhenARowWasFirstSeen() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        let store = session.apps

        try store.saveWindow([AppRecord(id: "a1", stdName: "Freer", onChain: true)])
        let seen = try XCTUnwrap(try store.window().first?.addedAt)

        try await Task.sleep(nanoseconds: 10_000_000)
        try store.saveWindow([AppRecord(id: "a1", stdName: "Freer renamed", onChain: true)])

        XCTAssertEqual(try store.window().first?.addedAt, seen)
        XCTAssertEqual(try store.window().first?.stdName, "Freer renamed")
    }

    func testHidingIsLocalIdempotentAndReversible() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        let store = session.apps

        try store.saveWindow([
            AppRecord(id: "a1", stdName: "A", onChain: true),
            AppRecord(id: "a2", stdName: "B", onChain: true)
        ])
        try store.hide(ids: ["a1"])
        try store.hide(ids: ["a1"])
        XCTAssertEqual(try store.hiddenIds(), ["a1"])
        XCTAssertEqual(try store.visibleWindow().map(\.id), ["a2"])
        XCTAssertEqual(try store.hidden().map(\.id), ["a1"])
        // Hiding carves nothing: the record is untouched.
        XCTAssertNil(try store.window().first?.active)

        try store.unhide(ids: ["a1"])
        XCTAssertEqual(try store.visibleWindow().count, 2)
    }

    /// A hidden row that falls out of the window must stay hidden —
    /// forgetting the decision silently un-hides it on the next refresh.
    func testAHiddenIdSurvivesItsRowLeavingTheWindow() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        let store = session.apps

        try store.saveWindow([AppRecord(id: "a1", onChain: true)])
        try store.hide(ids: ["a1"])
        try store.saveWindow([AppRecord(id: "a2", onChain: true)])

        XCTAssertTrue(try store.hidden().isEmpty, "the row is gone")
        XCTAssertEqual(try store.hiddenIds(), ["a1"], "the decision is not")
    }
}

private final class Captured: @unchecked Sendable {
    var value: String?
}
