import XCTest
import FCCore
import FCTransport
@testable import FCDomain

/// The code write path through `ActiveSession`, and the store that holds
/// the results.
///
/// The carve assertions decode the broadcast raw hex rather than trusting
/// the builder: what the chain sees is the only thing that registers an
/// implementation, and a builder that is right about a payload nobody
/// broadcasts is right about nothing.
final class CodeCarveTests: XCTestCase {

    private var baseDir: URL!
    private var manager: ConfigureManager!

    override func setUpWithError() throws {
        baseDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("CodeCarveTests-\(UUID().uuidString)")
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
            password: Data("code-tests".utf8), kdfKind: .legacySha256
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
        txid: String = "code-txid-001",
        onBroadcast: @escaping @Sendable (String) -> Void = { _ in }
    ) throws {
        mock.responder = { call in
            switch call.api {
            case "base.cashValid":
                return try makeResponse(
                    data: [try self.cashDict(
                        owner: senderFid,
                        txid: String(repeating: "cd", count: 32),
                        value: funds
                    )],
                    bestHeight: 3_500_000
                )
            case "base.search":
                // The incremental cash sync a second carve runs. Nothing
                // new since the first, which is true: the change output
                // is already spendable from the local snapshot.
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

    /// Publishing is a registration, not a message: it pays nobody, and
    /// the record's id is the carve's txid.
    func testPublishCarvesTheFeipAndTakesTheTxidAsItsId() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        let broadcast = Captured()
        try stage(mock, senderFid: session.mainFid, onBroadcast: { broadcast.value = $0 })

        let code = try await session.carveCodePublishOnChain(
            name: "freer-mac", ver: "1.4.2", did: "D1",
            desc: "a mac client", langs: ["swift"],
            home: ["git": "https://example.com/freer.git"],
            protocols: ["pid1"], waiters: ["FIDA"]
        )

        let raw = Data(fromHex: try XCTUnwrap(broadcast.value))
        XCTAssertNotNil(raw.range(of: Data(#""sn":"2","ver":"1""#.utf8)), "envelope")
        XCTAssertNotNil(raw.range(of: Data(#""name":"Code""#.utf8)))
        XCTAssertNotNil(raw.range(of: Data(#""op":"publish""#.utf8)))
        XCTAssertNotNil(raw.range(of: Data(#""langs":["swift"]"#.utf8)))
        XCTAssertNotNil(raw.range(of: Data(#""protocols":["pid1"]"#.utf8)))
        XCTAssertNotNil(raw.range(of: Data(#""waiters":["FIDA"]"#.utf8)))
        XCTAssertNotNil(raw.range(of: Data(#""home":{"git":"https://example.com/freer.git"}"#.utf8)))

        XCTAssertEqual(code.id, "code-txid-001")
        XCTAssertEqual(code.owner, session.liveFid)
        XCTAssertEqual(code.lastTxId, "code-txid-001")
        // Broadcast, not confirmed.
        XCTAssertNil(code.onChain)
        XCTAssertEqual(code.state, .broadcast)
        XCTAssertEqual(code.lastHeight, CodesStore.unconfirmedHeight)
    }

    /// The carve the user just paid for has to be visible before a block
    /// confirms it, or the pane looks like the publish did nothing.
    func testPublishPutsTheBroadcastRowAtTheHeadOfTheWindow() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        try stage(mock, senderFid: session.mainFid)

        _ = try await session.carveCodePublishOnChain(name: "freer-mac")

        let window = try session.codes.window()
        XCTAssertEqual(window.first?.id, "code-txid-001")
        XCTAssertEqual(window.first?.name, "freer-mac")
        XCTAssertNil(window.first?.onChain)
    }

    /// The size guard runs before coin selection, so an oversize
    /// registration costs nothing and broadcasts nothing.
    func testAnOversizeRegistrationIsRefusedBeforeBroadcast() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        try stage(mock, senderFid: session.mainFid)

        do {
            _ = try await session.carveCodePublishOnChain(
                name: "C",
                desc: String(repeating: "x", count: CodeFeip.maxOpReturnSize)
            )
            XCTFail("expected a throw")
        } catch {
            XCTAssertTrue(mock.recorded.isEmpty, "nothing may be spent or broadcast")
        }
    }

    /// A protocol list long enough to blow the OP_RETURN is refused the
    /// same way a long description is — 64 hex characters an entry adds
    /// up faster than prose.
    func testAnOversizeProtocolListIsRefusedBeforeBroadcast() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        try stage(mock, senderFid: session.mainFid)

        let many = (0..<80).map { String(format: "%064x", $0) }
        do {
            _ = try await session.carveCodePublishOnChain(name: "C", protocols: many)
            XCTFail("expected a throw")
        } catch {
            XCTAssertTrue(mock.recorded.isEmpty, "nothing may be spent or broadcast")
        }
    }

    /// Carving a draft rekeys it to the txid and takes it out of the
    /// draft namespace: it is not a draft any more.
    func testCarvingADraftPromotesItOutOfTheDraftNamespace() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        try stage(mock, senderFid: session.mainFid)

        let draft = Code.createLocal(
            name: "freer-mac", ver: "1.4.2", desc: "d",
            protocols: ["pid1"], owner: session.liveFid
        )
        try session.codes.upsertDraft(draft)
        XCTAssertEqual(try session.codes.drafts().count, 1)

        let carved = try await session.carveCodePublishOnChain(
            name: "freer-mac", ver: "1.4.2", desc: "d",
            protocols: ["pid1"], draftId: draft.id
        )

        XCTAssertEqual(carved.id, "code-txid-001")
        XCTAssertNil(carved.onChain)
        XCTAssertEqual(carved.protocols, ["pid1"], "the draft's fields survive the promotion")
        XCTAssertTrue(try session.codes.drafts().isEmpty)
        XCTAssertNil(try session.codes.draft(id: draft.id))
        XCTAssertEqual(try session.codes.window().first?.id, "code-txid-001")
    }

    // MARK: - update

    /// `update` names the record by `codeId` — not `pid`, which is the
    /// protocol record's spelling of the same idea. The chain keeps the
    /// original publish txid as the id, so only `lastTxId` moves.
    func testUpdateNamesTheRecordByCodeIdAndResendsEveryField() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        let broadcast = Captured()
        try stage(mock, senderFid: session.mainFid,
                  txid: "update-txid", onBroadcast: { broadcast.value = $0 })

        let txid = try await session.carveCodeUpdateOnChain(
            codeId: "cid0", name: "freer-mac", ver: "1.5.0", desc: "revised",
            langs: ["swift"], protocols: ["pid1"]
        )
        XCTAssertEqual(txid, "update-txid")

        let raw = Data(fromHex: try XCTUnwrap(broadcast.value))
        XCTAssertNotNil(raw.range(of: Data(#""op":"update""#.utf8)))
        XCTAssertNotNil(raw.range(of: Data(#""codeId":"cid0""#.utf8)))
        XCTAssertNil(raw.range(of: Data(#""pid""#.utf8)), "that is the protocol record's field")
        XCTAssertNotNil(raw.range(of: Data(#""ver":"1.5.0""#.utf8)))
        XCTAssertNotNil(raw.range(of: Data(#""desc":"revised""#.utf8)))
        XCTAssertNotNil(raw.range(of: Data(#""protocols":["pid1"]"#.utf8)))
    }

    // MARK: - stop / recover / close

    /// The id-list ops take a list because the protocol does, and for a
    /// paid operation that is one miner fee instead of several.
    func testStopCarvesOneListInOneTransaction() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        let broadcast = Captured()
        try stage(mock, senderFid: session.mainFid, onBroadcast: { broadcast.value = $0 })

        _ = try await session.carveCodeStopOnChain(codeIds: ["c1", "c2"])

        let raw = Data(fromHex: try XCTUnwrap(broadcast.value))
        XCTAssertNotNil(raw.range(of: Data(#""op":"stop""#.utf8)))
        XCTAssertNotNil(raw.range(of: Data(#""codeIds":["c1","c2"]"#.utf8)))
        XCTAssertEqual(
            mock.recorded.filter { $0.api == "base.broadcastTx" }.count, 1,
            "one carve for the whole batch"
        )
    }

    func testRecoverCarvesTheOppositeOpOverTheSameList() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        let broadcast = Captured()
        try stage(mock, senderFid: session.mainFid, onBroadcast: { broadcast.value = $0 })

        _ = try await session.carveCodeRecoverOnChain(codeIds: ["c1", "c2"])

        let raw = Data(fromHex: try XCTUnwrap(broadcast.value))
        XCTAssertNotNil(raw.range(of: Data(#""op":"recover""#.utf8)))
        XCTAssertNotNil(raw.range(of: Data(#""codeIds":["c1","c2"]"#.utf8)))
    }

    func testCloseCarriesItsStatement() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        let broadcast = Captured()
        try stage(mock, senderFid: session.mainFid, onBroadcast: { broadcast.value = $0 })

        _ = try await session.carveCodeCloseOnChain(
            codeIds: ["c1"], closeStatement: "superseded by v2"
        )
        let raw = Data(fromHex: try XCTUnwrap(broadcast.value))
        XCTAssertNotNil(raw.range(of: Data(#""op":"close""#.utf8)))
        XCTAssertNotNil(raw.range(of: Data(#""closeStatement":"superseded by v2""#.utf8)))
    }

    /// A stop the user pressed has to have a visible effect before the
    /// next block, so the cached copy is marked. The chain is still the
    /// authority — the next refresh overwrites this wholesale.
    func testStopAndCloseMarkTheCachedCopyImmediately() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        try stage(mock, senderFid: session.mainFid)

        try session.codes.saveWindow([
            Code(id: "c1", name: "One", owner: session.liveFid,
                 active: true, closed: false, onChain: true),
            Code(id: "c2", name: "Two", owner: session.liveFid,
                 active: true, closed: false, onChain: true)
        ])

        _ = try await session.carveCodeStopOnChain(codeIds: ["c1"])
        var window = try session.codes.window()
        XCTAssertEqual(window.first { $0.id == "c1" }?.state, .stopped)
        XCTAssertEqual(window.first { $0.id == "c2" }?.state, .live, "untouched")

        _ = try await session.carveCodeCloseOnChain(codeIds: ["c1"], closeStatement: "done")
        window = try session.codes.window()
        XCTAssertEqual(window.first { $0.id == "c1" }?.state, .closed)
        XCTAssertEqual(window.first { $0.id == "c1" }?.closeStatement, "done")
    }

    /// A recover puts a stopped record back without touching `closed`.
    func testRecoverMarksTheCachedCopyActiveAgain() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        try stage(mock, senderFid: session.mainFid)

        try session.codes.saveWindow([
            Code(id: "c1", owner: session.liveFid, active: false, closed: false, onChain: true)
        ])
        _ = try await session.carveCodeRecoverOnChain(codeIds: ["c1"])
        XCTAssertEqual(try session.codes.window().first?.state, .live)
    }

    func testAnEmptyIdListIsRefusedBeforeBroadcast() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        try stage(mock, senderFid: session.mainFid)

        do {
            _ = try await session.carveCodeStopOnChain(codeIds: [])
            XCTFail("expected a throw")
        } catch {
            XCTAssertTrue(mock.recorded.isEmpty, "nothing may be spent or broadcast")
        }
    }

    // MARK: - the store

    /// Drafts and the window are separate namespaces precisely so a
    /// window truncation cannot reach a draft — the only copy of work the
    /// user has not yet paid to publish.
    func testTruncatingTheWindowNeverTouchesADraft() throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)

        let draft = Code.createLocal(name: "Draft", owner: session.liveFid)
        try session.codes.upsertDraft(draft)

        let many = (0..<(CodesStore.maxCachedCodes + 50)).map {
            Code(id: "c\($0)", name: "C\($0)", onChain: true)
        }
        try session.codes.saveWindow(many)

        XCTAssertEqual(try session.codes.window().count, CodesStore.maxCachedCodes)
        XCTAssertEqual(try session.codes.drafts().map(\.id), [draft.id])
    }

    /// The code and protocol stores share a shape and a device. They must
    /// not share a keyspace — a code draft appearing in the protocol pane
    /// would be a decode failure at best and a wrong carve at worst.
    func testCodeAndProtocolStoresDoNotShareAKeyspace() throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)

        try session.codes.upsertDraft(Code.createLocal(name: "C", owner: session.liveFid))
        try session.protocols.upsertDraft(
            ProtocolSpec.createLocal(name: "P", owner: session.liveFid)
        )
        try session.codes.saveWindow([Code(id: "c1", onChain: true)])
        try session.protocols.saveWindow([ProtocolSpec(id: "p1", onChain: true)])

        XCTAssertEqual(try session.codes.drafts().map(\.name), ["C"])
        XCTAssertEqual(try session.protocols.drafts().map(\.name), ["P"])
        XCTAssertEqual(try session.codes.window().map(\.id), ["c1"])
        XCTAssertEqual(try session.protocols.window().map(\.id), ["p1"])
    }

    /// Rows carried across a refresh keep their original `addedAt`, so
    /// "when did this first appear here" survives.
    func testARefreshKeepsWhenARowWasFirstSeen() throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)

        var row = Code(id: "c1", name: "One", onChain: true)
        row.addedAt = Date(timeIntervalSince1970: 1000)
        try session.codes.saveWindow([row])

        try session.codes.saveWindow([Code(id: "c1", name: "One renamed", onChain: true)])
        let kept = try XCTUnwrap(try session.codes.window().first)
        XCTAssertEqual(kept.name, "One renamed", "the chain is the authority for the fields")
        XCTAssertEqual(kept.addedAt.timeIntervalSince1970, 1000, accuracy: 0.5)
    }

    /// Hiding is local and idempotent, and it is not stopping: nothing is
    /// carved and the record carries on existing.
    func testHidingIsLocalIdempotentAndReversible() throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        try session.codes.saveWindow([
            Code(id: "c1", onChain: true),
            Code(id: "c2", onChain: true)
        ])

        try session.codes.hide(ids: ["c1", "c1", ""])
        XCTAssertEqual(try session.codes.hiddenIds(), ["c1"])
        XCTAssertEqual(try session.codes.visibleWindow().map(\.id), ["c2"])
        XCTAssertEqual(try session.codes.hidden().map(\.id), ["c1"])
        // Still there, still live — hiding carves nothing.
        XCTAssertEqual(try session.codes.window().count, 2)

        try session.codes.unhide(ids: ["c1"])
        XCTAssertEqual(try session.codes.visibleWindow().map(\.id), ["c1", "c2"])
    }

    /// A hidden id whose row has fallen out of the window stays hidden:
    /// the row may come back on the next refresh, and forgetting the
    /// decision would silently un-hide it.
    func testAHiddenIdSurvivesItsRowLeavingTheWindow() throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        try session.codes.saveWindow([Code(id: "c1", onChain: true)])
        try session.codes.hide(ids: ["c1"])

        try session.codes.saveWindow([Code(id: "c9", onChain: true)])
        XCTAssertTrue(try session.codes.hidden().isEmpty, "no row to show")
        XCTAssertEqual(try session.codes.hiddenIds(), ["c1"], "the decision is kept")
    }

    /// A re-broadcast of the same record replaces its row rather than
    /// adding a second one.
    func testRememberBroadcastIsKeyedByIdAndGoesToTheHead() throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        try session.codes.saveWindow([
            Code(id: "c1", name: "One", onChain: true),
            Code(id: "c2", name: "Two", onChain: true)
        ])

        try session.codes.rememberBroadcast(Code(id: "c2", name: "Two v2", onChain: nil))
        let window = try session.codes.window()
        XCTAssertEqual(window.map(\.id), ["c2", "c1"])
        XCTAssertEqual(window[0].name, "Two v2")
    }
}

private final class Captured: @unchecked Sendable {
    var value: String?
}
