import XCTest
import FCCore
import FCTransport
@testable import FCDomain

/// The protocol write path through `ActiveSession`, and the store that
/// holds the results.
///
/// The carve assertions decode the broadcast raw hex rather than
/// trusting the builder: what the chain sees is the only thing that
/// registers a protocol, and a builder that is right about a payload
/// nobody broadcasts is right about nothing.
final class ProtocolCarveTests: XCTestCase {

    private var baseDir: URL!
    private var manager: ConfigureManager!

    override func setUpWithError() throws {
        baseDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("ProtocolCarveTests-\(UUID().uuidString)")
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
            password: Data("protocol-tests".utf8), kdfKind: .legacySha256
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
        txid: String = "protocol-txid-001",
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

        let spec = try await session.carveProtocolPublishOnChain(
            name: "Contact", type: "FEIP", sn: "12", ver: "3", did: "D1",
            desc: "the contact protocol", lang: "en",
            home: ["spec": "https://example.com/feip12"],
            waiters: ["FIDA"]
        )

        let raw = Data(fromHex: try XCTUnwrap(broadcast.value))
        XCTAssertNotNil(raw.range(of: Data(#""sn":"1","ver":"7""#.utf8)), "envelope")
        XCTAssertNotNil(raw.range(of: Data(#""name":"FeipProtocol""#.utf8)))
        XCTAssertNotNil(raw.range(of: Data(#""op":"publish""#.utf8)))
        XCTAssertNotNil(raw.range(of: Data(#""sn":"12""#.utf8)), "payload sn")
        XCTAssertNotNil(raw.range(of: Data(#""waiters":["FIDA"]"#.utf8)))
        XCTAssertNotNil(raw.range(of: Data(#""home":{"spec":"https://example.com/feip12"}"#.utf8)))

        XCTAssertEqual(spec.id, "protocol-txid-001")
        XCTAssertEqual(spec.owner, session.liveFid)
        XCTAssertEqual(spec.birthTxId, "protocol-txid-001")
        // Broadcast, not confirmed.
        XCTAssertNil(spec.onChain)
        XCTAssertEqual(spec.state, .broadcast)
        XCTAssertEqual(spec.lastHeight, ProtocolsStore.unconfirmedHeight)
    }

    /// The carve the user just paid for has to be visible before a block
    /// confirms it, or the pane looks like the publish did nothing.
    func testPublishPutsTheBroadcastRowAtTheHeadOfTheWindow() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        try stage(mock, senderFid: session.mainFid)

        _ = try await session.carveProtocolPublishOnChain(name: "Contact")

        let window = try session.protocols.window()
        XCTAssertEqual(window.first?.id, "protocol-txid-001")
        XCTAssertEqual(window.first?.name, "Contact")
        XCTAssertNil(window.first?.onChain)
    }

    /// The size guard runs before coin selection, so an oversize
    /// registration costs nothing and broadcasts nothing.
    func testAnOversizeRegistrationIsRefusedBeforeBroadcast() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        try stage(mock, senderFid: session.mainFid)

        do {
            _ = try await session.carveProtocolPublishOnChain(
                name: "P",
                desc: String(repeating: "x", count: ProtocolFeip.maxOpReturnSize)
            )
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

        let draft = ProtocolSpec.createLocal(
            name: "Contact", ver: "3", desc: "d", owner: session.liveFid
        )
        try session.protocols.upsertDraft(draft)
        XCTAssertEqual(try session.protocols.drafts().count, 1)

        let carved = try await session.carveProtocolPublishOnChain(
            name: "Contact", ver: "3", desc: "d", draftId: draft.id
        )

        XCTAssertEqual(carved.id, "protocol-txid-001")
        XCTAssertNil(carved.onChain)
        XCTAssertTrue(try session.protocols.drafts().isEmpty)
        XCTAssertNil(try session.protocols.draft(id: draft.id))
        XCTAssertEqual(try session.protocols.window().first?.id, "protocol-txid-001")
    }

    // MARK: - update

    /// `update` names the record by `pid`; the chain keeps the original
    /// publish txid as the id, so only `lastTxId` moves.
    func testUpdateNamesTheRecordByPidAndResendsEveryField() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        let broadcast = Captured()
        try stage(mock, senderFid: session.mainFid,
                  txid: "update-txid", onBroadcast: { broadcast.value = $0 })

        let txid = try await session.carveProtocolUpdateOnChain(
            pid: "pid0", name: "Contact", ver: "4", desc: "revised"
        )
        XCTAssertEqual(txid, "update-txid")

        let raw = Data(fromHex: try XCTUnwrap(broadcast.value))
        XCTAssertNotNil(raw.range(of: Data(#""op":"update""#.utf8)))
        XCTAssertNotNil(raw.range(of: Data(#""pid":"pid0""#.utf8)))
        XCTAssertNotNil(raw.range(of: Data(#""ver":"4""#.utf8)))
        XCTAssertNotNil(raw.range(of: Data(#""desc":"revised""#.utf8)))
    }

    // MARK: - stop / recover / close

    /// The id-list ops take a list because the protocol does, and for a
    /// paid operation that is one miner fee instead of several.
    func testStopCarvesOneListInOneTransaction() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        let broadcast = Captured()
        try stage(mock, senderFid: session.mainFid, onBroadcast: { broadcast.value = $0 })

        _ = try await session.carveProtocolStopOnChain(pids: ["p1", "p2"])

        let raw = Data(fromHex: try XCTUnwrap(broadcast.value))
        XCTAssertNotNil(raw.range(of: Data(#""op":"stop""#.utf8)))
        XCTAssertNotNil(raw.range(of: Data(#""pids":["p1","p2"]"#.utf8)))
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

        _ = try await session.carveProtocolRecoverOnChain(pids: ["p1", "p2"])

        let raw = Data(fromHex: try XCTUnwrap(broadcast.value))
        XCTAssertNotNil(raw.range(of: Data(#""op":"recover""#.utf8)))
        XCTAssertNotNil(raw.range(of: Data(#""pids":["p1","p2"]"#.utf8)))
    }

    func testCloseCarriesItsStatement() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        let broadcast = Captured()
        try stage(mock, senderFid: session.mainFid, onBroadcast: { broadcast.value = $0 })

        _ = try await session.carveProtocolCloseOnChain(
            pids: ["p1"], closeStatement: "superseded by FEIP-13"
        )
        let raw = Data(fromHex: try XCTUnwrap(broadcast.value))
        XCTAssertNotNil(raw.range(of: Data(#""op":"close""#.utf8)))
        XCTAssertNotNil(raw.range(of: Data(#""closeStatement":"superseded by FEIP-13""#.utf8)))
    }

    /// A stop the user pressed has to have a visible effect before the
    /// next block, so the cached copy is marked. The chain is still the
    /// authority — the next refresh overwrites this wholesale.
    func testStopAndCloseMarkTheCachedCopyImmediately() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        try stage(mock, senderFid: session.mainFid)

        try session.protocols.saveWindow([
            ProtocolSpec(id: "p1", name: "One", owner: session.liveFid,
                         active: true, closed: false, onChain: true),
            ProtocolSpec(id: "p2", name: "Two", owner: session.liveFid,
                         active: true, closed: false, onChain: true)
        ])

        _ = try await session.carveProtocolStopOnChain(pids: ["p1"])
        var window = try session.protocols.window()
        XCTAssertEqual(window.first { $0.id == "p1" }?.state, .stopped)
        XCTAssertEqual(window.first { $0.id == "p2" }?.state, .live, "untouched")

        _ = try await session.carveProtocolCloseOnChain(pids: ["p1"], closeStatement: "done")
        window = try session.protocols.window()
        XCTAssertEqual(window.first { $0.id == "p1" }?.state, .closed)
        XCTAssertEqual(window.first { $0.id == "p1" }?.closeStatement, "done")
    }

    /// A recover puts a stopped record back without touching `closed`.
    func testRecoverMarksTheCachedCopyActiveAgain() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        try stage(mock, senderFid: session.mainFid)

        try session.protocols.saveWindow([
            ProtocolSpec(id: "p1", owner: session.liveFid,
                         active: false, closed: false, onChain: true)
        ])
        _ = try await session.carveProtocolRecoverOnChain(pids: ["p1"])
        XCTAssertEqual(try session.protocols.window().first?.state, .live)
    }

    func testAnEmptyIdListIsRefusedBeforeBroadcast() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        try stage(mock, senderFid: session.mainFid)

        do {
            _ = try await session.carveProtocolStopOnChain(pids: [])
            XCTFail("expected a throw")
        } catch {
            XCTAssertTrue(mock.recorded.isEmpty, "nothing may be spent or broadcast")
        }
    }

    // MARK: - the store

    /// Drafts and the window are separate namespaces precisely so a
    /// window truncation cannot reach a draft — the only copy of work
    /// the user has not yet paid to publish.
    func testTruncatingTheWindowNeverTouchesADraft() throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)

        let draft = ProtocolSpec.createLocal(name: "Draft", owner: session.liveFid)
        try session.protocols.upsertDraft(draft)

        let many = (0..<(ProtocolsStore.maxCachedProtocols + 50)).map {
            ProtocolSpec(id: "p\($0)", name: "P\($0)", onChain: true)
        }
        try session.protocols.saveWindow(many)

        XCTAssertEqual(try session.protocols.window().count, ProtocolsStore.maxCachedProtocols)
        XCTAssertEqual(try session.protocols.drafts().map(\.id), [draft.id])
    }

    /// Rows carried across a refresh keep their original `addedAt`, so
    /// "when did this first appear here" survives.
    func testARefreshKeepsWhenARowWasFirstSeen() throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)

        var row = ProtocolSpec(id: "p1", name: "One", onChain: true)
        row.addedAt = Date(timeIntervalSince1970: 1000)
        try session.protocols.saveWindow([row])

        try session.protocols.saveWindow([ProtocolSpec(id: "p1", name: "One renamed", onChain: true)])
        let kept = try XCTUnwrap(try session.protocols.window().first)
        XCTAssertEqual(kept.name, "One renamed", "the chain is the authority for the fields")
        XCTAssertEqual(kept.addedAt.timeIntervalSince1970, 1000, accuracy: 0.5)
    }

    /// Hiding is local and idempotent, and it is not stopping: nothing
    /// is carved and the record carries on existing.
    func testHidingIsLocalIdempotentAndReversible() throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        try session.protocols.saveWindow([
            ProtocolSpec(id: "p1", onChain: true),
            ProtocolSpec(id: "p2", onChain: true)
        ])

        try session.protocols.hide(ids: ["p1", "p1", ""])
        XCTAssertEqual(try session.protocols.hiddenIds(), ["p1"])
        XCTAssertEqual(try session.protocols.visibleWindow().map(\.id), ["p2"])
        XCTAssertEqual(try session.protocols.hidden().map(\.id), ["p1"])
        // Still there, still live — hiding carves nothing.
        XCTAssertEqual(try session.protocols.window().count, 2)

        try session.protocols.unhide(ids: ["p1"])
        XCTAssertEqual(try session.protocols.visibleWindow().map(\.id), ["p1", "p2"])
    }

    /// A hidden id whose row has fallen out of the window stays hidden:
    /// the row may come back on the next refresh, and forgetting the
    /// decision would silently un-hide it.
    func testAHiddenIdSurvivesItsRowLeavingTheWindow() throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        try session.protocols.saveWindow([ProtocolSpec(id: "p1", onChain: true)])
        try session.protocols.hide(ids: ["p1"])

        try session.protocols.saveWindow([ProtocolSpec(id: "p9", onChain: true)])
        XCTAssertTrue(try session.protocols.hidden().isEmpty, "no row to show")
        XCTAssertEqual(try session.protocols.hiddenIds(), ["p1"], "the decision is kept")
    }

    /// A re-broadcast of the same record replaces its row rather than
    /// adding a second one.
    func testRememberBroadcastIsKeyedByIdAndGoesToTheHead() throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        try session.protocols.saveWindow([
            ProtocolSpec(id: "p1", name: "One", onChain: true),
            ProtocolSpec(id: "p2", name: "Two", onChain: true)
        ])

        try session.protocols.rememberBroadcast(ProtocolSpec(id: "p2", name: "Two v2", onChain: nil))
        let window = try session.protocols.window()
        XCTAssertEqual(window.map(\.id), ["p2", "p1"])
        XCTAssertEqual(window[0].name, "Two v2")
    }
}

private final class Captured: @unchecked Sendable {
    var value: String?
}
