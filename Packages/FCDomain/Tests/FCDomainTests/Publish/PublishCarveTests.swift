import XCTest
import FCCore
import FCTransport
@testable import FCDomain

/// The publish write path through `ActiveSession`, and the stores that
/// hold the results.
///
/// The assertions decode the **broadcast raw hex** rather than trusting
/// the builder: what a record ends up saying is whatever went into the
/// transaction, and every mismatch between the two — a wrong subject
/// field, a field silently dropped from an update — is invisible at the
/// builder and permanent on the chain.
final class PublishCarveTests: XCTestCase {

    private var baseDir: URL!
    private var manager: ConfigureManager!

    override func setUpWithError() throws {
        baseDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("PublishCarveTests-\(UUID().uuidString)")
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
            password: Data("publish-tests".utf8), kdfKind: .legacySha256
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
            // Aged enough to satisfy the CD requirement. `bestHeight`
            // below is deliberately *past* `cddCheckHeight`, so these
            // carves exercise the coin-day rule rather than dodging it.
            "cd": 5,
            "lockScript": Cash.canonicalP2PKHLockScript(hash160: h160)
        ]
    }

    private func stage(
        _ mock: MockFapiClient,
        senderFid: String,
        txid: String = "text-txid-001",
        onBroadcast: @escaping @Sendable (String) -> Void = { _ in }
    ) throws {
        mock.responder = { call in
            switch call.api {
            case "base.cashValid":
                return try makeResponse(
                    data: [try self.cashDict(
                        owner: senderFid,
                        txid: String(repeating: "cd", count: 32),
                        value: 10_000_000
                    )],
                    bestHeight: 4_100_000
                )
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

    /// A publish pays nobody, names no id of its own, and the record it
    /// returns is keyed by the carve's txid.
    func testPublishCarvesTheFeipAndTakesTheTxidAsItsId() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        let broadcast = Captured()
        try stage(mock, senderFid: session.mainFid, onBroadcast: { broadcast.value = $0 })

        let did = String(repeating: "ab", count: 32)
        let record = try await session.carveTextPublishOnChain(
            title: "Why Freecash", type: "essay", did: did, lang: "en",
            authors: ["FIDA"], format: "markdown", summary: "Short form."
        )

        let raw = Data(fromHex: try XCTUnwrap(broadcast.value))
        XCTAssertNotNil(raw.range(of: Data(#""sn":"21""#.utf8)))
        XCTAssertNotNil(raw.range(of: Data(#""name":"Text""#.utf8)))
        XCTAssertNotNil(raw.range(of: Data(#""op":"publish""#.utf8)))
        XCTAssertNotNil(raw.range(of: Data(#""title":"Why Freecash""#.utf8)))
        XCTAssertNotNil(raw.range(of: Data(#""did":"\#(did)""#.utf8)))
        XCTAssertNil(raw.range(of: Data("textId".utf8)), "rule 1: the client never names the id")

        XCTAssertEqual(record.id, "text-txid-001")
        XCTAssertEqual(record.publisher, session.liveFid)
        XCTAssertEqual(record.ver, "1")
        XCTAssertNil(record.onChain, "broadcast, not confirmed")
        XCTAssertEqual(record.lastHeight, TextsStore.unconfirmedHeight)
        XCTAssertEqual(try session.texts.get(id: "text-txid-001")?.title, "Why Freecash")
    }

    /// Carving a draft rekeys it to the txid: a record's id *is* its
    /// carve, so the row moves rather than gaining a second identity.
    func testCarvingADraftRekeysItToTheTxid() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        try stage(mock, senderFid: session.mainFid)

        let draft = TextRecord.createLocal(
            title: "Why Freecash", summary: "Short form.", publisher: session.liveFid
        )
        try session.texts.upsert(draft)
        XCTAssertEqual(try session.texts.drafts().count, 1)

        let carved = try await session.carveTextPublishOnChain(
            title: "Why Freecash", summary: "Short form.", draftId: draft.id
        )
        XCTAssertEqual(carved.id, "text-txid-001")
        XCTAssertNil(try session.texts.get(id: draft.id), "the draft key is gone")
        XCTAssertEqual(carved.ver, "1", "a promoted draft is a first edition")
        XCTAssertNil(carved.onChain)
        XCTAssertTrue(try session.texts.drafts().isEmpty)
    }

    /// The size guard runs before coin selection, so an oversize carve
    /// costs nothing and broadcasts nothing.
    func testAnOversizeCarveIsRefusedBeforeBroadcast() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        try stage(mock, senderFid: session.mainFid)

        do {
            _ = try await session.carveTextPublishOnChain(
                title: "t", summary: String(repeating: "x", count: TextFeip.maxOpReturnSize)
            )
            XCTFail("expected a throw")
        } catch {
            XCTAssertTrue(mock.recorded.isEmpty, "nothing may be spent or broadcast")
        }
    }

    // MARK: - update

    /// The reference parser copies nulls onto the entity, so an update
    /// that omits a field clears it. Every field the caller passed has
    /// to reach the transaction.
    func testAnUpdateResendsEveryFieldRatherThanClearingThem() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        let broadcast = Captured()
        try stage(mock, senderFid: session.mainFid, txid: "update-txid", onBroadcast: { broadcast.value = $0 })

        try session.texts.upsert(TextRecord(
            id: "T1", title: "Why Freecash", ver: "1", publisher: session.liveFid, onChain: true
        ))

        _ = try await session.carveTextUpdateOnChain(
            textId: "T1", title: "Why Freecash (rev 2)", type: "essay",
            did: "deadbeef", lang: "en", authors: ["FIDA"],
            format: "markdown", summary: "Expanded abstract."
        )

        let raw = Data(fromHex: try XCTUnwrap(broadcast.value))
        XCTAssertNotNil(raw.range(of: Data(#""op":"update""#.utf8)))
        XCTAssertNotNil(raw.range(of: Data(#""textId":"T1""#.utf8)))
        for fragment in [#""type":"essay""#, #""did":"deadbeef""#, #""lang":"en""#,
                         #""authors":["FIDA"]"#, #""format":"markdown""#,
                         #""summary":"Expanded abstract.""#] {
            XCTAssertNotNil(raw.range(of: Data(fragment.utf8)), "missing \(fragment)")
        }

        // The cached row shows the new edition without waiting for a block.
        let updated = try XCTUnwrap(try session.texts.get(id: "T1"))
        XCTAssertEqual(updated.ver, "2")
        XCTAssertEqual(updated.title, "Why Freecash (rev 2)")
        XCTAssertEqual(updated.lastTxId, "update-txid")
        XCTAssertEqual(updated.onChain, true, "the record is still as confirmed as it was")
    }

    /// A row whose `ver` the server never set (the pre-fix parser)
    /// still updates to a sane edition instead of crashing on a parse.
    func testAnUpdateOfARowWithNoVerBecomesEditionTwo() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        try stage(mock, senderFid: session.mainFid, txid: "update-txid")

        try session.texts.upsert(TextRecord(
            id: "T1", title: "t", ver: nil, publisher: session.liveFid, onChain: true
        ))
        _ = try await session.carveTextUpdateOnChain(textId: "T1", title: "t2")
        XCTAssertEqual(try session.texts.get(id: "T1")?.ver, "2")
    }

    // MARK: - delete / recover

    /// Deletion is soft at both ends: the op sets a flag, and the
    /// cached row keeps everything but that flag.
    func testDeleteFlipsTheFlagOnEveryNamedRow() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        let broadcast = Captured()
        try stage(mock, senderFid: session.mainFid, txid: "del-txid", onBroadcast: { broadcast.value = $0 })

        try session.texts.upsert(TextRecord(id: "T1", title: "a", publisher: session.liveFid, onChain: true))
        try session.texts.upsert(TextRecord(id: "T2", title: "b", publisher: session.liveFid, onChain: true))

        _ = try await session.carveTextDeleteOnChain(textIds: ["T1", "T2"])

        let raw = Data(fromHex: try XCTUnwrap(broadcast.value))
        XCTAssertNotNil(raw.range(of: Data(#""op":"delete""#.utf8)))
        XCTAssertNotNil(raw.range(of: Data(#""textIds":["T1","T2"]"#.utf8)))
        XCTAssertEqual(try session.texts.get(id: "T1")?.deleted, true)
        XCTAssertEqual(try session.texts.get(id: "T2")?.deleted, true)
        XCTAssertEqual(try session.texts.get(id: "T1")?.title, "a", "a delete is not an erase")
    }

    /// Recover is delete with one boolean flipped at both ends, which
    /// is why they share a private carve — and why it is worth pinning
    /// that the op name changes with the flag.
    func testRecoverClearsTheFlagOnOnlyTheNamedRow() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        let broadcast = Captured()
        try stage(mock, senderFid: session.mainFid, txid: "rec-txid", onBroadcast: { broadcast.value = $0 })

        try session.texts.upsert(TextRecord(id: "T1", title: "a", publisher: session.liveFid, deleted: true, onChain: true))
        try session.texts.upsert(TextRecord(id: "T2", title: "b", publisher: session.liveFid, deleted: true, onChain: true))

        _ = try await session.carveTextRecoverOnChain(textIds: ["T1"])

        let raw = Data(fromHex: try XCTUnwrap(broadcast.value))
        XCTAssertNotNil(raw.range(of: Data(#""op":"recover""#.utf8)))
        XCTAssertNotNil(raw.range(of: Data(#""textIds":["T1"]"#.utf8)))
        XCTAssertEqual(try session.texts.get(id: "T1")?.deleted, false)
        XCTAssertEqual(try session.texts.get(id: "T2")?.deleted, true, "only what was named")
    }

    // MARK: - remark

    /// `onDid` is the target's **record id**, and the subject field is
    /// `remarkId` — the two places a copy of the Text file would be
    /// wrong in a way nothing else catches.
    func testARemarkAnchorsToTheTargetsRecordId() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        let broadcast = Captured()
        try stage(mock, senderFid: session.mainFid, txid: "remark-txid", onBroadcast: { broadcast.value = $0 })

        let remark = try await session.carveRemarkPublishOnChain(
            title: "Errata for section 3", onDid: "text-txid-001",
            did: "cafebabe", summary: "Suggested correction."
        )

        let raw = Data(fromHex: try XCTUnwrap(broadcast.value))
        XCTAssertNotNil(raw.range(of: Data(#""sn":"22""#.utf8)))
        XCTAssertNotNil(raw.range(of: Data(#""name":"Remark""#.utf8)))
        XCTAssertNotNil(raw.range(of: Data(#""onDid":"text-txid-001""#.utf8)))
        XCTAssertNil(raw.range(of: Data("remarkId".utf8)), "publish never names its own id")
        // The envelope's own `"type":"FEIP"` is the only `type` a
        // remark carve may contain — a second one would mean the Text
        // builder had been copied into this file.
        XCTAssertEqual(
            String(data: raw, encoding: .isoLatin1)?.components(separatedBy: #""type""#).count, 2,
            "a remark has no type of its own"
        )

        XCTAssertEqual(remark.id, "remark-txid")
        XCTAssertEqual(remark.onDid, "text-txid-001")
        XCTAssertEqual(try session.remarks.all(on: "text-txid-001").count, 1)
    }

    func testRemarkUpdateNamesTheRemarkAndKeepsItsTarget() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        let broadcast = Captured()
        try stage(mock, senderFid: session.mainFid, txid: "r-upd", onBroadcast: { broadcast.value = $0 })

        try session.remarks.upsert(Remark(
            id: "R1", title: "Errata", ver: "1", onDid: "T1",
            publisher: session.liveFid, onChain: true
        ))
        _ = try await session.carveRemarkUpdateOnChain(
            remarkId: "R1", title: "Errata (v2)", onDid: "T1"
        )

        let raw = Data(fromHex: try XCTUnwrap(broadcast.value))
        XCTAssertNotNil(raw.range(of: Data(#""remarkId":"R1""#.utf8)))
        XCTAssertNotNil(raw.range(of: Data(#""onDid":"T1""#.utf8)))
        XCTAssertEqual(try session.remarks.get(id: "R1")?.ver, "2")
    }

    func testRemarkDeleteUsesRemarkIds() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        let broadcast = Captured()
        try stage(mock, senderFid: session.mainFid, txid: "r-del", onBroadcast: { broadcast.value = $0 })

        try session.remarks.upsert(Remark(id: "R1", onDid: "T1", publisher: session.liveFid, onChain: true))
        _ = try await session.carveRemarkDeleteOnChain(remarkIds: ["R1"])

        let raw = Data(fromHex: try XCTUnwrap(broadcast.value))
        XCTAssertNotNil(raw.range(of: Data(#""remarkIds":["R1"]"#.utf8)))
        XCTAssertNil(raw.range(of: Data("textIds".utf8)))
        XCTAssertEqual(try session.remarks.get(id: "R1")?.deleted, true)
    }

    // MARK: - the stores

    /// A refresh replaces chain copies and must never touch a draft —
    /// the draft is the only copy of work nobody has paid to publish.
    func testARefreshDropsStaleChainRowsAndKeepsDrafts() throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)

        let draft = TextRecord.createLocal(title: "unsent", publisher: session.liveFid)
        try session.texts.upsert(draft)
        try session.texts.upsert(TextRecord(id: "T1", title: "old", onChain: true))

        _ = try session.texts.replaceChainRows(with: [
            TextRecord(id: "T2", title: "new", onChain: true)
        ])

        XCTAssertNil(try session.texts.get(id: "T1"), "a row the chain no longer returns is dropped")
        XCTAssertNotNil(try session.texts.get(id: "T2"))
        XCTAssertNotNil(try session.texts.get(id: draft.id), "a draft survives every refresh")
    }
}

/// The broadcast raw hex, captured out of the mock's responder. One per
/// test file, matching the other carve suites.
private final class Captured: @unchecked Sendable {
    var value: String?
}
