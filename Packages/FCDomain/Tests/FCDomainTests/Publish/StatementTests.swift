import XCTest
import FCCore
import FCTransport
@testable import FCDomain

/// FEIP8 `Statement` — the model, the builder and the one carve.
///
/// Statement is the Publish family's odd one, and every test here is
/// about a difference: no `op`, no lifecycle, an exact confirmation
/// phrase the parser compares byte for byte, and content that is
/// genuinely on the chain rather than behind a `did`.
final class StatementTests: XCTestCase {

    private var baseDir: URL!
    private var manager: ConfigureManager!

    override func setUpWithError() throws {
        baseDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("StatementTests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: baseDir, withIntermediateDirectories: true)
        manager = try ConfigureManager(baseDirectory: baseDir)
    }

    override func tearDownWithError() throws {
        manager = nil
        if let baseDir { try? FileManager.default.removeItem(at: baseDir) }
    }

    // MARK: - the payload

    func testTheEnvelopeCarriesStatementsNumbers() {
        let json = StatementFeip.envelope(dataJson: "{}")
        XCTAssertTrue(json.contains(#""sn":"8""#))
        XCTAssertTrue(json.contains(#""ver":"1""#))
        XCTAssertTrue(json.contains(#""name":"Statement""#))
        XCTAssertEqual(StatementFeip.sn, FeipProtocol.statement.sn)
        XCTAssertEqual(StatementFeip.ver, FeipProtocol.statement.ver)
    }

    /// **There is no `op`.** Every other FEIP in this app names one, so
    /// emitting one here is what a port does out of habit — and the
    /// parser never looks for it, so the stray key would just be paid
    /// for.
    func testAStatementCarriesNoOpField() throws {
        let json = try StatementFeip.carve(title: "Notice", content: "Body.")
        XCTAssertFalse(json.contains(#""op""#))
    }

    /// The parser compares `confirm` with `equals`. Case, punctuation
    /// and the trailing full stop all matter; one wrong capital and the
    /// statement is ignored with the fee paid.
    func testTheConfirmPhraseIsExactAndAlwaysPresent() throws {
        XCTAssertEqual(
            StatementFeip.confirmPhrase,
            "This is a formal and irrevocable statement."
        )
        let json = try StatementFeip.carve(title: "Notice", content: nil)
        XCTAssertTrue(json.contains(#""confirm":"This is a formal and irrevocable statement.""#))
    }

    /// FEIP8 requires at least one of title and content — and accepts
    /// either alone.
    func testEitherTitleOrContentAloneIsEnoughButNeitherIsNot() throws {
        XCTAssertTrue(try StatementFeip.carve(title: "Title only", content: nil)
            .contains(#""title":"Title only""#))
        XCTAssertTrue(try StatementFeip.carve(title: nil, content: "Content only")
            .contains(#""content":"Content only""#))

        XCTAssertThrowsError(try StatementFeip.carve(title: nil, content: nil))
        XCTAssertThrowsError(try StatementFeip.carve(title: "   ", content: "\n"))
    }

    /// An empty field is omitted rather than carved as `""` — the
    /// parser copies only non-null values, and every byte is paid for.
    func testEmptyFieldsAreOmitted() throws {
        let json = try StatementFeip.carve(title: "", content: "Body.")
        XCTAssertFalse(json.contains(#""title""#))
    }

    /// The budget matters here in a way it does not for Text: this
    /// content is carved in full, so the ceiling is reached by ordinary
    /// prose rather than by pathological input.
    func testTheContentBudgetShrinksByExactlyWhatIsTyped() {
        let empty = StatementFeip.remainingContentBytes(title: "t", content: "")
        let one = StatementFeip.remainingContentBytes(title: "t", content: "x")
        XCTAssertEqual(empty - one, 1)
        XCTAssertLessThan(empty, StatementFeip.maxOpReturnSize)
    }

    func testAnOversizeStatementIsRefused() {
        XCTAssertThrowsError(
            try StatementFeip.carve(
                title: "t",
                content: String(repeating: "x", count: StatementFeip.maxOpReturnSize)
            )
        ) { error in
            guard case StatementFeip.Failure.tooLarge = error else {
                return XCTFail("expected tooLarge, got \(error)")
            }
        }
    }

    // MARK: - the model

    /// A statement may have no title at all, so a list needs something
    /// else to draw — the opening of the content beats the raw id.
    func testAnUntitledStatementIsLabelledByItsOpeningLine() {
        let untitled = Statement(id: "S1", content: "We hereby declare\nsecond line")
        XCTAssertEqual(untitled.name, "We hereby declare")

        let bare = Statement(id: "S1")
        XCTAssertEqual(bare.name, "S1")

        let titled = Statement(id: "S1", title: "Notice", content: "Body")
        XCTAssertEqual(titled.name, "Notice")
    }

    func testADraftIdIsStableAndDistinctFromOtherProtocols() {
        let a = Statement.createLocal(title: "t", content: "c", publisher: "FID")
        let b = Statement.createLocal(title: "t", content: "c", publisher: "FID")
        XCTAssertEqual(a.id, b.id)
        XCTAssertEqual(a.id.count, 64)
        XCTAssertEqual(a.onChain, false)

        // A proof has a title and content too; the envelope's `sn` is
        // what keeps the two drafts apart.
        let proof = Proof.localId(title: "t", content: "c", cosigners: nil, transferable: nil)
        XCTAssertNotEqual(a.id, proof)
    }

    func testSearchMatchesTitleContentAndPublisher() {
        let row = Statement(
            id: "S1", title: "Notice of intent",
            content: "The undersigned declares", publisher: "FIDA"
        )
        XCTAssertTrue(row.matches(query: "intent"))
        XCTAssertTrue(row.matches(query: "UNDERSIGNED"))
        XCTAssertTrue(row.matches(query: "fida"))
        XCTAssertFalse(row.matches(query: "nothing here"))
    }

    /// Nothing in the model can express retirement, because nothing in
    /// the protocol can.
    func testAStatementHasNoLifecycleFields() throws {
        let row = try JSONDecoder().decode(
            Statement.self,
            from: Data(#"{"id":"S1","title":"t","deleted":true,"ver":"3","lastHeight":9}"#.utf8)
        )
        let encoded = String(data: try JSONEncoder().encode(row), encoding: .utf8) ?? ""
        XCTAssertFalse(encoded.contains("deleted"))
        XCTAssertFalse(encoded.contains("ver"))
        XCTAssertFalse(encoded.contains("lastHeight"))
    }

    // MARK: - the carve

    func testCarvingWritesTheStatementAndKeysItByTxid() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        let broadcast = Captured()
        try stage(mock, senderFid: session.mainFid, onBroadcast: { broadcast.value = $0 })

        let statement = try await session.carveStatementOnChain(
            title: "Notice of intent", content: "The undersigned declares."
        )

        let raw = Data(fromHex: try XCTUnwrap(broadcast.value))
        XCTAssertNotNil(raw.range(of: Data(#""sn":"8""#.utf8)))
        XCTAssertNotNil(raw.range(of: Data(#""name":"Statement""#.utf8)))
        XCTAssertNotNil(raw.range(of: Data(#""title":"Notice of intent""#.utf8)))
        // The content really is in the transaction — this is the one
        // Publish record where that is true.
        XCTAssertNotNil(raw.range(of: Data(#""content":"The undersigned declares.""#.utf8)))
        XCTAssertNotNil(raw.range(of: Data(StatementFeip.confirmPhrase.utf8)))
        XCTAssertNil(raw.range(of: Data(#""op""#.utf8)))
        XCTAssertNil(raw.range(of: Data(#""did""#.utf8)), "a statement points at nothing")

        XCTAssertEqual(statement.id, "statement-txid-001")
        XCTAssertEqual(statement.publisher, session.liveFid)
        XCTAssertNil(statement.onChain, "broadcast, not confirmed")
        XCTAssertEqual(try session.statements.get(id: "statement-txid-001")?.title, "Notice of intent")
    }

    func testAnOversizeStatementIsRefusedBeforeBroadcast() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        try stage(mock, senderFid: session.mainFid)

        do {
            _ = try await session.carveStatementOnChain(
                title: "t",
                content: String(repeating: "x", count: StatementFeip.maxOpReturnSize)
            )
            XCTFail("expected a throw")
        } catch {
            XCTAssertTrue(mock.recorded.isEmpty, "nothing may be spent or broadcast")
        }
    }

    func testCarvingADraftRekeysItToTheTxid() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        try stage(mock, senderFid: session.mainFid)

        let draft = Statement.createLocal(title: "Notice", content: "Body.", publisher: session.liveFid)
        try session.statements.upsert(draft)

        let carved = try await session.carveStatementOnChain(
            title: "Notice", content: "Body.", draftId: draft.id
        )
        XCTAssertEqual(carved.id, "statement-txid-001")
        XCTAssertNil(try session.statements.get(id: draft.id))
        XCTAssertTrue(try session.statements.drafts().isEmpty)
    }

    // MARK: - the query

    /// A statement has no `lastHeight` — nothing ever touches it again
    /// — so sorting on one would sort every row on a field the parser
    /// never writes.
    func testStatementsSortOnBirthHeightNotLastHeight() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in try makeResponse(data: [] as [Any]) }
        _ = try await PublishService(fapi: mock).fetchStatements(publisher: "ME")

        let sent = try XCTUnwrap(
            JSONSerialization.jsonObject(with: try XCTUnwrap(mock.recorded[0].fcdsl)) as? [String: Any]
        )
        XCTAssertEqual(sent["entity"] as? String, "statement")
        let sort = try XCTUnwrap(sent["sort"] as? [[String: String]])
        XCTAssertEqual(sort, [
            ["field": "birthHeight", "order": "desc"],
            ["field": "id", "order": "desc"]
        ])
        let query = try XCTUnwrap(sent["query"] as? [String: Any])
        let equals = try XCTUnwrap(query["equals"] as? [String: Any])
        XCTAssertEqual(equals["fields"] as? [String], ["publisher", "publisher.keyword"])
        // No lifecycle flag exists, so none may be sent.
        XCTAssertNil(query["terms"])
    }

    /// The body is in the index here, so it is searchable — the one
    /// Publish record where that is true.
    func testTheSearchableSetIncludesContent() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in try makeResponse(data: [] as [Any]) }
        _ = try await PublishService(fapi: mock).searchStatements(query: "declares")

        let sent = try XCTUnwrap(
            JSONSerialization.jsonObject(with: try XCTUnwrap(mock.recorded[0].fcdsl)) as? [String: Any]
        )
        let query = try XCTUnwrap(sent["query"] as? [String: Any])
        let match = try XCTUnwrap(query["match"] as? [String: Any])
        XCTAssertEqual(match["fields"] as? [String], ["title", "content", "publisher", "id"])
    }

    /// **The "Mine" repair.** `equals` compiles to an Elasticsearch
    /// `terms` query, which is unanalysed. The `statement` mapping
    /// never declared `publisher` — it declared `owner`, `active` and
    /// `lastHeight`, none of which the parser writes — so on any index
    /// built from it `publisher` arrives through dynamic mapping as
    /// analysed text, whose token is lowercased, and a `terms` query
    /// for a mixed-case FID matched nothing: the Mine tab came back
    /// empty for a FID with statements in it.
    ///
    /// Naming both fields is a bool-should across them, so whichever
    /// the index actually has answers — and a `terms` query against an
    /// absent field matches nothing rather than erroring, so this
    /// survives the reindex in either direction.
    func testTheMineClauseMatchesEitherMappingOfPublisher() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in try makeResponse(data: [] as [Any]) }
        let service = PublishService(fapi: mock)

        _ = try await service.fetchStatements(publisher: "FEk41Kqjar45fLDriztUDTUkdki7mmcjWK")
        var query = try XCTUnwrap(
            try sent(mock.recorded[0])["query"] as? [String: Any]
        )
        var equals = try XCTUnwrap(query["equals"] as? [String: Any])
        XCTAssertEqual(equals["fields"] as? [String], ["publisher", "publisher.keyword"])
        XCTAssertEqual(
            equals["values"] as? [String], ["FEk41Kqjar45fLDriztUDTUkdki7mmcjWK"],
            "the FID goes in with its case intact — the query is unanalysed")

        _ = try await service.searchStatements(
            query: "notice", publisher: "FEk41Kqjar45fLDriztUDTUkdki7mmcjWK")
        query = try XCTUnwrap(try sent(mock.recorded[1])["query"] as? [String: Any])
        equals = try XCTUnwrap(query["equals"] as? [String: Any])
        XCTAssertEqual(equals["fields"] as? [String], ["publisher", "publisher.keyword"])
    }

    /// Discover names no publisher at all — an empty clause would ask
    /// for statements belonging to nobody and return none.
    func testDiscoverSendsNoPublisherClause() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in try makeResponse(data: [] as [Any]) }
        _ = try await PublishService(fapi: mock).fetchStatements(publisher: nil)
        XCTAssertNil(try sent(mock.recorded[0])["query"])
    }

    private func sent(_ call: MockFapiClient.Recorded) throws -> [String: Any] {
        try XCTUnwrap(
            JSONSerialization.jsonObject(with: try XCTUnwrap(call.fcdsl)) as? [String: Any]
        )
    }

    // MARK: - fixtures

    private func makeSession(fapi: any FapiCalling) throws -> ActiveSession {
        let configure = try manager.createConfigure(
            password: Data("statement-tests".utf8), kdfKind: .legacySha256
        )
        let info = try configure.addMain(
            privkey: Hash.sha256(Data("declarer".utf8)), label: "declarer"
        )
        return try configure.unlockMain(fid: info.fid, fapi: fapi)
    }

    private func stage(
        _ mock: MockFapiClient,
        senderFid: String,
        onBroadcast: @escaping @Sendable (String) -> Void = { _ in }
    ) throws {
        mock.responder = { call in
            switch call.api {
            case "base.cashValid":
                let h160 = try FchAddress(fid: senderFid).hash160
                return try makeResponse(
                    data: [[
                        "id": try Cash.makeId(
                            birthTxId: String(repeating: "cd", count: 32), birthIndex: 0),
                        "owner": senderFid,
                        "value": 10_000_000,
                        "type": "P2PKH",
                        "birthTxId": String(repeating: "cd", count: 32),
                        "birthIndex": 0,
                        "cd": 5,
                        "lockScript": Cash.canonicalP2PKHLockScript(hash160: h160)
                    ]],
                    bestHeight: 4_100_000
                )
            case "base.broadcastTx":
                let params = try JSONSerialization.jsonObject(with: call.params!) as? [String: Any]
                onBroadcast((params?["rawTx"] as? String) ?? "")
                return try makeResponse(data: "statement-txid-001")
            default:
                XCTFail("unexpected api: \(call.api)")
                return FapiResponse(code: 1, message: "unexpected")
            }
        }
    }
}

private final class Captured: @unchecked Sendable {
    var value: String?
}