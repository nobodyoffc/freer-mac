import XCTest
import FCCore
import FCTransport
@testable import FCDomain

/// The proof write path through `ActiveSession`, and the store that
/// holds the results.
///
/// The carve assertions decode the broadcast raw hex rather than
/// trusting the builder, because for a `transfer` the recipient output
/// is not a detail of the transaction — it *is* the new owner, and
/// nothing else on chain records who the proof went to.
final class ProofCarveTests: XCTestCase {

    private var baseDir: URL!
    private var manager: ConfigureManager!

    private let recipientPrivkey = Data(repeating: 0xC3, count: 32)

    override func setUpWithError() throws {
        baseDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("ProofCarveTests-\(UUID().uuidString)")
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
            password: Data("proof-tests".utf8), kdfKind: .legacySha256
        )
        let info = try configure.addMain(
            privkey: Hash.sha256(Data("prover".utf8)), label: "prover"
        )
        return try configure.unlockMain(fid: info.fid, fapi: fapi)
    }

    private func recipientFid() throws -> String {
        try FchAddress(publicKey: Secp256k1.publicKey(fromPrivateKey: recipientPrivkey)).fid
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
        txid: String = "proof-txid-001",
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

    private func payOutputBytes(to fid: String, value: Int64) throws -> Data {
        var out = Data()
        var le = UInt64(value).littleEndian
        withUnsafeBytes(of: &le) { out.append(contentsOf: $0) }
        out.append(0x19)
        out.append(try ScriptBuilder.p2pkhOutput(hash160: FchAddress(fid: fid).hash160).bytes)
        return out
    }

    // MARK: - issue

    /// Issuing is a statement, not a message: it pays nobody, and the
    /// proof's id is the carve's txid.
    func testIssueCarvesTheFeipAndPaysNobody() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        let broadcast = Captured()
        try stage(mock, senderFid: session.mainFid, onBroadcast: { broadcast.value = $0 })

        let proof = try await session.carveProofIssueOnChain(
            title: "Lease", content: "Twelve months",
            cosigners: ["FIDA"], transferable: true, allSignsRequired: true
        )

        let raw = Data(fromHex: try XCTUnwrap(broadcast.value))
        XCTAssertNotNil(raw.range(of: Data(#""sn":"14""#.utf8)))
        XCTAssertNotNil(raw.range(of: Data(#""op":"issue""#.utf8)))
        XCTAssertNotNil(raw.range(of: Data(#""title":"Lease""#.utf8)))
        XCTAssertNotNil(raw.range(of: Data(#""cosigners":["FIDA"]"#.utf8)))
        XCTAssertNil(
            raw.range(of: try payOutputBytes(
                to: try recipientFid(), value: ActiveSession.proofTransferSats
            )),
            "issuing addresses nobody"
        )

        XCTAssertEqual(proof.id, "proof-txid-001")
        XCTAssertEqual(proof.issuer, session.liveFid)
        XCTAssertEqual(proof.owner, session.liveFid)
        // Broadcast, not confirmed.
        XCTAssertNil(proof.onChain)
        XCTAssertEqual(proof.lastHeight, ProofsStore.unconfirmedHeight)
        XCTAssertEqual(try session.proofs.get(id: "proof-txid-001")?.title, "Lease")
    }

    /// `allSignsRequired` means nothing without cosigners, so it is not
    /// sent — a flag with no referent is bytes spent on nothing.
    func testAllSignsRequiredIsOmittedWithoutCosigners() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        let broadcast = Captured()
        try stage(mock, senderFid: session.mainFid, onBroadcast: { broadcast.value = $0 })

        _ = try await session.carveProofIssueOnChain(
            title: "t", content: "c", cosigners: [], allSignsRequired: true
        )
        let raw = Data(fromHex: try XCTUnwrap(broadcast.value))
        XCTAssertNil(raw.range(of: Data("allSignsRequired".utf8)))
        XCTAssertNil(raw.range(of: Data("cosigners".utf8)))
    }

    /// The size guard runs before coin selection, so an oversize proof
    /// costs nothing and broadcasts nothing.
    func testAnOversizeProofIsRefusedBeforeBroadcast() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        try stage(mock, senderFid: session.mainFid)

        do {
            _ = try await session.carveProofIssueOnChain(
                title: "t",
                content: String(repeating: "x", count: ProofFeip.maxOpReturnSize)
            )
            XCTFail("expected a throw")
        } catch {
            XCTAssertTrue(mock.recorded.isEmpty, "nothing may be spent or broadcast")
        }
    }

    /// Carving a draft rekeys it to the txid: a proof's id *is* its
    /// carve, so the row moves rather than gaining a second identity.
    func testCarvingADraftRekeysItToTheTxid() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        try stage(mock, senderFid: session.mainFid)

        let draft = Proof.createLocal(
            title: "Lease", content: "Twelve months", cosigners: [],
            transferable: false, issuer: session.liveFid
        )
        try session.proofs.upsert(draft)

        let carved = try await session.carveProofIssueOnChain(
            title: "Lease", content: "Twelve months", draftId: draft.id
        )
        XCTAssertEqual(carved.id, "proof-txid-001")
        XCTAssertNil(try session.proofs.get(id: draft.id), "the draft key is gone")
        XCTAssertNotNil(try session.proofs.get(id: "proof-txid-001"))
        XCTAssertNil(carved.onChain)
        XCTAssertTrue(try session.proofs.drafts().isEmpty)
    }

    // MARK: - sign / destroy

    func testSignCarriesTheProofIdAndPaysNobody() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        let broadcast = Captured()
        try stage(mock, senderFid: session.mainFid, onBroadcast: { broadcast.value = $0 })

        _ = try await session.carveProofSignOnChain(proofId: "p1")
        let raw = Data(fromHex: try XCTUnwrap(broadcast.value))
        XCTAssertNotNil(raw.range(of: Data(#""op":"sign""#.utf8)))
        XCTAssertNotNil(raw.range(of: Data(#""proofId":"p1""#.utf8)))
        XCTAssertNil(raw.range(of: try payOutputBytes(
            to: try recipientFid(), value: ActiveSession.proofTransferSats
        )))
    }

    /// The protocol takes a list, which for a paid op is the difference
    /// between one miner fee and several.
    func testDestroyRetiresAWholeBatchInOneCarve() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        let broadcast = Captured()
        try stage(mock, senderFid: session.mainFid, onBroadcast: { broadcast.value = $0 })

        _ = try await session.carveProofDestroyOnChain(proofIds: ["a", "b", "c"])
        let raw = Data(fromHex: try XCTUnwrap(broadcast.value))
        XCTAssertNotNil(raw.range(of: Data(#""op":"destroy""#.utf8)))
        XCTAssertNotNil(raw.range(of: Data(#""proofIds":["a","b","c"]"#.utf8)))
        let broadcasts = mock.recorded.filter { $0.api == "base.broadcastTx" }
        XCTAssertEqual(broadcasts.count, 1, "one carve, one fee")
    }

    // MARK: - transfer

    /// The transfer op names no recipient — the payment is the
    /// addressing. If the output were missing the carve would move the
    /// proof to nobody.
    func testTransferPaysTheNewOwner() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        let broadcast = Captured()
        try stage(mock, senderFid: session.mainFid, onBroadcast: { broadcast.value = $0 })

        let recipient = try recipientFid()
        _ = try await session.carveProofTransferOnChain(proofId: "p1", to: recipient)

        let raw = Data(fromHex: try XCTUnwrap(broadcast.value))
        XCTAssertNotNil(raw.range(of: Data(#""op":"transfer""#.utf8)))
        XCTAssertNotNil(raw.range(of: Data(#""proofId":"p1""#.utf8)))
        XCTAssertNotNil(
            raw.range(of: try payOutputBytes(
                to: recipient, value: ActiveSession.proofTransferSats
            )),
            "the payment is how the protocol names the new owner"
        )
    }

    /// Android sends `Cash.MIN_AMOUNT` (0.0001 F). The two clients have
    /// to agree on what an ownership change looks like on chain.
    func testTransferAmountMatchesAndroid() {
        XCTAssertEqual(ActiveSession.proofTransferSats, 10_000)
        XCTAssertEqual(NoticeFee.coinString(satoshis: ActiveSession.proofTransferSats), "0.0001")
        XCTAssertGreaterThan(ActiveSession.proofTransferSats, CoinSelector.dustThresholdSats)
    }

    // MARK: - store

    /// A draft is the only copy of work the user has not paid to
    /// publish; a chain refresh must never take it.
    func testReplacingChainRowsLeavesDraftsAlone() throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        let draft = Proof.createLocal(
            title: "draft", content: "c", cosigners: [],
            transferable: false, issuer: session.liveFid
        )
        try session.proofs.upsert(draft)
        try session.proofs.upsert(Proof(id: "stale", title: "gone", onChain: true))

        try session.proofs.replaceChainRows(with: [
            Proof(id: "fresh", title: "here", onChain: true)
        ])

        XCTAssertNotNil(try session.proofs.get(id: draft.id))
        XCTAssertNotNil(try session.proofs.get(id: "fresh"))
        XCTAssertNil(try session.proofs.get(id: "stale"), "a dropped chain row is dropped")
        XCTAssertEqual(try session.proofs.drafts().map(\.id), [draft.id])
    }

    /// "When did this first appear here" has to survive a refresh, or
    /// every sync would reset it.
    func testReplacingChainRowsKeepsTheOriginalAddedAt() throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        let first = Date(timeIntervalSince1970: 1_600_000_000)
        try session.proofs.upsert(
            Proof(id: "p1", title: "old", onChain: true, addedAt: first)
        )
        try session.proofs.replaceChainRows(with: [
            Proof(id: "p1", title: "new", onChain: true)
        ])
        let kept = try XCTUnwrap(try session.proofs.get(id: "p1"))
        XCTAssertEqual(kept.title, "new", "the chain is the authority on the fields")
        XCTAssertEqual(kept.addedAt.timeIntervalSince1970, first.timeIntervalSince1970, accuracy: 1)
    }

    /// A just-broadcast carve sorts above every confirmed row — that is
    /// where the user just put it.
    func testUnconfirmedCarvesSortToTheTop() throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        try session.proofs.upsert(Proof(id: "old", lastHeight: 10, onChain: true))
        try session.proofs.upsert(Proof(id: "new", lastHeight: 900, onChain: true))
        try session.proofs.upsert(
            Proof(id: "fresh", lastHeight: ProofsStore.unconfirmedHeight, onChain: nil)
        )
        XCTAssertEqual(try session.proofs.all().map(\.id), ["fresh", "new", "old"])
    }
}

private final class Captured: @unchecked Sendable {
    var value: String?
}
