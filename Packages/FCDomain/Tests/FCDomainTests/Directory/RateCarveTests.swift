import XCTest
import FCCore
import FCTransport
@testable import FCDomain

/// Rating another FID through `ActiveSession.rateOnChain`.
///
/// **The assertions decode the broadcast raw hex on purpose.** The
/// ratee is `data.fid` and a rating pays nobody, so the two ways this
/// can silently go wrong are both invisible in the JSON the builder
/// returns: an output to the ratee sneaking back in (making a rating
/// cost money and look like a transfer), or the carve reaching the
/// chain with the wrong payload attached. Reading the transaction that
/// was actually broadcast catches both.
final class RateCarveTests: XCTestCase {

    private var baseDir: URL!
    private var manager: ConfigureManager!

    private let rateePrivkey = Data(repeating: 0xC3, count: 32)

    override func setUpWithError() throws {
        baseDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("RateCarveTests-\(UUID().uuidString)")
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
            password: Data("rate-tests".utf8), kdfKind: .legacySha256
        )
        let info = try configure.addMain(
            privkey: Hash.sha256(Data("rater".utf8)), label: "rater"
        )
        return try configure.unlockMain(fid: info.fid, fapi: fapi)
    }

    private func rateeFid() throws -> String {
        try FchAddress(publicKey: Secp256k1.publicKey(fromPrivateKey: rateePrivkey)).fid
    }

    private func cashDict(
        owner: String, txid: String, value: Int64, cd: Int64
    ) throws -> [String: Any] {
        let h160 = try FchAddress(fid: owner).hash160
        return [
            "id": try Cash.makeId(birthTxId: txid, birthIndex: 0),
            "owner": owner,
            "value": value,
            "cd": cd,
            "type": "P2PKH",
            "birthTxId": txid,
            "birthIndex": 0,
            "lockScript": Cash.canonicalP2PKHLockScript(hash160: h160)
        ]
    }

    /// `hasRecord: false` models a FID the index has never seen, which
    /// FEIP16 refuses to rate.
    private func stage(
        _ mock: MockFapiClient,
        raterFid: String,
        rateeFid: String,
        hasRecord: Bool = true,
        cashCd: Int64 = 500,
        history: [[String: Any]] = [],
        onBroadcast: @escaping @Sendable (String) -> Void = { _ in }
    ) {
        mock.responder = { call in
            switch call.api {
            case "base.freerByIds":
                guard hasRecord else { return FapiResponse(code: 404, message: "NOT_FOUND") }
                return try makeResponse(data: [rateeFid: ["id": rateeFid, "reputation": 10]])
            case "base.search":
                return try makeResponse(data: history)
            case "base.cashValid":
                return try makeResponse(
                    data: [try self.cashDict(
                        owner: raterFid,
                        txid: String(repeating: "cd", count: 32),
                        value: 10_000_000,
                        cd: cashCd
                    )],
                    // Below CDD_CHECK_HEIGHT, so the generic FEIP
                    // CoinDay floor is waived — only the rating's own
                    // weight is left to satisfy, which is the point.
                    bestHeight: 3_500_000
                )
            case "base.broadcastTx":
                let params = try JSONSerialization.jsonObject(with: call.params!) as? [String: Any]
                onBroadcast((params?["rawTx"] as? String) ?? "")
                return try makeResponse(data: "rate-txid-001")
            default:
                XCTFail("unexpected api: \(call.api)")
                return FapiResponse(code: 1, message: "unexpected")
            }
        }
    }

    // MARK: - the carve

    /// The whole point: the ratee is named in the payload, so the
    /// parser needs nothing else to apply the rating.
    func testRatingCarvesTheRateeInTheData() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        let ratee = try rateeFid()

        let broadcast = Captured()
        stage(mock, raterFid: session.mainFid, rateeFid: ratee,
              onBroadcast: { broadcast.value = $0 })

        let txid = try await session.rateOnChain(
            ratee: ratee, rate: .good, cause: "shipped on time", weightCd: 100
        )
        XCTAssertEqual(txid, "rate-txid-001")

        let raw = Data(fromHex: try XCTUnwrap(broadcast.value))
        let feip = Data(#"{"type":"FEIP","sn":"16","ver":"1","name":"Reputation","data":{"cause":"shipped on time","fid":"\#(ratee)","rate":"good"}}"#.utf8)
        XCTAssertNotNil(raw.range(of: feip), "the carve must name the ratee in data.fid")
        XCTAssertNotNil(raw.range(of: Data([0x6A])), "OP_RETURN opcode")
    }

    /// A rating is a statement about someone, not a transfer to them.
    /// Nothing in the transaction pays the ratee — every output belongs
    /// to the rater as change, or to the OP_RETURN.
    func testRatingPaysTheRateeNothing() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        let ratee = try rateeFid()

        let broadcast = Captured()
        stage(mock, raterFid: session.mainFid, rateeFid: ratee,
              onBroadcast: { broadcast.value = $0 })

        _ = try await session.rateOnChain(ratee: ratee, rate: .good, weightCd: 100)

        let raw = Data(fromHex: try XCTUnwrap(broadcast.value))
        let rateeScript = try ScriptBuilder.p2pkhOutput(
            hash160: FchAddress(fid: ratee).hash160
        ).bytes
        XCTAssertNil(
            raw.range(of: rateeScript),
            "a rating must not pay its subject — the payload names them"
        )
        // Change still comes back to the rater, so the transaction is
        // not simply missing its outputs.
        let changeScript = try ScriptBuilder.p2pkhOutput(
            hash160: FchAddress(fid: session.mainFid).hash160
        ).bytes
        XCTAssertNotNil(raw.range(of: changeScript))
    }

    func testBadRatingCarvesTheOtherVerdict() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        let broadcast = Captured()
        stage(mock, raterFid: session.mainFid, rateeFid: try rateeFid(),
              onBroadcast: { broadcast.value = $0 })

        _ = try await session.rateOnChain(ratee: try rateeFid(), rate: .bad)

        let raw = Data(fromHex: try XCTUnwrap(broadcast.value))
        XCTAssertNotNil(
            raw.range(of: Data(#"{"fid":"\#(try rateeFid())","rate":"bad"}"#.utf8))
        )
    }

    // MARK: - the refusals

    /// A FID cannot rate itself, and nothing is spent finding out.
    func testRatingYourselfIsRefusedBeforeAnythingIsSpent() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        stage(mock, raterFid: session.mainFid, rateeFid: session.mainFid)

        do {
            _ = try await session.rateOnChain(ratee: session.mainFid, rate: .good)
            XCTFail("expected a refusal")
        } catch {
            XCTAssertTrue("\(error)".contains("cannot rate itself"), "\(error)")
        }
        XCTAssertFalse(mock.recorded.contains { $0.api == "base.broadcastTx" })
    }

    /// FEIP16 §6: the ratee must have a `Freer`, or the operation fails
    /// with no state change. Checked before the fee is spent, because
    /// the chain's way of telling you is to take it and say nothing.
    func testRatingAFidWithNoChainRecordIsRefused() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        stage(mock, raterFid: session.mainFid, rateeFid: try rateeFid(), hasRecord: false)

        do {
            _ = try await session.rateOnChain(ratee: try rateeFid(), rate: .good)
            XCTFail("expected a refusal")
        } catch {
            XCTAssertTrue("\(error)".contains("no on-chain record"), "\(error)")
        }
        XCTAssertFalse(mock.recorded.contains { $0.api == "base.broadcastTx" })
    }

    func testWeightBelowTheProtocolFloorIsRefused() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        stage(mock, raterFid: session.mainFid, rateeFid: try rateeFid())

        do {
            _ = try await session.rateOnChain(
                ratee: try rateeFid(), rate: .good, weightCd: 0
            )
            XCTFail("expected a refusal")
        } catch {
            XCTAssertTrue("\(error)".contains("at least 1 CoinDay"), "\(error)")
        }
        XCTAssertFalse(mock.recorded.contains { $0.api == "base.broadcastTx" })
    }

    /// The weight is a floor coin selection must meet. Asking for more
    /// CoinDays than the identity holds fails the selection rather than
    /// quietly carving a weaker rating than the user asked for.
    func testWeightBeyondTheHeldCoinDaysFailsSelection() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        stage(mock, raterFid: session.mainFid, rateeFid: try rateeFid(), cashCd: 5)

        do {
            _ = try await session.rateOnChain(
                ratee: try rateeFid(), rate: .good, weightCd: 1_000
            )
            XCTFail("expected the coin selection to fail")
        } catch {
            XCTAssertTrue("\(error)".contains("CoinDay"), "\(error)")
        }
        XCTAssertFalse(mock.recorded.contains { $0.api == "base.broadcastTx" })
    }

    // MARK: - the quote

    func testQuoteReportsWhatWeHaveAlreadySaid() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        let ratee = try rateeFid()
        stage(mock, raterFid: session.mainFid, rateeFid: ratee, history: [
            [
                "id": "prior-txid", "height": 900_000, "time": 1_770_000_000,
                "ratee": ratee, "rater": session.mainFid,
                "rate": "good", "hot": 50, "reputation": 50
            ]
        ])

        let quote = try await session.quoteRating(of: ratee)
        XCTAssertTrue(quote.canRate)
        XCTAssertEqual(quote.freer?.reputation, 10)
        XCTAssertEqual(quote.alreadyRated.count, 1)
        XCTAssertEqual(quote.alreadyRated.first?.kind, .good)
    }

    func testQuoteSaysWhenThereIsNothingToRate() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        stage(mock, raterFid: session.mainFid, rateeFid: try rateeFid(), hasRecord: false)

        let quote = try await session.quoteRating(of: try rateeFid())
        XCTAssertFalse(quote.canRate)
        XCTAssertTrue(quote.alreadyRated.isEmpty)
    }

    func testQuotingYourselfThrows() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        stage(mock, raterFid: session.mainFid, rateeFid: session.mainFid)

        do {
            _ = try await session.quoteRating(of: session.mainFid)
            XCTFail("expected a refusal")
        } catch {
            XCTAssertTrue("\(error)".contains("cannot rate itself"), "\(error)")
        }
    }
}

private final class Captured: @unchecked Sendable {
    var value: String?
}
