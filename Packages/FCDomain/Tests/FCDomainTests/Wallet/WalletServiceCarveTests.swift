import XCTest
import FCCore
import FCTransport
@testable import FCDomain

/// End-to-end exercise of the carve pipeline through
/// `ActiveSession.carveContactOnChain`: encrypt → FEIP wrap → refresh
/// → CD-aware coin-select → build (change + OP_RETURN) → Schnorr-sign
/// → broadcast. The mock stages `base.cashValid` and `base.broadcastTx`;
/// assertions decode the broadcast raw hex to verify the OP_RETURN
/// actually carries the FEIP JSON.
final class WalletServiceCarveTests: XCTestCase {

    private var baseDir: URL!

    override func setUpWithError() throws {
        baseDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("WalletServiceCarveTests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: baseDir, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        if let baseDir { try? FileManager.default.removeItem(at: baseDir) }
    }

    private func makeSession(fapi: any FapiCalling) throws -> ActiveSession {
        let mgr = try ConfigureManager(baseDirectory: baseDir)
        let configure = try mgr.createConfigure(
            password: Data("carve-tests".utf8), kdfKind: .legacySha256
        )
        let priv = Hash.sha256(Data("carver".utf8))
        let info = try configure.addMain(privkey: priv, label: "carver")
        return try configure.unlockMain(fid: info.fid, fapi: fapi)
    }

    private func cashDict(
        owner: String, txid: String, index: Int, value: Int64, cd: Int64? = nil
    ) throws -> [String: Any] {
        let h160 = try FchAddress(fid: owner).hash160
        var dict: [String: Any] = [
            "id": try Cash.makeId(birthTxId: txid, birthIndex: index),
            "owner": owner,
            "value": value,
            "type": "P2PKH",
            "birthTxId": txid,
            "birthIndex": index,
            "lockScript": Cash.canonicalP2PKHLockScript(hash160: h160)
        ]
        if let cd { dict["cd"] = cd }
        return dict
    }

    func testCarveContactFullPipeline() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        let fid = session.mainFid

        var broadcastRawHex: String?
        mock.responder = { call in
            switch call.api {
            case "base.cashValid":
                // bestHeight below CDD_CHECK_HEIGHT → no CD requirement,
                // matching mainnet today.
                return try makeResponse(
                    data: [try self.cashDict(
                        owner: fid,
                        txid: String(repeating: "ab", count: 32),
                        index: 0,
                        value: 1_000_000
                    )],
                    bestHeight: 3_500_000
                )
            case "base.broadcastTx":
                let params = try JSONSerialization.jsonObject(with: call.params!) as? [String: Any]
                broadcastRawHex = params?["rawTx"] as? String
                return try makeResponse(data: "carve-txid-001")
            default:
                XCTFail("unexpected api: \(call.api)")
                return FapiResponse(code: 1, message: "unexpected")
            }
        }

        var contact = Contact(id: try FchAddress(
            publicKey: try Secp256k1.publicKey(fromPrivateKey: Data(repeating: 0xF1, count: 32))
        ).fid)
        contact.titles = ["Tester"]
        contact.memo = "carved from the mac"

        let txid = try await session.carveContactOnChain(contact)
        XCTAssertEqual(txid, "carve-txid-001")

        // Decode the broadcast tx and find the OP_RETURN payload.
        let rawHex = try XCTUnwrap(broadcastRawHex)
        let raw = Data(fromHex: rawHex)
        // The FEIP JSON must appear verbatim in the serialized tx.
        let feipPrefix = Data(#"{"type":"FEIP","sn":"12","ver":"3","name":"Contact","data":{"#.utf8)
        XCTAssertNotNil(
            raw.range(of: feipPrefix),
            "serialized tx must embed the FEIP envelope"
        )
        // And the op payload must be an `add` (no carveId on the contact).
        XCTAssertNotNil(raw.range(of: Data(#""op":"add""#.utf8)))
        // OP_RETURN marker right before a PUSHDATA of the JSON.
        XCTAssertNotNil(raw.range(of: Data([0x6A, 0x4D])))
    }

    func testCarveUsesUpdateOpWhenCarveIdKnown() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        let fid = session.mainFid

        var broadcastRawHex: String?
        mock.responder = { call in
            switch call.api {
            case "base.cashValid":
                return try makeResponse(
                    data: [try self.cashDict(
                        owner: fid, txid: String(repeating: "cd", count: 32),
                        index: 0, value: 1_000_000
                    )],
                    bestHeight: 3_500_000
                )
            case "base.broadcastTx":
                let params = try JSONSerialization.jsonObject(with: call.params!) as? [String: Any]
                broadcastRawHex = params?["rawTx"] as? String
                return try makeResponse(data: "carve-txid-002")
            default:
                return FapiResponse(code: 1, message: "unexpected")
            }
        }

        var contact = Contact(id: fid)
        contact.carveId = "earlier-carve-id"
        _ = try await session.carveContactOnChain(contact)

        let raw = Data(fromHex: try XCTUnwrap(broadcastRawHex))
        XCTAssertNotNil(raw.range(of: Data(#""op":"update""#.utf8)))
        XCTAssertNotNil(raw.range(of: Data(#""contactId":"earlier-carve-id""#.utf8)))
    }

    func testCarveRequiresCoinDaysPastCheckHeight() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        let fid = session.mainFid

        mock.responder = { call in
            switch call.api {
            case "base.cashValid":
                // Chain past CDD_CHECK_HEIGHT and the only cash has
                // zero CoinDays → carve must refuse.
                return try makeResponse(
                    data: [try self.cashDict(
                        owner: fid, txid: String(repeating: "ef", count: 32),
                        index: 0, value: 1_000_000, cd: 0
                    )],
                    bestHeight: 4_100_000
                )
            default:
                XCTFail("carve should fail before broadcasting")
                return FapiResponse(code: 1, message: "unexpected")
            }
        }

        do {
            _ = try await session.carveContactOnChain(Contact(id: fid))
            XCTFail("expected insufficientCoinDays")
        } catch let error as CoinSelector.Failure {
            guard case .insufficientCoinDays = error else {
                XCTFail("wrong failure: \(error)"); return
            }
        }
    }
}
