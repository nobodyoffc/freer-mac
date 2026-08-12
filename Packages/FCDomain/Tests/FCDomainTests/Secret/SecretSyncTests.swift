import XCTest
import FCCore
import FCTransport
@testable import FCDomain

/// Secrets: local create (Pattern B cipher-only storage), on-chain
/// sync merge + deletion cleanup, FEIP builders, and the carve op
/// selection (add vs update).
final class SecretSyncTests: XCTestCase {

    private var baseDir: URL!

    override func setUpWithError() throws {
        baseDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("SecretSyncTests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: baseDir, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        if let baseDir { try? FileManager.default.removeItem(at: baseDir) }
    }

    private func makeSession(fapi: any FapiCalling) throws -> ActiveSession {
        let mgr = try ConfigureManager(baseDirectory: baseDir)
        let configure = try mgr.createConfigure(
            password: Data("secret-tests".utf8), kdfKind: .legacySha256
        )
        let priv = Hash.sha256(Data("secret-owner".utf8))
        let info = try configure.addMain(privkey: priv, label: "owner")
        return try configure.unlockMain(fid: info.fid, fapi: fapi)
    }

    /// One on-chain secret record whose cipher is a real AsyOneWay
    /// envelope over the detail JSON, decryptable with `ownerPriv`.
    private func record(
        id: String,
        ownerPriv: Data,
        lastHeight: Int64,
        active: Bool,
        type: String = "text",
        title: String? = nil,
        content: String,
        memo: String? = nil
    ) throws -> [String: Any] {
        let detail = try SecretFeip.detailJson(
            type: type, title: title, content: content, memo: memo
        )
        let ownerPub = try Secp256k1.publicKey(fromPrivateKey: ownerPriv)
        let cipher = try AsyOneWayCipher.encrypt(
            plaintext: Data(detail.utf8), toPubkey: ownerPub
        )
        return [
            "id": id,
            "cipher": cipher,
            "birthTime": 1_700_000_000,
            "lastHeight": lastHeight,
            "active": active
        ]
    }

    // MARK: - local create

    func testCreateLocalStoresCipherOnly() throws {
        let priv = Hash.sha256(Data("k".utf8))
        let pub = try Secp256k1.publicKey(fromPrivateKey: priv)
        let secret = try Secret.createLocal(
            type: .totp, title: "GitHub", content: "JBSWY3DPEHPK3PXP", memo: "work", ownPubkey: pub
        )
        XCTAssertTrue(secret.isTotp)
        XCTAssertFalse(secret.onChain)
        XCTAssertEqual(secret.id.count, 64) // sha256x2 hex
        // Plaintext is recoverable only via the privkey.
        XCTAssertEqual(try secret.decryptContent(privkey: priv), "JBSWY3DPEHPK3PXP")
        // And nothing about the struct itself carries the plaintext.
        let encoded = String(data: try JSONEncoder().encode(secret), encoding: .utf8)!
        XCTAssertFalse(encoded.contains("JBSWY3DPEHPK3PXP"))
    }

    func testStoreTotpsFilter() throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        let pub = try Secp256k1.publicKey(fromPrivateKey: session.livePrikey())
        try session.secrets.upsert(
            try Secret.createLocal(type: .totp, title: "t1", content: "MZXW6YTB", memo: nil, ownPubkey: pub)
        )
        try session.secrets.upsert(
            try Secret.createLocal(type: .password, title: "p1", content: "hunter2", memo: nil, ownPubkey: pub)
        )
        XCTAssertEqual(try session.secrets.all().count, 2)
        XCTAssertEqual(try session.secrets.totps().map(\.title), ["t1"])
    }

    // MARK: - FEIP builders

    func testFeipEnvelopeShape() throws {
        let add = try SecretFeip.addOp(cipher: "CIPHER")
        XCTAssertEqual(add, #"{"cipher":"CIPHER","op":"add"}"#)
        let envelope = SecretFeip.envelope(opJson: add)
        XCTAssertEqual(
            envelope,
            #"{"type":"FEIP","sn":"17","ver":"3","name":"Secret","data":{"cipher":"CIPHER","op":"add"}}"#
        )
        let del = try SecretFeip.deleteOp(secretIds: ["a", "b"])
        XCTAssertEqual(del, #"{"op":"delete","secretIds":["a","b"]}"#)
        let update = try SecretFeip.updateOp(secretId: "sid", cipher: "C")
        XCTAssertEqual(update, #"{"cipher":"C","op":"update","secretId":"sid"}"#)
    }

    func testDetailJsonOmitsNilFields() throws {
        let bare = try SecretFeip.detailJson(type: nil, title: nil, content: "c", memo: nil)
        XCTAssertEqual(bare, #"{"content":"c"}"#)
        let full = try SecretFeip.detailJson(type: "TOTP", title: "t", content: "c", memo: "m")
        XCTAssertEqual(full, #"{"content":"c","memo":"m","title":"t","type":"TOTP"}"#)
    }

    // MARK: - sync

    func testSyncMergesActiveAndRemovesDeleted() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        let ownerPriv = try session.livePrikey()
        let ownPub = try Secp256k1.publicKey(fromPrivateKey: ownerPriv)

        // Pre-seed: a chain-sourced row that the chain now deletes, and
        // a local-only row that must survive.
        var chainSourced = try Secret.createLocal(
            type: .text, title: "gone soon", content: "x", memo: nil, ownPubkey: ownPub
        )
        chainSourced.id = "carve-deleted"
        chainSourced.onChain = true
        try session.secrets.upsert(chainSourced)
        let localOnly = try Secret.createLocal(
            type: .text, title: "local", content: "keep me", memo: nil, ownPubkey: ownPub
        )
        try session.secrets.upsert(localOnly)

        let records: [[String: Any]] = [
            try record(id: "carve-alive", ownerPriv: ownerPriv, lastHeight: 300, active: true,
                       type: "TOTP", title: "GitHub", content: "JBSWY3DPEHPK3PXP", memo: "work"),
            try record(id: "carve-deleted", ownerPriv: ownerPriv, lastHeight: 200, active: false,
                       content: "x"),
            // Older duplicate state of carve-alive — newest-first wins.
            try record(id: "carve-alive", ownerPriv: ownerPriv, lastHeight: 100, active: true,
                       type: "TOTP", title: "stale title", content: "STALE", memo: nil)
        ]

        mock.responder = { call in
            switch call.api {
            case "base.search":
                // Entity must be `secret`, owner in query.terms.
                let dict = try XCTUnwrap(
                    JSONSerialization.jsonObject(with: call.fcdsl!) as? [String: Any]
                )
                XCTAssertEqual(dict["entity"] as? String, "secret")
                return try makeResponse(data: records)
            default:
                XCTFail("unexpected api: \(call.api)")
                return FapiResponse(code: 1, message: "unexpected")
            }
        }

        let result = try await session.secretService.syncOnChainSecrets(
            owner: session.liveFid, privkey: ownerPriv, into: session.secrets
        )

        XCTAssertEqual(result.total, 3)
        XCTAssertEqual(result.merged, 1)
        XCTAssertEqual(result.removed, 1)
        XCTAssertEqual(result.undecryptable, 0)

        // Merged: newest detail won; content round-trips via the
        // re-encrypted contentCipher; carve id captured.
        let alive = try XCTUnwrap(session.secrets.get(id: "carve-alive"))
        XCTAssertEqual(alive.title, "GitHub")
        XCTAssertEqual(alive.memo, "work")
        XCTAssertTrue(alive.isTotp)
        XCTAssertTrue(alive.onChain)
        XCTAssertEqual(alive.carveId, "carve-alive")
        XCTAssertEqual(try alive.decryptContent(privkey: ownerPriv), "JBSWY3DPEHPK3PXP")

        // Chain-sourced deleted row removed; local-only row kept.
        XCTAssertNil(try session.secrets.get(id: "carve-deleted"))
        XCTAssertNotNil(try session.secrets.get(id: localOnly.id))
    }

    func testSyncCountsUndecryptableRecords() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        let ownerPriv = try session.livePrikey()

        // A record encrypted to someone ELSE's pubkey.
        let strangerPriv = Hash.sha256(Data("stranger".utf8))
        let strangerPub = try Secp256k1.publicKey(fromPrivateKey: strangerPriv)
        let foreignCipher = try AsyOneWayCipher.encrypt(
            plaintext: Data(#"{"content":"not yours"}"#.utf8), toPubkey: strangerPub
        )
        let records: [[String: Any]] = [
            ["id": "carve-foreign", "cipher": foreignCipher, "lastHeight": 10, "active": true]
        ]
        mock.responder = { _ in try makeResponse(data: records) }

        let result = try await session.secretService.syncOnChainSecrets(
            owner: session.liveFid, privkey: ownerPriv, into: session.secrets
        )
        XCTAssertEqual(result.total, 1)
        XCTAssertEqual(result.merged, 0)
        XCTAssertEqual(result.undecryptable, 1)
        XCTAssertFalse(result.failureReasons.isEmpty)
        XCTAssertNil(try session.secrets.get(id: "carve-foreign"))
    }

    // MARK: - TOTP generation from a stored secret

    func testTotpFromStoredSecret() throws {
        let priv = Hash.sha256(Data("totp".utf8))
        let pub = try Secp256k1.publicKey(fromPrivateKey: priv)
        // RFC 6238's SHA-1 test secret, Base32-encoded.
        let base32Secret = Base32.encode(Data("12345678901234567890".utf8))
        let secret = try Secret.createLocal(
            type: .totp, title: "rfc", content: base32Secret, memo: nil, ownPubkey: pub
        )
        let content = try secret.decryptContent(privkey: priv)
        let code = Totp.generate(secret: try Base32.decode(content), unixTime: 59, digits: 8)
        XCTAssertEqual(code, "94287082")
    }
}
