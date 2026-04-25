import XCTest
import FCCore
import FCTransport
@testable import FCDomain

final class IdentitySessionTests: XCTestCase {

    private var baseDir: URL!

    override func setUpWithError() throws {
        baseDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("IdentitySessionTests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: baseDir, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        if let baseDir { try? FileManager.default.removeItem(at: baseDir) }
    }

    private func makeSession(passphrase: String = "alice-secret") throws -> IdentitySession {
        let vault = try IdentityVault(baseDirectory: baseDir)
        let id = try vault.register(
            passphrase: passphrase, displayName: "Alice", scheme: .legacySha256
        )
        return IdentitySession(identity: id, fapi: MockFapiClient())
    }

    // MARK: - lazy stores

    func testStoresLazyInitButShareTheSameUnderlyingKv() throws {
        let s = try makeSession()
        // Settings get/set via session.settings.
        try s.settings.save(Settings(theme: .dark))
        XCTAssertEqual(try s.settings.load().theme, .dark)

        // ContactsStore reachable via session — store a real FID and verify.
        let priv = Data(repeating: 0x55, count: 32)
        let pub = try Secp256k1.publicKey(fromPrivateKey: priv)
        let fid = try FchAddress(publicKey: pub).fid
        try s.contacts.upsert(Contact(fid: fid, nickname: "buddy"))
        XCTAssertEqual(try s.contacts.get(fid: fid)?.nickname, "buddy")

        // KeysStore reachable too.
        try s.keys.upsert(PubkeyRecord(fid: fid, pubkey: pub))
        XCTAssertEqual(try s.keys.pubkey(forFid: fid), pub)
    }

    func testWalletServiceUsesProvidedFapiClient() async throws {
        let mock = MockFapiClient()
        mock.responder = { call in
            // Reply differently per api so we can verify dispatch hit.
            switch call.api {
            case "base.health":
                return FapiResponse(code: 0, message: "alive")
            default:
                return FapiResponse(code: 1)
            }
        }
        let vault = try IdentityVault(baseDirectory: baseDir)
        let id = try vault.register(passphrase: "fapi", displayName: "F", scheme: .legacySha256)
        let session = IdentitySession(identity: id, fapi: mock)

        let ok = try await session.wallet.health()
        XCTAssertTrue(ok)
        XCTAssertEqual(mock.recorded.first?.api, "base.health")
    }

    // MARK: - lock

    func testLockChainsToIdentityAndRefusesFurtherStoreAccess() throws {
        let s = try makeSession()
        // Touch settings so the lazy is populated, then lock.
        _ = try s.settings.load()
        XCTAssertFalse(s.isLocked)
        s.lock()
        XCTAssertTrue(s.isLocked)
        XCTAssertTrue(s.identity.isLocked)

        // Re-accessing storage on a locked session must throw.
        XCTAssertThrowsError(try s.settings.load()) { error in
            guard case Identity.Failure.locked = error else {
                XCTFail("expected locked, got \(error)"); return
            }
        }
    }

    func testIdentityMetadataReadablePostLock() throws {
        let s = try makeSession()
        let recordedFid = s.fid
        let recordedPub = s.pubkey
        s.lock()
        // FID and pubkey are not secret — UI should still be able
        // to show "you were logged in as <name>".
        XCTAssertEqual(s.fid, recordedFid)
        XCTAssertEqual(s.pubkey, recordedPub)
        XCTAssertEqual(s.displayName, "Alice")
    }
}
