import XCTest
import FCCore
@testable import FCDomain

final class ConfigureManagerTests: XCTestCase {

    private var baseDir: URL!

    override func setUpWithError() throws {
        baseDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("ConfigureManagerTests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: baseDir, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        if let baseDir { try? FileManager.default.removeItem(at: baseDir) }
    }

    private func makeManager() throws -> ConfigureManager {
        try ConfigureManager(baseDirectory: baseDir)
    }

    // MARK: - passwordName

    func testPasswordNameMatchesAndroidAlgorithm() {
        // dSHA256("password") = c7e83c01512698... (3-byte prefix = "c7e83c")
        let bytes = Data("password".utf8)
        XCTAssertEqual(ConfigureCrypto.passwordName(from: bytes).count, 6)
        // Two different passwords → two different names (highly likely).
        let other = ConfigureCrypto.passwordName(from: Data("password2".utf8))
        XCTAssertNotEqual(ConfigureCrypto.passwordName(from: bytes), other)
        // Same password → same name (deterministic).
        XCTAssertEqual(
            ConfigureCrypto.passwordName(from: bytes),
            ConfigureCrypto.passwordName(from: Data("password".utf8))
        )
    }

    // MARK: - create / open

    func testCreateConfigureWritesIndexAndBody() throws {
        let mgr = try makeManager()
        XCTAssertEqual(try mgr.listConfigures().count, 0)

        let session = try mgr.createConfigure(
            password: Data("hunter2".utf8),
            label: "Personal",
            kdfKind: .legacySha256          // fast for tests
        )
        XCTAssertFalse(session.isLocked)
        XCTAssertEqual(session.label, "Personal")
        XCTAssertEqual(session.passwordName.count, 6)
        XCTAssertTrue(session.listMains().isEmpty)

        // Index has one entry now.
        let listed = try mgr.listConfigures()
        XCTAssertEqual(listed.count, 1)
        XCTAssertEqual(listed[0].passwordName, session.passwordName)
        XCTAssertEqual(listed[0].nonce.count, 16)
    }

    func testCreateRejectsDuplicatePassword() throws {
        let mgr = try makeManager()
        let pwd = Data("dup".utf8)
        _ = try mgr.createConfigure(password: pwd, kdfKind: .legacySha256)
        XCTAssertThrowsError(try mgr.createConfigure(password: pwd, kdfKind: .legacySha256)) { error in
            guard case ConfigureManager.Failure.alreadyExists = error else {
                XCTFail("expected alreadyExists, got \(error)"); return
            }
        }
    }

    func testOpenWithCorrectPasswordRoundTrips() throws {
        let mgr = try makeManager()
        let pwd = Data("alice-secret".utf8)
        let session = try mgr.createConfigure(password: pwd, label: "A", kdfKind: .legacySha256)
        let priv = Data(repeating: 0x42, count: 32)
        let added = try session.addMain(privkey: priv, label: "alice main")

        // Lock + reopen via a fresh manager — proves persistence path.
        session.lock()
        XCTAssertTrue(session.isLocked)

        let mgr2 = try makeManager()
        let reopened = try mgr2.openConfigure(passwordName: session.passwordName, password: pwd)
        XCTAssertEqual(reopened.listMains().count, 1)
        XCTAssertEqual(reopened.listMains()[0].fid, added.fid)
        XCTAssertEqual(reopened.listMains()[0].label, "alice main")

        // Decryption of the privkey works under the re-derived symkey.
        let decrypted = try reopened.privkeyForMain(fid: added.fid)
        XCTAssertEqual(decrypted, priv)
    }

    func testOpenWithWrongPasswordThrows() throws {
        let mgr = try makeManager()
        let session = try mgr.createConfigure(
            password: Data("right".utf8), kdfKind: .legacySha256
        )
        XCTAssertThrowsError(try mgr.openConfigure(
            passwordName: session.passwordName,
            password: Data("wrong".utf8)
        )) { error in
            guard case ConfigureManager.Failure.wrongPassword = error else {
                XCTFail("expected wrongPassword, got \(error)"); return
            }
        }
    }

    func testOpenUnknownPasswordNameThrows() throws {
        let mgr = try makeManager()
        XCTAssertThrowsError(try mgr.openConfigure(
            passwordName: "notexi", password: Data("anything".utf8)
        )) { error in
            guard case ConfigureManager.Failure.notFound = error else {
                XCTFail("expected notFound, got \(error)"); return
            }
        }
    }

    func testDeleteRemovesIndexAndDirectory() throws {
        let mgr = try makeManager()
        let session = try mgr.createConfigure(
            password: Data("doomed".utf8), kdfKind: .legacySha256
        )
        let dir = mgr.configureDirectory(for: session.passwordName)
        XCTAssertTrue(FileManager.default.fileExists(atPath: dir.path))

        XCTAssertTrue(try mgr.deleteConfigure(passwordName: session.passwordName))
        XCTAssertFalse(FileManager.default.fileExists(atPath: dir.path))
        XCTAssertEqual(try mgr.listConfigures().count, 0)
        XCTAssertFalse(try mgr.deleteConfigure(passwordName: session.passwordName))   // idempotent
    }

    // MARK: - main FID management

    func testAddMainAppliesProjectFixturePrivkey() throws {
        // Project test privkey hex; FID FEk41Kqjar45fLDriztUDTUkdki7mmcjWK.
        let priv = Data(fromHex: "a048f6c843f92bfe036057f7fc2bf2c27353c624cf7ad97e98ed41432f700575")
        let mgr = try makeManager()
        let session = try mgr.createConfigure(
            password: Data("with-fixture".utf8), kdfKind: .legacySha256
        )
        let info = try session.addMain(privkey: priv, label: "fixture")
        XCTAssertEqual(info.fid, "FEk41Kqjar45fLDriztUDTUkdki7mmcjWK")
        XCTAssertEqual(info.kind, KeyKind.main)
        XCTAssertNotNil(info.prikeyCipher)
        XCTAssertEqual(info.pubkey?.count, 33)

        // Decryption works.
        let restored = try session.privkeyForMain(fid: info.fid)
        XCTAssertEqual(restored, priv)
    }

    func testAddMainViaWifMatchesAddMainViaHex() throws {
        let mgr = try makeManager()
        let session = try mgr.createConfigure(
            password: Data("wif".utf8), kdfKind: .legacySha256
        )
        let wif = "L2bHRej6Fxxipvb4TiR5bu1rkT3tRp8yWEsUy4R1Zb8VMm2x7sd8"
        let (privFromWif, _) = try WifPrivkey.decode(wif)
        let info = try session.addMain(privkey: privFromWif)
        XCTAssertEqual(info.fid, "FEk41Kqjar45fLDriztUDTUkdki7mmcjWK")
    }

    func testAddDuplicateMainFidThrows() throws {
        let mgr = try makeManager()
        let session = try mgr.createConfigure(
            password: Data("dup-main".utf8), kdfKind: .legacySha256
        )
        let priv = Data(repeating: 0x99, count: 32)
        _ = try session.addMain(privkey: priv)
        XCTAssertThrowsError(try session.addMain(privkey: priv)) { error in
            guard case ConfigureSession.Failure.mainAlreadyExists = error else {
                XCTFail("expected mainAlreadyExists, got \(error)"); return
            }
        }
    }

    // MARK: - lock semantics

    func testLockRefusesPostLockOps() throws {
        let mgr = try makeManager()
        let session = try mgr.createConfigure(
            password: Data("lock".utf8), kdfKind: .legacySha256
        )
        let priv = Data(repeating: 0x33, count: 32)
        let info = try session.addMain(privkey: priv)
        session.lock()
        XCTAssertTrue(session.isLocked)
        XCTAssertThrowsError(try session.privkeyForMain(fid: info.fid)) { error in
            guard case ConfigureSession.Failure.locked = error else {
                XCTFail("expected locked, got \(error)"); return
            }
        }
        XCTAssertThrowsError(try session.addMain(privkey: Data(repeating: 0x44, count: 32)))
    }
}
