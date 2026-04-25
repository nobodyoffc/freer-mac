import XCTest
import FCCore
@testable import FCDomain

/// Phase 5.1 acceptance test: an identity can be registered from a
/// passphrase, persisted, logged-out, logged-in again, and its
/// encrypted store survives the round-trip.
///
/// Uses ``PhraseKey/Scheme/legacySha256`` (deterministic, milliseconds
/// to derive) instead of `.argon2id` (~300 ms each). Argon2 has its
/// own byte-parity tests in `FCCore`; here we're testing identity
/// lifecycle, not the KDF.
final class IdentityVaultTests: XCTestCase {

    private var baseDir: URL!

    override func setUpWithError() throws {
        baseDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("IdentityVaultTests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: baseDir, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        if let baseDir { try? FileManager.default.removeItem(at: baseDir) }
    }

    private func makeVault() throws -> IdentityVault {
        try IdentityVault(baseDirectory: baseDir)
    }

    // MARK: - register

    func testRegisterAddsRecordAndOpensStore() throws {
        let vault = try makeVault()
        XCTAssertEqual(try vault.listIdentities().count, 0)

        let id = try vault.register(
            passphrase: "alice-secret",
            displayName: "Alice",
            scheme: .legacySha256
        )

        XCTAssertFalse(id.isLocked)
        XCTAssertEqual(id.displayName, "Alice")
        XCTAssertFalse(id.fid.isEmpty)

        // Sanity: the record is persisted.
        let listed = try vault.listIdentities()
        XCTAssertEqual(listed.count, 1)
        XCTAssertEqual(listed[0].fid, id.fid)
        XCTAssertEqual(listed[0].phraseScheme, .legacySha256)

        // Sanity: the store actually accepts a write+read.
        let kv = try id.storage()
        try kv.put("hello", namespace: "test", key: "k1")
        XCTAssertEqual(try kv.get(String.self, namespace: "test", key: "k1"), "hello")
    }

    func testRegisterRejectsDuplicateFid() throws {
        let vault = try makeVault()
        _ = try vault.register(
            passphrase: "carol", displayName: "Carol", scheme: .legacySha256
        )
        XCTAssertThrowsError(
            try vault.register(passphrase: "carol", displayName: "Carol2", scheme: .legacySha256)
        ) { error in
            guard case IdentityVault.Failure.alreadyRegistered = error else {
                XCTFail("expected alreadyRegistered, got \(error)"); return
            }
        }
    }

    // MARK: - login (the round-trip)

    func testLoginUnlocksWithCorrectPassphraseAndReadsEarlierData() throws {
        let vault = try makeVault()

        // Register and write a value.
        let alice = try vault.register(
            passphrase: "alice-secret", displayName: "Alice", scheme: .legacySha256
        )
        let aliceFid = alice.fid
        try alice.storage().put(["a", "b"], namespace: "ns", key: "list")

        // Lock the session — simulating logout / app quit.
        alice.lock()
        XCTAssertTrue(alice.isLocked)
        XCTAssertThrowsError(try alice.privateKey()) { error in
            guard case Identity.Failure.locked = error else {
                XCTFail("expected locked, got \(error)"); return
            }
        }

        // Reopen the vault from scratch (file-backed index reload).
        let vault2 = try makeVault()
        let alice2 = try vault2.login(fid: aliceFid, passphrase: "alice-secret")

        XCTAssertEqual(alice2.fid, aliceFid)
        XCTAssertFalse(alice2.isLocked)
        let restored = try alice2.storage().get([String].self, namespace: "ns", key: "list")
        XCTAssertEqual(restored, ["a", "b"])
    }

    func testLoginRejectsWrongPassphrase() throws {
        let vault = try makeVault()
        let id = try vault.register(
            passphrase: "right", displayName: "Bob", scheme: .legacySha256
        )

        XCTAssertThrowsError(try vault.login(fid: id.fid, passphrase: "wrong")) { error in
            guard case IdentityVault.Failure.wrongPassphrase = error else {
                XCTFail("expected wrongPassphrase, got \(error)"); return
            }
        }
    }

    func testLoginUnknownFidThrowsNotRegistered() throws {
        let vault = try makeVault()
        XCTAssertThrowsError(try vault.login(fid: "FNotARealFidEver12345", passphrase: "x")) { error in
            guard case IdentityVault.Failure.notRegistered = error else {
                XCTFail("expected notRegistered, got \(error)"); return
            }
        }
    }

    // MARK: - delete

    func testDeleteRemovesRecordAndDirectory() throws {
        let vault = try makeVault()
        let id = try vault.register(
            passphrase: "delete-me", displayName: "Doomed", scheme: .legacySha256
        )
        let fid = id.fid

        let identityDir = baseDir
            .appendingPathComponent("identities")
            .appendingPathComponent(fid)
        XCTAssertTrue(FileManager.default.fileExists(atPath: identityDir.path))

        XCTAssertTrue(try vault.delete(fid: fid))
        XCTAssertFalse(FileManager.default.fileExists(atPath: identityDir.path))
        XCTAssertNil(try vault.record(forFid: fid))

        // Idempotent: second delete returns false, doesn't throw.
        XCTAssertFalse(try vault.delete(fid: fid))
    }

    // MARK: - identity isolation (paranoia)

    func testTwoIdentitiesProduceDifferentVaultKeys() throws {
        // Spec: vault key = HKDF(privkey, salt, info, 32). Different
        // privkeys must yield different vault keys, otherwise stolen
        // privkey #1 reads identity #2's data.
        let pk1 = try PhraseKey.privateKey(fromPhrase: "first", scheme: .legacySha256)
        let pk2 = try PhraseKey.privateKey(fromPhrase: "second", scheme: .legacySha256)
        XCTAssertNotEqual(pk1, pk2)
        let v1 = IdentityVault.deriveVaultKey(fromPrivkey: pk1)
        let v2 = IdentityVault.deriveVaultKey(fromPrivkey: pk2)
        XCTAssertEqual(v1.count, 32)
        XCTAssertNotEqual(v1, v2)
    }
}
