import XCTest
import FCCore
@testable import FCDomain

final class StoresTests: XCTestCase {

    private var baseDir: URL!

    override func setUpWithError() throws {
        baseDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("StoresTests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: baseDir, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        if let baseDir { try? FileManager.default.removeItem(at: baseDir) }
    }

    // MARK: - helpers

    /// Mint two distinct identities under one vault. Used to verify
    /// per-identity isolation: writes to identity A must not be
    /// visible from identity B.
    private func makeTwoIdentities() throws -> (Identity, Identity, IdentityVault) {
        let vault = try IdentityVault(baseDirectory: baseDir)
        let a = try vault.register(passphrase: "alpha", displayName: "A", scheme: .legacySha256)
        let b = try vault.register(passphrase: "beta",  displayName: "B", scheme: .legacySha256)
        return (a, b, vault)
    }

    // MARK: - Settings

    func testSettingsRoundTripAndDefaults() throws {
        let (a, _, _) = try makeTwoIdentities()
        let store = try SettingsStore(a)

        // First read on a fresh identity returns defaults.
        let blank = try store.load()
        XCTAssertEqual(blank, Settings.defaults)

        try store.save(Settings(
            preferredFapiService: "fapi.example:8500",
            preferredFapiServicePubkeyHex: "03cd14...",
            theme: .dark,
            autoLockSeconds: 600
        ))
        let loaded = try store.load()
        XCTAssertEqual(loaded.preferredFapiService, "fapi.example:8500")
        XCTAssertEqual(loaded.theme, .dark)
        XCTAssertEqual(loaded.autoLockSeconds, 600)
    }

    func testSettingsUpdateClosure() throws {
        let (a, _, _) = try makeTwoIdentities()
        let store = try SettingsStore(a)
        try store.save(Settings(autoLockSeconds: 300))
        let result = try store.update { $0.autoLockSeconds = 900 }
        XCTAssertEqual(result.autoLockSeconds, 900)
        XCTAssertEqual(try store.load().autoLockSeconds, 900)
    }

    func testSettingsAreIsolatedPerIdentity() throws {
        let (a, b, _) = try makeTwoIdentities()
        try SettingsStore(a).save(Settings(theme: .dark))
        // B never wrote anything → still defaults.
        XCTAssertEqual(try SettingsStore(b).load(), Settings.defaults)
    }

    // MARK: - Contacts

    /// Build a real (Base58Check) FID by deriving from a fixed
    /// privkey. The string-FID literals from the earlier test pass
    /// would fail FCH address validation now that ContactsStore
    /// enforces it.
    private func realFid(byte: UInt8) throws -> String {
        let priv = Data(repeating: byte, count: 32)
        let pub = try Secp256k1.publicKey(fromPrivateKey: priv)
        return try FchAddress(publicKey: pub).fid
    }

    func testContactsUpsertAndDelete() throws {
        let (a, _, _) = try makeTwoIdentities()
        let store = try ContactsStore(a)

        let f1 = try realFid(byte: 0xA1)
        let f2 = try realFid(byte: 0xA2)
        let f3 = try realFid(byte: 0xA3)

        try store.upsert(Contact(fid: f1, nickname: "Friend1"))
        try store.upsert(Contact(fid: f2, nickname: "Friend2", pinnedAt: Date()))
        try store.upsert(Contact(fid: f3, nickname: "AAA")) // sorts first by name

        let listed = try store.all()
        XCTAssertEqual(listed.count, 3)
        // Pinned bubbles to top regardless of nickname order.
        XCTAssertEqual(listed.first?.fid, f2)
        // Then alphabetical by nickname (case-insensitive).
        XCTAssertEqual(listed[1].nickname, "AAA")

        // Re-upserting the same FID overwrites instead of duplicating.
        try store.upsert(Contact(fid: f1, nickname: "RenamedFriend"))
        XCTAssertEqual(try store.all().count, 3)
        XCTAssertEqual(try store.get(fid: f1)?.nickname, "RenamedFriend")

        XCTAssertTrue(try store.remove(fid: f1))
        XCTAssertNil(try store.get(fid: f1))
        XCTAssertFalse(try store.remove(fid: f1)) // idempotent
    }

    func testContactsAreIsolatedPerIdentity() throws {
        let (a, b, _) = try makeTwoIdentities()
        try ContactsStore(a).upsert(Contact(fid: try realFid(byte: 0xB0), nickname: "alice"))
        XCTAssertEqual(try ContactsStore(b).all().count, 0)
    }

    func testContactsRejectsInvalidFid() throws {
        let (a, _, _) = try makeTwoIdentities()
        let store = try ContactsStore(a)
        XCTAssertThrowsError(try store.upsert(Contact(fid: "not-a-fid", nickname: "x"))) { error in
            guard case ContactsStore.Failure.invalidFid = error else {
                XCTFail("expected invalidFid, got \(error)"); return
            }
        }
        XCTAssertThrowsError(try store.upsert(Contact(fid: "", nickname: "x")))
    }

    // MARK: - KeysStore (validation matters here)

    func testKeysStoreValidatesFidAgainstPubkey() throws {
        let (a, _, _) = try makeTwoIdentities()
        let store = try KeysStore(a)

        // Build a valid (fid, pubkey) pair from a known privkey.
        let privkey = Data(repeating: 0x42, count: 32)
        let pubkey = try Secp256k1.publicKey(fromPrivateKey: privkey)
        let fid = try FchAddress(publicKey: pubkey).fid

        try store.upsert(PubkeyRecord(fid: fid, pubkey: pubkey, nickname: "0x42 key"))
        let fetched = try XCTUnwrap(try store.record(forFid: fid))
        XCTAssertEqual(fetched.pubkey, pubkey)
        XCTAssertEqual(fetched.pubkeyHex.count, 66) // 33 bytes → 66 hex chars
    }

    func testKeysStoreRejectsMismatchedFid() throws {
        let (a, _, _) = try makeTwoIdentities()
        let store = try KeysStore(a)

        let privkey = Data(repeating: 0x77, count: 32)
        let pubkey = try Secp256k1.publicKey(fromPrivateKey: privkey)

        XCTAssertThrowsError(
            try store.upsert(PubkeyRecord(fid: "FNotTheRightFid", pubkey: pubkey))
        ) { error in
            guard case KeysStore.Failure.fidPubkeyMismatch = error else {
                XCTFail("expected fidPubkeyMismatch, got \(error)"); return
            }
        }
    }

    func testKeysStoreRejectsBadPubkeyLength() throws {
        let (a, _, _) = try makeTwoIdentities()
        let store = try KeysStore(a)
        XCTAssertThrowsError(
            try store.upsert(PubkeyRecord(fid: "FAnything", pubkey: Data(repeating: 0x02, count: 32)))
        ) { error in
            guard case KeysStore.Failure.invalidPubkeyLength(32) = error else {
                XCTFail("expected invalidPubkeyLength(32), got \(error)"); return
            }
        }
    }

    func testKeysStoreSurvivesLogout() throws {
        // Persist via identity A, lock A, reopen via login → cache still readable.
        let vault = try IdentityVault(baseDirectory: baseDir)
        let a = try vault.register(passphrase: "secret", displayName: "A", scheme: .legacySha256)
        let aFid = a.fid

        let privkey = Data(repeating: 0x33, count: 32)
        let peerPubkey = try Secp256k1.publicKey(fromPrivateKey: privkey)
        let peerFid = try FchAddress(publicKey: peerPubkey).fid

        try KeysStore(a).upsert(PubkeyRecord(fid: peerFid, pubkey: peerPubkey, nickname: "peer"))
        a.lock()

        let a2 = try IdentityVault(baseDirectory: baseDir).login(fid: aFid, passphrase: "secret")
        let restored = try XCTUnwrap(try KeysStore(a2).record(forFid: peerFid))
        XCTAssertEqual(restored.pubkey, peerPubkey)
        XCTAssertEqual(restored.nickname, "peer")
    }
}
