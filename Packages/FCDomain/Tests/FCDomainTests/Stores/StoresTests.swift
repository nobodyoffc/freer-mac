import XCTest
import FCCore
import FCTransport
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

    /// Two ActiveSessions under the same Configure (so the symkey is
    /// shared but the per-main HKDF derivation gives them distinct
    /// vault keys → per-main row isolation). Used to verify
    /// cross-identity isolation: writes via `a` must not be visible
    /// via `b`.
    private func makeTwoSessions() throws -> (ActiveSession, ActiveSession) {
        let mgr = try ConfigureManager(baseDirectory: baseDir)
        let configure = try mgr.createConfigure(
            password: Data("shared-pwd".utf8), kdfKind: .legacySha256
        )
        let aPriv = Data(repeating: 0xA1, count: 32)
        let bPriv = Data(repeating: 0xB2, count: 32)
        let aInfo = try configure.addMain(privkey: aPriv, label: "A")
        let bInfo = try configure.addMain(privkey: bPriv, label: "B")
        let a = try configure.unlockMain(fid: aInfo.fid, fapi: MockFapiClient())
        let b = try configure.unlockMain(fid: bInfo.fid, fapi: MockFapiClient())
        return (a, b)
    }

    // MARK: - Preferences

    func testPreferencesRoundTripAndDefaults() throws {
        let (a, _) = try makeTwoSessions()
        let store = a.preferences

        // First read on a fresh main returns defaults.
        let blank = try store.load()
        XCTAssertEqual(blank, Preferences.defaults)

        try store.save(Preferences(
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

    func testPreferencesUpdateClosure() throws {
        let (a, _) = try makeTwoSessions()
        let store = a.preferences
        try store.save(Preferences(autoLockSeconds: 300))
        let result = try store.update { $0.autoLockSeconds = 900 }
        XCTAssertEqual(result.autoLockSeconds, 900)
        XCTAssertEqual(try store.load().autoLockSeconds, 900)
    }

    func testPreferencesAreIsolatedPerMain() throws {
        let (a, b) = try makeTwoSessions()
        try a.preferences.save(Preferences(theme: .dark))
        // B's per-main store has a distinct HKDF-derived key → distinct
        // sqlite namespace → defaults for B.
        XCTAssertEqual(try b.preferences.load(), Preferences.defaults)
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
        let (a, _) = try makeTwoSessions()
        let store = a.contacts

        let f1 = try realFid(byte: 0xC1)
        let f2 = try realFid(byte: 0xC2)
        let f3 = try realFid(byte: 0xC3)

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

    func testContactsAreIsolatedPerMain() throws {
        let (a, b) = try makeTwoSessions()
        try a.contacts.upsert(Contact(fid: try realFid(byte: 0xD0), nickname: "alice"))
        XCTAssertEqual(try b.contacts.all().count, 0)
    }

    func testContactsRejectsInvalidFid() throws {
        let (a, _) = try makeTwoSessions()
        let store = a.contacts
        XCTAssertThrowsError(try store.upsert(Contact(fid: "not-a-fid", nickname: "x"))) { error in
            guard case ContactsStore.Failure.invalidFid = error else {
                XCTFail("expected invalidFid, got \(error)"); return
            }
        }
        XCTAssertThrowsError(try store.upsert(Contact(fid: "", nickname: "x")))
    }

    // MARK: - KeysStore (validation matters here)

    func testKeysStoreValidatesFidAgainstPubkey() throws {
        let (a, _) = try makeTwoSessions()
        let store = a.keys

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
        let (a, _) = try makeTwoSessions()
        let store = a.keys

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
        let (a, _) = try makeTwoSessions()
        let store = a.keys
        XCTAssertThrowsError(
            try store.upsert(PubkeyRecord(fid: "FAnything", pubkey: Data(repeating: 0x02, count: 32)))
        ) { error in
            guard case KeysStore.Failure.invalidPubkeyLength(32) = error else {
                XCTFail("expected invalidPubkeyLength(32), got \(error)"); return
            }
        }
    }

    func testKeysStoreSurvivesLogout() throws {
        // Persist via configure A unlocked, lock + reopen + unlock-main again,
        // expect cached pubkey to still be readable.
        let mgr = try ConfigureManager(baseDirectory: baseDir)
        let configure = try mgr.createConfigure(
            password: Data("logout-secret".utf8), kdfKind: .legacySha256
        )
        let aPriv = Data(repeating: 0xEE, count: 32)
        let aMain = try configure.addMain(privkey: aPriv, label: "A")
        let a = try configure.unlockMain(fid: aMain.fid, fapi: MockFapiClient())

        let peerPriv = Data(repeating: 0x33, count: 32)
        let peerPub  = try Secp256k1.publicKey(fromPrivateKey: peerPriv)
        let peerFid  = try FchAddress(publicKey: peerPub).fid

        try a.keys.upsert(PubkeyRecord(fid: peerFid, pubkey: peerPub, nickname: "peer"))

        // Lock the configure → re-open via fresh manager → re-unlock main.
        configure.lock()
        let mgr2 = try ConfigureManager(baseDirectory: baseDir)
        let cfg2 = try mgr2.openConfigure(
            passwordName: configure.passwordName, password: Data("logout-secret".utf8)
        )
        let a2 = try cfg2.unlockMain(fid: aMain.fid, fapi: MockFapiClient())

        let restored = try XCTUnwrap(try a2.keys.record(forFid: peerFid))
        XCTAssertEqual(restored.pubkey, peerPub)
        XCTAssertEqual(restored.nickname, "peer")
    }
}
