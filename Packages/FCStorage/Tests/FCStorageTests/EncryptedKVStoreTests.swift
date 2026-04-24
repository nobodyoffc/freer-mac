import XCTest
import GRDB
@testable import FCStorage

final class EncryptedKVStoreTests: XCTestCase {

    private struct Sample: Codable, Equatable {
        let name: String
        let count: Int
        let tags: [String]
    }

    private var dbURL: URL!
    private var keychainService = ""
    private let keychainAccount = "vault"

    override func setUpWithError() throws {
        keychainService = "cash.freer.mac.test.\(UUID().uuidString)"
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("EncryptedKVStoreTests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        dbURL = dir.appendingPathComponent("test.sqlite")
    }

    override func tearDownWithError() throws {
        _ = try? Keychain.delete(service: keychainService, account: keychainAccount)
        if let dbURL { try? FileManager.default.removeItem(at: dbURL.deletingLastPathComponent()) }
    }

    private func makeStore() throws -> EncryptedKVStore {
        try EncryptedKVStore(
            databasePath: dbURL.path,
            keychainService: keychainService,
            keychainAccount: keychainAccount
        )
    }

    func testPutAndGet() throws {
        let store = try makeStore()
        let value = Sample(name: "alice", count: 42, tags: ["vip"])
        try store.put(value, namespace: "contacts", key: "alice")
        let read = try store.get(Sample.self, namespace: "contacts", key: "alice")
        XCTAssertEqual(read, value)
    }

    func testGetMissingReturnsNil() throws {
        let store = try makeStore()
        let read = try store.get(Sample.self, namespace: "contacts", key: "does-not-exist")
        XCTAssertNil(read)
    }

    func testPutOverwritesExisting() throws {
        let store = try makeStore()
        try store.put(Sample(name: "v1", count: 1, tags: []), namespace: "x", key: "k")
        try store.put(Sample(name: "v2", count: 2, tags: ["a"]), namespace: "x", key: "k")
        let read = try store.get(Sample.self, namespace: "x", key: "k")
        XCTAssertEqual(read?.name, "v2")
    }

    func testDelete() throws {
        let store = try makeStore()
        try store.put(Sample(name: "tmp", count: 0, tags: []), namespace: "x", key: "k")
        try store.delete(namespace: "x", key: "k")
        XCTAssertNil(try store.get(Sample.self, namespace: "x", key: "k"))
        XCTAssertFalse(try store.exists(namespace: "x", key: "k"))
    }

    func testListKeys() throws {
        let store = try makeStore()
        try store.put(Sample(name: "a", count: 0, tags: []), namespace: "ns1", key: "alpha")
        try store.put(Sample(name: "b", count: 0, tags: []), namespace: "ns1", key: "beta")
        try store.put(Sample(name: "c", count: 0, tags: []), namespace: "ns2", key: "gamma")
        XCTAssertEqual(try store.listKeys(namespace: "ns1"), ["alpha", "beta"])
        XCTAssertEqual(try store.listKeys(namespace: "ns2"), ["gamma"])
        XCTAssertEqual(try store.listKeys(namespace: "empty"), [])
    }

    func testNamespaceIsolation() throws {
        let store = try makeStore()
        try store.put(Sample(name: "in-ns1", count: 1, tags: []), namespace: "ns1", key: "k")
        try store.put(Sample(name: "in-ns2", count: 2, tags: []), namespace: "ns2", key: "k")
        XCTAssertEqual(try store.get(Sample.self, namespace: "ns1", key: "k")?.name, "in-ns1")
        XCTAssertEqual(try store.get(Sample.self, namespace: "ns2", key: "k")?.name, "in-ns2")
    }

    /// The value stored as BLOB in SQLite must *not* contain the plaintext —
    /// guards against accidentally forgetting to encrypt.
    func testStoredBlobIsEncrypted() throws {
        let store = try makeStore()
        let value = Sample(name: "UNIQUE_MARKER_9f3c", count: 1, tags: ["secret"])
        try store.put(value, namespace: "x", key: "k")

        let raw = try readRawBlob(namespace: "x", key: "k")
        let rawAsString = String(data: raw, encoding: .utf8) ?? ""
        XCTAssertFalse(rawAsString.contains("UNIQUE_MARKER_9f3c"),
                       "raw blob should not contain plaintext marker")
        // nonce(12) + at-least-1-byte ciphertext + tag(16) = 29+
        XCTAssertGreaterThanOrEqual(raw.count, 29)
    }

    /// Closing and reopening the store (fresh instance, same Keychain
    /// service) must read back everything that was written. This is the
    /// core "persistence" check — confirms the vault key is recovered
    /// from Keychain on second open, not regenerated.
    func testPersistsAcrossReopen() throws {
        do {
            let store = try makeStore()
            try store.put(Sample(name: "persisted", count: 99, tags: ["p"]),
                          namespace: "x", key: "k")
        }
        let reopened = try makeStore()
        let read = try reopened.get(Sample.self, namespace: "x", key: "k")
        XCTAssertEqual(read?.name, "persisted")
        XCTAssertEqual(read?.count, 99)
    }

    /// Opening the same DB path with a *different* Keychain account
    /// (different vault key) must fail to decrypt rows written by the
    /// previous vault — not silently succeed with garbage.
    func testWrongVaultKeyFailsDecryption() throws {
        do {
            let store = try makeStore()
            try store.put(Sample(name: "v", count: 1, tags: []), namespace: "x", key: "k")
        }
        // Delete the original vault key so a new one will be generated on
        // the next open.
        _ = try Keychain.delete(service: keychainService, account: keychainAccount)

        let freshVaultStore = try makeStore()
        XCTAssertThrowsError(
            try freshVaultStore.get(Sample.self, namespace: "x", key: "k")
        ) { error in
            guard case EncryptedKVStore.Failure.decryptionFailed = error else {
                XCTFail("expected decryptionFailed, got \(error)"); return
            }
        }
    }

    /// Each put must use a fresh random nonce — two puts of the same
    /// value should produce *different* ciphertexts.
    func testNoncesAreFreshPerPut() throws {
        let store = try makeStore()
        let value = Sample(name: "same", count: 1, tags: ["same"])

        try store.put(value, namespace: "x", key: "k1")
        let blob1 = try readRawBlob(namespace: "x", key: "k1")

        try store.put(value, namespace: "x", key: "k2")
        let blob2 = try readRawBlob(namespace: "x", key: "k2")

        XCTAssertNotEqual(blob1, blob2, "same value should encrypt differently under fresh nonces")
    }

    // MARK: - raw-blob read (bypasses decryption)

    private func readRawBlob(namespace: String, key: String) throws -> Data {
        // Open a parallel GRDB queue just to read the raw bytes; bypasses
        // our store's decrypt step on purpose.
        let db = try DatabaseQueue(path: dbURL.path)
        return try db.read { dbConn in
            try Data.fetchOne(
                dbConn,
                sql: "SELECT ciphertext FROM kv WHERE namespace = ? AND key = ?",
                arguments: [namespace, key]
            )!
        }
    }
}
