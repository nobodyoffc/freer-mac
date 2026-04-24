import Foundation
import Security
import GRDB
import FCCore

/// Row-level AES-256-GCM encrypted key-value store backed by SQLite.
///
/// Design:
/// - Single `kv` table keyed by `(namespace, key)`. Values are `Codable`
///   and serialized through `JSONEncoder/JSONDecoder`.
/// - Each row's plaintext is encrypted with AES-GCM using a shared
///   32-byte **vault key** that lives in the Keychain. The vault key is
///   generated on first open and never leaves the Keychain otherwise.
/// - Wire format in the blob: `nonce(12) || ciphertext || tag(16)`.
/// - AAD = UTF-8(`"<namespace>:<key>"`), binding the ciphertext to its
///   storage location so an attacker who moves a row to a different key
///   breaks auth.
///
/// We don't use SQLCipher. Row-level AEAD is cleaner than bolting a
/// second cipher on top of the DB file, uses primitives we already have
/// in FCCore, and integrates with macOS Keychain natively.
public final class EncryptedKVStore {

    public enum Failure: Error, CustomStringConvertible {
        case blobTooShort(got: Int)
        case decryptionFailed
        case randomBytesUnavailable(OSStatus)
        case vaultKeyWrongSize(got: Int)
        case underlying(Error)

        public var description: String {
            switch self {
            case let .blobTooShort(got):
                return "EncryptedKVStore: stored blob is \(got) bytes, need at least 28"
            case .decryptionFailed:
                return "EncryptedKVStore: decryption failed (tampered or wrong vault key)"
            case let .randomBytesUnavailable(code):
                return "EncryptedKVStore: SecRandomCopyBytes failed (\(code))"
            case let .vaultKeyWrongSize(got):
                return "EncryptedKVStore: vault key must be 32 bytes, got \(got)"
            case let .underlying(error):
                return "EncryptedKVStore: \(error)"
            }
        }
    }

    private static let nonceLength = 12
    private static let tagLength = 16

    private let dbQueue: DatabaseQueue
    private let vaultKey: Data

    /// Open a store at `databasePath`. If the Keychain has no vault key
    /// at `(keychainService, keychainAccount)`, one is generated and
    /// written transparently. The DB schema is created on first open.
    public init(
        databasePath: String,
        keychainService: String,
        keychainAccount: String
    ) throws {
        self.vaultKey = try EncryptedKVStore.loadOrCreateVaultKey(
            service: keychainService,
            account: keychainAccount
        )
        do {
            self.dbQueue = try DatabaseQueue(path: databasePath)
        } catch {
            throw Failure.underlying(error)
        }
        do {
            try dbQueue.write { db in
                try db.execute(sql: """
                    CREATE TABLE IF NOT EXISTS kv (
                        namespace TEXT NOT NULL,
                        key       TEXT NOT NULL,
                        ciphertext BLOB NOT NULL,
                        PRIMARY KEY (namespace, key)
                    ) WITHOUT ROWID
                    """)
            }
        } catch {
            throw Failure.underlying(error)
        }
    }

    // MARK: - API

    public func put<T: Encodable>(_ value: T, namespace: String, key: String) throws {
        let plaintext = try JSONEncoder().encode(value)
        let blob = try encrypt(plaintext: plaintext, namespace: namespace, key: key)
        do {
            try dbQueue.write { db in
                try db.execute(
                    sql: "INSERT OR REPLACE INTO kv (namespace, key, ciphertext) VALUES (?, ?, ?)",
                    arguments: [namespace, key, blob]
                )
            }
        } catch {
            throw Failure.underlying(error)
        }
    }

    public func get<T: Decodable>(_ type: T.Type, namespace: String, key: String) throws -> T? {
        let blob: Data?
        do {
            blob = try dbQueue.read { db -> Data? in
                try Data.fetchOne(
                    db,
                    sql: "SELECT ciphertext FROM kv WHERE namespace = ? AND key = ?",
                    arguments: [namespace, key]
                )
            }
        } catch {
            throw Failure.underlying(error)
        }
        guard let blob else { return nil }
        let plaintext = try decrypt(blob: blob, namespace: namespace, key: key)
        return try JSONDecoder().decode(type, from: plaintext)
    }

    public func delete(namespace: String, key: String) throws {
        do {
            try dbQueue.write { db in
                try db.execute(
                    sql: "DELETE FROM kv WHERE namespace = ? AND key = ?",
                    arguments: [namespace, key]
                )
            }
        } catch {
            throw Failure.underlying(error)
        }
    }

    public func exists(namespace: String, key: String) throws -> Bool {
        do {
            return try dbQueue.read { db in
                try Int.fetchOne(
                    db,
                    sql: "SELECT 1 FROM kv WHERE namespace = ? AND key = ?",
                    arguments: [namespace, key]
                ) != nil
            }
        } catch {
            throw Failure.underlying(error)
        }
    }

    public func listKeys(namespace: String) throws -> [String] {
        do {
            return try dbQueue.read { db in
                try String.fetchAll(
                    db,
                    sql: "SELECT key FROM kv WHERE namespace = ? ORDER BY key",
                    arguments: [namespace]
                )
            }
        } catch {
            throw Failure.underlying(error)
        }
    }

    // MARK: - encryption

    private func encrypt(plaintext: Data, namespace: String, key: String) throws -> Data {
        let nonce = try EncryptedKVStore.randomBytes(count: EncryptedKVStore.nonceLength)
        let aad = EncryptedKVStore.aad(namespace: namespace, key: key)
        let sealed = try AesGcm256.seal(
            key: vaultKey, nonce: nonce, plaintext: plaintext, aad: aad
        )
        var blob = Data(capacity: nonce.count + sealed.ciphertext.count + sealed.tag.count)
        blob.append(nonce)
        blob.append(sealed.ciphertext)
        blob.append(sealed.tag)
        return blob
    }

    private func decrypt(blob: Data, namespace: String, key: String) throws -> Data {
        let bytes = [UInt8](blob)
        let minLength = EncryptedKVStore.nonceLength + EncryptedKVStore.tagLength
        guard bytes.count >= minLength else {
            throw Failure.blobTooShort(got: bytes.count)
        }
        let nonce = Data(bytes[0..<EncryptedKVStore.nonceLength])
        let tag = Data(bytes[(bytes.count - EncryptedKVStore.tagLength)..<bytes.count])
        let ciphertext = Data(bytes[EncryptedKVStore.nonceLength..<(bytes.count - EncryptedKVStore.tagLength)])
        let aad = EncryptedKVStore.aad(namespace: namespace, key: key)
        do {
            return try AesGcm256.open(
                key: vaultKey, nonce: nonce,
                ciphertext: ciphertext, tag: tag, aad: aad
            )
        } catch {
            throw Failure.decryptionFailed
        }
    }

    private static func aad(namespace: String, key: String) -> Data {
        Data("\(namespace):\(key)".utf8)
    }

    // MARK: - vault key

    private static func loadOrCreateVaultKey(service: String, account: String) throws -> Data {
        do {
            let existing = try Keychain.get(service: service, account: account)
            guard existing.count == 32 else {
                throw Failure.vaultKeyWrongSize(got: existing.count)
            }
            return existing
        } catch Keychain.Failure.itemNotFound {
            let fresh = try randomBytes(count: 32)
            try Keychain.set(fresh, service: service, account: account)
            return fresh
        } catch let error as Failure {
            throw error
        } catch {
            throw Failure.underlying(error)
        }
    }

    private static func randomBytes(count: Int) throws -> Data {
        var out = Data(count: count)
        let status = out.withUnsafeMutableBytes { ptr -> OSStatus in
            guard let base = ptr.baseAddress else { return errSecAllocate }
            return SecRandomCopyBytes(kSecRandomDefault, count, base)
        }
        guard status == errSecSuccess else {
            throw Failure.randomBytesUnavailable(status)
        }
        return out
    }
}
