import Foundation
import FCCore
import FCStorage

/// Top-level lifecycle service for identities on this Mac. Owns the
/// plaintext index and the per-identity directory layout.
///
/// Filesystem layout under `baseDirectory` (defaults to
/// `~/Library/Application Support/fc.freer.mac`):
///
/// ```
/// baseDirectory/
/// ├── identities.json                  # IdentityIndex (no secrets)
/// └── identities/
///     └── <fid>/
///         └── store.sqlite             # EncryptedKVStore for that fid
/// ```
///
/// **No vault keys are stored on disk or in Keychain.** Each identity's
/// vault key is derived at login time via:
///
/// ```
/// vaultKey = HKDF-SHA256(
///     ikm:  privkey,
///     salt: "fc.freer.vault.v1",
///     info: "fc.freer.vault",
///     L:    32
/// )
/// ```
///
/// Losing the passphrase is therefore unrecoverable — the data on disk
/// is meaningless without it. That is the desired property: a stolen
/// laptop reveals nothing without the passphrase.
public final class IdentityVault {

    public enum Failure: Error, CustomStringConvertible {
        case alreadyRegistered(fid: String)
        case notRegistered(fid: String)
        case wrongPassphrase
        case derivedKeyInvalid
        case storeOpenFailed(Error)
        case io(Error)

        public var description: String {
            switch self {
            case .alreadyRegistered(let fid):
                return "IdentityVault: identity \(fid) is already registered"
            case .notRegistered(let fid):
                return "IdentityVault: no identity registered with FID \(fid)"
            case .wrongPassphrase:
                return "IdentityVault: passphrase did not derive the registered FID"
            case .derivedKeyInvalid:
                return "IdentityVault: derived scalar is not a valid secp256k1 private key"
            case .storeOpenFailed(let e):
                return "IdentityVault: failed to open encrypted store — \(e)"
            case .io(let e):
                return "IdentityVault: filesystem error — \(e)"
            }
        }
    }

    private static let vaultKeyHkdfSalt = Data("fc.freer.vault.v1".utf8)
    private static let vaultKeyHkdfInfo = Data("fc.freer.vault".utf8)

    public let baseDirectory: URL
    private let indexStore: IdentityIndexStore

    public convenience init() throws {
        try self.init(baseDirectory: IdentityVault.defaultBaseDirectory())
    }

    public init(baseDirectory: URL) throws {
        self.baseDirectory = baseDirectory
        self.indexStore = IdentityIndexStore(
            url: baseDirectory.appendingPathComponent("identities.json")
        )
        do {
            try FileManager.default.createDirectory(
                at: baseDirectory.appendingPathComponent("identities"),
                withIntermediateDirectories: true
            )
        } catch {
            throw Failure.io(error)
        }
    }

    // MARK: - read

    public func listIdentities() throws -> [IdentityRecord] {
        try indexStore.load().identities
    }

    public func record(forFid fid: String) throws -> IdentityRecord? {
        try indexStore.load().find(fid: fid)
    }

    // MARK: - register

    /// Mint a new identity from a passphrase. The privkey is derived,
    /// the FID is computed, the index is updated, and a fresh
    /// ``Identity`` is returned already unlocked.
    @discardableResult
    public func register(
        passphrase: String,
        displayName: String,
        scheme: PhraseKey.Scheme = .argon2id
    ) throws -> Identity {
        let (privkey, pubkey, fid) = try Self.deriveKeyMaterial(passphrase: passphrase, scheme: scheme)

        var index = try indexStore.load()
        if index.find(fid: fid) != nil {
            throw Failure.alreadyRegistered(fid: fid)
        }

        let record = IdentityRecord(
            fid: fid, displayName: displayName, phraseScheme: scheme
        )
        let kv = try openStore(forFid: fid, privkey: privkey)
        index.upsert(record)
        try indexStore.save(index)

        return Identity(record: record, pubkey: pubkey, privkey: privkey, kv: kv)
    }

    // MARK: - login

    /// Verify a passphrase against a registered identity and return an
    /// unlocked ``Identity``. Selecting a non-matching `(fid,passphrase)`
    /// pair produces ``Failure/wrongPassphrase`` without leaking timing
    /// or content of the stored data.
    public func login(fid: String, passphrase: String) throws -> Identity {
        guard let record = try indexStore.load().find(fid: fid) else {
            throw Failure.notRegistered(fid: fid)
        }
        let (privkey, pubkey, derivedFid) = try Self.deriveKeyMaterial(
            passphrase: passphrase, scheme: record.phraseScheme
        )
        guard derivedFid == record.fid else {
            throw Failure.wrongPassphrase
        }
        let kv = try openStore(forFid: fid, privkey: privkey)
        return Identity(record: record, pubkey: pubkey, privkey: privkey, kv: kv)
    }

    // MARK: - delete

    /// Remove an identity from the index AND delete its on-disk store.
    /// Returns true if something was actually removed.
    @discardableResult
    public func delete(fid: String) throws -> Bool {
        var index = try indexStore.load()
        guard index.remove(fid: fid) else { return false }
        try indexStore.save(index)

        let dir = identityDirectory(for: fid)
        if FileManager.default.fileExists(atPath: dir.path) {
            do {
                try FileManager.default.removeItem(at: dir)
            } catch {
                throw Failure.io(error)
            }
        }
        return true
    }

    // MARK: - paths

    public static func defaultBaseDirectory() -> URL {
        let appSupport = FileManager.default
            .urls(for: .applicationSupportDirectory, in: .userDomainMask)
            .first ?? FileManager.default.temporaryDirectory
        return appSupport.appendingPathComponent("fc.freer.mac", isDirectory: true)
    }

    private func identityDirectory(for fid: String) -> URL {
        baseDirectory
            .appendingPathComponent("identities", isDirectory: true)
            .appendingPathComponent(fid, isDirectory: true)
    }

    // MARK: - helpers

    private func openStore(forFid fid: String, privkey: Data) throws -> EncryptedKVStore {
        let dir = identityDirectory(for: fid)
        do {
            try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        } catch {
            throw Failure.io(error)
        }
        let dbPath = dir.appendingPathComponent("store.sqlite").path
        let vaultKey = Self.deriveVaultKey(fromPrivkey: privkey)
        do {
            return try EncryptedKVStore(databasePath: dbPath, vaultKey: vaultKey)
        } catch {
            throw Failure.storeOpenFailed(error)
        }
    }

    static func deriveVaultKey(fromPrivkey privkey: Data) -> Data {
        Hkdf.sha256(
            ikm: privkey,
            salt: vaultKeyHkdfSalt,
            info: vaultKeyHkdfInfo,
            outputLength: 32
        )
    }

    private static func deriveKeyMaterial(
        passphrase: String,
        scheme: PhraseKey.Scheme
    ) throws -> (privkey: Data, pubkey: Data, fid: String) {
        let privkey = try PhraseKey.privateKey(fromPhrase: passphrase, scheme: scheme)
        let pubkey: Data
        do {
            pubkey = try Secp256k1.publicKey(fromPrivateKey: privkey)
        } catch {
            throw Failure.derivedKeyInvalid
        }
        let fid = try FchAddress(publicKey: pubkey).fid
        return (privkey, pubkey, fid)
    }
}
