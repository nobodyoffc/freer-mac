import Foundation
import FCCore
import FCStorage
import FCTransport

/// One unlocked Configure. Holds the symkey in memory and gives
/// access to the list of main FIDs. Calling ``unlockMain(fid:)``
/// produces an ``ActiveSession`` for one of those FIDs (Phase 5.7c).
///
/// The symkey is *the* secret here — every encrypted privkey, every
/// encrypted body file under this Configure decrypts under it.
/// ``lock()`` zeroizes the buffer in-place; subsequent operations
/// throw ``Failure/locked``.
public final class ConfigureSession {

    public enum Failure: Error, CustomStringConvertible {
        case locked
        case mainNotFound(fid: String)
        case mainAlreadyExists(fid: String)
        case settingBelongsToAnotherMain(expected: String, found: String)
        case underlying(Error)

        public var description: String {
            switch self {
            case .locked:                       return "ConfigureSession: vault is locked"
            case .mainNotFound(let fid):        return "ConfigureSession: no main FID \(fid) in this Configure"
            case .mainAlreadyExists(let fid):   return "ConfigureSession: main FID \(fid) already exists"
            case let .settingBelongsToAnotherMain(expected, found):
                return "ConfigureSession: this setting file belongs to \(found), not \(expected)"
            case .underlying(let err):          return "ConfigureSession: \(err)"
            }
        }
    }

    public let record: ConfigureRecord
    public private(set) var configure: Configure
    public private(set) var isLocked: Bool = false

    /// Held mutable so ``lock()`` can overwrite in-place. Not exposed.
    private var symkeyBuffer: [UInt8]
    private weak var manager: ConfigureManager?

    init(record: ConfigureRecord, configure: Configure, symkey: Data, manager: ConfigureManager) {
        self.record = record
        self.configure = configure
        self.symkeyBuffer = Array(symkey)
        self.manager = manager
    }

    deinit { lockUnchecked() }

    public var passwordName: String { record.passwordName }
    public var label: String { record.label }

    // MARK: - main FID listing

    /// Sorted list of main KeyInfos under this Configure.
    public func listMains() -> [KeyInfo] {
        configure.mainCidInfoMap.values.sorted { $0.fid < $1.fid }
    }

    public func mainKeyInfo(fid: String) -> KeyInfo? {
        configure.mainCidInfoMap[fid]
    }

    // MARK: - add main

    /// Add a main FID by importing a raw 32-byte privkey. Encrypts
    /// the privkey under the symkey, builds a ``KeyInfo``, persists
    /// the updated Configure body, and returns the new ``KeyInfo``.
    @discardableResult
    public func addMain(privkey: Data, label: String = "") throws -> KeyInfo {
        try ensureUnlocked()
        let keyInfo = try KeyInfo.make(
            fromPrivkey: privkey,
            symkey: Data(symkeyBuffer),
            label: label,
            kind: .main
        )
        if configure.mainCidInfoMap[keyInfo.fid] != nil {
            throw Failure.mainAlreadyExists(fid: keyInfo.fid)
        }
        configure.mainCidInfoMap[keyInfo.fid] = keyInfo
        try persistBody()
        return keyInfo
    }

    /// Rename a main FID. Returns false when the FID isn't a main
    /// under this Configure.
    ///
    /// The label is duplicated between here and the main's own
    /// ``Setting`` on purpose: the identity chooser runs before any
    /// Setting is decrypted, so it can only read what the Configure
    /// body holds. ``ActiveSession/setLabel(_:forFid:)`` writes both.
    @discardableResult
    public func setMainLabel(_ label: String, fid: String) throws -> Bool {
        try ensureUnlocked()
        guard var info = configure.mainCidInfoMap[fid] else { return false }
        guard info.label != label else { return true }
        info.label = label
        configure.mainCidInfoMap[fid] = info
        try persistBody()
        return true
    }

    /// Record a main FID's registered CID in the Configure body, so the
    /// identity chooser can show it without decrypting a Setting.
    /// Returns false when the FID isn't a main under this Configure.
    @discardableResult
    public func setMainCid(_ cid: String?, fid: String) throws -> Bool {
        try ensureUnlocked()
        guard var info = configure.mainCidInfoMap[fid] else { return false }
        guard info.cid != cid else { return true }
        info.cid = cid
        configure.mainCidInfoMap[fid] = info
        try persistBody()
        return true
    }

    /// Remove a main FID. The associated Setting directory (if any)
    /// is **not** automatically deleted — call
    /// ``deleteMainAndSetting(fid:)`` if you want both gone.
    @discardableResult
    public func removeMain(fid: String) throws -> Bool {
        try ensureUnlocked()
        guard configure.mainCidInfoMap.removeValue(forKey: fid) != nil else {
            return false
        }
        try persistBody()
        return true
    }

    /// Remove a main FID AND its on-disk Setting directory. Use when
    /// a user "deletes the identity" — they expect the keys gone, the
    /// caches gone, the lot.
    @discardableResult
    public func deleteMainAndSetting(fid: String) throws -> Bool {
        try ensureUnlocked()
        let removed = try removeMain(fid: fid)
        guard let manager else { return removed }
        let dir = manager.settingDirectory(passwordName: record.passwordName, mainFid: fid)
        if FileManager.default.fileExists(atPath: dir.path) {
            do { try FileManager.default.removeItem(at: dir) }
            catch { throw Failure.underlying(error) }
        }
        return removed
    }

    // MARK: - decrypt prikey for a main

    /// Decrypt the privkey for the given main FID. Throws for
    /// watch-only entries or wrong symkey (which shouldn't happen
    /// inside an unlocked session).
    public func privkeyForMain(fid: String) throws -> Data {
        try ensureUnlocked()
        guard let info = configure.mainCidInfoMap[fid] else {
            throw Failure.mainNotFound(fid: fid)
        }
        do {
            return try info.decryptPrikey(symkey: Data(symkeyBuffer))
        } catch {
            throw Failure.underlying(error)
        }
    }

    // MARK: - password

    /// Whether `password` is this vault's password.
    ///
    /// Re-derives the KDF and compares the verification token, so it costs a full
    /// Argon2id run (64 MiB) — call it off the main thread. The point is to make a
    /// backup that a *typo* cannot seal: ``BackupPrikeySheet`` encrypts the privkey
    /// under the password the user types, and if that were allowed to be anything
    /// they would end up holding a cipher nobody can ever open, discovering it on
    /// the day the original key is gone.
    public func verifyPassword(_ password: Data) -> Bool {
        guard !isLocked else { return false }
        guard var derived = ConfigureCrypto.verify(password: password, against: record) else {
            return false
        }
        derived.resetBytes(in: 0 ..< derived.count)
        return true
    }

    // MARK: - lock

    public func lock() { lockUnchecked() }

    private func lockUnchecked() {
        guard !isLocked else { return }
        for i in symkeyBuffer.indices { symkeyBuffer[i] = 0 }
        symkeyBuffer.removeAll(keepingCapacity: false)
        isLocked = true
    }

    private func ensureUnlocked() throws {
        guard !isLocked else { throw Failure.locked }
    }

    // MARK: - persist

    /// Internal hook: re-encrypt and write the Configure body to disk
    /// after a mutation.
    private func persistBody() throws {
        guard let manager else { return }
        try ensureUnlocked()
        do {
            try manager.writeConfigureBody(configure, for: record, symkey: Data(symkeyBuffer))
        } catch {
            throw Failure.underlying(error)
        }
    }

    // MARK: - symkey access for friends

    /// Internal accessor for ``ActiveSession`` so it can
    /// derive per-Setting vault keys without needing to redo Argon2id.
    /// Throws if the session is locked.
    func symkey() throws -> Data {
        try ensureUnlocked()
        return Data(symkeyBuffer)
    }

    // MARK: - unlock a main (→ ActiveSession)

    private static let storeVaultKeySalt = Data("fc.freer.setting.store.v1".utf8)
    private static let storeVaultKeyInfo = Data("fc.freer.setting.store".utf8)

    /// Unlock one main FID under this Configure. Loads (or creates)
    /// its ``Setting`` body, opens the per-main ``EncryptedKVStore``,
    /// and returns an ``ActiveSession`` ready to drive the wallet UI.
    ///
    /// Per-main store key is `HKDF(symkey, salt: "…store.v1", info: fid)`,
    /// scoped to this FID under this Configure — so an attacker who
    /// renamed two mains' sqlite files couldn't make alice's rows
    /// decrypt under bob's key.
    /// The authenticated data binding a setting file to its main FID.
    static func settingAad(fid: String) -> Data {
        Data("setting:v1:\(fid)".utf8)
    }

    /// Read a setting file, accepting one written before the AAD named
    /// the FID and rewriting it under the new binding.
    ///
    /// **The fallback has to stay until existing vaults have opened
    /// once.** Files on disk today authenticate under the filename
    /// alone; refusing them outright would lock every current user out
    /// of their own settings. Reading one under the old AAD is no
    /// weaker than what the file already was, and the rewrite that
    /// follows means each vault pays that cost exactly once. The
    /// `mainFid` check at the call site applies either way, so even the
    /// legacy path rejects a file from the wrong main.
    private func readSetting(at url: URL, symkey: Data, fid: String) throws -> Setting? {
        if let bound = try? EncryptedFile.read(
            Setting.self, from: url, key: symkey, aad: Self.settingAad(fid: fid)
        ) {
            return bound
        }
        guard let legacy = try EncryptedFile.read(Setting.self, from: url, key: symkey) else {
            return nil
        }
        // Re-seal under the FID-bound AAD. A failure here is not fatal:
        // the setting was read, and the next unlock tries again.
        try? EncryptedFile.write(
            legacy, to: url, key: symkey, aad: Self.settingAad(fid: fid)
        )
        return legacy
    }

    public func unlockMain(fid: String, fapi: any FapiCalling) throws -> ActiveSession {
        try ensureUnlocked()
        guard let mainKeyInfo = configure.mainCidInfoMap[fid] else {
            throw Failure.mainNotFound(fid: fid)
        }
        let symkey = Data(symkeyBuffer)

        // Sanity: we must be able to decrypt the prikey. If this throws,
        // the symkey is wrong (which shouldn't happen post-verify).
        _ = try mainKeyInfo.decryptPrikey(symkey: symkey)

        guard let manager else { throw Failure.locked }

        let dir = manager.settingDirectory(passwordName: record.passwordName, mainFid: fid)
        do {
            try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        } catch {
            throw Failure.underlying(error)
        }
        let settingUrl = dir.appendingPathComponent("setting.encrypted.dat")

        // Load or initialise the Setting body.
        //
        // **The ciphertext is bound to this FID.** Every main under one
        // Configure keeps its setting in a file of the same name,
        // encrypted under the same Configure symkey, and the default
        // AAD was that shared filename — so the files differed only by
        // which directory they sat in. Moving one into another main's
        // directory left it cryptographically valid, and the session
        // that opened it went on to force-unwrap `keyInfoMap[mainFid]`
        // for a FID the file has never heard of. Naming the FID in the
        // AAD makes the swap fail to decrypt, and the check below
        // catches a file whose contents disagree with where it lives.
        let setting: Setting
        do {
            if let existing = try readSetting(at: settingUrl, symkey: symkey, fid: fid) {
                guard existing.mainFid == fid else {
                    throw Failure.settingBelongsToAnotherMain(
                        expected: fid, found: existing.mainFid
                    )
                }
                setting = existing
            } else {
                let fresh = Setting(mainFid: fid, keyInfoMap: [fid: mainKeyInfo])
                try EncryptedFile.write(
                    fresh, to: settingUrl, key: symkey, aad: Self.settingAad(fid: fid)
                )
                setting = fresh
            }
        } catch let failure as Failure {
            throw failure
        } catch {
            throw Failure.underlying(error)
        }

        // Per-main store key (HKDF-scoped to the FID).
        let storeKey = Hkdf.sha256(
            ikm: symkey,
            salt: Self.storeVaultKeySalt,
            info: Data(fid.utf8),
            outputLength: 32
        )
        let dbUrl = dir.appendingPathComponent("store.sqlite")
        let kv: EncryptedKVStore
        do {
            kv = try EncryptedKVStore(databasePath: dbUrl.path, vaultKey: storeKey)
        } catch {
            throw Failure.underlying(error)
        }

        return ActiveSession(
            configureSession: self,
            mainFid: fid,
            setting: setting,
            settingUrl: settingUrl,
            storage: kv,
            dataDirectory: dir.appendingPathComponent("data", isDirectory: true),
            fapi: fapi
        )
    }
}
