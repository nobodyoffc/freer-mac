import Foundation
import FCCore
import FCStorage
import FCTransport

/// One unlocked main FID inside one unlocked Configure. The runtime
/// container that the SwiftUI app shell holds while the user is
/// "logged in." Owns:
///
///   - a back-reference to its parent ``ConfigureSession``
///   - the per-main ``Setting`` (decrypted, in-memory, mutated and
///     re-persisted on every change)
///   - a per-main ``EncryptedKVStore`` for fast-changing cached state
///     (UTXO snapshots, contacts, message logs)
///   - the `liveFid` — what FID the user is *currently operating as*,
///     which may be the main itself or any of its sub-identities
///     (watch-only / multisig / servant) registered in
///     ``Setting/keyInfoMap``.
///
/// **Switching live FID.** Calling ``switchLive(fid:)`` changes which
/// FID the wallet/contact/etc. services act as — without re-auth, no
/// network round-trip. Operations that need a privkey check
/// ``canSign`` first; for watch-only entries the wallet exposes a
/// `buildUnsignedTxInfo` path instead (Phase 8).
public final class ActiveSession {

    public enum Failure: Error, CustomStringConvertible {
        case unknownLive(fid: String)
        case watchOnlyCannotSign(fid: String)
        case underlying(Error)

        public var description: String {
            switch self {
            case .unknownLive(let fid):
                return "ActiveSession: \(fid) is not registered in this Setting"
            case .watchOnlyCannotSign(let fid):
                return "ActiveSession: \(fid) is watch-only — cannot sign or decrypt"
            case .underlying(let err):
                return "ActiveSession: \(err)"
            }
        }
    }

    public let configureSession: ConfigureSession
    public let mainFid: String
    public private(set) var setting: Setting
    public private(set) var liveFid: String

    public let storage: EncryptedKVStore
    /// The FAPI client used by ``wallet`` and any other domain
    /// service that talks to a server. Mutable so the app shell can
    /// swap a stub for a real `FapiClient` after the user configures
    /// the FAPI server in Settings, without rebuilding the whole
    /// session.
    public private(set) var fapi: any FapiCalling

    private let settingUrl: URL

    init(
        configureSession: ConfigureSession,
        mainFid: String,
        setting: Setting,
        settingUrl: URL,
        storage: EncryptedKVStore,
        fapi: any FapiCalling
    ) {
        self.configureSession = configureSession
        self.mainFid = mainFid
        self.setting = setting
        self.liveFid = mainFid
        self.settingUrl = settingUrl
        self.storage = storage
        self.fapi = fapi
    }

    // MARK: - identity views

    /// The KeyInfo for whatever FID the user is currently operating
    /// as (defaults to the main FID).
    public var liveKeyInfo: KeyInfo {
        // Setting.keyInfoMap is guaranteed to contain at least the
        // main entry (added at session-creation time). If liveFid is
        // ever set to something not in the map, switchLive(fid:)
        // refuses — so this force-unwrap is sound.
        setting.keyInfoMap[liveFid] ?? setting.keyInfoMap[mainFid]!
    }

    public var mainKeyInfo: KeyInfo { setting.keyInfoMap[mainFid]! }

    /// Whether the live FID can sign/decrypt. Watch-only entries
    /// return false; the UI should show "cold-sign export" affordances
    /// instead of the normal send button.
    public var canSign: Bool { liveKeyInfo.hasPrivkey && liveKeyInfo.kind.canSign }

    public func switchLive(fid: String) throws {
        guard setting.keyInfoMap[fid] != nil else {
            throw Failure.unknownLive(fid: fid)
        }
        liveFid = fid
    }

    // MARK: - prikey

    /// The 32-byte privkey for the **main** FID. Always available
    /// while the session is unlocked (the main always has a privkey).
    public func mainPrikey() throws -> Data {
        try configureSession.privkeyForMain(fid: mainFid)
    }

    /// The 32-byte privkey for the **live** FID. Throws for watch-only
    /// entries — callers handle that as the cold-sign path.
    public func livePrikey() throws -> Data {
        let info = liveKeyInfo
        guard info.hasPrivkey else { throw Failure.watchOnlyCannotSign(fid: info.fid) }
        do {
            let symkey = try configureSession.symkey()
            return try info.decryptPrikey(symkey: symkey)
        } catch let e as ConfigureSession.Failure {
            throw Failure.underlying(e)
        } catch {
            throw Failure.underlying(error)
        }
    }

    // MARK: - sub-identities

    /// Add a watch-only sub-identity (just an FID we want to track,
    /// no privkey). Phase 5.7 handles `.watched`; the other kinds
    /// (multisig / servant) follow the same shape but need their own
    /// signing UI and are deferred.
    @discardableResult
    public func addWatchedFid(
        _ fid: String,
        label: String = "",
        master: String? = nil
    ) throws -> KeyInfo {
        let info = KeyInfo(
            fid: fid,
            pubkey: nil,
            prikeyCipher: nil,
            label: label,
            kind: .watched,
            master: master
        )
        setting.keyInfoMap[fid] = info
        try saveSetting()
        return info
    }

    @discardableResult
    public func removeSubIdentity(fid: String) throws -> Bool {
        guard fid != mainFid else { return false }   // never remove the main
        guard setting.keyInfoMap.removeValue(forKey: fid) != nil else {
            return false
        }
        if liveFid == fid { liveFid = mainFid }
        try saveSetting()
        return true
    }

    // MARK: - persistence

    /// Re-encrypt and write the Setting body file. Called automatically
    /// after any mutation; exposed for callers who batch changes.
    public func saveSetting() throws {
        let symkey: Data
        do {
            symkey = try configureSession.symkey()
        } catch {
            throw Failure.underlying(error)
        }
        do {
            try EncryptedFile.write(setting, to: settingUrl, key: symkey)
        } catch {
            throw Failure.underlying(error)
        }
    }

    // MARK: - lazy domain services

    public lazy var preferences: PreferencesStore = PreferencesStore(kv: storage)
    public lazy var contacts: ContactsStore = ContactsStore(kv: storage)
    public lazy var keys: KeysStore        = KeysStore(kv: storage)
    public lazy var utxos: UtxosStore      = UtxosStore(kv: storage)

    /// Computed (not lazy) so ``setFapi(_:)`` is picked up the next
    /// time something asks for the wallet. WalletService is a struct;
    /// constructing it is essentially a Foundation pointer copy.
    public var wallet: WalletService { WalletService(fapi: fapi, utxos: utxos) }

    // MARK: - mutating fapi

    /// Replace the active FAPI client. Used by the app shell after
    /// the user saves new server settings — the previous client (and
    /// its underlying transport) is released and the next call to
    /// `wallet`/`fapi` uses the new one. The caller is responsible
    /// for closing the *previous* transport if it owns one (the
    /// `ActiveSession` is type-erased to `FapiCalling` and can't
    /// know how to tear it down).
    public func setFapi(_ client: any FapiCalling) {
        self.fapi = client
    }

    // MARK: - send convenience

    /// Send from the **live** FID. Throws for watch-only —
    /// callers should fall back to a cold-sign builder (Phase 8).
    @discardableResult
    public func sendFromLive(
        to toFid: String,
        amount: Int64,
        feePerByte: Int64 = 1,
        useCache: Bool = false,
        timeoutMs: Int = 10_000
    ) async throws -> WalletService.SendResult {
        let priv = try livePrikey()
        return try await wallet.send(
            fromAddress: liveFid, privkey: priv,
            to: toFid, amount: amount,
            feePerByte: feePerByte,
            useCache: useCache,
            timeoutMs: timeoutMs
        )
    }
}
