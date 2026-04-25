import Foundation
import FCTransport

/// Composition root for one active identity. Bundles the unlocked
/// ``Identity`` together with the per-identity stores and the
/// ``WalletService``, so the app shell holds **one** value per
/// active session rather than a half-dozen scattered references.
///
/// **Lazy-initialized stores.** A session that only opens
/// ``settings`` doesn't pay to spin up ``utxos`` or ``wallet``. The
/// stores all share the identity's single ``EncryptedKVStore`` so
/// the cost is one Codable wrapper each — but the lazy keeps cold
/// paths cold.
///
/// **Locking.** Calling ``lock()`` zeroizes the identity's privkey
/// and detaches its store, after which calls into any of the
/// services will throw ``Identity/Failure/locked``. The
/// ``IdentitySession`` itself stays around as a tombstone with
/// `record` and `pubkey` still readable for "you were logged in
/// as Alice" UI strings.
///
/// **Single FAPI client.** Every service that needs network access
/// uses the same ``FapiCalling`` we were constructed with. Building
/// one ``FudpClient``/``FapiClient`` per identity (rather than per
/// call) is what lets the underlying UDP connection stay warm and
/// keeps the AsyTwoWay ECDH cache hot.
public final class IdentitySession {

    public let identity: Identity
    public let fapi: any FapiCalling

    public init(identity: Identity, fapi: any FapiCalling) {
        self.identity = identity
        self.fapi = fapi
    }

    public var fid: String { identity.fid }
    public var displayName: String { identity.displayName }
    public var pubkey: Data { identity.pubkey }
    public var isLocked: Bool { identity.isLocked }

    // MARK: - lazy stores
    //
    // Each computed property uses a backing optional that gets
    // populated on first access. Wrapping with a tiny inline lock
    // would protect against multi-threaded first-touch races but
    // that overhead isn't worth it — these are fundamentally view-
    // model-side accesses and the SwiftUI runtime is single-threaded
    // on the main actor anyway.

    private var _settings: SettingsStore?
    public var settings: SettingsStore {
        get throws {
            if let s = _settings { return s }
            let s = try SettingsStore(identity)
            _settings = s
            return s
        }
    }

    private var _contacts: ContactsStore?
    public var contacts: ContactsStore {
        get throws {
            if let s = _contacts { return s }
            let s = try ContactsStore(identity)
            _contacts = s
            return s
        }
    }

    private var _keys: KeysStore?
    public var keys: KeysStore {
        get throws {
            if let s = _keys { return s }
            let s = try KeysStore(identity)
            _keys = s
            return s
        }
    }

    private var _utxos: UtxosStore?
    public var utxos: UtxosStore {
        get throws {
            if let s = _utxos { return s }
            let s = try UtxosStore(identity)
            _utxos = s
            return s
        }
    }

    private var _wallet: WalletService?
    public var wallet: WalletService {
        get throws {
            if let s = _wallet { return s }
            // WalletService takes the UtxosStore too so refreshUtxos
            // auto-persists. Fetching it here forces the lazy on first
            // wallet access.
            let s = WalletService(fapi: fapi, utxos: try utxos)
            _wallet = s
            return s
        }
    }

    // MARK: - lifecycle

    /// Lock the identity (zeroize privkey, detach store) and drop
    /// the cached store handles so the next access — if any — fails
    /// cleanly via ``Identity/Failure/locked``.
    public func lock() {
        identity.lock()
        _settings = nil
        _contacts = nil
        _keys = nil
        _utxos = nil
        _wallet = nil
    }
}
