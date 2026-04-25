import Foundation
import FCCore
import FCStorage

/// An active identity session. Created by ``IdentityVault/login`` after
/// the passphrase has been verified, and held by the app for as long as
/// the user is "logged in".
///
/// Owns the per-identity ``EncryptedKVStore`` so all storage is scoped
/// to this identity at the type level — there is no global "current
/// store" singleton, the compiler enforces that callers pass an
/// `Identity` to access its data.
///
/// Lifecycle:
/// - ``lock()`` zeroizes the private key buffer and detaches the store.
///   After lock the session is dead — operations on a locked identity
///   throw ``Failure/locked``.
/// - The pubkey and FID stay readable post-lock (they're not secret),
///   so a UI can still show "you were logged in as Alice" after auto-lock.
public final class Identity {

    public enum Failure: Error, CustomStringConvertible {
        case locked
        case storeUnavailable

        public var description: String {
            switch self {
            case .locked:           return "Identity: session is locked — re-login required"
            case .storeUnavailable: return "Identity: encrypted store is no longer available"
            }
        }
    }

    public let record: IdentityRecord
    public let pubkey: Data

    public var fid: String { record.fid }
    public var displayName: String { record.displayName }

    /// Lock state. Read on every privkey/store access; set true exactly
    /// once by ``lock()``.
    public private(set) var isLocked: Bool = false

    /// Backing store for the private key. Held as a mutable byte array
    /// so ``lock()`` can deterministically overwrite the buffer.
    private var privkeyBuffer: [UInt8]
    private var kvStore: EncryptedKVStore?

    public init(record: IdentityRecord, pubkey: Data, privkey: Data, kv: EncryptedKVStore) {
        self.record = record
        self.pubkey = pubkey
        self.privkeyBuffer = Array(privkey)
        self.kvStore = kv
    }

    deinit { lockUnchecked() }

    /// Read the active private key. Throws if the session is locked.
    /// Callers should consume the bytes immediately and not retain them.
    public func privateKey() throws -> Data {
        guard !isLocked else { throw Failure.locked }
        return Data(privkeyBuffer)
    }

    /// The encrypted KV store scoped to this identity.
    public func storage() throws -> EncryptedKVStore {
        guard !isLocked else { throw Failure.locked }
        guard let kvStore else { throw Failure.storeUnavailable }
        return kvStore
    }

    /// Permanently lock this session: overwrite the private key buffer
    /// with zeros, drop the store handle, and refuse further use.
    /// Idempotent — calling twice is fine.
    public func lock() {
        lockUnchecked()
    }

    private func lockUnchecked() {
        guard !isLocked else { return }
        // Overwrite in place. Swift `Data` is COW so this won't reach
        // every historical copy that ever held the secret, but it
        // shortens the window the live buffer is recoverable from a
        // process dump or paged-out memory.
        for i in privkeyBuffer.indices { privkeyBuffer[i] = 0 }
        privkeyBuffer.removeAll(keepingCapacity: false)
        kvStore = nil
        isLocked = true
    }
}
