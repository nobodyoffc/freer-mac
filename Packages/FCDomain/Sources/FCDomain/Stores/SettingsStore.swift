import Foundation
import FCStorage

/// Per-identity user preferences. Stored as one Codable row inside the
/// identity's ``EncryptedKVStore``. Adding a new field is forward-safe:
/// existing rows decode it as `nil` (because every field is Optional)
/// and the next save fills it in.
///
/// Anything that's *secret* (privkeys, passphrases) does NOT go here —
/// the encryption is automatic but the Settings struct is meant to be
/// audit-grade boring. Secrets live in dedicated stores.
public struct Settings: Codable, Equatable, Sendable {

    public var version: Int
    /// Default FAPI service the wallet talks to: `"<host>:<port>"`. The
    /// service's pubkey is in ``preferredFapiServicePubkeyHex`` so we
    /// don't store it here in `Data` (Codable round-trips Data as
    /// base-64 which is annoying to inspect by hand).
    public var preferredFapiService: String?
    public var preferredFapiServicePubkeyHex: String?
    public var theme: Theme?
    public var autoLockSeconds: Int?

    public enum Theme: String, Codable, Sendable, CaseIterable {
        case system
        case light
        case dark
    }

    public init(
        version: Int = 1,
        preferredFapiService: String? = nil,
        preferredFapiServicePubkeyHex: String? = nil,
        theme: Theme? = nil,
        autoLockSeconds: Int? = nil
    ) {
        self.version = version
        self.preferredFapiService = preferredFapiService
        self.preferredFapiServicePubkeyHex = preferredFapiServicePubkeyHex
        self.theme = theme
        self.autoLockSeconds = autoLockSeconds
    }

    public static let defaults = Settings()
}

/// Read/write the per-identity ``Settings`` row. Single-key store
/// (`namespace=settings, key=app`) — the whole struct is one blob, so
/// updates are atomic at the row level.
public struct SettingsStore {

    public static let namespace = "settings"
    public static let key = "app"

    private let inner: TypedStore<Settings>

    public init(_ identity: Identity) throws {
        self.inner = TypedStore(kv: try identity.storage(), namespace: Self.namespace)
    }

    /// Load current settings, or return ``Settings/defaults`` on first read.
    public func load() throws -> Settings {
        try inner.get(Self.key) ?? .defaults
    }

    public func save(_ settings: Settings) throws {
        try inner.put(settings, key: Self.key)
    }

    /// Read-modify-write helper. The mutation runs in-process; if you
    /// expect concurrent writers, serialize them at a higher layer.
    @discardableResult
    public func update(_ mutate: (inout Settings) throws -> Void) throws -> Settings {
        var current = try load()
        try mutate(&current)
        try save(current)
        return current
    }
}
