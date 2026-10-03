import Foundation
import FCStorage

/// Per-identity user preferences. Stored as one Codable row inside the
/// identity's ``EncryptedKVStore``. Adding a new field is forward-safe:
/// existing rows decode it as `nil` (because every field is Optional)
/// and the next save fills it in.
///
/// Anything that's *secret* (privkeys, passphrases) does NOT go here —
/// the encryption is automatic but the Preferences struct is meant to be
/// audit-grade boring. Secrets live in dedicated stores.
public struct Preferences: Codable, Equatable, Sendable {

    public var version: Int
    /// Default FAPI service the wallet talks to: `"<host>:<port>"`. The
    /// service's pubkey is in ``preferredFapiServicePubkeyHex`` so we
    /// don't store it here in `Data` (Codable round-trips Data as
    /// base-64 which is annoying to inspect by hand).
    public var preferredFapiService: String?
    public var preferredFapiServicePubkeyHex: String?
    /// Service id of the DISK provider new uploads are tagged with.
    /// A `(sid)` location survives the server changing address — the
    /// client re-resolves it — so it is preferred over a raw
    /// `fudp://host:port`. Nil until the user pins a provider, in
    /// which case uploads fall back to the service URL.
    public var preferredDiskServiceSid: String?
    /// The most this identity will pay as a mail notice fee, in
    /// satoshis. Nil means ``NoticeFee/defaultMaxPayingSats``. A
    /// recipient charging more than this gets no mail — see
    /// ``NoticeFee/decide(recipientNoticeFee:maxPayingSats:payBack:receivedNoticeFeeSats:)``.
    public var maxPayingNoticeFeeSats: Int64?
    /// When replying, match a notice fee the correspondent paid us if it
    /// was larger than what we would otherwise pay (Android's
    /// `PAY_BACK_NOTICE_FEE`, on by default). Nil means on.
    public var payBackNoticeFee: Bool?
    /// Show the transaction — inputs, outputs, fee, and any carved
    /// payload — for approval before anything is signed. Nil means on,
    /// which matches the Android client's `userConfirmTx` default and
    /// is the only safe default: a wallet that signs without showing
    /// its work asks the user to trust code they cannot see.
    public var confirmBeforeSigning: Bool?
    public var theme: Theme?
    public var autoLockSeconds: Int?
    /// Connect to the BASE the main FID's home names, once it is known.
    /// Nil means on. Off pins this Mac to ``preferredFapiService`` — the
    /// way to test a server, or to get past one that is down, without
    /// carving anything.
    public var followHomeBase: Bool?
    /// The home BASE last found, verified and reached: `"<host>:<port>"`
    /// and its pubkey. Where the next launch starts, so a FID that has
    /// moved its BASE never touches ``preferredFapiService`` again unless
    /// this one is down. Written only by the app, never by the form.
    public var homeBaseService: String?
    public var homeBaseServicePubkeyHex: String?

    public enum Theme: String, Codable, Sendable, CaseIterable {
        case system
        case light
        case dark
    }

    public init(
        version: Int = 1,
        preferredFapiService: String? = nil,
        preferredFapiServicePubkeyHex: String? = nil,
        preferredDiskServiceSid: String? = nil,
        maxPayingNoticeFeeSats: Int64? = nil,
        payBackNoticeFee: Bool? = nil,
        confirmBeforeSigning: Bool? = nil,
        theme: Theme? = nil,
        autoLockSeconds: Int? = nil,
        followHomeBase: Bool? = nil,
        homeBaseService: String? = nil,
        homeBaseServicePubkeyHex: String? = nil
    ) {
        self.version = version
        self.preferredFapiService = preferredFapiService
        self.preferredFapiServicePubkeyHex = preferredFapiServicePubkeyHex
        self.preferredDiskServiceSid = preferredDiskServiceSid
        self.maxPayingNoticeFeeSats = maxPayingNoticeFeeSats
        self.payBackNoticeFee = payBackNoticeFee
        self.confirmBeforeSigning = confirmBeforeSigning
        self.theme = theme
        self.autoLockSeconds = autoLockSeconds
        self.followHomeBase = followHomeBase
        self.homeBaseService = homeBaseService
        self.homeBaseServicePubkeyHex = homeBaseServicePubkeyHex
    }

    /// The project's FAPI server, used until the user points the app
    /// somewhere else. New identities connect here automatically.
    public static let defaultFapiService = "fapi.cid.cash:8500"
    public static let defaultFapiServicePubkeyHex =
        "03f55c464d74dc97f3636bfb713a86cb1af9ec9321255b58f107533579d2b4f89c"

    public static let defaults = Preferences(
        preferredFapiService: defaultFapiService,
        preferredFapiServicePubkeyHex: defaultFapiServicePubkeyHex
    )
}

/// A FAPI server to connect to, and why this one.
public struct BaseEndpoint: Equatable, Sendable {
    public enum Source: Equatable, Sendable {
        /// The BASE the main FID's home names.
        case home
        /// The server set in Settings, with following turned off.
        case thisMac
        /// The server set in Settings, used until the home is read — and
        /// whenever the home names no BASE, or names one that is down.
        case starting
    }

    /// `"<host>:<port>"`.
    public var service: String
    public var pubkeyHex: String
    public var source: Source

    public init(service: String, pubkeyHex: String, source: Source) {
        self.service = service
        self.pubkeyHex = pubkeyHex
        self.source = source
    }
}

extension Preferences {
    public var followsHomeBase: Bool { followHomeBase ?? true }

    /// The servers to try at launch, best first. The home BASE leads when
    /// one is known and followed; the Settings server comes after it, as
    /// the way back in if the home BASE is down — a FID whose own server
    /// has failed must still reach the chain to move it.
    public var baseCandidates: [BaseEndpoint] {
        var candidates: [BaseEndpoint] = []
        if followsHomeBase, let service = homeBaseService, let pubkey = homeBaseServicePubkeyHex {
            candidates.append(BaseEndpoint(service: service, pubkeyHex: pubkey, source: .home))
        }
        if let service = preferredFapiService, let pubkey = preferredFapiServicePubkeyHex,
           !candidates.contains(where: { $0.service == service }) {
            candidates.append(BaseEndpoint(
                service: service, pubkeyHex: pubkey,
                source: followsHomeBase ? .starting : .thisMac
            ))
        }
        return candidates
    }
}

/// Read/write the per-identity ``Preferences`` row. Single-key store
/// (`namespace=settings, key=app`) — the whole struct is one blob, so
/// updates are atomic at the row level.
public struct PreferencesStore {

    public static let namespace = "settings"
    public static let key = "app"

    private let inner: TypedStore<Preferences>

    public init(kv: EncryptedKVStore) {
        self.inner = TypedStore(kv: kv, namespace: Self.namespace)
    }

    /// Load current settings, or return ``Preferences/defaults`` on first read.
    ///
    /// A row written before ``Preferences/defaultFapiService`` existed
    /// carries a nil service, and a nil service means the app quietly
    /// talks to nobody — every pane loads empty with no error to explain
    /// it. Backfill the default here so an identity created by an older
    /// build lands on the project server exactly like a fresh one does.
    /// The two fields move together: pairing the project pubkey with a
    /// host the user chose would aim a real server at the wrong key.
    public func load() throws -> Preferences {
        guard var settings = try inner.get(Self.key) else { return .defaults }
        if settings.preferredFapiService == nil {
            settings.preferredFapiService = Preferences.defaultFapiService
            settings.preferredFapiServicePubkeyHex = Preferences.defaultFapiServicePubkeyHex
        }
        return settings
    }

    public func save(_ settings: Preferences) throws {
        try inner.put(settings, key: Self.key)
    }

    /// Read-modify-write helper. The mutation runs in-process; if you
    /// expect concurrent writers, serialize them at a higher layer.
    @discardableResult
    public func update(_ mutate: (inout Preferences) throws -> Void) throws -> Preferences {
        var current = try load()
        try mutate(&current)
        try save(current)
        return current
    }
}
