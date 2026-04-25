import Foundation

/// Encrypted body of a per-main-FID Setting file. Holds every key
/// the main FID manages (itself + watch-only / multisig / servant
/// sub-identities) plus generic state buckets.
///
/// Mac improvement vs. Android `BaseSetting`: only one map keyed by
/// FID, distinguished by ``KeyInfo/kind``, instead of three parallel
/// arrays (`watchedFidList` / `multisigFidList` / `servantFidList`).
/// Querying which sub-identities of a given kind exist is then an
/// O(N) filter, but N is human-scale so the simpler invariant wins.
///
/// Transient runtime services (FudpClient, IM, etc.) live on the
/// runtime ``ActiveSession``, not here. This struct is pure data —
/// safe to JSON round-trip without losing or corrupting state.
public struct Setting: Codable, Equatable, Sendable {

    public var version: Int

    /// The owning main FID. Always present in ``keyInfoMap``.
    public var mainFid: String

    /// Every FID this Setting knows about: the main itself plus
    /// every watch-only / multisig / servant sub-identity.
    public var keyInfoMap: [String: KeyInfo]

    /// Per-Setting generic state bag. JSON values; callers cast on
    /// read. Mirrors Android's `Setting.settingMap`.
    public var settingMap: [String: SettingValue]

    /// Last-known best block height per chain (e.g. "FCH" → 800001).
    /// Helpful for hinting "you're behind by N blocks" UI without
    /// hitting the network.
    public var bestHeightMap: [String: Int64]

    public init(
        version: Int = 1,
        mainFid: String,
        keyInfoMap: [String: KeyInfo] = [:],
        settingMap: [String: SettingValue] = [:],
        bestHeightMap: [String: Int64] = [:]
    ) {
        self.version = version
        self.mainFid = mainFid
        self.keyInfoMap = keyInfoMap
        self.settingMap = settingMap
        self.bestHeightMap = bestHeightMap
    }

    /// Sub-identities of a given kind. The main FID itself is
    /// excluded even if filtered for `.main` — there's only ever one
    /// owning main per Setting and it's at ``mainFid``.
    public func subIdentities(of kind: KeyKind) -> [KeyInfo] {
        keyInfoMap.values
            .filter { $0.fid != mainFid && $0.kind == kind }
            .sorted { $0.fid < $1.fid }
    }

    public var mainKeyInfo: KeyInfo? { keyInfoMap[mainFid] }
}

/// Tiny JSON-serializable value enum for ``Setting/settingMap``.
/// Avoids depending on a third-party AnyCodable wrapper while still
/// supporting the Android-side state shape (mostly bools and strings).
public enum SettingValue: Codable, Equatable, Sendable {
    case bool(Bool)
    case int(Int64)
    case double(Double)
    case string(String)
    case data(Data)

    public init(from decoder: Decoder) throws {
        let c = try decoder.singleValueContainer()
        if let b = try? c.decode(Bool.self) { self = .bool(b); return }
        if let i = try? c.decode(Int64.self) { self = .int(i); return }
        if let d = try? c.decode(Double.self) { self = .double(d); return }
        if let s = try? c.decode(String.self) { self = .string(s); return }
        if let dt = try? c.decode(Data.self) { self = .data(dt); return }
        throw DecodingError.dataCorruptedError(
            in: c, debugDescription: "SettingValue: unrecognized JSON type"
        )
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.singleValueContainer()
        switch self {
        case .bool(let v):   try c.encode(v)
        case .int(let v):    try c.encode(v)
        case .double(let v): try c.encode(v)
        case .string(let v): try c.encode(v)
        case .data(let v):   try c.encode(v)
        }
    }
}
