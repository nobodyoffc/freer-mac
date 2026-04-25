import Foundation
import FCCore

/// Plaintext index entry — one per password Configure on this Mac.
/// Lives in `configures.json` under the base directory. Carries
/// **only the data needed to ask "do I know which Configure this
/// password unlocks?" without trying to decrypt anything.**
///
/// Per Android `BaseConfigure`:
///   - `passwordName` is the deterministic-from-password disambiguator
///     (first 6 hex of double-SHA256 of password). On password input
///     the app computes this and looks up which Configure to load.
///   - `nonce` is the per-Configure salt for the KDF.
///   - `passwordHash` is a fixed-length verification token derived
///     from the symkey via HKDF — comparing it lets us reject wrong
///     passwords without an AES-GCM "tag mismatch" round-trip.
public struct ConfigureRecord: Codable, Equatable, Sendable {

    /// The 6-hex-char public hint matching
    /// `IdNameUtils.makePasswordHashName` in FC-AJDK:
    /// `dSHA256(password)[0..6]`.
    public var passwordName: String

    /// Random per-Configure salt for the KDF. 16 B from CSPRNG.
    public var nonce: Data

    public var kdfKind: KdfKind

    /// HKDF-SHA256(symkey, salt: "fc.freer.configure.verify", info: "verify", L: 32).
    /// Used to verify a candidate password without decrypting the body.
    public var passwordHash: Data

    /// User-supplied label, e.g. "Personal", "Work". Optional.
    public var label: String

    public var createdAt: Date

    public init(
        passwordName: String,
        nonce: Data,
        kdfKind: KdfKind,
        passwordHash: Data,
        label: String,
        createdAt: Date = Date()
    ) {
        self.passwordName = passwordName
        self.nonce = nonce
        self.kdfKind = kdfKind
        self.passwordHash = passwordHash
        self.label = label
        self.createdAt = createdAt
    }
}

/// On-disk index file: every Configure on this device.
public struct ConfigureIndex: Codable, Equatable, Sendable {
    public var version: Int
    public var configures: [ConfigureRecord]

    public init(version: Int = 1, configures: [ConfigureRecord] = []) {
        self.version = version
        self.configures = configures
    }

    public func find(passwordName: String) -> ConfigureRecord? {
        configures.first { $0.passwordName == passwordName }
    }

    public mutating func upsert(_ record: ConfigureRecord) {
        if let i = configures.firstIndex(where: { $0.passwordName == record.passwordName }) {
            configures[i] = record
        } else {
            configures.append(record)
        }
    }

    public mutating func remove(passwordName: String) -> Bool {
        guard let i = configures.firstIndex(where: { $0.passwordName == passwordName }) else {
            return false
        }
        configures.remove(at: i)
        return true
    }
}

/// Encrypted body of a Configure file. Holds every main FID's
/// ``KeyInfo`` (with encrypted privkey) plus the FAPI account map
/// (deferred — Phase 5.7 ships an empty map). Persisted as
/// `configure.encrypted.dat` next to the index.
public struct Configure: Codable, Equatable, Sendable {
    public var version: Int
    /// FID → KeyInfo for every main FID under this Configure.
    public var mainCidInfoMap: [String: KeyInfo]
    /// FAPI providers known to this Configure. Empty for now.
    public var apiProviderMap: [String: Data]
    /// FAPI account credentials. Empty for now.
    public var apiAccountMap: [String: Data]

    public init(
        version: Int = 1,
        mainCidInfoMap: [String: KeyInfo] = [:],
        apiProviderMap: [String: Data] = [:],
        apiAccountMap: [String: Data] = [:]
    ) {
        self.version = version
        self.mainCidInfoMap = mainCidInfoMap
        self.apiProviderMap = apiProviderMap
        self.apiAccountMap = apiAccountMap
    }

    public var mainFids: [String] {
        // Sort for stable UI order.
        mainCidInfoMap.keys.sorted()
    }
}

/// Helpers to derive the deterministic ``ConfigureRecord/passwordName``
/// and the verification token used in ``ConfigureRecord/passwordHash``.
public enum ConfigureCrypto {

    /// `dSHA256(password)[0..6]` hex — matches FC-AJDK
    /// `IdNameUtils.makePasswordHashName`.
    public static func passwordName(from password: Data) -> String {
        let dh = Hash.sha256(Hash.sha256(password))
        return dh.prefix(3).map { String(format: "%02x", $0) }.joined()
    }

    /// 32-byte verification token derived from the symkey. Storing
    /// this lets us reject wrong passwords cheaply without trying
    /// to decrypt anything.
    public static let verifySalt = Data("fc.freer.configure.verify".utf8)
    public static let verifyInfo = Data("verify".utf8)

    public static func verificationToken(symkey: Data) -> Data {
        Hkdf.sha256(ikm: symkey, salt: verifySalt, info: verifyInfo, outputLength: 32)
    }

    /// Constant-time-ish equality for the verification token. The
    /// Foundation `==` on `Data` is short-circuit, but we're checking
    /// 32 bytes of HKDF output that's already public-on-disk anyway,
    /// so the timing leak doesn't matter for confidentiality. We
    /// still iterate full-length to keep it predictable.
    public static func verify(password: Data, against record: ConfigureRecord) -> Data? {
        let candidate: Data
        do {
            candidate = try record.kdfKind.deriveSymkey(password: password, salt: record.nonce)
        } catch {
            return nil
        }
        let expected = verificationToken(symkey: candidate)
        guard expected.count == record.passwordHash.count else { return nil }
        var diff: UInt8 = 0
        for i in 0..<expected.count {
            diff |= expected[expected.startIndex + i] ^ record.passwordHash[record.passwordHash.startIndex + i]
        }
        return diff == 0 ? candidate : nil
    }
}
