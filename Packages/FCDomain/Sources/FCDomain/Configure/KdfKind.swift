import Foundation
import FCCore

/// Password → symkey derivation. The newly-recommended scheme is
/// ``argon2id`` (memory-hard, slow on GPU). ``legacySha256`` is kept
/// **only** for importing Configures from Android Freer builds — never
/// offer it for new vaults.
public enum KdfKind: String, Codable, Sendable, CaseIterable {

    case argon2id     = "argon2id_no1_nrc7"
    case legacySha256 = "sha256iv_no1_nrc7"

    /// Matches `Kdf.Argon2id_No1_NrC7` / `Sha256Iv_No1_NrC7` in
    /// `FC-AJDK/.../core/crypto/Kdf.java`. Output is always 32 bytes.
    public func deriveSymkey(password: Data, salt: Data) throws -> Data {
        switch self {
        case .argon2id:
            return try Argon2.hashID(password: password, salt: salt)
        case .legacySha256:
            // dSha256-style: SHA256(SHA256(password) ‖ salt). Note this
            // is NOT salted in the password→hash sense — `salt` here
            // is FC-AJDK's `iv` parameter (random per Configure).
            let inner = Hash.sha256(password)
            return Hash.sha256(inner + salt)
        }
    }

    /// User-facing advisory shown in the UI when this scheme is chosen.
    /// `nil` when there's nothing unusual to warn about.
    public var advisory: String? {
        switch self {
        case .argon2id: return nil
        case .legacySha256:
            return "Legacy SHA-256 is grindable on GPUs and exists only to "
                 + "import Configures created with older Android Freer builds. "
                 + "Don't pick it for a new vault."
        }
    }

    public var isRecommendedForNewVaults: Bool {
        self == .argon2id
    }
}
