import Foundation

/// Derive a 32-byte private key from a user-typed phrase.
///
/// Supports two schemes:
/// - ``Scheme/legacySha256`` — **weak**; kept only for importing
///   phrase-derived keys from legacy Freer Android builds.
/// - ``Scheme/argon2id`` — recommended; Argon2id with the project
///   parameters and a fixed protocol salt.
///
/// Call sites that present UI to the user should show ``Scheme/advisory``
/// when it is non-nil so the user understands which scheme they're using
/// and the security implications.
public enum PhraseKey {

    /// Fixed salt for the argon2id phrase-to-key derivation.
    ///
    /// A constant salt is required here because the derivation is
    /// *deterministic recovery* (same phrase → same key) rather than
    /// password storage. The Mac and Android sides must agree on this
    /// string byte-for-byte for cross-platform phrase-import to work.
    public static let argon2idProtocolSalt: Data = Data("fc.freer.phrase.v1".utf8)

    public enum Scheme: String, Codable, Sendable, CaseIterable {

        /// ⚠️ **Weak.** Plain `SHA-256(UTF-8(phrase))`. No salt. No memory
        /// cost. Grindable at billions of guesses per second on a GPU,
        /// and a shared rainbow table can be built once and reused
        /// against every user of this scheme.
        ///
        /// Provided **only** to round-trip phrase-derived keys created
        /// under the legacy Android scheme (see
        /// `docs/android-issues-to-fix.md` entry S9). Never offer this
        /// option to a user creating a *new* key — use
        /// ``Scheme/argon2id`` for that.
        case legacySha256 = "legacy_sha256"

        /// Recommended. Argon2id with the project-standard parameters
        /// (iter=3, mem=64 MiB, par=1, 32-byte output) and the fixed
        /// protocol salt ``PhraseKey/argon2idProtocolSalt``. One
        /// derivation costs ~300 ms — roughly a 10⁸× grinding slowdown
        /// versus ``Scheme/legacySha256``.
        case argon2id = "argon2id"

        /// Whether this scheme should be offered for *new* keys.
        /// ``legacySha256`` returns `false`.
        public var isRecommendedForNewKeys: Bool {
            switch self {
            case .legacySha256: return false
            case .argon2id:     return true
            }
        }

        /// A user-facing advisory explaining the security of this scheme.
        /// `nil` when there is nothing unusual to warn about.
        public var advisory: String? {
            switch self {
            case .legacySha256:
                return "This phrase scheme is weak (plain SHA-256) and "
                     + "grindable. It exists only to import phrase-derived "
                     + "keys from legacy Freer Android builds. Do not use "
                     + "it for new keys."
            case .argon2id:
                return nil
            }
        }
    }

    public enum Failure: Error, CustomStringConvertible {
        case emptyPhrase

        public var description: String {
            switch self {
            case .emptyPhrase: return "PhraseKey: phrase must not be empty"
            }
        }
    }

    /// Derive a 32-byte private key from `phrase` under `scheme`.
    ///
    /// The returned bytes are the raw scalar; validate by feeding them
    /// through ``Secp256k1/publicKey(fromPrivateKey:)`` which rejects
    /// keys outside `[1, n)`. In practice both schemes produce a valid
    /// scalar with probability ~1 - 2⁻¹²⁸.
    public static func privateKey(fromPhrase phrase: String, scheme: Scheme) throws -> Data {
        guard !phrase.isEmpty else { throw Failure.emptyPhrase }
        let phraseBytes = Data(phrase.utf8)
        switch scheme {
        case .legacySha256:
            return Hash.sha256(phraseBytes)
        case .argon2id:
            return try Argon2.hashID(
                password: phraseBytes,
                salt: argon2idProtocolSalt
            )
        }
    }
}
