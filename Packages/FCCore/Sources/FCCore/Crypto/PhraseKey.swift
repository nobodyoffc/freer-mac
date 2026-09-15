import Foundation

/// Derive a 32-byte private key from a user-typed phrase.
///
/// Supports three schemes:
/// - ``Scheme/argon2id`` — recommended; FTSP28, Argon2id with the project
///   parameters and an empty salt — the derivation Safe and Freer Android use.
/// - ``Scheme/legacySha256`` — **weak**; kept only for importing
///   phrase-derived keys from legacy Freer Android builds.
/// - ``Scheme/legacyFreerMacArgon2id`` — recovery only; the salted
///   derivation FreerForMac used before FTSP28.
///
/// Call sites that present UI to the user should show ``Scheme/advisory``
/// when it is non-nil so the user understands which scheme they're using
/// and the security implications.
public enum PhraseKey {

    /// Salt of the conformant FTSP28 derivation: empty. A fixed input is what
    /// lets the same phrase reproduce the same key in every wallet; the
    /// memory-hard cost, not the salt, is the defense.
    public static let argon2idSalt = Data()

    /// The salt FreerForMac used before FTSP28 pinned it empty. Keys made with
    /// it don't match the same phrase in Safe or Freer Android; it survives
    /// only so those keys can be recovered.
    public static let legacyFreerMacSalt: Data = Data("fc.freer.phrase.v1".utf8)

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

        /// Recommended. FTSP28: Argon2id with the project-standard parameters
        /// (iter=3, mem=64 MiB, par=1, 32-byte output) and the empty salt
        /// ``PhraseKey/argon2idSalt``, so a phrase gives the same key here as
        /// in Safe and Freer Android. One derivation costs ~300 ms — roughly
        /// a 10⁸× grinding slowdown versus ``Scheme/legacySha256``.
        case argon2id = "argon2id"

        /// ⚠️ **Recovery only.** Argon2id with ``PhraseKey/legacyFreerMacSalt``,
        /// the salt FreerForMac used before FTSP28. It gives a different key
        /// from ``Scheme/argon2id`` for the same phrase, so it exists only to
        /// recover keys created by those builds.
        case legacyFreerMacArgon2id = "legacy_freermac_argon2id"

        /// Whether this scheme should be offered for *new* keys.
        /// ``legacySha256`` returns `false`.
        public var isRecommendedForNewKeys: Bool {
            switch self {
            case .legacySha256: return false
            case .argon2id:     return true
            case .legacyFreerMacArgon2id: return false
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
            case .legacyFreerMacArgon2id:
                return "This scheme uses the salt older FreerForMac builds used, "
                     + "which Safe and Freer Android don't. Use it only to "
                     + "recover a key created by one of those builds."
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
            return try Argon2.hashID(password: phraseBytes, salt: argon2idSalt)
        case .legacyFreerMacArgon2id:
            return try Argon2.hashID(password: phraseBytes, salt: legacyFreerMacSalt)
        }
    }
}
