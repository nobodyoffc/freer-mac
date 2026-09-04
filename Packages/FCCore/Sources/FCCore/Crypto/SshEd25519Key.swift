import Foundation
import CryptoKit

/// The SSH identity belonging to an FCH main FID: an ed25519 keypair
/// derived one-way from the main private key.
///
/// **Why a derived key and not the FID key itself.** OpenSSH has no
/// `secp256k1` key type. `sshd` accepts `ssh-ed25519`,
/// `ecdsa-sha2-nistp256/384/521`, `ssh-rsa` and the `sk-*` FIDO
/// variants, and nothing else, so an FCH private key cannot be handed
/// to a stock Linux server at all. It can seed one. Unlike secp256k1,
/// where a private key is a scalar that must land below the curve
/// order, ed25519 hashes its seed internally and accepts any 32 bytes
/// — so this is a plain HKDF read with no rejection loop.
///
/// What that buys, in order of how much it matters:
///
///   - **Nothing to store.** The key is a pure function of the vault,
///     so it is re-derived on demand and never written down. The same
///     Configure restored on another Mac produces a byte-identical
///     key, with nothing exported between them.
///   - **The money key stays out of reach.** HKDF is one-way and the
///     curves are unrelated, so a server that is fully compromised —
///     or an ssh signature harvested off the wire — reveals nothing
///     about the secp256k1 key that holds the coins. This key cannot
///     spend.
///   - **It is bound to the FID, not just the key.** `mainFid` is the
///     HKDF `info`, matching how ``ConfigureSession`` derives the
///     per-main store key. The cost of that binding is real and
///     belongs in the UI: change the main identity and every
///     `authorized_keys` line already installed is dead.
///
/// The derivation follows the two domain separations already in this
/// codebase (`Configure.verificationToken`, the per-main store key): a
/// versioned salt naming the purpose, the FID as `info`.
public struct SshEd25519Key {

    /// Bump the trailing version if the derivation ever changes —
    /// every server's `authorized_keys` would have to be rewritten, so
    /// this string is effectively frozen.
    public static let derivationSalt = "fc.freer.ssh.ed25519.v1"

    /// The SSH algorithm name, on the wire and in `authorized_keys`.
    public static let algorithmName = "ssh-ed25519"

    public enum Failure: Error, CustomStringConvertible {
        case badPrivkeyLength(Int)
        case emptyFid

        public var description: String {
            switch self {
            case let .badPrivkeyLength(n):
                return "SshEd25519Key: expected a 32-byte private key, got \(n)"
            case .emptyFid:
                return "SshEd25519Key: the main FID is empty"
            }
        }
    }

    private let key: Curve25519.Signing.PrivateKey

    /// The FID this key belongs to. Also the comment on the
    /// `authorized_keys` line, so the line says whose it is.
    public let mainFid: String

    /// - Parameters:
    ///   - mainPrikey: the 32-byte secp256k1 scalar from
    ///     ``ActiveSession/mainPrikey()``. Not retained.
    ///   - mainFid: the FID that key belongs to.
    public init(mainPrikey: Data, mainFid: String) throws {
        guard mainPrikey.count == 32 else { throw Failure.badPrivkeyLength(mainPrikey.count) }
        guard !mainFid.isEmpty else { throw Failure.emptyFid }

        var seed = Hkdf.sha256(
            ikm: mainPrikey,
            salt: Data(Self.derivationSalt.utf8),
            info: Data(mainFid.utf8),
            outputLength: 32
        )
        // CryptoKit copies the seed into its own storage, which we
        // cannot reach — so wiping ours is the most that can be done
        // here, and the real lifetime guarantee is that the whole
        // object is dropped on vault lock.
        defer { seed.resetBytes(in: 0 ..< seed.count) }

        self.key = try Curve25519.Signing.PrivateKey(rawRepresentation: seed)
        self.mainFid = mainFid
    }

    // MARK: - Public key

    /// The raw 32-byte ed25519 point.
    public var publicKeyBytes: Data { key.publicKey.rawRepresentation }

    /// The 51-byte SSH public key blob (RFC 8709 §4):
    /// `string "ssh-ed25519" ‖ string A`.
    ///
    /// This exact blob is what goes in an agent identities answer, what
    /// `ssh` sends back in a sign request to name the key, and what is
    /// base64'd into `authorized_keys` — so all three read it from here
    /// rather than each rebuilding it.
    public var publicKeyBlob: Data {
        SshWire.string(Self.algorithmName) + SshWire.string(publicKeyBytes)
    }

    /// One `authorized_keys` line, newline-free.
    public func authorizedKeysLine(comment: String? = nil) -> String {
        let c = comment ?? "freer:\(mainFid)"
        let encoded = publicKeyBlob.base64EncodedString()
        return c.isEmpty
            ? "\(Self.algorithmName) \(encoded)"
            : "\(Self.algorithmName) \(encoded) \(c)"
    }

    /// The `SHA256:…` fingerprint `ssh-keygen -l` prints — base64 of
    /// the digest of the blob, with the padding stripped.
    public var fingerprint: String {
        let digest = SHA256.hash(data: publicKeyBlob)
        let b64 = Data(digest).base64EncodedString()
        return "SHA256:" + b64.replacingOccurrences(of: "=", with: "")
    }

    /// The `.pub` file body: one line, trailing newline, exactly what
    /// `ssh-keygen -y` writes.
    public func publicKeyFileContents(comment: String? = nil) -> String {
        authorizedKeysLine(comment: comment) + "\n"
    }

    // MARK: - Signing

    /// The raw 64-byte ed25519 signature (R ‖ S).
    ///
    /// Ed25519 is PureEdDSA: the message is signed as-is, with no
    /// caller-side hashing. `data` here is the whole
    /// `SSH_MSG_USERAUTH_REQUEST` blob the client hands the agent.
    public func sign(_ data: Data) throws -> Data {
        try key.signature(for: data)
    }

    /// The 83-byte SSH signature blob:
    /// `string "ssh-ed25519" ‖ string sig64`.
    public func signatureBlob(_ data: Data) throws -> Data {
        SshWire.string(Self.algorithmName) + SshWire.string(try sign(data))
    }
}
