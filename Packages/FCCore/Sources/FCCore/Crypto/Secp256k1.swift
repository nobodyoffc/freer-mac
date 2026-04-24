import Foundation
import P256K

/// A `Digest`-conforming wrapper around a pre-computed 32-byte hash.
/// Lets us hand a raw sighash to
/// `P256K.Signing.PrivateKey.signature(for:)` without making
/// swift-secp256k1 re-hash it internally.
///
/// We intentionally do **not** `import CryptoKit` in this file: both
/// `CryptoKit.Digest` and `P256K.Digest` exist (with identical shapes),
/// and the signing API requires the P256K one. Importing only P256K
/// makes the name resolve unambiguously.
struct RawSighashDigest: Digest {
    static let byteCount: Int = 32
    let storage: Data

    init(_ bytes: Data) {
        precondition(bytes.count == Self.byteCount, "sighash must be \(Self.byteCount) bytes")
        self.storage = Data(bytes)
    }

    func makeIterator() -> Data.Iterator {
        storage.makeIterator()
    }

    func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        try storage.withUnsafeBytes(body)
    }

    var description: String { "RawSighashDigest(\(storage.count) bytes)" }
}

/// secp256k1 elliptic-curve operations: key derivation, ECDSA, ECDH.
///
/// Wraps `swift-secp256k1` (Bitcoin Core's libsecp256k1) with a Data-in /
/// Data-out interface. ECDSA signatures use RFC 6979 deterministic nonces
/// and are low-S normalized (matches freecashj / bitcoinj behaviour).
///
/// Schnorr signing is **not** exposed here yet — freecashj ships a
/// BitcoinCash-2019 Schnorr variant that predates BIP340, and the Mac
/// port needs to reproduce that variant exactly. Tracked for a follow-up
/// phase.
public enum Secp256k1 {

    public enum Failure: Error, CustomStringConvertible {
        case invalidPrivateKey
        case invalidPublicKey
        case invalidSignature

        public var description: String {
            switch self {
            case .invalidPrivateKey: return "secp256k1: invalid private key"
            case .invalidPublicKey:  return "secp256k1: invalid public key"
            case .invalidSignature:  return "secp256k1: invalid signature"
            }
        }
    }

    /// Derive the 33-byte compressed public key from a 32-byte private key.
    public static func publicKey(fromPrivateKey privkey: Data) throws -> Data {
        let key = try signingKey(privkey)
        return key.publicKey.dataRepresentation
    }

    /// Sign `message` with RFC 6979 deterministic ECDSA. Hashes `message` with
    /// SHA-256 internally, then signs. Matches `ECKey.sign(Sha256Hash.of(msg))`.
    ///
    /// - Returns: DER-encoded signature (low-S normalized).
    public static func signMessage(privateKey: Data, message: Data) throws -> Data {
        let key = try signingKey(privateKey)
        let sig = key.signature(for: message)
        return sig.derRepresentation
    }

    /// Sign `message` with RFC 6979 deterministic ECDSA. Returns the compact
    /// 64-byte `R || S` form (Bitcoin convention when low-S normalized).
    public static func signMessageCompact(privateKey: Data, message: Data) throws -> Data {
        let key = try signingKey(privateKey)
        let sig = key.signature(for: message)
        return sig.dataRepresentation
    }

    /// Sign a pre-computed 32-byte hash (e.g. a BCH sighash) directly —
    /// does *not* re-hash. Deterministic RFC 6979; output is low-S
    /// normalized DER.
    public static func signSighash(privateKey: Data, sighash: Data) throws -> Data {
        guard sighash.count == 32 else {
            throw Failure.invalidSignature
        }
        let key = try signingKey(privateKey)
        let sig = key.signature(for: RawSighashDigest(sighash))
        return sig.derRepresentation
    }

    /// Verify a DER-encoded ECDSA signature against a pre-computed 32-byte hash.
    public static func verifySighashSig(
        publicKey pubkey: Data,
        sighash: Data,
        signatureDER: Data
    ) throws -> Bool {
        guard sighash.count == 32 else {
            throw Failure.invalidSignature
        }
        let pub: P256K.Signing.PublicKey
        do {
            pub = try P256K.Signing.PublicKey(dataRepresentation: pubkey, format: .compressed)
        } catch {
            throw Failure.invalidPublicKey
        }
        let sig: P256K.Signing.ECDSASignature
        do {
            sig = try P256K.Signing.ECDSASignature(derRepresentation: Array(signatureDER))
        } catch {
            throw Failure.invalidSignature
        }
        return pub.isValidSignature(sig, for: RawSighashDigest(sighash))
    }

    /// Verify a DER-encoded ECDSA signature against `message` (hashed with SHA-256).
    public static func verifyMessage(
        publicKey pubkey: Data,
        message: Data,
        signatureDER: Data
    ) throws -> Bool {
        let pub = try P256K.Signing.PublicKey(dataRepresentation: pubkey, format: .compressed)
        let sig: P256K.Signing.ECDSASignature
        do {
            sig = try P256K.Signing.ECDSASignature(derRepresentation: Array(signatureDER))
        } catch {
            throw Failure.invalidSignature
        }
        return pub.isValidSignature(sig, for: message)
    }

    /// Raw ECDH: compute the 32-byte x-coordinate of `privkey · pubkey`.
    ///
    /// Matches BouncyCastle's `ECDHBasicAgreement.calculateAgreement(...)` output
    /// used in `FC-AJDK/.../core/crypto/Algorithm/Ecc256K1Hkdf.java`. Any
    /// higher-level KDF (HKDF with nonce as salt, etc.) is layered on top by
    /// the caller.
    public static func sharedSecretX(privateKey: Data, publicKey pubkey: Data) throws -> Data {
        let priv: P256K.KeyAgreement.PrivateKey
        do {
            priv = try P256K.KeyAgreement.PrivateKey(dataRepresentation: privateKey)
        } catch {
            throw Failure.invalidPrivateKey
        }
        let pub: P256K.KeyAgreement.PublicKey
        do {
            pub = try P256K.KeyAgreement.PublicKey(dataRepresentation: pubkey, format: .compressed)
        } catch {
            throw Failure.invalidPublicKey
        }
        let shared = priv.sharedSecretFromKeyAgreement(with: pub)
        let raw = shared.withUnsafeBytes { Data($0) }
        // Compressed format: [ 0x02|0x03 (parity) || X (32) ]. Strip the parity byte.
        return raw.dropFirst()
    }

    // MARK: - private

    private static func signingKey(_ privkey: Data) throws -> P256K.Signing.PrivateKey {
        do {
            return try P256K.Signing.PrivateKey(dataRepresentation: privkey)
        } catch {
            throw Failure.invalidPrivateKey
        }
    }
}
