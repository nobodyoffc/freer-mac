import Foundation
import BigInt
import P256K

/// BitcoinCash 2019 Schnorr signature — the pre-BIP-340 variant used by
/// freecashj. Algorithm ported from
/// `FC-AJDK/.../core/fch/SchnorrSignature.java`, which itself is a port
/// of https://github.com/miketwk/bip-schnorr-java.
///
/// **Not interoperable with BIP-340.** Key differences from BIP-340:
/// - Nonce: `SHA-256(d || m)` (no tagged hash, no auxiliary data).
/// - Challenge: `SHA-256(R.x || P_compressed_33 || m)` (no tags, 33-byte
///   compressed pubkey, not 32-byte x-only).
/// - R selection: Y is a quadratic residue (`jacobi(R.y) == 1`), not
///   "even Y".
///
/// **Implementation notes.** EC point multiplications run through
/// libsecp256k1 (`secp256k1_ec_pubkey_create`, `_tweak_mul`,
/// `_seckey_tweak_*`), so signing and verification each take a few
/// milliseconds rather than the ~30 s the previous BigInt-only path
/// took. The remaining BigInt work is a single mod-n reduction per
/// SHA-256 output and the jacobi mod-p exponentiation on `R.y` —
/// roughly 256 BigInt squarings, each microseconds.
///
/// The wire format is byte-identical to the prior BigInt version (the
/// `BchSchnorrTests` byte-exact parity vectors against freecashj still
/// pass).
public enum BchSchnorr {

    public enum Failure: Error, CustomStringConvertible {
        case invalidMessageLength
        case invalidSeckey
        case invalidPubkey
        case invalidSignatureLength
        case signingFailed

        public var description: String {
            switch self {
            case .invalidMessageLength:   return "BchSchnorr: message must be 32 bytes"
            case .invalidSeckey:          return "BchSchnorr: seckey out of range"
            case .invalidPubkey:          return "BchSchnorr: pubkey must be 33-byte compressed"
            case .invalidSignatureLength: return "BchSchnorr: signature must be 64 bytes"
            case .signingFailed:          return "BchSchnorr: signing failed"
            }
        }
    }

    // MARK: - secp256k1 constants

    /// Field prime — used for the jacobi(R.y) check (mod-p exponentiation).
    static let p = BigInt("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", radix: 16)!
    /// Curve order — used to reduce SHA-256 outputs into valid scalars.
    static let n = BigInt("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", radix: 16)!

    // MARK: - Public API

    /// Sign a 32-byte `message` (typically a sighash) with `privateKey`.
    /// Returns a 64-byte signature in the BCH 2019 Schnorr wire layout
    /// `R.x || s`. Deterministic: same `(privateKey, message)` always
    /// yields the same bytes.
    public static func sign(message: Data, privateKey: Data) throws -> Data {
        guard message.count == 32 else { throw Failure.invalidMessageLength }
        guard privateKey.count == 32 else { throw Failure.invalidSeckey }

        // Validate privkey via libsecp256k1 (1 <= d < n).
        let dKey: P256K.Signing.PrivateKey
        do {
            dKey = try P256K.Signing.PrivateKey(dataRepresentation: privateKey)
        } catch {
            throw Failure.invalidSeckey
        }

        // 1) k0 = SHA-256(d || m) reduced mod n. SHA-256 output is
        //    almost always already < n; reduction handles the
        //    ~2⁻¹²⁸ tail.
        var nonceInput = Data(capacity: 64)
        nonceInput.append(privateKey)
        nonceInput.append(message)
        let k0Bytes = try reduceModN(Hash.sha256(nonceInput))

        // 2) R = k0 · G. Treat k0 as a privkey; libsecp256k1 derives
        //    the corresponding pubkey, which is exactly k0·G.
        let k0Key: P256K.Signing.PrivateKey
        do {
            k0Key = try P256K.Signing.PrivateKey(dataRepresentation: k0Bytes)
        } catch {
            throw Failure.signingFailed
        }
        let rUncompressed = k0Key.publicKey.uncompressedRepresentation
        guard rUncompressed.count == 65 else { throw Failure.signingFailed }
        let rx = rUncompressed.subdata(in: 1..<33)
        let ry = rUncompressed.subdata(in: 33..<65)

        // 3) BCH Schnorr canonicalization: pick the (x, y) where
        //    jacobi(y) == 1. If the natural y from k0·G fails the
        //    jacobi test, flip k0 → n - k0 (which gives the same x
        //    with the opposite y).
        let kKey = (jacobiIsOne(bigInt(ry))) ? k0Key : k0Key.negation
        let kBytes = kKey.dataRepresentation

        // 4) e = SHA-256(R.x || P_compressed(33) || m) reduced mod n.
        let pCompressed = dKey.publicKey.dataRepresentation
        guard pCompressed.count == 33 else { throw Failure.signingFailed }
        var challenge = Data(capacity: 32 + 33 + 32)
        challenge.append(rx)
        challenge.append(pCompressed)
        challenge.append(message)
        let eBytes = try reduceModN(Hash.sha256(challenge))

        // 5) s = (e * d + k) mod n via the seckey-tweak primitives.
        //    Both operations fail iff the result is zero, which has
        //    negligible probability for random k0/e — surface as
        //    `signingFailed` if it ever happens.
        let edKey: P256K.Signing.PrivateKey
        let sKey: P256K.Signing.PrivateKey
        do {
            edKey = try dKey.multiply(Array(eBytes))
            sKey = try edKey.add(Array(kBytes))
        } catch {
            throw Failure.signingFailed
        }

        var out = Data(capacity: 64)
        out.append(rx)
        out.append(sKey.dataRepresentation)
        return out
    }

    /// Verify a 64-byte BCH Schnorr signature against a 33-byte
    /// compressed pubkey and a 32-byte message. Returns false (rather
    /// than throwing) for any cryptographic mismatch; only the input
    /// shape errors throw.
    public static func verify(message: Data, publicKey: Data, signature: Data) throws -> Bool {
        guard message.count == 32 else { throw Failure.invalidMessageLength }
        guard publicKey.count == 33 else { throw Failure.invalidPubkey }
        guard signature.count == 64 else { throw Failure.invalidSignatureLength }

        // Parse pubkey. An invalid encoding (wrong prefix byte, off-curve x)
        // is a verification failure, not a programmer error.
        let pubKey: P256K.Signing.PublicKey
        do {
            pubKey = try P256K.Signing.PublicKey(dataRepresentation: publicKey, format: .compressed)
        } catch {
            return false
        }

        let sig = Data(signature)
        let rBytes = sig.prefix(32)
        let sBytes = sig.suffix(32)
        let r = bigInt(rBytes)
        let s = bigInt(sBytes)
        // r < p (field), s < n (curve order). r == 0 isn't excluded
        // by the spec — leave to the final x-equality check to reject.
        guard r < p, s < n, s.signum() > 0 else { return false }

        // 1) e = SHA-256(R.x || P_compressed || m) mod n.
        var challenge = Data(capacity: 32 + 33 + 32)
        challenge.append(rBytes)
        challenge.append(publicKey)
        challenge.append(message)
        let eBytes: Data
        do {
            eBytes = try reduceModN(Hash.sha256(challenge))
        } catch {
            return false
        }

        // 2) Reconstruct R = s·G + (n - e)·P  ≡  s·G - e·P.
        do {
            let sKey = try P256K.Signing.PrivateKey(dataRepresentation: sBytes)
            let sG = sKey.publicKey
            let ePNeg = try pubKey.multiply(Array(eBytes), format: .compressed).negation
            let reconstructed = try sG.combine([ePNeg], format: .uncompressed)
            let raw = reconstructed.uncompressedRepresentation
            guard raw.count == 65 else { return false }
            let xBytes = raw.subdata(in: 1..<33)
            let yBytes = raw.subdata(in: 33..<65)

            // 3) Accept iff jacobi(R.y) == 1 AND R.x == r.
            return jacobiIsOne(bigInt(yBytes)) && bigInt(xBytes) == r
        } catch {
            return false
        }
    }

    // MARK: - helpers

    /// Reduce a 32-byte big-endian integer to the canonical
    /// `[1, n-1]` range. Returns the 32-byte big-endian representation
    /// of `value mod n`. Throws ``Failure/signingFailed`` if the
    /// reduced value is zero (negligible probability for SHA-256
    /// outputs, but a hard signing failure when it occurs).
    static func reduceModN(_ raw: Data) throws -> Data {
        let reduced = bigInt(raw).modulus(n)
        guard reduced.signum() > 0 else { throw Failure.signingFailed }
        return to32(reduced)
    }

    /// True iff `y` is a quadratic residue mod `p`. For secp256k1
    /// (where `p ≡ 3 (mod 4)`) this is `y^((p-1)/2) mod p == 1`.
    static func jacobiIsOne(_ y: BigInt) -> Bool {
        y.power((p - 1) / 2, modulus: p) == BigInt(1)
    }

    static func bigInt(_ data: Data) -> BigInt {
        BigInt(sign: .plus, magnitude: BigUInt(Data(data)))
    }

    static func to32(_ value: BigInt) -> Data {
        let raw = value.magnitude.serialize()
        if raw.count == 32 { return raw }
        if raw.count > 32 { return raw.suffix(32) }
        var padded = Data(repeating: 0, count: 32 - raw.count)
        padded.append(raw)
        return padded
    }
}
