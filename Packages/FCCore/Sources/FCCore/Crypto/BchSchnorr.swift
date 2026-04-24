import Foundation
import BigInt

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
/// **Implementation note:** naive textbook EC math via `BigInt`. Not
/// constant-time. The Java reference is equivalent. Acceptable here
/// because Schnorr callers in Freer sign data that a peer will verify —
/// the private key is the secret we care about and our nonce is
/// deterministic, so simple EC math is correct. If a future call site
/// needs side-channel resistance, re-implement over libsecp256k1
/// scalar/point primitives while keeping the wire format byte-identical.
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

    static let p  = BigInt("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", radix: 16)!
    static let n  = BigInt("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", radix: 16)!
    static let gx = BigInt("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", radix: 16)!
    static let gy = BigInt("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", radix: 16)!

    typealias Point = (BigInt, BigInt)

    // MARK: - Public API

    public static func sign(message: Data, privateKey: Data) throws -> Data {
        guard message.count == 32 else { throw Failure.invalidMessageLength }
        guard privateKey.count == 32 else { throw Failure.invalidSeckey }
        let d = bigInt(privateKey)
        guard d.signum() > 0 && d < n else { throw Failure.invalidSeckey }

        // k0 = SHA256(d || m) mod n
        var nonceInput = Data(capacity: 64)
        nonceInput.append(to32(d))
        nonceInput.append(message)
        let k0 = bigInt(Hash.sha256(nonceInput)).modulus(n)
        guard k0.signum() != 0 else { throw Failure.signingFailed }

        // R = k0·G, flip k if Y is not a quadratic residue.
        guard let rPoint = pointMul((gx, gy), k0) else { throw Failure.signingFailed }
        let k = (jacobi(rPoint.1) == 1) ? k0 : (n - k0)

        // e = SHA256(R.x || P_compressed(33) || m) mod n
        let rxBytes = to32(rPoint.0)
        guard let pPoint = pointMul((gx, gy), d) else { throw Failure.signingFailed }
        var challenge = Data(capacity: 32 + 33 + 32)
        challenge.append(rxBytes)
        challenge.append(compress(pPoint))
        challenge.append(message)
        let e = bigInt(Hash.sha256(challenge)).modulus(n)

        // s = (e*d + k) mod n
        let s = (e * d + k).modulus(n)

        var out = Data(capacity: 64)
        out.append(rxBytes)
        out.append(to32(s))
        return out
    }

    public static func verify(message: Data, publicKey: Data, signature: Data) throws -> Bool {
        guard message.count == 32 else { throw Failure.invalidMessageLength }
        guard publicKey.count == 33 else { throw Failure.invalidPubkey }
        guard signature.count == 64 else { throw Failure.invalidSignatureLength }

        guard let point = decompress(publicKey) else { return false }

        let sigBytes = Data(signature)   // normalise slice indices
        let r = bigInt(sigBytes.prefix(32))
        let s = bigInt(sigBytes.suffix(32))
        guard r < p && s < n else { return false }

        var challenge = Data(capacity: 32 + 33 + 32)
        challenge.append(sigBytes.prefix(32))
        challenge.append(compress(point))
        challenge.append(message)
        let e = bigInt(Hash.sha256(challenge)).modulus(n)

        // R = s·G + (n - e)·P
        guard let sG = pointMul((gx, gy), s) else { return false }
        guard let negEp = pointMul(point, (n - e).modulus(n)) else { return false }
        guard let reconstructed = pointAdd(sG, negEp) else { return false }

        return jacobi(reconstructed.1) == 1 && r == reconstructed.0
    }

    // MARK: - EC math (textbook)

    static func pointAdd(_ a: Point?, _ b: Point?) -> Point? {
        guard let a else { return b }
        guard let b else { return a }
        if a.0 == b.0 && a.1 != b.1 { return nil }  // P + (-P) = ∞

        let lam: BigInt
        if a.0 == b.0 && a.1 == b.1 {
            // doubling: λ = (3·x² · (2·y)⁻¹) mod p
            let numerator = (BigInt(3) * a.0 * a.0).modulus(p)
            let denomInv = (BigInt(2) * a.1).power(p - 2, modulus: p)
            lam = (numerator * denomInv).modulus(p)
        } else {
            // addition: λ = ((y2 - y1) · (x2 - x1)⁻¹) mod p
            let numerator = (b.1 - a.1).modulus(p)
            let denomInv = (b.0 - a.0).modulus(p).power(p - 2, modulus: p)
            lam = (numerator * denomInv).modulus(p)
        }
        let x3 = (lam * lam - a.0 - b.0).modulus(p)
        let y3 = (lam * (a.0 - x3) - a.1).modulus(p)
        return (x3, y3)
    }

    static func pointMul(_ base: Point, _ k: BigInt) -> Point? {
        var result: Point? = nil
        var current: Point? = base
        for i in 0..<256 {
            if ((k >> i) & BigInt(1)) == BigInt(1) {
                result = pointAdd(result, current)
            }
            current = pointAdd(current, current)
        }
        return result
    }

    static func jacobi(_ x: BigInt) -> BigInt {
        x.power((p - 1) / 2, modulus: p)
    }

    static func compress(_ point: Point) -> Data {
        var out = Data(capacity: 33)
        let parity: UInt8 = ((point.1 & BigInt(1)) == BigInt(1)) ? 0x03 : 0x02
        out.append(parity)
        out.append(to32(point.0))
        return out
    }

    static func decompress(_ bytes: Data) -> Point? {
        let normal = Data(bytes)
        let prefix = normal[0]
        guard prefix == 0x02 || prefix == 0x03 else { return nil }
        let odd = (prefix == 0x03)
        let x = bigInt(normal.dropFirst())
        let ySq = (x.power(3, modulus: p) + BigInt(7)).modulus(p)
        let y0 = ySq.power((p + 1) / 4, modulus: p)
        guard y0.power(BigInt(2), modulus: p) == ySq else { return nil }
        let y0IsOdd = ((y0 & BigInt(1)) == BigInt(1))
        let y = (y0IsOdd != odd) ? (p - y0) : y0
        return (x, y)
    }

    // MARK: - helpers

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
