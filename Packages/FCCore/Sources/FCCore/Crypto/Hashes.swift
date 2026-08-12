import Foundation
import CryptoKit

/// Cryptographic hash functions used throughout Freer.
///
/// SHA-256 uses Apple's CryptoKit. RIPEMD-160 is not in CryptoKit — it is
/// implemented in pure Swift in ``RIPEMD160``.
public enum Hash {

    public static func sha256(_ message: Data) -> Data {
        Data(CryptoKit.SHA256.hash(data: message))
    }

    public static func doubleSha256(_ message: Data) -> Data {
        sha256(sha256(message))
    }

    public static func ripemd160(_ message: Data) -> Data {
        RIPEMD160.digest(message)
    }

    /// Hash-160: RIPEMD-160(SHA-256(x)). Used for Bitcoin-style P2PKH
    /// address derivation, including FCH / FID.
    public static func hash160(_ message: Data) -> Data {
        ripemd160(sha256(message))
    }

    public static func sha1(_ message: Data) -> Data {
        Data(CryptoKit.Insecure.SHA1.hash(data: message))
    }

    public static func md5(_ message: Data) -> Data {
        Data(CryptoKit.Insecure.MD5.hash(data: message))
    }

    /// Keccak-256 — the pre-NIST-padding SHA-3 variant (Ethereum-style).
    /// The Java `Hash.sha3*` helpers are BouncyCastle `Keccak.Digest256`,
    /// *not* NIST SHA3-256; this matches them.
    public static func keccak256(_ message: Data) -> Data {
        Keccak256.digest(message)
    }

    /// HMAC-SHA256 — the FC symmetric message signature
    /// (`Sha256SymSignMsg@No1_NrC7`, post-legacy form).
    public static func hmacSha256(_ message: Data, key: Data) -> Data {
        let mac = CryptoKit.HMAC<CryptoKit.SHA256>.authenticationCode(
            for: message, using: SymmetricKey(data: key)
        )
        return Data(mac)
    }

    /// HMAC-SHA1 — used by TOTP (RFC 6238 with the default SHA-1 PRF).
    public static func hmacSha1(_ message: Data, key: Data) -> Data {
        let mac = CryptoKit.HMAC<CryptoKit.Insecure.SHA1>.authenticationCode(
            for: message, using: SymmetricKey(data: key)
        )
        return Data(mac)
    }
}
