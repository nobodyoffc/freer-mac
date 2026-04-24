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
}
