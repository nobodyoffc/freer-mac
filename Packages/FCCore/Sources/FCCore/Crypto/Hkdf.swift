import Foundation
import CryptoKit

/// HMAC-based Key Derivation Function (RFC 5869) over SHA-256 or SHA-512.
///
/// The Android reference uses HKDF-SHA512 (see `FC-AJDK/.../core/crypto/HKDF.java`
/// — the class is named "HKDF" but internally drives HMAC-SHA512). Both
/// variants are exposed here; pick based on the call site's convention.
public enum Hkdf {

    public static func sha256(ikm: Data, salt: Data, info: Data, outputLength: Int) -> Data {
        let derived = CryptoKit.HKDF<CryptoKit.SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: ikm),
            salt: salt,
            info: info,
            outputByteCount: outputLength
        )
        return derived.withUnsafeBytes { Data($0) }
    }

    public static func sha512(ikm: Data, salt: Data, info: Data, outputLength: Int) -> Data {
        let derived = CryptoKit.HKDF<CryptoKit.SHA512>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: ikm),
            salt: salt,
            info: info,
            outputByteCount: outputLength
        )
        return derived.withUnsafeBytes { Data($0) }
    }
}
