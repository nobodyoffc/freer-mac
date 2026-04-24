import Foundation
import CryptoKit

/// Authenticated-encryption namespace. Holds the shared ``SealedBox`` type
/// and error cases used by both ``AesGcm256`` and ``ChaChaPoly``.
public enum Aead {

    /// Output of a `seal` call. `ciphertext` excludes the authentication tag;
    /// `tag` is the 16-byte tag produced by the underlying AEAD.
    public struct SealedBox: Equatable, Sendable {
        public let ciphertext: Data
        public let tag: Data
    }

    public enum Failure: Error, CustomStringConvertible {
        case invalidKeyLength(expected: Int, got: Int)
        case invalidNonceLength(expected: Int, got: Int)
        case authenticationFailed

        public var description: String {
            switch self {
            case let .invalidKeyLength(expected, got):
                return "AEAD key must be \(expected) bytes, got \(got)"
            case let .invalidNonceLength(expected, got):
                return "AEAD nonce must be \(expected) bytes, got \(got)"
            case .authenticationFailed:
                return "AEAD authentication failed"
            }
        }
    }
}

/// AES-256 in Galois/Counter Mode. 12-byte nonce, 16-byte tag.
///
/// Wraps CryptoKit's ``AES.GCM`` with explicit-length checks and a
/// narrow error type. The nonce must never be reused with the same key —
/// callers are responsible for generating a fresh random nonce per seal.
public enum AesGcm256 {
    public static let keyLength = 32
    public static let nonceLength = 12
    public static let tagLength = 16

    public static func seal(
        key: Data,
        nonce: Data,
        plaintext: Data,
        aad: Data = Data()
    ) throws -> Aead.SealedBox {
        guard key.count == keyLength else {
            throw Aead.Failure.invalidKeyLength(expected: keyLength, got: key.count)
        }
        guard nonce.count == nonceLength else {
            throw Aead.Failure.invalidNonceLength(expected: nonceLength, got: nonce.count)
        }
        let symKey = SymmetricKey(data: key)
        let gcmNonce = try AES.GCM.Nonce(data: nonce)
        let box = try AES.GCM.seal(plaintext, using: symKey, nonce: gcmNonce, authenticating: aad)
        return Aead.SealedBox(ciphertext: box.ciphertext, tag: box.tag)
    }

    public static func open(
        key: Data,
        nonce: Data,
        ciphertext: Data,
        tag: Data,
        aad: Data = Data()
    ) throws -> Data {
        guard key.count == keyLength else {
            throw Aead.Failure.invalidKeyLength(expected: keyLength, got: key.count)
        }
        guard nonce.count == nonceLength else {
            throw Aead.Failure.invalidNonceLength(expected: nonceLength, got: nonce.count)
        }
        let symKey = SymmetricKey(data: key)
        let box = try AES.GCM.SealedBox(
            nonce: AES.GCM.Nonce(data: nonce),
            ciphertext: ciphertext,
            tag: tag
        )
        do {
            return try AES.GCM.open(box, using: symKey, authenticating: aad)
        } catch {
            throw Aead.Failure.authenticationFailed
        }
    }
}

/// ChaCha20-Poly1305 AEAD. 32-byte key, 12-byte nonce, 16-byte tag.
///
/// Wraps CryptoKit's ``CryptoKit/ChaChaPoly``. Same nonce-uniqueness
/// requirement as ``AesGcm256``.
public enum ChaChaPoly {
    public static let keyLength = 32
    public static let nonceLength = 12
    public static let tagLength = 16

    public static func seal(
        key: Data,
        nonce: Data,
        plaintext: Data,
        aad: Data = Data()
    ) throws -> Aead.SealedBox {
        guard key.count == keyLength else {
            throw Aead.Failure.invalidKeyLength(expected: keyLength, got: key.count)
        }
        guard nonce.count == nonceLength else {
            throw Aead.Failure.invalidNonceLength(expected: nonceLength, got: nonce.count)
        }
        let symKey = SymmetricKey(data: key)
        let ccNonce = try CryptoKit.ChaChaPoly.Nonce(data: nonce)
        let box = try CryptoKit.ChaChaPoly.seal(
            plaintext,
            using: symKey,
            nonce: ccNonce,
            authenticating: aad
        )
        return Aead.SealedBox(ciphertext: box.ciphertext, tag: box.tag)
    }

    public static func open(
        key: Data,
        nonce: Data,
        ciphertext: Data,
        tag: Data,
        aad: Data = Data()
    ) throws -> Data {
        guard key.count == keyLength else {
            throw Aead.Failure.invalidKeyLength(expected: keyLength, got: key.count)
        }
        guard nonce.count == nonceLength else {
            throw Aead.Failure.invalidNonceLength(expected: nonceLength, got: nonce.count)
        }
        let symKey = SymmetricKey(data: key)
        let box = try CryptoKit.ChaChaPoly.SealedBox(
            nonce: CryptoKit.ChaChaPoly.Nonce(data: nonce),
            ciphertext: ciphertext,
            tag: tag
        )
        do {
            return try CryptoKit.ChaChaPoly.open(box, using: symKey, authenticating: aad)
        } catch {
            throw Aead.Failure.authenticationFailed
        }
    }
}
