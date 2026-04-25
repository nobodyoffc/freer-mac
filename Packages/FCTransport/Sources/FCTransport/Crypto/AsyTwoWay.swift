import Foundation
import FCCore

/// FUDP packet payload encryption: AsyTwoWay over secp256k1 + AES-256-GCM.
///
/// **Key idea (FUDP differs from TLS/QUIC here):** the sender's public
/// key on the wire is the sender's *long-term identity pubkey*, not an
/// ephemeral one. Receiving a valid bundle from sender X proves it was
/// encrypted by someone holding X's identity privkey, because only they
/// can derive the matching shared secret. Authentication and encryption
/// are the same primitive — no handshake, no separate signature.
///
/// Trade-off: no forward secrecy (compromise of identity key reveals all
/// past traffic). Accepted by design — identity *is* the authority.
///
/// Bundle layout (`FC_EccK1AesGcm256_No1_NrC7` + `EncryptType.AsyTwoWay`):
/// ```
///   6 B   algId            00 00 00 00 00 04
///   1 B   encryptType      02 (AsyTwoWay)
///  33 B   senderPubkey     compressed secp256k1
///  12 B   iv               AES-GCM nonce (caller-supplied; production = random per call)
///   N B   cipher           AES-GCM ciphertext (last 16 bytes = tag)
/// ```
///
/// Symmetric key derivation:
/// ```
///   sharedSecret = ECDH(localPriv, peerPub)        (raw 32-byte X)
///   symKey       = HKDF-SHA512(ikm = sharedSecret,
///                              salt = iv,
///                              info = "hkdf",
///                              L = 32)
/// ```
///
/// Per FUDP v2 F1, the 21-byte packet header is bound as AEAD AAD on
/// every encrypted data/ACK packet. `aad` parameter here is that header.
public enum AsyTwoWay {

    public static let algorithmIdEccK1AesGcm256: [UInt8] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x04]
    public static let encryptTypeAsyTwoWay: UInt8 = 0x02
    public static let pubkeyLength = 33
    public static let ivLength = 12
    public static let tagLength = 16
    public static let headerOverhead = 6 + 1 + pubkeyLength + ivLength  // = 52
    public static let minBundleSize = headerOverhead + tagLength       // = 68

    /// HKDF info string. Must match `CryptoManager.HKDF_INFO` in FC-JDK.
    public static let hkdfInfo: Data = Data("hkdf".utf8)

    public enum Failure: Error, CustomStringConvertible {
        case invalidIvLength(got: Int)
        case invalidPubkeyLength(got: Int)
        case bundleTooShort(got: Int)
        case unknownAlgorithmId(prefix: Data)
        case unknownEncryptType(byte: UInt8)
        case decryptionFailed
        case ecdhFailed(underlying: Error)

        public var description: String {
            switch self {
            case .invalidIvLength(let got):
                return "AsyTwoWay: IV must be \(AsyTwoWay.ivLength) bytes, got \(got)"
            case .invalidPubkeyLength(let got):
                return "AsyTwoWay: pubkey must be \(AsyTwoWay.pubkeyLength) bytes, got \(got)"
            case .bundleTooShort(let got):
                return "AsyTwoWay: bundle must be ≥ \(AsyTwoWay.minBundleSize) bytes, got \(got)"
            case .unknownAlgorithmId(let prefix):
                return "AsyTwoWay: unsupported algorithm id \(prefix.map { String(format: "%02x", $0) }.joined())"
            case .unknownEncryptType(let byte):
                return String(format: "AsyTwoWay: unsupported encrypt type 0x%02x", byte)
            case .decryptionFailed:
                return "AsyTwoWay: decryption failed (tampered bundle, wrong recipient, or AAD mismatch)"
            case .ecdhFailed(let underlying):
                return "AsyTwoWay: ECDH failed — \(underlying)"
            }
        }
    }

    /// Encrypt `plaintext` for `peerPubkey` using `localPrivkey` (and its
    /// derived `localPubkey`, included in the bundle as the sender's
    /// identity).
    ///
    /// Caller is responsible for supplying a fresh `iv` (12 bytes); reusing
    /// an `(symKey, iv)` pair completely breaks AES-GCM.
    public static func seal(
        plaintext: Data,
        aad: Data,
        peerPubkey: Data,
        localPrivkey: Data,
        localPubkey: Data,
        iv: Data
    ) throws -> Data {
        guard iv.count == ivLength else { throw Failure.invalidIvLength(got: iv.count) }
        guard peerPubkey.count == pubkeyLength else {
            throw Failure.invalidPubkeyLength(got: peerPubkey.count)
        }
        guard localPubkey.count == pubkeyLength else {
            throw Failure.invalidPubkeyLength(got: localPubkey.count)
        }

        let symKey = try deriveSymKey(localPrivkey: localPrivkey, peerPubkey: peerPubkey, iv: iv)
        let sealed: Aead.SealedBox
        do {
            sealed = try AesGcm256.seal(key: symKey, nonce: iv, plaintext: plaintext, aad: aad)
        } catch {
            throw Failure.decryptionFailed  // shouldn't happen on encrypt; defensive
        }

        var bundle = Data(capacity: minBundleSize + plaintext.count)
        bundle.append(contentsOf: algorithmIdEccK1AesGcm256)
        bundle.append(encryptTypeAsyTwoWay)
        bundle.append(localPubkey)
        bundle.append(iv)
        bundle.append(sealed.ciphertext)
        bundle.append(sealed.tag)
        return bundle
    }

    /// Decrypt a bundle directed at `localPrivkey`. Returns the sender's
    /// identity pubkey (extracted from the bundle) plus the plaintext.
    public static func open(
        bundle: Data,
        aad: Data,
        localPrivkey: Data
    ) throws -> (senderPubkey: Data, plaintext: Data) {
        guard bundle.count >= minBundleSize else {
            throw Failure.bundleTooShort(got: bundle.count)
        }
        let bytes = [UInt8](bundle)

        // 6B algId
        let algIdEnd = 6
        let algId = Data(bytes[0..<algIdEnd])
        guard algId == Data(algorithmIdEccK1AesGcm256) else {
            throw Failure.unknownAlgorithmId(prefix: algId)
        }

        // 1B type
        let typeByte = bytes[algIdEnd]
        guard typeByte == encryptTypeAsyTwoWay else {
            throw Failure.unknownEncryptType(byte: typeByte)
        }

        // 33B sender pubkey
        let pubkeyStart = algIdEnd + 1
        let pubkeyEnd = pubkeyStart + pubkeyLength
        let senderPubkey = Data(bytes[pubkeyStart..<pubkeyEnd])

        // 12B iv
        let ivEnd = pubkeyEnd + ivLength
        let iv = Data(bytes[pubkeyEnd..<ivEnd])

        // remaining: ciphertext || tag
        let cipherEnd = bytes.count - tagLength
        guard cipherEnd >= ivEnd else {
            throw Failure.bundleTooShort(got: bundle.count)
        }
        let ciphertext = Data(bytes[ivEnd..<cipherEnd])
        let tag = Data(bytes[cipherEnd..<bytes.count])

        let symKey = try deriveSymKey(localPrivkey: localPrivkey, peerPubkey: senderPubkey, iv: iv)
        let plaintext: Data
        do {
            plaintext = try AesGcm256.open(
                key: symKey, nonce: iv,
                ciphertext: ciphertext, tag: tag, aad: aad
            )
        } catch {
            throw Failure.decryptionFailed
        }
        return (senderPubkey, plaintext)
    }

    // MARK: - key derivation

    /// `symKey = HKDF-SHA512(ikm = ECDH(localPriv, peerPub),
    ///                       salt = iv, info = "hkdf", L = 32)`
    private static func deriveSymKey(localPrivkey: Data, peerPubkey: Data, iv: Data) throws -> Data {
        let sharedSecret: Data
        do {
            sharedSecret = try Secp256k1.sharedSecretX(
                privateKey: localPrivkey, publicKey: peerPubkey
            )
        } catch {
            throw Failure.ecdhFailed(underlying: error)
        }
        return Hkdf.sha512(
            ikm: sharedSecret,
            salt: iv,
            info: hkdfInfo,
            outputLength: 32
        )
    }
}
