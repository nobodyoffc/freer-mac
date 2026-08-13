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
///   6 B   algId            a5 ac d7 07 78 05  (first 6 B of the on-chain PID)
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

    /// Bundle prefix written by `seal`: the first 6 bytes (12 hex chars) of
    /// `FC_EccK1AesGcm256_No1_NrC7`'s on-chain protocol PID
    /// (a5acd7077805d3e8ae6ddf7fb9d9ebd52c665942e5096e3d308f66d4cf5e844a).
    /// Must match `ALG_PID_PREFIX_EccK1AesGcm256` in FC-JDK's `CryptoDataByte`.
    public static let algorithmIdEccK1AesGcm256: [UInt8] = [0xa5, 0xac, 0xd7, 0x07, 0x78, 0x05]

    /// Legacy sequential prefix used before the PID-based scheme. FC-JDK's
    /// `fromBundle` still decrypts bundles carrying it, so `open` accepts it
    /// too for backward-compatible reads. `seal` only ever writes the new one.
    public static let legacyAlgorithmIdEccK1AesGcm256: [UInt8] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x04]
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
        guard algId == Data(algorithmIdEccK1AesGcm256)
                || algId == Data(legacyAlgorithmIdEccK1AesGcm256) else {
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

    /// F2: LRU cache for the ECDH shared secret. The secret depends
    /// only on the key pair — not the per-packet IV — so during a bulk
    /// transfer every packet to/from the same peer reuses one ECDH
    /// (~0.8 ms each on this hardware; uncached it dominates transfer
    /// throughput). Cap mirrors the Java repair (512 entries).
    private static let ecdhCache = EcdhCache(capacity: 512)

    /// `symKey = HKDF-SHA512(ikm = ECDH(localPriv, peerPub),
    ///                       salt = iv, info = "hkdf", L = 32)`
    private static func deriveSymKey(localPrivkey: Data, peerPubkey: Data, iv: Data) throws -> Data {
        // Cache key: digest of the pair, so raw private keys are never
        // used as dictionary keys.
        var keyMaterial = Data(capacity: localPrivkey.count + peerPubkey.count)
        keyMaterial.append(localPrivkey)
        keyMaterial.append(peerPubkey)
        let cacheKey = Hash.sha256(keyMaterial)

        let sharedSecret: Data
        if let cached = ecdhCache.lookup(cacheKey) {
            sharedSecret = cached
        } else {
            do {
                sharedSecret = try Secp256k1.sharedSecretX(
                    privateKey: localPrivkey, publicKey: peerPubkey
                )
            } catch {
                throw Failure.ecdhFailed(underlying: error)
            }
            ecdhCache.store(cacheKey, sharedSecret)
        }
        return Hkdf.sha512(
            ikm: sharedSecret,
            salt: iv,
            info: hkdfInfo,
            outputLength: 32
        )
    }
}

/// Bounded LRU for ECDH shared secrets (AsyTwoWay F2).
private final class EcdhCache: @unchecked Sendable {
    private let lock = NSLock()
    private var map: [Data: Data] = [:]
    private var order: [Data] = []
    private let capacity: Int

    init(capacity: Int) {
        self.capacity = capacity
    }

    func lookup(_ key: Data) -> Data? {
        lock.lock(); defer { lock.unlock() }
        guard let value = map[key] else { return nil }
        // Touch: move to most-recently-used. O(entries) but the cap is
        // small and the win (skipping an EC multiply) is three orders
        // of magnitude larger.
        if let idx = order.firstIndex(of: key) {
            order.remove(at: idx)
            order.append(key)
        }
        return value
    }

    func store(_ key: Data, _ value: Data) {
        lock.lock(); defer { lock.unlock() }
        if map[key] == nil {
            order.append(key)
            if order.count > capacity {
                let evicted = order.removeFirst()
                map.removeValue(forKey: evicted)
            }
        }
        map[key] = value
    }
}
