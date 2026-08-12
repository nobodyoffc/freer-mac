import Foundation
import FCCore

/// Password / symkey text encryption in the FC `CryptoDataStr` JSON
/// envelope — the formats Android's Encrypt / Decrypt tools speak
/// (`Encryptor.encryptByPassword` / `encryptBySymkey` with
/// `AesGcm256@No1_NrC7`, and `Decryptor` for the legacy variants).
///
/// Pubkey (AsyOneWay) encryption lives in ``AsyOneWayCipher``; this type
/// routes to it so callers have a single entry point for all three modes.
public enum TextCipher {

    public enum Failure: Error, CustomStringConvertible {
        case badEnvelope
        case badField(String)
        case unsupportedType(String?)
        case unsupportedAlgorithm(String?)
        case decryptFailed

        public var description: String {
            switch self {
            case .badEnvelope:
                return "not a CryptoDataStr JSON envelope"
            case .badField(let f):
                return "envelope field '\(f)' missing or malformed"
            case .unsupportedType(let t):
                return "unsupported cipher type '\(t ?? "<nil>")'"
            case .unsupportedAlgorithm(let a):
                return "unsupported algorithm '\(a ?? "<nil>")'"
            case .decryptFailed:
                return "decryption failed — wrong key or corrupted cipher"
            }
        }
    }

    /// The CryptoDataStr wire fields relevant to text ciphers.
    public struct Envelope: Decodable, Sendable {
        public var type: String?
        public var alg: String?
        public var kdf: String?
        public var cipher: String?
        public var iv: String?
        public var keyName: String?
        public var sum: String?
        public var pubkeyA: String?
    }

    static let algGcm = "AesGcm256@No1_NrC7"
    static let algCbc = "AesCbc256@No1_NrC7"
    static let kdfArgon2id = "Argon2id@No1_NrC7"
    static let kdfLegacySha256 = "Sha256Iv@No1_NrC7"

    // MARK: - Parse

    public static func parse(_ cipherString: String) throws -> Envelope {
        let trimmed = cipherString.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed.hasPrefix("{"),
              let envelope = try? JSONDecoder().decode(Envelope.self, from: Data(trimmed.utf8)) else {
            throw Failure.badEnvelope
        }
        return envelope
    }

    // MARK: - Encrypt (always AES-256-GCM, like Android's Encrypt tool)

    /// Password mode: symkey = Argon2id(password, salt = iv), Freer
    /// parameters (3 iterations, 64 MiB, parallelism 1).
    public static func encryptWithPassword(_ plaintext: Data, password: Data) throws -> String {
        let iv = randomBytes(AesGcm256.nonceLength)
        let symkey = try Argon2.hashID(password: password, salt: iv)
        return try sealEnvelope(plaintext, symkey: symkey, iv: iv, type: "Password", kdf: kdfArgon2id)
    }

    /// Symkey mode: direct AES-256-GCM under a 32-byte key.
    public static func encryptWithSymkey(_ plaintext: Data, symkey: Data) throws -> String {
        guard symkey.count == AesGcm256.keyLength else { throw Failure.badField("symkey") }
        let iv = randomBytes(AesGcm256.nonceLength)
        return try sealEnvelope(plaintext, symkey: symkey, iv: iv, type: "Symkey", kdf: nil)
    }

    /// Pubkey (AsyOneWay) mode — delegates to ``AsyOneWayCipher``.
    public static func encryptWithPubkey(_ plaintext: Data, pubkey: Data) throws -> String {
        try AsyOneWayCipher.encrypt(plaintext: plaintext, toPubkey: pubkey)
    }

    private static func sealEnvelope(
        _ plaintext: Data, symkey: Data, iv: Data, type: String, kdf: String?
    ) throws -> String {
        let box = try AesGcm256.seal(key: symkey, nonce: iv, plaintext: plaintext)
        let cipherB64 = (box.ciphertext + box.tag).base64EncodedString()
        // keyName = first 6 bytes of sha256(symkey) — `makeKeyName`.
        let keyName = Hash.sha256(symkey).prefix(6).fcToolHex
        var fields = [
            "\"type\":\"\(type)\"",
            "\"alg\":\"\(algGcm)\"",
        ]
        if let kdf { fields.append("\"kdf\":\"\(kdf)\"") }
        fields.append("\"cipher\":\"\(cipherB64)\"")
        fields.append("\"keyName\":\"\(keyName)\"")
        fields.append("\"iv\":\"\(iv.fcToolHex)\"")
        return "{\(fields.joined(separator: ","))}"
    }

    // MARK: - Decrypt

    /// Decrypt a Password-type envelope. Honors the stamped `kdf`; when
    /// absent, tries Argon2id first and falls back to the legacy
    /// `sha256(sha256(password) ‖ iv)` derivation — mirroring
    /// `Decryptor.decryptByPassword`.
    public static func decrypt(envelope: Envelope, password: Data) throws -> Data {
        let (alg, iv, cipher) = try symmetricParts(envelope)
        switch envelope.kdf {
        case kdfArgon2id:
            return try open(alg: alg, key: Argon2.hashID(password: password, salt: iv), iv: iv, cipher: cipher)
        case kdfLegacySha256:
            return try open(alg: alg, key: legacyKey(password, iv: iv), iv: iv, cipher: cipher)
        case nil:
            if let plain = try? open(alg: alg, key: Argon2.hashID(password: password, salt: iv), iv: iv, cipher: cipher) {
                return plain
            }
            return try open(alg: alg, key: legacyKey(password, iv: iv), iv: iv, cipher: cipher)
        case .some(let other):
            throw Failure.unsupportedAlgorithm(other)
        }
    }

    /// Decrypt a Symkey-type envelope with a 32-byte key.
    public static func decrypt(envelope: Envelope, symkey: Data) throws -> Data {
        let (alg, iv, cipher) = try symmetricParts(envelope)
        return try open(alg: alg, key: symkey, iv: iv, cipher: cipher)
    }

    private static func legacyKey(_ password: Data, iv: Data) -> Data {
        Hash.sha256(Hash.sha256(password) + iv)
    }

    private static func symmetricParts(_ envelope: Envelope) throws -> (alg: String, iv: Data, cipher: Data) {
        guard let ivHex = envelope.iv, let iv = Data(fcHex: ivHex) else {
            throw Failure.badField("iv")
        }
        guard let cipherB64 = envelope.cipher, let cipher = Data(base64Encoded: cipherB64) else {
            throw Failure.badField("cipher")
        }
        // Missing alg defaults to the CBC scheme, like the Java Decryptor.
        return (envelope.alg ?? algCbc, iv, cipher)
    }

    private static func open(alg: String, key: Data, iv: Data, cipher: Data) throws -> Data {
        switch alg {
        case algGcm:
            guard cipher.count > AesGcm256.tagLength else { throw Failure.badField("cipher") }
            do {
                return try AesGcm256.open(
                    key: key, nonce: iv,
                    ciphertext: cipher.dropLast(AesGcm256.tagLength),
                    tag: cipher.suffix(AesGcm256.tagLength)
                )
            } catch {
                throw Failure.decryptFailed
            }
        case algCbc:
            guard iv.count == 16 else { throw Failure.badField("iv") }
            do {
                return try AsyOneWayCipher.cbcOpen(alg: alg, key: key, iv: iv, cipher: cipher)
            } catch {
                throw Failure.decryptFailed
            }
        default:
            throw Failure.unsupportedAlgorithm(alg)
        }
    }

    static func randomBytes(_ count: Int) -> Data {
        Data((0..<count).map { _ in UInt8.random(in: .min ... .max) })
    }
}
