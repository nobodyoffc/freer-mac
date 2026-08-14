import Foundation
import CommonCrypto
import CryptoKit
import FCCore

/// One row of the on-chain `contact` index as returned by `base.search`.
/// Mirrors the wire fields of the Java `feipData.Contact` *before*
/// `parseDetail` runs: the human-readable detail (fid / titles / memo /
/// seeStatement / seeWritings) is inside `cipher`, encrypted to the
/// owner's own pubkey when the contact was carved.
public struct OnChainContactRecord: Decodable, Sendable {
    /// sha256x2 of the carve — NOT the contact's FID. The FID only
    /// becomes known after decrypting `cipher`.
    public var id: String?
    public var alg: String?
    public var cipher: String?
    public var owner: String?
    public var birthTime: Int64?
    public var lastHeight: Int64?
    public var active: Bool?
}

/// The decrypted payload of an ``OnChainContactRecord/cipher`` — what
/// the Android client serialized before encrypting (`makeAddContactFeip`
/// in `ContactActivity.java`): a `feipData.Contact` carrying only the
/// editable detail block.
struct OnChainContactDetail: Decodable {
    var fid: String?
    var titles: [String]?
    var memo: String?
    var seeStatement: Bool?
    var seeWritings: Bool?
}

/// Decryptor for the FC "CryptoData" cipher in AsyOneWay mode — the
/// formats Android's `Decryptor.decryptTry(...)` accepts for on-chain
/// contact/secret payloads (see `FC-AJDK/.../core/crypto/`):
///
///   - a **CryptoDataStr JSON envelope** (`{"type":"AsyOneWay","alg":…,
///     "cipher":"<base64>","pubkeyA":"<hex>","iv":"<hex>",…}`), or
///   - a **binary bundle**, base64-encoded (6 B alg-PID prefix · 1 B
///     type · 33 B pubkeyA · iv · ciphertext · optional 4 B sum).
///
/// Supported algorithms, mirroring `Decryptor.decryptByAsyKey`:
///
/// | alg (display name) | KDF | cipher |
/// |---|---|---|
/// | `EccK1AesGcm256@No1_NrC7` | HKDF-SHA512(ikm: ECDH.x 32 B, salt: iv, info: "hkdf") | AES-256-GCM, 12 B iv, tag appended |
/// | `EccK1AesCbc256@No1_NrC7` | SHA-512(iv ‖ ECDH.x*)[0..<32] | AES-256-CBC/PKCS7, 16 B iv |
/// | `EccAes256K1P7@No1_NrC7` (or alg absent) | SHA-256²(SHA-256(ECDH.x*) ‖ iv) | AES-256-CBC/PKCS7, 16 B iv |
///
/// `ECDH.x*` = the x-coordinate encoded like Java's
/// `BigInteger.toByteArray()` — minimal big-endian, leading zeros
/// stripped, one 0x00 re-prepended when the top bit is set. The GCM
/// scheme instead right-aligns into a fixed 32 bytes (`Ecc256K1Hkdf`).
public enum AsyOneWayCipher {

    public enum Failure: Error, CustomStringConvertible {
        case badEnvelope(underlying: Error)
        case badBundle
        case unsupportedAlgorithm(String?)
        case badField(String)
        case decryptFailed(alg: String, underlying: Error)
        case plaintextNotJson(alg: String)
        case badSum(alg: String)

        public var description: String {
            switch self {
            case .badEnvelope(let e):
                return "cipher is neither CryptoDataStr JSON nor a known bundle — \(e)"
            case .badBundle:
                return "base64 bundle is malformed or its algorithm prefix is unknown"
            case .unsupportedAlgorithm(let alg):
                return "unsupported algorithm '\(alg ?? "<nil>")'"
            case .badField(let f):
                return "field '\(f)' missing or malformed"
            case let .decryptFailed(alg, e):
                return "decryption failed (alg=\(alg)) — \(e)"
            case .plaintextNotJson(let alg):
                return "decrypted plaintext is not the expected JSON (alg=\(alg)) — wrong key?"
            case .badSum(let alg):
                return "checksum mismatch (alg=\(alg)) — the ciphertext was altered or the key is wrong"
            }
        }
    }

    struct Envelope: Decodable {
        var type: String?
        var alg: String?
        var cipher: String?
        var pubkeyA: String?
        /// Only present on AsyTwoWay envelopes, where the sender's key is
        /// real rather than ephemeral and both sides must be recorded —
        /// see ``AsyTwoWayCipher``.
        var pubkeyB: String?
        var iv: String?
        /// `sha256(symkey ‖ iv ‖ sha256x2(plaintext))[0..<4]`, emitted by
        /// the Java encryptor for the non-AEAD algorithms only.
        var sum: String?
    }

    // Display names the Java `AlgorithmId` serializes to.
    static let algGcm = "EccK1AesGcm256@No1_NrC7"
    static let algCbc = "EccK1AesCbc256@No1_NrC7"
    static let algP7  = "EccAes256K1P7@No1_NrC7"

    // Bundle prefixes (first 6 bytes of each algorithm's on-chain PID,
    // plus the legacy sequential ids) → display name. Only the Asy
    // variants matter for AsyOneWay payloads.
    static let bundleAlgByPrefix: [String: String] = [
        "3ea47cd61381": algCbc, "000000000002": algCbc,
        "a5acd7077805": algGcm, "000000000004": algGcm,
    ]

    /// Encrypt `plaintext` to `pubkeyB` in AsyOneWay mode and return
    /// the CryptoDataStr JSON envelope — the exact string Android's
    /// `new Encryptor(FC_EccK1AesGcm256_No1_NrC7)
    ///     .encryptStrByAsyOneWay(data, pubkey).toJson()` produces
    /// (modulo JSON key order, which every parser in the ecosystem
    /// ignores): a fresh ephemeral secp256k1 keypair per call, random
    /// 12-byte GCM iv, symkey = HKDF-SHA512(ECDH.x, salt: iv,
    /// info: "hkdf"), `cipher` = base64(ciphertext ‖ tag). GCM carries
    /// its own authentication, so — like the Java encryptor — no `sum`
    /// field is emitted.
    public static func encrypt(plaintext: Data, toPubkey pubkeyB: Data) throws -> String {
        guard pubkeyB.count == 33 else { throw Failure.badField("pubkeyB") }

        // Ephemeral scalar. SystemRandomNumberGenerator is
        // cryptographically secure; the retry handles the ~2^-128
        // chance of landing outside [1, n-1].
        var ephemeralPrivkey: Data
        var pubkeyA: Data
        while true {
            ephemeralPrivkey = Data((0..<32).map { _ in UInt8.random(in: .min ... .max) })
            if let pk = try? Secp256k1.publicKey(fromPrivateKey: ephemeralPrivkey) {
                pubkeyA = pk
                break
            }
        }
        defer { ephemeralPrivkey.resetBytes(in: 0..<ephemeralPrivkey.count) }

        let iv = Data((0..<AesGcm256.nonceLength).map { _ in UInt8.random(in: .min ... .max) })
        let x = try Secp256k1.sharedSecretX(privateKey: ephemeralPrivkey, publicKey: pubkeyB)
        let symkey = Hkdf.sha512(
            ikm: x, salt: iv,
            info: Data("hkdf".utf8),
            outputLength: AesGcm256.keyLength
        )
        let box = try AesGcm256.seal(key: symkey, nonce: iv, plaintext: plaintext)

        // base64 and hex never contain characters that need JSON
        // escaping, so the envelope can be assembled literally — in
        // the Java field-declaration order for byte-familiarity.
        let cipherB64 = (box.ciphertext + box.tag).base64EncodedString()
        let pubkeyAHex = pubkeyA.map { String(format: "%02x", $0) }.joined()
        let ivHex = iv.map { String(format: "%02x", $0) }.joined()
        return #"{"type":"AsyOneWay","alg":"\#(algGcm)","cipher":"\#(cipherB64)","pubkeyA":"\#(pubkeyAHex)","iv":"\#(ivHex)"}"#
    }

    /// Decrypt an on-chain AsyOneWay cipher string (JSON envelope or
    /// base64 bundle) with the recipient's 32-byte privkey. Returns
    /// the plaintext bytes.
    public static func decrypt(cipherString: String, privkey: Data) throws -> Data {
        let trimmed = cipherString.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.hasPrefix("{") {
            let env: Envelope
            do {
                env = try JSONDecoder().decode(Envelope.self, from: Data(trimmed.utf8))
            } catch {
                throw Failure.badEnvelope(underlying: error)
            }
            guard let pubkeyAHex = env.pubkeyA, let pubkeyA = Data(fcHex: pubkeyAHex) else {
                throw Failure.badField("pubkeyA")
            }
            guard let ivHex = env.iv, let iv = Data(fcHex: ivHex) else {
                throw Failure.badField("iv")
            }
            guard let cipherB64 = env.cipher,
                  let cipher = Data(base64Encoded: cipherB64) else {
                throw Failure.badField("cipher")
            }
            // Android defaults a missing alg to the legacy P7 scheme
            // (`Decryptor.decryptByAsyKey`).
            return try decryptParts(
                alg: env.alg ?? algP7,
                pubkeyA: pubkeyA, iv: iv, cipher: cipher,
                privkey: privkey,
                sum: env.sum.flatMap { Data(fcHex: $0) }
            )
        }

        // Bundle path: Android tries this for any base64-looking cipher
        // (`decryptBundleTry`). Layout per `CryptoDataByte.toBundle`.
        guard let bundle = Data(base64Encoded: trimmed) else {
            throw Failure.badEnvelope(underlying: Failure.badBundle)
        }
        guard bundle.count > 6 + 1 + 33 else { throw Failure.badBundle }
        let prefixHex = bundle.prefix(6).map { String(format: "%02x", $0) }.joined()
        guard let alg = bundleAlgByPrefix[prefixHex] else {
            throw Failure.badBundle
        }
        // type byte: 1 = AsyOneWay, 2 = AsyTwoWay — both carry pubkeyA next.
        let typeByte = bundle[bundle.startIndex + 6]
        guard typeByte == 1 || typeByte == 2 else { throw Failure.badBundle }
        var offset = bundle.startIndex + 7
        let pubkeyA = bundle[offset..<(offset + 33)]
        offset += 33
        let ivLen = (alg == algGcm) ? 12 : 16
        // CBC bundles end with a 4-byte sum; GCM's tag is inside cipher.
        let sumLen = (alg == algGcm) ? 0 : 4
        guard bundle.endIndex - offset > ivLen + sumLen else { throw Failure.badBundle }
        let iv = bundle[offset..<(offset + ivLen)]
        offset += ivLen
        let cipher = bundle[offset..<(bundle.endIndex - sumLen)]
        return try decryptParts(
            alg: alg,
            pubkeyA: Data(pubkeyA), iv: Data(iv), cipher: Data(cipher),
            privkey: privkey,
            sum: sumLen == 0 ? nil : Data(bundle.suffix(sumLen))
        )
    }

    /// - Parameter sum: the envelope's `sum`, when it carried one. Only the
    ///   non-AEAD algorithms emit it, and it is the only integrity check they
    ///   have — CBC will happily "decrypt" a tampered ciphertext into garbage
    ///   whenever the corrupted final block still unpads.
    static func decryptParts(
        alg: String,
        pubkeyA: Data,
        iv: Data,
        cipher: Data,
        privkey: Data,
        sum: Data? = nil
    ) throws -> Data {
        guard pubkeyA.count == 33 else { throw Failure.badField("pubkeyA") }
        let x: Data
        do {
            x = try Secp256k1.sharedSecretX(privateKey: privkey, publicKey: pubkeyA)
        } catch {
            throw Failure.decryptFailed(alg: alg, underlying: error)
        }

        switch alg {
        case algGcm:
            guard iv.count == AesGcm256.nonceLength else { throw Failure.badField("iv") }
            guard cipher.count > AesGcm256.tagLength else { throw Failure.badField("cipher") }
            // Ecc256K1Hkdf: fixed 32-byte x → HKDF-SHA512, salt = iv.
            let symkey = Hkdf.sha512(
                ikm: x, salt: iv,
                info: Data("hkdf".utf8),
                outputLength: AesGcm256.keyLength
            )
            do {
                return try AesGcm256.open(
                    key: symkey, nonce: iv,
                    ciphertext: cipher.dropLast(AesGcm256.tagLength),
                    tag: cipher.suffix(AesGcm256.tagLength)
                )
            } catch {
                throw Failure.decryptFailed(alg: alg, underlying: error)
            }

        case algCbc:
            guard iv.count == 16 else { throw Failure.badField("iv") }
            // Ecc256K1.sharedSecretToSymkey: SHA-512(iv ‖ secret)[0..<32],
            // secret in BigInteger minimal encoding.
            let symkey = Data(Data(SHA512.hash(data: iv + bigIntMinimal(x))).prefix(32))
            let plaintext = try cbcOpen(alg: alg, key: symkey, iv: iv, cipher: cipher)
            try verifySum(sum, alg: alg, symkey: symkey, iv: iv, plaintext: plaintext)
            return plaintext

        case algP7:
            guard iv.count == 16 else { throw Failure.badField("iv") }
            // EccAes256K1P7.asyKeyToSymkey:
            // sha256(sha256(sha256(secret) ‖ iv)).
            let symkey = Hash.sha256(Hash.sha256(Hash.sha256(bigIntMinimal(x)) + iv))
            // No sum check: this legacy algorithm computes its sum over the
            // *ciphertext* via `EccAes256K1P7.getSum4`, not over the plaintext
            // did, so `verifySum` would reject every valid P7 payload.
            return try cbcOpen(alg: alg, key: symkey, iv: iv, cipher: cipher)

        default:
            throw Failure.unsupportedAlgorithm(alg)
        }
    }

    /// Java `CryptoDataByte.makeSum4`: `sha256(symkey ‖ iv ‖ did)[0..<4]`
    /// where `did = sha256x2(plaintext)`. A no-op when the envelope carried
    /// no `sum` — the AEAD algorithms omit it because the tag already covers
    /// integrity, and Java's own `checkSum` short-circuits to true for them.
    static func verifySum(
        _ sum: Data?, alg: String, symkey: Data, iv: Data, plaintext: Data
    ) throws {
        guard let sum, !sum.isEmpty else { return }
        let expected = Hash.sha256(symkey + iv + Hash.doubleSha256(plaintext)).prefix(4)
        guard Data(expected) == sum else { throw Failure.badSum(alg: alg) }
    }

    /// Java `BigInteger.toByteArray()` of a positive 256-bit value:
    /// minimal big-endian — leading zero bytes stripped, one 0x00
    /// re-prepended when the top remaining bit is set.
    static func bigIntMinimal(_ fixed: Data) -> Data {
        var bytes = Data(fixed.drop(while: { $0 == 0 }))
        if bytes.isEmpty { bytes = Data([0]) }
        if bytes[bytes.startIndex] & 0x80 != 0 {
            bytes.insert(0, at: bytes.startIndex)
        }
        return bytes
    }

    /// AES-256-CBC with PKCS7 padding via CommonCrypto. CBC has no
    /// authentication — a wrong key usually (255/256) fails the unpad,
    /// and callers additionally validate the plaintext shape (JSON).
    static func cbcOpen(alg: String, key: Data, iv: Data, cipher: Data) throws -> Data {
        var out = Data(count: cipher.count + kCCBlockSizeAES128)
        var moved = 0
        let status = out.withUnsafeMutableBytes { ob in
            key.withUnsafeBytes { kb in
                iv.withUnsafeBytes { ivb in
                    cipher.withUnsafeBytes { cb in
                        CCCrypt(
                            CCOperation(kCCDecrypt),
                            CCAlgorithm(kCCAlgorithmAES),
                            CCOptions(kCCOptionPKCS7Padding),
                            kb.baseAddress, key.count,
                            ivb.baseAddress,
                            cb.baseAddress, cipher.count,
                            ob.baseAddress, ob.count,
                            &moved
                        )
                    }
                }
            }
        }
        guard status == kCCSuccess else {
            throw Failure.decryptFailed(
                alg: alg,
                underlying: NSError(
                    domain: "CommonCrypto", code: Int(status),
                    userInfo: [NSLocalizedDescriptionKey: "CCCrypt status \(status)"]
                )
            )
        }
        return out.prefix(moved)
    }
}

extension Data {
    /// Strict hex → bytes. Returns nil on odd length or any non-hex
    /// character.
    init?(fcHex s: String) {
        guard s.count % 2 == 0 else { return nil }
        var data = Data(capacity: s.count / 2)
        var idx = s.startIndex
        while idx < s.endIndex {
            let next = s.index(idx, offsetBy: 2)
            guard let b = UInt8(s[idx..<next], radix: 16) else { return nil }
            data.append(b)
            idx = next
        }
        self = data
    }
}
