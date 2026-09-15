import Foundation
import FCCore

/// The **binary** CryptoDataByte envelope — Java's
/// `CryptoDataByte.toBundle()` / `fromBundle(byte[])`, specified by FTSP30.
///
/// The JSON `CryptoDataStr` envelopes in ``AsyTwoWayCipher`` and
/// ``TextCipher`` carry the same cryptographic material, in the same
/// algorithms, wrapped in JSON with every field hex- or base64-encoded.
/// That is fine for an on-chain record, which is text anyway. It is
/// expensive for an IM body, which is already binary: the JSON envelope
/// plus base64 costs roughly a third of the payload on top of a payload
/// that was raw bytes to begin with.
///
/// FIMP v2 seals message bodies with this form instead. The layout is
/// fixed-width and positional — there are no field names, so nothing is
/// escaped and nothing is expanded:
///
/// ```
///   alg      6 bytes   first 6 bytes of the algorithm's on-chain PID
///   type     1 byte    0 Symkey, 1 AsyOneWay, 2 AsyTwoWay,
///                      3 Password (no KDF recorded), 4 Password + kdfId
///   pubkeyA  33 bytes  only for AsyOneWay / AsyTwoWay (32 for X25519)
///   keyName  6 bytes   only for Symkey — sha256(symkey)[0..<6]
///   kdfId    1 byte    only for type 4 — ``KdfKind/bundleId``
///   iv       12 bytes  GCM and ChaCha; 16 for CBC
///   cipher   rest      for AEAD profiles, ciphertext ‖ 16-byte tag
///   sum      4 bytes   only for non-AEAD profiles (32 for BitCore)
/// ```
///
/// Overhead is 52 bytes for AsyTwoWay and 25 for Symkey, against ~200
/// plus 33% for the JSON forms.
///
/// **Parsing covers every FTSP30 layout**, legacy algorithm prefixes
/// included, so a bundle from any conforming writer is either understood or
/// rejected with a reason. **Opening is narrower:** AES-256-GCM and
/// AES-256-CBC for Symkey and Password, EccK1AesGcm256 for the asymmetric
/// types. Everything sealed here is GCM.
///
/// **An AsyTwoWay bundle records only `pubkeyA`.** The JSON envelope
/// carries both pubkeys, which is what lets a sender reopen their own
/// outbox copy; the bundle does not, so a sender cannot decrypt what they
/// sealed. That is not a regression in practice — ``MessagesStore`` keeps
/// our own messages as plaintext and never re-reads them off the wire —
/// but it is why ``open(bundle:privkey:)`` ECDHs against `pubkeyA`
/// unconditionally instead of doing the side-selection
/// ``AsyTwoWayCipher/counterparty(env:myPubkey:)`` does.
public enum CryptoBundle {

    // MARK: - constants

    /// Whether ``sealPassword(plaintext:password:)`` records its KDF (type 4)
    /// rather than writing legacy type 3. On since the release after every
    /// reader we exchange bundles with learned type 4 (FTSP30).
    static let writePasswordBundleWithKdf = true

    /// How one FTSP30 algorithm frames its bundle.
    struct Algorithm: Equatable {
        /// The `AlgorithmId` display name, as in CryptoDataStr JSON.
        let name: String
        /// First 12 hex chars of the on-chain PID — `ALG_PID_PREFIX_*` in `CryptoDataByte`.
        let prefix: String
        /// The sequential prefix older writers used. Read, never written.
        let legacyPrefix: String?
        let ivLength: Int
        /// 0 for AEAD profiles, whose tag is part of `cipher`.
        let sumLength: Int
        let pubkeyLength: Int
    }

    static let algorithms: [Algorithm] = [
        Algorithm(name: "AesCbc256@No1_NrC7", prefix: "51515d32878c", legacyPrefix: "000000000001", ivLength: 16, sumLength: 4, pubkeyLength: 33),
        Algorithm(name: "EccK1AesCbc256@No1_NrC7", prefix: "3ea47cd61381", legacyPrefix: "000000000002", ivLength: 16, sumLength: 4, pubkeyLength: 33),
        Algorithm(name: "AesGcm256@No1_NrC7", prefix: "76f7b226a8b3", legacyPrefix: "000000000003", ivLength: 12, sumLength: 0, pubkeyLength: 33),
        Algorithm(name: "EccK1AesGcm256@No1_NrC7", prefix: "a5acd7077805", legacyPrefix: "000000000004", ivLength: 12, sumLength: 0, pubkeyLength: 33),
        Algorithm(name: "X25519AesGcm256@No1_NrC7", prefix: "b4a25b3c3043", legacyPrefix: "000000000005", ivLength: 12, sumLength: 0, pubkeyLength: 32),
        Algorithm(name: "ChaCha20@No1_NrC7", prefix: "bcc39a9628e2", legacyPrefix: "000000000006", ivLength: 12, sumLength: 4, pubkeyLength: 33),
        Algorithm(name: "EccK1ChaCha20@No1_NrC7", prefix: "355319f84bd5", legacyPrefix: "000000000007", ivLength: 12, sumLength: 4, pubkeyLength: 33),
        Algorithm(name: "ChaCha20Poly1305@No1_NrC7", prefix: "b1788c3b7320", legacyPrefix: "000000000008", ivLength: 12, sumLength: 0, pubkeyLength: 33),
        Algorithm(name: "EccK1ChaCha20Poly1305@No1_NrC7", prefix: "d1691132aee1", legacyPrefix: "000000000009", ivLength: 12, sumLength: 0, pubkeyLength: 33),
        Algorithm(name: "ECC256k1-AES256CBC", prefix: "e308bc027946", legacyPrefix: nil, ivLength: 16, sumLength: 32, pubkeyLength: 33),
    ]

    static let aesGcm256 = algorithm(named: "AesGcm256@No1_NrC7")
    static let aesCbc256 = algorithm(named: "AesCbc256@No1_NrC7")
    static let eccK1AesGcm256 = algorithm(named: "EccK1AesGcm256@No1_NrC7")

    static let algPrefixAesGcm256 = aesGcm256.prefix
    static let algPrefixEccK1AesGcm256 = eccK1AesGcm256.prefix

    /// `EncryptType`'s wire numbers. Symkey is 0, so a bundle's type byte
    /// is not a presence flag — it has to be read as an ordinal.
    enum EncryptType: UInt8 {
        case symkey = 0
        case asyOneWay = 1
        case asyTwoWay = 2
        case password = 3
    }

    /// The type byte of a Password bundle that records its KDF (FTSP30).
    static let typePasswordWithKdf: UInt8 = 4

    static let algLength = 6
    static let keyNameLength = 6
    static let kdfIdLength = 1
    static let pubkeyLength = 33
    static let ivLength = AesGcm256.nonceLength   // 12
    static let tagLength = AesGcm256.tagLength    // 16

    /// The smallest bundle that can carry anything: symkey framing plus a
    /// GCM tag over an empty plaintext.
    static let minimumSymkeySize = algLength + 1 + keyNameLength + ivLength + tagLength

    // MARK: - sealing

    /// Seal to `pubkeyB` from our real key, so the recipient can open it
    /// by pairing their private key with the `pubkeyA` recorded inside.
    ///
    /// This is the P2P path on the DOCK and ROAD channels (FIMP1V2 §7).
    public static func sealAsyTwoWay(
        plaintext: Data, privkeyA: Data, toPubkey pubkeyB: Data
    ) throws -> Data {
        guard pubkeyB.count == pubkeyLength else { throw Failure.badField("pubkeyB") }
        let pubkeyA: Data
        do {
            pubkeyA = try Secp256k1.publicKey(fromPrivateKey: privkeyA)
        } catch {
            throw Failure.badField("privkeyA")
        }
        let iv = randomIv()
        let x = try Secp256k1.sharedSecretX(privateKey: privkeyA, publicKey: pubkeyB)
        return try assemble(
            algorithm: eccK1AesGcm256,
            type: .asyTwoWay,
            pubkeyA: pubkeyA,
            iv: iv,
            symkey: eccSymkey(x: x, iv: iv),
            plaintext: plaintext
        )
    }

    /// Seal to `pubkeyB` with a throwaway sender key, so only the holder
    /// of `pubkeyB` can ever reopen it.
    ///
    /// Used for self-chat, where AsyTwoWay is not usable: both slots would
    /// hold the same key and side-selection cannot resolve that.
    public static func sealAsyOneWay(plaintext: Data, toPubkey pubkeyB: Data) throws -> Data {
        guard pubkeyB.count == pubkeyLength else { throw Failure.badField("pubkeyB") }
        let ephemeralPrivkey = randomBytes(32)
        let ephemeralPubkey: Data
        do {
            ephemeralPubkey = try Secp256k1.publicKey(fromPrivateKey: ephemeralPrivkey)
        } catch {
            throw Failure.badField("ephemeral")
        }
        let iv = randomIv()
        let x = try Secp256k1.sharedSecretX(privateKey: ephemeralPrivkey, publicKey: pubkeyB)
        return try assemble(
            algorithm: eccK1AesGcm256,
            type: .asyOneWay,
            pubkeyA: ephemeralPubkey,
            iv: iv,
            symkey: eccSymkey(x: x, iv: iv),
            plaintext: plaintext
        )
    }

    /// Seal under a group key. The 6-byte `keyName` lets a receiver holding
    /// several rotations tell at a glance which one this is, without
    /// trial decryption.
    public static func sealSymkey(plaintext: Data, symkey: Data) throws -> Data {
        guard symkey.count == AesGcm256.keyLength else { throw Failure.badField("symkey") }
        return try assemble(
            algorithm: aesGcm256,
            type: .symkey,
            keyName: keyName(for: symkey),
            iv: randomIv(),
            symkey: symkey,
            plaintext: plaintext
        )
    }

    /// Seal under a password: Argon2id salted with the IV (FTSP29), then
    /// AES-256-GCM. Written as legacy type 3 until
    /// ``writePasswordBundleWithKdf`` is switched on, and as type 4 after.
    public static func sealPassword(plaintext: Data, password: Data) throws -> Data {
        let iv = randomIv()
        let key: Data
        do {
            key = try KdfKind.argon2id.deriveSymkey(password: password, salt: iv)
        } catch {
            throw Failure.encryptFailed(underlying: error)
        }
        return try assemble(
            algorithm: aesGcm256,
            type: .password,
            kdf: .argon2id,
            iv: iv,
            symkey: key,
            plaintext: plaintext
        )
    }

    // MARK: - opening

    /// Open an AsyOneWay or AsyTwoWay bundle with our private key.
    ///
    /// Both shapes open the same way — ECDH against the single recorded
    /// `pubkeyA` — which is why the type byte only has to be *checked*
    /// here, not branched on.
    public static func open(bundle: Data, privkey: Data) throws -> Data {
        let parsed = try parse(bundle)
        guard parsed.type == .asyOneWay || parsed.type == .asyTwoWay else {
            throw Failure.wrongType(expected: "AsyOneWay/AsyTwoWay", got: String(describing: parsed.type))
        }
        guard parsed.algorithm == eccK1AesGcm256 else {
            throw Failure.unsupportedAlgorithm(parsed.algorithm.prefix)
        }
        guard let pubkeyA = parsed.pubkeyA else { throw Failure.badField("pubkeyA") }
        let x: Data
        do {
            x = try Secp256k1.sharedSecretX(privateKey: privkey, publicKey: pubkeyA)
        } catch {
            throw Failure.decryptFailed(underlying: error)
        }
        return try openGcm(
            symkey: eccSymkey(x: x, iv: parsed.iv), iv: parsed.iv, cipher: parsed.cipher
        )
    }

    /// Open a Symkey bundle with a group key.
    public static func open(bundle: Data, symkey: Data) throws -> Data {
        let parsed = try parse(bundle)
        guard parsed.type == .symkey else {
            throw Failure.wrongType(expected: "Symkey", got: String(describing: parsed.type))
        }
        guard symkey.count == AesGcm256.keyLength else { throw Failure.badField("symkey") }
        // A keyName mismatch is a wrong-key answer we can give before
        // spending an AES-GCM open on it, and a clearer one than a tag
        // failure — but it is advisory: Java writes it, and a bundle that
        // somehow lacks it should still decrypt if the key is right.
        if let stamped = parsed.keyName, stamped != keyName(for: symkey) {
            throw Failure.keyNameMismatch
        }
        return try openSymmetric(parsed, key: symkey)
    }

    /// Open a Password bundle. Type 4 names its KDF and only that one runs.
    /// Type 3 names none, so Argon2id is tried and then the legacy SHA-256
    /// KDF, and the first that decrypts wins (FTSP29).
    public static func open(bundle: Data, password: Data) throws -> Data {
        let parsed = try parse(bundle)
        guard parsed.type == .password else {
            throw Failure.wrongType(expected: "Password", got: String(describing: parsed.type))
        }
        let candidates: [KdfKind] = parsed.kdf.map { [$0] } ?? [.argon2id, .legacySha256]
        var lastFailure = Failure.sumMismatch
        for kdf in candidates {
            let key: Data
            do {
                key = try kdf.deriveSymkey(password: password, salt: parsed.iv)
            } catch {
                // A KDF that cannot run is an error, never a cue to try a weaker one.
                throw Failure.decryptFailed(underlying: error)
            }
            do {
                return try openSymmetric(parsed, key: key)
            } catch Failure.decryptFailed(let underlying) {
                lastFailure = .decryptFailed(underlying: underlying)
            } catch Failure.sumMismatch {
                lastFailure = .sumMismatch
            }
        }
        throw lastFailure
    }

    /// Which envelope a bundle holds, without opening it. The cue for
    /// choosing between the privkey and symkey paths when the caller does
    /// not already know from the message type.
    public static func encryptType(of bundle: Data) -> String? {
        guard let parsed = try? parse(bundle) else { return nil }
        return String(describing: parsed.type)
    }

    // MARK: - parsing

    struct Parsed {
        var algorithm: Algorithm
        var type: EncryptType
        /// Set only for a type-4 bundle.
        var kdf: KdfKind?
        var pubkeyA: Data?
        var keyName: Data?
        var iv: Data
        var cipher: Data
        var sum: Data?
    }

    static func parse(_ bundle: Data) throws -> Parsed {
        guard bundle.count >= algLength + 2 else { throw Failure.truncated("type") }
        var cursor = bundle.startIndex

        func take(_ n: Int, _ field: String) throws -> Data {
            guard n >= 0, bundle.endIndex - cursor >= n else { throw Failure.truncated(field) }
            defer { cursor += n }
            return bundle[cursor ..< cursor + n]
        }

        let prefix = try take(algLength, "alg").fcToolHex
        guard let algorithm = algorithms.first(where: { $0.prefix == prefix || $0.legacyPrefix == prefix }) else {
            throw Failure.unsupportedAlgorithm(prefix)
        }

        guard let typeByte = try take(1, "type").first else { throw Failure.badField("type") }
        let recordsKdf = typeByte == typePasswordWithKdf
        let type: EncryptType
        if recordsKdf {
            type = .password
        } else {
            guard let plain = EncryptType(rawValue: typeByte) else { throw Failure.badField("type") }
            type = plain
        }

        var pubkeyA: Data?
        var keyName: Data?
        var kdf: KdfKind?
        switch type {
        case .asyOneWay, .asyTwoWay:
            pubkeyA = Data(try take(algorithm.pubkeyLength, "pubkeyA"))
        case .symkey:
            keyName = Data(try take(keyNameLength, "keyName"))
        case .password:
            if recordsKdf {
                guard let id = try take(kdfIdLength, "kdfId").first else { throw Failure.truncated("kdfId") }
                guard let known = KdfKind(bundleId: id) else { throw Failure.unsupportedKdf(id) }
                kdf = known
            }
        }

        let iv = Data(try take(algorithm.ivLength, "iv"))
        let cipherLength = (bundle.endIndex - cursor) - algorithm.sumLength
        guard cipherLength >= 1 else { throw Failure.truncated("cipher") }
        let cipher = Data(try take(cipherLength, "cipher"))
        let sum = algorithm.sumLength > 0 ? Data(try take(algorithm.sumLength, "sum")) : nil

        return Parsed(
            algorithm: algorithm, type: type, kdf: kdf,
            pubkeyA: pubkeyA, keyName: keyName, iv: iv, cipher: cipher, sum: sum
        )
    }

    /// Write a bundle in FTSP30 field order, always with the PID prefix.
    /// A Password bundle with a known KDF becomes type 4 only once
    /// ``writePasswordBundleWithKdf`` is on.
    static func serialize(_ p: Parsed) -> Data {
        let writeKdf = p.type == .password && p.kdf != nil && writePasswordBundleWithKdf
        var out = Data(fcHex: p.algorithm.prefix) ?? Data()
        out.append(writeKdf ? typePasswordWithKdf : p.type.rawValue)
        if p.type == .asyOneWay || p.type == .asyTwoWay, let pubkeyA = p.pubkeyA { out.append(pubkeyA) }
        if p.type == .symkey, let keyName = p.keyName { out.append(keyName) }
        if writeKdf, let kdf = p.kdf { out.append(kdf.bundleId) }
        out.append(p.iv)
        out.append(p.cipher)
        if let sum = p.sum { out.append(sum) }
        return out
    }

    // MARK: - helpers

    private static func assemble(
        algorithm: Algorithm,
        type: EncryptType,
        kdf: KdfKind? = nil,
        pubkeyA: Data? = nil,
        keyName: Data? = nil,
        iv: Data,
        symkey: Data,
        plaintext: Data
    ) throws -> Data {
        let box: Aead.SealedBox
        do {
            box = try AesGcm256.seal(key: symkey, nonce: iv, plaintext: plaintext)
        } catch {
            throw Failure.encryptFailed(underlying: error)
        }
        return serialize(Parsed(
            algorithm: algorithm, type: type, kdf: kdf,
            pubkeyA: pubkeyA, keyName: keyName, iv: iv,
            cipher: box.ciphertext + box.tag, sum: nil
        ))
    }

    private static func openSymmetric(_ parsed: Parsed, key: Data) throws -> Data {
        switch parsed.algorithm {
        case aesGcm256:
            return try openGcm(symkey: key, iv: parsed.iv, cipher: parsed.cipher)
        case aesCbc256:
            let plain: Data
            do {
                plain = try AsyOneWayCipher.cbcOpen(alg: parsed.algorithm.name, key: key, iv: parsed.iv, cipher: parsed.cipher)
            } catch {
                throw Failure.decryptFailed(underlying: error)
            }
            guard let sum = parsed.sum, sumMatches(sum, key: key, iv: parsed.iv, plaintext: plain) else {
                throw Failure.sumMismatch
            }
            return plain
        default:
            throw Failure.unsupportedAlgorithm(parsed.algorithm.prefix)
        }
    }

    private static func openGcm(symkey: Data, iv: Data, cipher: Data) throws -> Data {
        guard cipher.count > tagLength else { throw Failure.truncated("cipher") }
        do {
            return try AesGcm256.open(
                key: symkey, nonce: iv,
                ciphertext: cipher.dropLast(tagLength),
                tag: cipher.suffix(tagLength)
            )
        } catch {
            throw Failure.decryptFailed(underlying: error)
        }
    }

    /// FVEP8 `sum`: the first 4 bytes of SHA256(symkey ‖ iv ‖ did), where
    /// did = SHA256(SHA256(plaintext)).
    static func sumMatches(_ sum: Data, key: Data, iv: Data, plaintext: Data) -> Bool {
        Data(Hash.sha256(key + iv + Hash.doubleSha256(plaintext)).prefix(4)) == sum
    }

    /// `Ecc256K1Hkdf`: the fixed 32-byte ECDH x-coordinate through
    /// HKDF-SHA512 with the iv as salt — the same derivation
    /// ``AsyTwoWayCipher`` uses, so the two encodings are interchangeable
    /// at the crypto layer and differ only in framing.
    private static func eccSymkey(x: Data, iv: Data) -> Data {
        Hkdf.sha512(
            ikm: x, salt: iv,
            info: Data("hkdf".utf8),
            outputLength: AesGcm256.keyLength
        )
    }

    /// `makeKeyName`: the first 6 bytes of sha256(key).
    static func keyName(for symkey: Data) -> Data {
        Data(Hash.sha256(symkey).prefix(keyNameLength))
    }

    private static func algorithm(named name: String) -> Algorithm {
        guard let algorithm = algorithms.first(where: { $0.name == name }) else {
            preconditionFailure("CryptoBundle: \(name) missing from the algorithm table")
        }
        return algorithm
    }

    private static func randomIv() -> Data { randomBytes(ivLength) }

    private static func randomBytes(_ count: Int) -> Data {
        Data((0 ..< count).map { _ in UInt8.random(in: .min ... .max) })
    }

    public enum Failure: Error, Equatable, CustomStringConvertible {
        case truncated(String)
        case badField(String)
        case unsupportedAlgorithm(String)
        case unsupportedType(String)
        case unsupportedKdf(UInt8)
        case wrongType(expected: String, got: String)
        case keyNameMismatch
        case sumMismatch
        case encryptFailed(underlying: Error)
        case decryptFailed(underlying: Error)

        public var description: String {
            switch self {
            case .truncated(let field):
                return "CryptoBundle: ended before \(field)"
            case .badField(let field):
                return "CryptoBundle: bad \(field)"
            case .unsupportedAlgorithm(let prefix):
                return "CryptoBundle: algorithm \(prefix) is not supported here"
            case .unsupportedType(let type):
                return "CryptoBundle: \(type) bundles are not produced or read"
            case .unsupportedKdf(let id):
                return "CryptoBundle: KDF id \(id) is not registered"
            case .wrongType(let expected, let got):
                return "CryptoBundle: expected \(expected), got \(got)"
            case .keyNameMismatch:
                return "CryptoBundle: sealed under a different key than the one offered"
            case .sumMismatch:
                return "CryptoBundle: sum does not match — wrong key or corrupted cipher"
            case .encryptFailed:
                return "CryptoBundle: could not seal"
            case .decryptFailed:
                return "CryptoBundle: could not open"
            }
        }

        public static func == (lhs: Failure, rhs: Failure) -> Bool {
            lhs.description == rhs.description
        }
    }
}
