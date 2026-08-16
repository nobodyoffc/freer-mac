import Foundation
import FCCore

/// The **binary** CryptoDataByte envelope — Java's
/// `CryptoDataByte.toBundle()` / `fromBundle(byte[])`.
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
///   type     1 byte    EncryptType ordinal
///   pubkeyA  33 bytes  only for AsyOneWay / AsyTwoWay
///   keyName  6 bytes   only for Symkey — sha256(symkey)[0..<6]
///   iv       12 bytes  (GCM)
///   cipher   rest      ciphertext ‖ 16-byte GCM tag
/// ```
///
/// Overhead is 52 bytes for AsyTwoWay and 25 for Symkey, against ~200
/// plus 33% for the JSON forms.
///
/// **Only the GCM algorithms are written here.** `fromBundle` in Java
/// also reads CBC and ChaCha variants and carries a trailing 4-byte `sum`
/// for the non-AEAD ones; those exist for legacy on-chain data, never for
/// an IM body, so this reads the AEAD shapes and rejects the rest rather
/// than growing a decryption path nothing produces.
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

    /// First 12 hex chars of each algorithm's on-chain protocol PID —
    /// `ALG_PID_PREFIX_*` in `CryptoDataByte`.
    static let algPrefixAesGcm256 = "76f7b226a8b3"
    static let algPrefixEccK1AesGcm256 = "a5acd7077805"

    /// `EncryptType`'s wire numbers. Symkey is 0, so a bundle's type byte
    /// is not a presence flag — it has to be read as an ordinal.
    enum EncryptType: UInt8 {
        case symkey = 0
        case asyOneWay = 1
        case asyTwoWay = 2
        case password = 3
    }

    static let algLength = 6
    static let keyNameLength = 6
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
            algPrefix: algPrefixEccK1AesGcm256,
            type: .asyTwoWay,
            pubkeyA: pubkeyA,
            keyName: nil,
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
            algPrefix: algPrefixEccK1AesGcm256,
            type: .asyOneWay,
            pubkeyA: ephemeralPubkey,
            keyName: nil,
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
            algPrefix: algPrefixAesGcm256,
            type: .symkey,
            pubkeyA: nil,
            keyName: keyName(for: symkey),
            iv: randomIv(),
            symkey: symkey,
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
        return try openGcm(symkey: symkey, iv: parsed.iv, cipher: parsed.cipher)
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
        var algPrefix: String
        var type: EncryptType
        var pubkeyA: Data?
        var keyName: Data?
        var iv: Data
        var cipher: Data
    }

    static func parse(_ bundle: Data) throws -> Parsed {
        var cursor = bundle.startIndex

        func take(_ n: Int, _ field: String) throws -> Data {
            guard n >= 0, bundle.endIndex - cursor >= n else { throw Failure.truncated(field) }
            defer { cursor += n }
            return bundle[cursor ..< cursor + n]
        }

        let algPrefix = try take(algLength, "alg").fcToolHex
        switch algPrefix {
        case algPrefixAesGcm256, algPrefixEccK1AesGcm256:
            break
        default:
            // CBC, ChaCha and the legacy sequential prefixes are readable
            // by Java and never written for an IM body. Rejecting is the
            // honest answer; silently guessing GCM would fail at the tag
            // with a much less useful message.
            throw Failure.unsupportedAlgorithm(algPrefix)
        }

        guard let typeByte = try take(1, "type").first,
              let type = EncryptType(rawValue: typeByte)
        else { throw Failure.badField("type") }

        var pubkeyA: Data?
        var keyName: Data?
        switch type {
        case .asyOneWay, .asyTwoWay:
            pubkeyA = Data(try take(pubkeyLength, "pubkeyA"))
        case .symkey:
            keyName = Data(try take(keyNameLength, "keyName"))
        case .password:
            // Java writes no keyName for Password in `toBundle` (it checks
            // for one and returns null), so no bundle of this shape is
            // produced. Nothing in FIMP uses it.
            throw Failure.unsupportedType("Password")
        }

        let iv = Data(try take(ivLength, "iv"))
        let cipher = Data(bundle[cursor...])
        guard cipher.count > tagLength else { throw Failure.truncated("cipher") }

        return Parsed(
            algPrefix: algPrefix, type: type,
            pubkeyA: pubkeyA, keyName: keyName, iv: iv, cipher: cipher
        )
    }

    // MARK: - helpers

    private static func assemble(
        algPrefix: String,
        type: EncryptType,
        pubkeyA: Data?,
        keyName: Data?,
        iv: Data,
        symkey: Data,
        plaintext: Data
    ) throws -> Data {
        guard let alg = Data(fcHex: algPrefix), alg.count == algLength else {
            throw Failure.badField("alg")
        }
        let box: Aead.SealedBox
        do {
            box = try AesGcm256.seal(key: symkey, nonce: iv, plaintext: plaintext)
        } catch {
            throw Failure.encryptFailed(underlying: error)
        }

        var out = Data()
        out.append(alg)
        out.append(type.rawValue)
        if let pubkeyA { out.append(pubkeyA) }
        if let keyName { out.append(keyName) }
        out.append(iv)
        out.append(box.ciphertext)
        out.append(box.tag)
        return out
    }

    private static func openGcm(symkey: Data, iv: Data, cipher: Data) throws -> Data {
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

    private static func randomIv() -> Data { randomBytes(ivLength) }

    private static func randomBytes(_ count: Int) -> Data {
        Data((0 ..< count).map { _ in UInt8.random(in: .min ... .max) })
    }

    public enum Failure: Error, Equatable, CustomStringConvertible {
        case truncated(String)
        case badField(String)
        case unsupportedAlgorithm(String)
        case unsupportedType(String)
        case wrongType(expected: String, got: String)
        case keyNameMismatch
        case encryptFailed(underlying: Error)
        case decryptFailed(underlying: Error)

        public var description: String {
            switch self {
            case .truncated(let field):
                return "CryptoBundle: ended before \(field)"
            case .badField(let field):
                return "CryptoBundle: bad \(field)"
            case .unsupportedAlgorithm(let prefix):
                return "CryptoBundle: algorithm \(prefix) is not one this reads (GCM only)"
            case .unsupportedType(let type):
                return "CryptoBundle: \(type) bundles are not produced or read"
            case .wrongType(let expected, let got):
                return "CryptoBundle: expected \(expected), got \(got)"
            case .keyNameMismatch:
                return "CryptoBundle: sealed under a different key than the one offered"
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
