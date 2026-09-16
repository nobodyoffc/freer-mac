import Foundation
import FCCore

/// Tells what a typed, pasted or scanned key text is, so one import box can take a
/// private key, public key, FID, password cipher or key backup JSON — the Swift port
/// of Android's `KeyInputDetector`.
///
/// **The order of the checks matters.** Hex, WIF and FID text are all valid Base64
/// too, so the checksummed and fixed-shape forms are tried before a Base64 cipher
/// bundle. A passphrase is never guessed: any text could be one, and a mistyped key
/// must not quietly become a different key — which is why ``AddMainView`` keeps
/// Passphrase as its own source rather than feeding it through here.
///
/// A near miss is *reported*, never repaired: 63 good hex characters and a typo is
/// ``Kind/badPrikey``, not ``Kind/unknown``, because the two need different words in
/// front of the user ("check the last character" vs "that isn't a key").
public enum KeyInput {

    public enum Kind: String, Equatable, Sendable {
        case empty
        /// 64 hex chars, `0x`-prefixed hex, or WIF.
        case prikey
        /// Compressed or uncompressed public key hex. Watch-only.
        case pubkey
        /// Watch-only.
        case fid
        /// One password-encrypted object, as JSON or a Base64 bundle.
        case cipher
        /// Encrypted, but not with a password, so it can't be opened here.
        case nonPasswordCipher
        /// Key JSON: KeyInfo, backup header/key lines, or several ciphers.
        case backup
        /// Shaped like a private key, but not a valid one.
        case badPrikey
        /// Shaped like a public key, but not a valid one.
        case badPubkey
        /// Shaped like an FID, but the checksum fails.
        case badFid
        /// Several items; only backup JSON may carry more than one key.
        case multiple
        case unknown
    }

    public enum Failure: Error, CustomStringConvertible {
        case notACipher
        case notPasswordEncrypted
        case underlying(Error)

        public var description: String {
            switch self {
            case .notACipher:
                return "not an encrypted cipher — expected the JSON envelope or a Base64 bundle"
            case .notPasswordEncrypted:
                return "that cipher wasn't encrypted with a password, so a password can't open it"
            case .underlying(let e):
                return String(describing: e)
            }
        }
    }

    // MARK: - detect

    public static func detect(_ input: String?) -> Kind {
        let text = (input ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        if text.isEmpty { return .empty }

        if text.hasPrefix("{") { return detectJson(text) }
        if text.rangeOfCharacter(from: .whitespacesAndNewlines) != nil { return .multiple }

        if prikey32(from: text) != nil { return .prikey }
        if PubkeyFormats.isPubkey(text) { return .pubkey }
        if isFid(text) { return .fid }

        if let type = bundleEncryptType(text) {
            return type == .password ? .cipher : .nonPasswordCipher
        }

        if looksLikePrikey(text) { return .badPrikey }
        if looksLikePubkey(text) { return .badPubkey }
        if looksLikeFid(text) { return .badFid }
        return .unknown
    }

    /// The 32-byte private key the text encodes, or nil. Never throws.
    /// Accepts 64 hex characters, `0x`-prefixed hex, and WIF (`L`/`K`/`5`).
    public static func prikey32(from text: String?) -> Data? {
        let trimmed = (text ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return nil }

        let hex = trimmed.hasPrefix("0x") || trimmed.hasPrefix("0X")
            ? String(trimmed.dropFirst(2))
            : trimmed
        if hex.count == 64, let data = Data(fcHex: hex), data.count == 32 {
            return data
        }
        if let (privkey, _) = try? WifPrivkey.decode(trimmed) {
            return privkey
        }
        return nil
    }

    // MARK: - ciphers

    /// Open a ``Kind/cipher`` input — either form — and return its plaintext.
    /// The caller decides what the plaintext is; ``prikey(fromPlaintext:)``
    /// answers the only question this type cares about.
    public static func openCipher(_ input: String, password: Data) throws -> Data {
        let text = input.trimmingCharacters(in: .whitespacesAndNewlines)

        if text.hasPrefix("{") {
            let objects = readJsonObjects(text)
            guard objects.count == 1,
                  let envelope = try? TextCipher.parse(objects[0]),
                  envelope.cipher != nil, envelope.iv != nil else {
                throw Failure.notACipher
            }
            guard isPasswordType(envelope.type) else { throw Failure.notPasswordEncrypted }
            do {
                return try TextCipher.decrypt(envelope: envelope, password: password)
            } catch {
                throw Failure.underlying(error)
            }
        }

        guard let bundle = Data(base64Encoded: text) else { throw Failure.notACipher }
        guard let type = (try? CryptoBundle.parse(bundle))?.type else { throw Failure.notACipher }
        guard type == .password else { throw Failure.notPasswordEncrypted }
        do {
            return try CryptoBundle.open(bundle: bundle, password: password)
        } catch {
            throw Failure.underlying(error)
        }
    }

    /// The private key inside a decrypted cipher: the raw 32 bytes, or its hex or
    /// WIF text (``BackupPrikeySheet`` encrypts the displayed text, so a backup made
    /// from the WIF view opens to WIF characters, not to bytes). Nil when the
    /// plaintext is something else, such as a key JSON.
    public static func prikey(fromPlaintext data: Data?) -> Data? {
        guard let data else { return nil }
        if data.count == 32 { return data }
        guard let text = String(data: data, encoding: .utf8) else { return nil }
        return prikey32(from: text)
    }

    public static func isJson(_ data: Data?) -> Bool {
        guard let data, let text = String(data: data, encoding: .utf8) else { return false }
        return text.trimmingCharacters(in: .whitespacesAndNewlines).hasPrefix("{")
    }

    // MARK: - JSON

    private static func detectJson(_ text: String) -> Kind {
        let objects = readJsonObjects(text)
        if objects.isEmpty { return .unknown }
        if objects.count == 1, let envelope = try? TextCipher.parse(objects[0]),
           envelope.cipher != nil, envelope.iv != nil {
            return isPasswordType(envelope.type) ? .cipher : .nonPasswordCipher
        }
        return .backup
    }

    /// Split concatenated JSON objects — the shape a backup file has, one object per
    /// line or none at all. Brace-depth scan that honors strings and escapes; an
    /// object left unterminated at the end contributes nothing, so half a paste reads
    /// as "not JSON" rather than as a truncated key.
    static func readJsonObjects(_ text: String) -> [String] {
        var objects: [String] = []
        var depth = 0
        var inString = false
        var escaped = false
        var start: String.Index?

        for index in text.indices {
            let character = text[index]
            if inString {
                if escaped { escaped = false }
                else if character == "\\" { escaped = true }
                else if character == "\"" { inString = false }
                continue
            }
            switch character {
            case "\"":
                inString = true
            case "{":
                if depth == 0 { start = index }
                depth += 1
            case "}":
                guard depth > 0 else { return objects }
                depth -= 1
                if depth == 0, let from = start {
                    objects.append(String(text[from ... index]))
                    start = nil
                }
            default:
                break
            }
        }
        return objects
    }

    /// A JSON cipher without a type was always treated as password-encrypted before.
    private static func isPasswordType(_ type: String?) -> Bool {
        type == nil || type?.caseInsensitiveCompare("Password") == .orderedSame
    }

    private static func bundleEncryptType(_ text: String) -> CryptoBundle.EncryptType? {
        guard let bundle = Data(base64Encoded: text) else { return nil }
        return (try? CryptoBundle.parse(bundle))?.type
    }

    // MARK: - shapes

    private static let base58 = CharacterSet(charactersIn: "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")
    private static let alphanumeric = CharacterSet(charactersIn: "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")

    private static func isBase58(_ text: String) -> Bool {
        !text.isEmpty && text.unicodeScalars.allSatisfy { base58.contains($0) }
    }

    private static func isAlphanumeric(_ text: String) -> Bool {
        !text.isEmpty && text.unicodeScalars.allSatisfy { alphanumeric.contains($0) }
    }

    /// Both mainnet forms: a "F…" P2PKH FID and a "3…" P2SH multisig address.
    private static func isFid(_ text: String) -> Bool {
        (26 ... 35).contains(text.count)
            && isBase58(text)
            && (try? FchAddress(fid: text, expectedVersionByte: nil)) != nil
    }

    private static func looksLikePrikey(_ text: String) -> Bool {
        let length = text.count
        if isBase58(text) {
            if length == 52, text.hasPrefix("K") || text.hasPrefix("L") { return true }
            if length == 51, text.hasPrefix("5") { return true }
        }
        if length == 66, text.hasPrefix("0x") || text.hasPrefix("0X") {
            return isAlphanumeric(String(text.dropFirst(2)))
        }
        return length == 64 && isAlphanumeric(text)
    }

    private static func looksLikePubkey(_ text: String) -> Bool {
        (text.count == 66 || text.count == 130) && isAlphanumeric(text)
    }

    private static func looksLikeFid(_ text: String) -> Bool {
        (text.count == 33 || text.count == 34)
            && (text.hasPrefix("F") || text.hasPrefix("3"))
            && isBase58(text)
    }
}
