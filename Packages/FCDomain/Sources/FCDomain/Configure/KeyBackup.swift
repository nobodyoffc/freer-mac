import Foundation
import FCCore

/// A key backup as Android Safe's Export Keys and Backup Keys write it: JSON
/// objects one after another, separated by blank lines —
///
///   1. a `BackupKey` (`keyName`, `time`, and either the random `password` the
///      export was sealed with or a `hint` that the app password was used),
///   2. a `BackupHeader` (`time`, `items`, `keyName`, `alg`, `tClass`),
///   3. one `KeyInfo` per key: `id`, `label`, `saveTime`, and the secret as
///      `prikeyCipher` (a Base64 password bundle), plain `prikey` hex, or — for a
///      watch-only entry — only a `pubkey`.
///
/// An unencrypted export has no key or header lines. Older backups may also carry
/// whole password envelopes whose plaintext is a KeyInfo JSON; those are read too,
/// as Android's `BackupUtils.readBackup` does.
///
/// Parsing never runs a KDF. ``open(_:password:)`` does, once per entry, so the
/// caller keeps it off the main actor.
public struct KeyBackup: Sendable {

    public struct Entry: Identifiable, Sendable {
        public enum Content: Sendable {
            /// Stored in the clear.
            case prikey(Data)
            /// `prikeyCipher`: a Base64 bundle sealed with the backup's password.
            case prikeyCipher(String)
            /// A whole password envelope whose plaintext is a KeyInfo JSON.
            case sealedKeyInfo(String)
            /// Pubkey or FID only: nothing here can sign.
            case watchOnly
            /// Encrypted, but not with a password — with the exporting app's own
            /// symkey — so it can't be opened here.
            case unopenable
        }

        /// Position in the backup; stable for the life of the parse.
        public let id: Int
        /// The FID the backup *claims*. Checked against the prikey on open.
        public let fid: String?
        public let label: String?
        public let content: Content

        public var canSign: Bool {
            switch content {
            case .prikey, .prikeyCipher, .sealedKeyInfo: return true
            case .watchOnly, .unopenable: return false
            }
        }

        public var needsPassword: Bool {
            switch content {
            case .prikeyCipher, .sealedKeyInfo: return true
            default: return false
            }
        }
    }

    public enum Failure: Error, CustomStringConvertible, Equatable {
        case notSignable
        case wrongPassword
        case noPrikeyInside
        case fidMismatch(claimed: String, actual: String)

        public var description: String {
            switch self {
            case .notSignable:
                return "that entry holds no prikey"
            case .wrongPassword:
                return "that password doesn't open this backup"
            case .noPrikeyInside:
                return "the entry opened, but what's inside isn't a prikey"
            case .fidMismatch(let claimed, let actual):
                return "the entry says it is \(claimed), but its prikey belongs to \(actual)"
            }
        }
    }

    public let entries: [Entry]
    /// The random password an Export Keys backup carries in its `BackupKey` line.
    public let password: String?
    /// `BackupKey.hint`, written when the exporting app's own password was used.
    public let hint: String?
    /// `sha256(password)` as 12 hex characters — Android's `makeKeyName` — when
    /// the backup names its key. Lets a wrong password fail before any KDF runs.
    public let keyName: String?
    /// `BackupHeader.tClass`, e.g. `KeyInfo`, or `Secret` for a secrets backup.
    public let itemClass: String?

    public var needsPassword: Bool { entries.contains { $0.needsPassword } }

    // MARK: - parse

    /// Nil when the text holds no key entries at all.
    public static func parse(_ text: String) -> KeyBackup? {
        var entries: [Entry] = []
        var password: String?
        var hint: String?
        var keyName: String?
        var itemClass: String?

        for object in KeyInput.readJsonObjects(text) {
            guard let data = object.data(using: .utf8),
                  let json = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else {
                continue
            }
            let id = entries.count

            if let envelope = try? TextCipher.parse(object), envelope.cipher != nil, envelope.iv != nil {
                let isPassword = envelope.type == nil
                    || envelope.type?.caseInsensitiveCompare("Password") == .orderedSame
                entries.append(Entry(id: id, fid: nil, label: nil,
                                     content: isPassword ? .sealedKeyInfo(object) : .unopenable))
                continue
            }

            let fid = nonEmpty(json["id"])
            let prikey = nonEmpty(json["prikey"])
            let prikeyCipher = nonEmpty(json["prikeyCipher"])
            let pubkey = nonEmpty(json["pubkey"])

            if fid == nil, prikey == nil, prikeyCipher == nil, pubkey == nil {
                // A BackupKey or BackupHeader line.
                if let value = nonEmpty(json["password"]) { password = value }
                if let value = nonEmpty(json["hint"]) { hint = value }
                if let value = nonEmpty(json["keyName"]) { keyName = keyName ?? value }
                if let value = nonEmpty(json["tClass"]) { itemClass = value }
                continue
            }

            let label = nonEmpty(json["label"])
            let content: Entry.Content
            if let prikey, let bytes = KeyInput.prikey32(from: prikey) {
                content = .prikey(bytes)
            } else if let prikeyCipher {
                content = KeyInput.detect(prikeyCipher) == .cipher ? .prikeyCipher(prikeyCipher) : .unopenable
            } else {
                content = .watchOnly
            }
            entries.append(Entry(id: id, fid: fid ?? pubkey.flatMap(fidOf(pubkeyHex:)),
                                 label: label, content: content))
        }

        guard !entries.isEmpty else { return nil }
        return KeyBackup(entries: entries, password: password, hint: hint,
                         keyName: keyName, itemClass: itemClass)
    }

    // MARK: - open

    /// False only when the backup names its key and `password` isn't it. A
    /// backup that names no key can't be checked this cheaply, so it passes.
    public func accepts(password: Data) -> Bool {
        guard let keyName else { return true }
        return Hash.sha256(password).prefix(6).fcToolHex.caseInsensitiveCompare(keyName) == .orderedSame
    }

    /// The entry's 32-byte prikey, checked against the FID it claims. Runs one
    /// Argon2id for an encrypted entry.
    public func open(_ entry: Entry, password: Data?) throws -> Data {
        let prikey: Data
        switch entry.content {
        case .prikey(let bytes):
            prikey = bytes
        case .prikeyCipher(let cipher):
            var plaintext = try decrypt(cipher, password: password)
            defer { plaintext.resetBytes(in: 0 ..< plaintext.count) }
            guard let bytes = KeyInput.prikey(fromPlaintext: plaintext) else { throw Failure.noPrikeyInside }
            prikey = bytes
        case .sealedKeyInfo(let envelope):
            var plaintext = try decrypt(envelope, password: password)
            defer { plaintext.resetBytes(in: 0 ..< plaintext.count) }
            guard let json = (try? JSONSerialization.jsonObject(with: plaintext)) as? [String: Any],
                  let bytes = KeyInput.prikey32(from: Self.nonEmpty(json["prikey"])) else {
                throw Failure.noPrikeyInside
            }
            prikey = bytes
        case .watchOnly, .unopenable:
            throw Failure.notSignable
        }

        let actual = try FchAddress(publicKey: Secp256k1.publicKey(fromPrivateKey: prikey)).fid
        if let claimed = entry.fid, claimed != actual {
            throw Failure.fidMismatch(claimed: claimed, actual: actual)
        }
        return prikey
    }

    private func decrypt(_ cipher: String, password: Data?) throws -> Data {
        guard let password, accepts(password: password) else { throw Failure.wrongPassword }
        do {
            return try KeyInput.openCipher(cipher, password: password)
        } catch {
            throw Failure.wrongPassword
        }
    }

    // MARK: - helpers

    private static func nonEmpty(_ value: Any?) -> String? {
        guard let text = (value as? String)?.trimmingCharacters(in: .whitespacesAndNewlines),
              !text.isEmpty else { return nil }
        return text
    }

    private static func fidOf(pubkeyHex: String) -> String? {
        guard let pubkey = Data(fcHex: pubkeyHex) else { return nil }
        return try? FchAddress(publicKey: pubkey).fid
    }
}
