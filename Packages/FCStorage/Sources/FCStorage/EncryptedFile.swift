import Foundation
import FCCore

/// AES-256-GCM-encrypted JSON file. Same on-disk wire shape as one
/// row of ``EncryptedKVStore``:
///
/// ```
/// nonce(12) ‖ ciphertext(N) ‖ tag(16)
/// ```
///
/// The AAD binds the ciphertext to a caller-supplied logical name
/// (typically the file's path or a stable identifier) so an attacker
/// who copies an encrypted-configure file from one location to
/// another can't get the decryption to succeed at the new location.
///
/// Used by the Configure / Setting layer in FCDomain. ``EncryptedKVStore``
/// remains the right tool for many small mutable rows; this helper is
/// the right tool for one Codable blob per file.
public enum EncryptedFile {

    public enum Failure: Error, CustomStringConvertible {
        case wrongKeyLength(Int)
        case fileTooShort(Int)
        case io(URL, Error)
        case encoding(Error)
        case decoding(Error)
        case decryption

        public var description: String {
            switch self {
            case .wrongKeyLength(let n):   return "EncryptedFile: key must be 32 bytes, got \(n)"
            case .fileTooShort(let n):     return "EncryptedFile: ciphertext file is \(n) B (need ≥ 28)"
            case let .io(url, err):        return "EncryptedFile: I/O at \(url.path) — \(err)"
            case .encoding(let err):       return "EncryptedFile: encoding failed — \(err)"
            case .decoding(let err):       return "EncryptedFile: decoding failed — \(err)"
            case .decryption:              return "EncryptedFile: decryption failed (tampered or wrong key)"
            }
        }
    }

    private static let nonceLength = 12
    private static let tagLength = 16

    /// Encrypt `value` (JSON-encoded) under `key` and write atomically
    /// to `url`. The directory is created if it doesn't exist. AAD
    /// defaults to the file name.
    public static func write<T: Encodable>(
        _ value: T,
        to url: URL,
        key: Data,
        aad: Data? = nil
    ) throws {
        guard key.count == 32 else { throw Failure.wrongKeyLength(key.count) }

        let plaintext: Data
        do {
            let encoder = JSONEncoder()
            encoder.dateEncodingStrategy = .iso8601
            encoder.outputFormatting = [.sortedKeys]
            plaintext = try encoder.encode(value)
        } catch {
            throw Failure.encoding(error)
        }

        let nonce = try randomBytes(count: nonceLength)
        let bindAad = aad ?? Data(url.lastPathComponent.utf8)
        let sealed: Aead.SealedBox
        do {
            sealed = try AesGcm256.seal(
                key: key, nonce: nonce, plaintext: plaintext, aad: bindAad
            )
        } catch {
            throw Failure.encoding(error)
        }

        var blob = Data(capacity: nonceLength + sealed.ciphertext.count + tagLength)
        blob.append(nonce)
        blob.append(sealed.ciphertext)
        blob.append(sealed.tag)

        do {
            try FileManager.default.createDirectory(
                at: url.deletingLastPathComponent(),
                withIntermediateDirectories: true
            )
            try blob.write(to: url, options: Data.WritingOptions.atomic)
        } catch {
            throw Failure.io(url, error)
        }
    }

    /// Read and decrypt. Returns nil if the file doesn't exist (so
    /// callers can decide whether that's "fresh install" or "missing
    /// data" without juggling NSError codes).
    public static func read<T: Decodable>(
        _ type: T.Type,
        from url: URL,
        key: Data,
        aad: Data? = nil
    ) throws -> T? {
        guard key.count == 32 else { throw Failure.wrongKeyLength(key.count) }

        let blob: Data
        do {
            blob = try Data(contentsOf: url)
        } catch let error as CocoaError where error.code == .fileReadNoSuchFile {
            return nil
        } catch {
            throw Failure.io(url, error)
        }

        let bytes = [UInt8](blob)
        guard bytes.count >= nonceLength + tagLength else {
            throw Failure.fileTooShort(bytes.count)
        }
        let nonce = Data(bytes[0..<nonceLength])
        let tag = Data(bytes[(bytes.count - tagLength)..<bytes.count])
        let ciphertext = Data(bytes[nonceLength..<(bytes.count - tagLength)])
        let bindAad = aad ?? Data(url.lastPathComponent.utf8)

        let plaintext: Data
        do {
            plaintext = try AesGcm256.open(
                key: key, nonce: nonce, ciphertext: ciphertext, tag: tag, aad: bindAad
            )
        } catch {
            throw Failure.decryption
        }

        do {
            let decoder = JSONDecoder()
            decoder.dateDecodingStrategy = .iso8601
            return try decoder.decode(type, from: plaintext)
        } catch {
            throw Failure.decoding(error)
        }
    }

    private static func randomBytes(count: Int) throws -> Data {
        var out = Data(count: count)
        let status = out.withUnsafeMutableBytes { ptr -> Int32 in
            guard let base = ptr.baseAddress else { return -1 }
            return SecRandomCopyBytes(kSecRandomDefault, count, base)
        }
        guard status == errSecSuccess else {
            throw Failure.io(URL(fileURLWithPath: "/dev/random"),
                             NSError(domain: "SecRandom", code: Int(status)))
        }
        return out
    }
}
