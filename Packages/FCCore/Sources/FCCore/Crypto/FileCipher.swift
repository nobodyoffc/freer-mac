import Foundation

/// The FAPI DISK cipher-file format — byte-compatible with FC-AJDK's
/// `Encryptor.encryptFileBySymkey` / `Decryptor.decryptFileBySymkey`.
///
/// Layout:
/// ```
///   {"type":"Symkey","alg":"AesGcm256@No1_NrC7","iv":"<24 hex>"}   UTF-8 JSON
///   <AES-256-GCM ciphertext || 16-byte tag>                        one GCM pass
/// ```
///
/// Two properties of the Java format drive this implementation:
///
/// **The header has no length prefix.** The reader
/// (`JsonUtils.readOneJsonFromInputStream`) finds its end by counting
/// braces, and it is *not* JSON-string-aware — a `{` inside a string
/// value would desynchronise it. ``headerLength(of:)`` reproduces that
/// exact algorithm rather than a stricter parser, because agreeing with
/// the producer on where ciphertext begins matters more than being
/// correct in the abstract. (The header only ever holds hex and enum
/// text, so no brace can appear inside a value.)
///
/// **The whole file is one GCM operation**, not a chain of per-chunk
/// boxes: the tag authenticates the entire ciphertext. Neither side can
/// emit or verify anything until the full body is processed, so
/// ``encrypt(plaintextAt:to:symkey:iv:)`` and ``decrypt(cipherAt:to:symkey:)``
/// hold one copy of the body in memory. Input is memory-mapped, so peak
/// anonymous usage is roughly one file's worth rather than two. This
/// matches the Java behaviour (its decrypt buffers the ciphertext and
/// calls `doFinal`) and is fine for desktop-scale files; a streaming
/// variant would require a different, incompatible container format.
public enum FileCipher {

    /// `alg` value in the header — `AlgorithmId.FC_AesGcm256_No1_NrC7`'s
    /// display name.
    public static let algAesGcm256 = "AesGcm256@No1_NrC7"
    /// `type` value in the header — `EncryptType.Symkey`.
    public static let typeSymkey = "Symkey"

    public static let ivLength = 12
    public static let keyLength = 32
    public static let tagLength = 16

    public enum Failure: Error, CustomStringConvertible {
        case invalidKeyLength(got: Int)
        case invalidIvLength(got: Int)
        case headerNotFound
        case headerNotJson
        case unsupportedType(String)
        case unsupportedAlg(String)
        case missingIv
        case bodyTooShort(got: Int)
        case authenticationFailed
        case io(Error)

        public var description: String {
            switch self {
            case .invalidKeyLength(let got):
                return "FileCipher: symkey must be \(FileCipher.keyLength) bytes, got \(got)"
            case .invalidIvLength(let got):
                return "FileCipher: iv must be \(FileCipher.ivLength) bytes, got \(got)"
            case .headerNotFound:
                return "FileCipher: no complete JSON header found (not a cipher file?)"
            case .headerNotJson:
                return "FileCipher: header is not a JSON object"
            case .unsupportedType(let t):
                return "FileCipher: unsupported encrypt type '\(t)' (expected \(FileCipher.typeSymkey))"
            case .unsupportedAlg(let a):
                return "FileCipher: unsupported algorithm '\(a)' (expected \(FileCipher.algAesGcm256))"
            case .missingIv:
                return "FileCipher: header has no iv"
            case .bodyTooShort(let got):
                return "FileCipher: body must be ≥ \(FileCipher.tagLength) bytes (the GCM tag), got \(got)"
            case .authenticationFailed:
                return "FileCipher: authentication failed (wrong key, or the file was altered)"
            case .io(let e):
                return "FileCipher: I/O — \(e)"
            }
        }
    }

    /// Parsed header of a cipher file.
    public struct Header: Equatable, Sendable {
        public let type: String
        public let alg: String
        public let iv: Data
        /// Byte length of the header as it appears in the file — the
        /// offset at which ciphertext begins.
        public let byteLength: Int
    }

    // MARK: - encrypt

    /// Encrypt `plaintextAt` into a cipher file at `to`.
    ///
    /// - parameter iv: 12 bytes, unique per (key, file). Defaults to a
    ///   fresh random value; pass one explicitly only to reproduce a
    ///   known vector — reusing an (key, iv) pair breaks AES-GCM.
    /// - returns: the header written, for callers that want the iv back.
    @discardableResult
    public static func encrypt(
        plaintextAt source: URL,
        to destination: URL,
        symkey: Data,
        iv: Data? = nil
    ) throws -> Header {
        guard symkey.count == keyLength else { throw Failure.invalidKeyLength(got: symkey.count) }
        let nonce = iv ?? randomIv()
        guard nonce.count == ivLength else { throw Failure.invalidIvLength(got: nonce.count) }

        let plaintext: Data
        do {
            plaintext = try Data(contentsOf: source, options: .alwaysMapped)
        } catch {
            throw Failure.io(error)
        }

        let sealed: Aead.SealedBox
        do {
            sealed = try AesGcm256.seal(key: symkey, nonce: nonce, plaintext: plaintext)
        } catch {
            throw Failure.io(error)
        }

        let headerBytes = headerJson(iv: nonce)
        var out = Data(capacity: headerBytes.count + sealed.ciphertext.count + sealed.tag.count)
        out.append(headerBytes)
        out.append(sealed.ciphertext)
        out.append(sealed.tag)

        do {
            let dir = destination.deletingLastPathComponent()
            try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
            try out.write(to: destination, options: .atomic)
        } catch {
            throw Failure.io(error)
        }

        return Header(type: typeSymkey, alg: algAesGcm256, iv: nonce, byteLength: headerBytes.count)
    }

    // MARK: - decrypt

    /// Decrypt a cipher file at `cipherAt` into `to`. Throws
    /// ``Failure/authenticationFailed`` if the key is wrong or any byte
    /// was altered; the output file is not created in that case.
    @discardableResult
    public static func decrypt(
        cipherAt source: URL,
        to destination: URL,
        symkey: Data
    ) throws -> Header {
        guard symkey.count == keyLength else { throw Failure.invalidKeyLength(got: symkey.count) }

        let file: Data
        do {
            file = try Data(contentsOf: source, options: .alwaysMapped)
        } catch {
            throw Failure.io(error)
        }

        let header = try parseHeader(file)
        let body = file[(file.startIndex + header.byteLength)...]
        guard body.count >= tagLength else { throw Failure.bodyTooShort(got: body.count) }

        let splitAt = body.endIndex - tagLength
        let ciphertext = body[body.startIndex..<splitAt]
        let tag = body[splitAt...]

        let plaintext: Data
        do {
            plaintext = try AesGcm256.open(
                key: symkey, nonce: header.iv,
                ciphertext: Data(ciphertext), tag: Data(tag)
            )
        } catch {
            throw Failure.authenticationFailed
        }

        do {
            let dir = destination.deletingLastPathComponent()
            try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
            try plaintext.write(to: destination, options: .atomic)
        } catch {
            throw Failure.io(error)
        }

        return header
    }

    // MARK: - header

    /// The header bytes for a given iv. Field order matches Gson's
    /// serialization of `CryptoDataStr` (declaration order, nulls
    /// omitted), so a Swift-written file is byte-identical to a
    /// Java-written one.
    public static func headerJson(iv: Data) -> Data {
        let ivHex = iv.map { String(format: "%02x", $0) }.joined()
        return Data(#"{"type":"Symkey","alg":"AesGcm256@No1_NrC7","iv":"\#(ivHex)"}"#.utf8)
    }

    /// Parse and validate the header at the start of `file`.
    public static func parseHeader(_ file: Data) throws -> Header {
        let length = try headerLength(of: file)
        let jsonBytes = file[file.startIndex..<(file.startIndex + length)]

        let parsed = try? JSONSerialization.jsonObject(with: jsonBytes, options: [])
        guard let dict = parsed as? [String: Any] else { throw Failure.headerNotJson }

        let type = dict["type"] as? String ?? ""
        guard type == typeSymkey else { throw Failure.unsupportedType(type) }
        let alg = dict["alg"] as? String ?? ""
        guard alg == algAesGcm256 else { throw Failure.unsupportedAlg(alg) }
        guard let ivHex = dict["iv"] as? String, let iv = Data(hexString: ivHex) else {
            throw Failure.missingIv
        }
        guard iv.count == ivLength else { throw Failure.invalidIvLength(got: iv.count) }

        return Header(type: type, alg: alg, iv: iv, byteLength: length)
    }

    /// Length of the leading JSON object, by brace counting — a port of
    /// `JsonUtils.readOneJsonFromInputStream`.
    ///
    /// Deliberately not string-aware: the Java reader isn't either, and
    /// both sides must agree on where the ciphertext starts. (Its
    /// backslash branch is a no-op there — `\` is never a brace — so
    /// plain counting reproduces it exactly.)
    public static func headerLength(of file: Data) throws -> Int {
        var depth = 0
        var counting = false
        var index = 0
        for byte in file {
            if byte == UInt8(ascii: "{") {
                counting = true
                depth += 1
            } else if byte == UInt8(ascii: "}") && counting {
                depth -= 1
            }
            index += 1
            if counting && depth == 0 {
                return index
            }
        }
        throw Failure.headerNotFound
    }

    // MARK: - helpers

    /// Fresh 12-byte GCM nonce.
    public static func randomIv() -> Data {
        var bytes = Data(count: ivLength)
        _ = bytes.withUnsafeMutableBytes { ptr in
            SecRandomCopyBytes(kSecRandomDefault, ivLength, ptr.baseAddress!)
        }
        return bytes
    }

    /// Fresh 32-byte symmetric key, as `DataSyncManager` generates per
    /// upload.
    public static func randomSymkey() -> Data {
        var bytes = Data(count: keyLength)
        _ = bytes.withUnsafeMutableBytes { ptr in
            SecRandomCopyBytes(kSecRandomDefault, keyLength, ptr.baseAddress!)
        }
        return bytes
    }
}

private extension Data {
    /// Strict hex decode: even length, hex digits only.
    init?(hexString: String) {
        let chars = Array(hexString.utf8)
        guard chars.count % 2 == 0 else { return nil }
        var out = Data(capacity: chars.count / 2)
        var i = 0
        while i < chars.count {
            guard let hi = Data.hexNibble(chars[i]), let lo = Data.hexNibble(chars[i + 1]) else {
                return nil
            }
            out.append(hi << 4 | lo)
            i += 2
        }
        self = out
    }

    static func hexNibble(_ c: UInt8) -> UInt8? {
        switch c {
        case UInt8(ascii: "0")...UInt8(ascii: "9"): return c - UInt8(ascii: "0")
        case UInt8(ascii: "a")...UInt8(ascii: "f"): return c - UInt8(ascii: "a") + 10
        case UInt8(ascii: "A")...UInt8(ascii: "F"): return c - UInt8(ascii: "A") + 10
        default: return nil
        }
    }
}

import Security
