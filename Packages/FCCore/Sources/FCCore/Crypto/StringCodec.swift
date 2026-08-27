import Foundation

/// The String converter's engine: take one string, work out what
/// encoding it is, and re-render the bytes underneath in every other
/// encoding. Port of Android's `StringConvertActivity` decode logic.
public enum StringCodec {

    /// The encodings the converter round-trips between.
    public enum Encoding: String, CaseIterable, Sendable {
        case hex = "Hex"
        case base58 = "Base58"
        case base64 = "Base64"
        case base32 = "Base32"
        case utf8 = "UTF-8"
    }

    public enum Failure: Error, CustomStringConvertible {
        case notDecodable(as: Encoding)
        case undetectable

        public var description: String {
            switch self {
            case let .notDecodable(encoding):
                return "This is not valid \(encoding.rawValue)"
            case .undetectable:
                return "Could not decode this as any known encoding"
            }
        }
    }

    /// Decode with a specific encoding.
    public static func decode(_ input: String, as encoding: Encoding) throws -> Data {
        guard let data = tryDecode(input, as: encoding) else {
            throw Failure.notDecodable(as: encoding)
        }
        return data
    }

    /// Guess the encoding and decode, returning both so the UI can say
    /// *which* reading it took.
    ///
    /// The order is Android's — Hex, Base58, Base64, Base32, then UTF-8
    /// as the encoding that never fails. It is worth knowing that this
    /// is a guess and the earlier alphabets are permissive: `beef` is
    /// legal hex *and* legal Base58 *and* ordinary text, and auto-detect
    /// will call it hex. When the reading matters, pick the encoding
    /// explicitly rather than trusting the guess.
    public static func decodeDetecting(_ input: String) throws -> (Data, Encoding) {
        for encoding in [Encoding.hex, .base58, .base64, .base32] {
            if let data = tryDecode(input, as: encoding), !data.isEmpty {
                return (data, encoding)
            }
        }
        return (Data(input.utf8), .utf8)
    }

    /// Render bytes in every encoding, in declaration order. UTF-8 is
    /// present only when the bytes actually *are* UTF-8 — Android calls
    /// `new String(bytes)`, which substitutes U+FFFD into arbitrary
    /// binary and produces a "UTF-8" line that does not decode back to
    /// the bytes it claims to represent.
    public static func renderAll(_ data: Data) -> [(Encoding, String)] {
        var out: [(Encoding, String)] = [
            (.hex, Hex.encode(data)),
            (.base58, Base58.encode(data)),
            (.base64, data.base64EncodedString()),
            (.base32, Base32.encode(data)),
        ]
        if let text = String(data: data, encoding: .utf8) {
            out.append((.utf8, text))
        }
        return out
    }

    private static func tryDecode(_ input: String, as encoding: Encoding) -> Data? {
        let trimmed = input.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return nil }
        switch encoding {
        case .hex:
            return Hex.isHex(trimmed) ? Hex.decodeOrNil(trimmed) : nil
        case .base58:
            return try? Base58.decode(trimmed)
        case .base64:
            return Data(base64Encoded: trimmed)
        case .base32:
            return try? Base32.decode(trimmed)
        case .utf8:
            return Data(trimmed.utf8)
        }
    }
}
