import Foundation

/// Hex encoding, matching Android's `utils.Hex`.
///
/// The converters need hex in three modes the ad-hoc `String(format:)`
/// one-liners scattered around this repo do not cover: a *strict*
/// decode that rejects garbage instead of silently truncating, a
/// `is`-predicate the String converter's auto-detect leans on, and
/// tolerance for a leading `0x` because that is how people paste keys.
public enum Hex {

    public enum Failure: Error, CustomStringConvertible {
        case oddLength(got: Int)
        case invalidCharacter(Character)

        public var description: String {
            switch self {
            case let .oddLength(got):
                return "Hex: string must have an even length, got \(got)"
            case let .invalidCharacter(c):
                return "Hex: '\(c)' is not a hex digit"
            }
        }
    }

    /// Lowercase hex, no separators — Java's `Hex.toHex`.
    public static func encode(_ data: Data) -> String {
        let digits = Array("0123456789abcdef".utf8)
        var out = [UInt8]()
        out.reserveCapacity(data.count * 2)
        for byte in data {
            out.append(digits[Int(byte >> 4)])
            out.append(digits[Int(byte & 0x0F)])
        }
        return String(decoding: out, as: UTF8.self)
    }

    /// Strict decode. A leading `0x`/`0X` is stripped first; anything
    /// else non-hex, or an odd length, throws rather than decoding a
    /// prefix — a silent prefix decode is how a mistyped key turns into
    /// a *valid-looking* wrong address.
    public static func decode(_ string: String) throws -> Data {
        let body = stripPrefix(string)
        guard body.count % 2 == 0 else { throw Failure.oddLength(got: body.count) }
        var data = Data(capacity: body.count / 2)
        var index = body.startIndex
        while index < body.endIndex {
            let next = body.index(index, offsetBy: 2)
            guard let byte = UInt8(body[index..<next], radix: 16) else {
                throw Failure.invalidCharacter(body[index])
            }
            data.append(byte)
            index = next
        }
        return data
    }

    /// Non-throwing decode for the `try?`-shaped call sites.
    public static func decodeOrNil(_ string: String) -> Data? {
        try? decode(string)
    }

    /// True when every character is a hex digit and the length is even.
    /// Empty is *not* hex — Android's `Hex.isHexString` says the same,
    /// and the auto-detect would otherwise claim every empty box.
    public static func isHex(_ string: String) -> Bool {
        let body = stripPrefix(string)
        guard !body.isEmpty, body.count % 2 == 0 else { return false }
        return body.allSatisfy(\.isHexDigit)
    }

    private static func stripPrefix(_ string: String) -> Substring {
        let s = Substring(string)
        if s.hasPrefix("0x") || s.hasPrefix("0X") { return s.dropFirst(2) }
        return s
    }
}
