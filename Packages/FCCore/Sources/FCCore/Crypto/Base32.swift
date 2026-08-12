import Foundation

/// RFC 4648 Base32, unpadded — byte-compatible with the Java
/// `fc_ajdk.utils.Base32` (which never emits or accepts `=` padding).
/// Decoding is case-insensitive, like the Java `toUpperCase` path.
public enum Base32 {

    public enum Failure: Error, CustomStringConvertible {
        case invalidCharacter(Character)

        public var description: String {
            switch self {
            case .invalidCharacter(let c):
                return "Base32: invalid character '\(c)'"
            }
        }
    }

    private static let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".utf8)

    private static let reverse: [Int8] = {
        var table = [Int8](repeating: -1, count: 128)
        for (i, c) in alphabet.enumerated() {
            table[Int(c)] = Int8(i)
        }
        return table
    }()

    public static func encode(_ data: Data) -> String {
        guard !data.isEmpty else { return "" }
        var out = [UInt8]()
        out.reserveCapacity((data.count * 8 + 4) / 5)
        var buffer = 0
        var bits = 0
        for byte in data {
            buffer = (buffer << 8) | Int(byte)
            bits += 8
            while bits >= 5 {
                out.append(alphabet[(buffer >> (bits - 5)) & 0x1F])
                bits -= 5
            }
        }
        if bits > 0 {
            out.append(alphabet[(buffer << (5 - bits)) & 0x1F])
        }
        return String(decoding: out, as: UTF8.self)
    }

    public static func decode(_ string: String) throws -> Data {
        guard !string.isEmpty else { return Data() }
        var out = Data(capacity: string.utf8.count * 5 / 8)
        var buffer = 0
        var bits = 0
        for ch in string.uppercased() {
            guard let ascii = ch.asciiValue, reverse[Int(ascii)] >= 0 else {
                throw Failure.invalidCharacter(ch)
            }
            buffer = (buffer << 5) | Int(reverse[Int(ascii)])
            bits += 5
            if bits >= 8 {
                out.append(UInt8((buffer >> (bits - 8)) & 0xFF))
                bits -= 8
            }
        }
        return out
    }
}
