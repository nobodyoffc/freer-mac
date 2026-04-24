import Foundation
import BigInt

/// Base58 and Base58Check encoding — the Bitcoin-legacy alphabet used by
/// FCH / Freer for legacy addresses (FIDs) and WIF private keys.
///
/// The alphabet deliberately omits `0`, `O`, `I`, `l` to reduce
/// transcription errors:
/// `123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz`
public enum Base58 {

    public enum Failure: Error, CustomStringConvertible {
        case invalidCharacter(Character)
        case invalidChecksum
        case tooShortForChecksum

        public var description: String {
            switch self {
            case .invalidCharacter(let c): return "Base58: invalid character '\(c)'"
            case .invalidChecksum:         return "Base58Check: checksum mismatch"
            case .tooShortForChecksum:     return "Base58Check: input shorter than 4 bytes"
            }
        }
    }

    static let alphabet: [UInt8] = Array(
        "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".utf8
    )

    /// ASCII→index lookup; entries for chars not in the alphabet are `-1`.
    private static let alphabetMap: [Int8] = {
        var map = [Int8](repeating: -1, count: 128)
        for (i, c) in alphabet.enumerated() {
            map[Int(c)] = Int8(i)
        }
        return map
    }()

    public static func encode(_ data: Data) -> String {
        if data.isEmpty { return "" }
        let bytes = [UInt8](data)

        // Leading zero bytes map to '1' characters in the output.
        var leadingZeros = 0
        while leadingZeros < bytes.count && bytes[leadingZeros] == 0 { leadingZeros += 1 }

        var n = BigUInt(Data(bytes))
        var digits: [UInt8] = []
        let base = BigUInt(58)
        while n > 0 {
            let (q, r) = n.quotientAndRemainder(dividingBy: base)
            digits.append(alphabet[Int(r)])
            n = q
        }

        var out = [UInt8](repeating: alphabet[0], count: leadingZeros)
        out.append(contentsOf: digits.reversed())
        return String(bytes: out, encoding: .ascii) ?? ""
    }

    public static func decode(_ string: String) throws -> Data {
        let chars = Array(string.utf8)
        if chars.isEmpty { return Data() }

        var n = BigUInt(0)
        let base = BigUInt(58)
        for c in chars {
            guard c < 128, alphabetMap[Int(c)] >= 0 else {
                throw Failure.invalidCharacter(Character(UnicodeScalar(c)))
            }
            n = n * base + BigUInt(Int(alphabetMap[Int(c)]))
        }

        // Each leading '1' character is one leading zero byte in the payload.
        var leadingOnes = 0
        while leadingOnes < chars.count && chars[leadingOnes] == alphabet[0] { leadingOnes += 1 }

        var out = Data(repeating: 0, count: leadingOnes)
        out.append(n.serialize())
        return out
    }
}

/// Base58Check — Base58 with a 4-byte `double_sha256(payload)[0..4]`
/// checksum suffix. Used for FCH legacy addresses (FIDs) and WIF private
/// keys.
public enum Base58Check {

    public static func encode(_ payload: Data) -> String {
        let checksum = Hash.doubleSha256(payload).prefix(4)
        var withChecksum = Data(payload)
        withChecksum.append(contentsOf: checksum)
        return Base58.encode(withChecksum)
    }

    public static func decode(_ string: String) throws -> Data {
        let decoded = try Base58.decode(string)
        guard decoded.count >= 4 else { throw Base58.Failure.tooShortForChecksum }
        let normal = Data(decoded)
        let payload = Data(normal.prefix(normal.count - 4))
        let provided = Data(normal.suffix(4))
        let expected = Data(Hash.doubleSha256(payload).prefix(4))
        guard provided == expected else { throw Base58.Failure.invalidChecksum }
        return payload
    }
}
