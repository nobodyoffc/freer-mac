import Foundation

/// Bitcoin variable-length integer encoding (a.k.a. `CompactSize`).
///
/// ```
/// value < 0xFD                 → 1 byte                                (value)
/// 0xFD  ≤ value ≤ 0xFFFF       → 3 bytes (0xFD + little-endian UInt16)
/// 0x10000 ≤ value ≤ 0xFFFFFFFF → 5 bytes (0xFE + little-endian UInt32)
/// value ≥ 0x100000000          → 9 bytes (0xFF + little-endian UInt64)
/// ```
///
/// Used for every length-prefix in Bitcoin-family wire formats
/// (script lengths, input/output counts, raw-tx length in packets, …).
public enum VarInt {

    public enum Failure: Error, CustomStringConvertible {
        case truncated

        public var description: String {
            switch self {
            case .truncated: return "VarInt: input truncated"
            }
        }
    }

    public static func encode(_ value: UInt64) -> Data {
        var out = Data()
        switch value {
        case 0..<0xFD:
            out.append(UInt8(value))
        case 0xFD...0xFFFF:
            out.append(0xFD)
            out.append(leBytes(UInt16(value)))
        case 0x10000...0xFFFFFFFF:
            out.append(0xFE)
            out.append(leBytes(UInt32(value)))
        default:
            out.append(0xFF)
            out.append(leBytes(value))
        }
        return out
    }

    /// Decode a VarInt from the start of `data`. Returns the decoded value
    /// and the number of bytes it occupied (1, 3, 5, or 9).
    public static func decode(_ data: Data) throws -> (value: UInt64, length: Int) {
        let bytes = [UInt8](data)
        guard !bytes.isEmpty else { throw Failure.truncated }
        let prefix = bytes[0]
        switch prefix {
        case 0..<0xFD:
            return (UInt64(prefix), 1)
        case 0xFD:
            guard bytes.count >= 3 else { throw Failure.truncated }
            let v = UInt16(bytes[1]) | (UInt16(bytes[2]) << 8)
            return (UInt64(v), 3)
        case 0xFE:
            guard bytes.count >= 5 else { throw Failure.truncated }
            var v: UInt32 = 0
            for i in 0..<4 { v |= UInt32(bytes[1 + i]) << (8 * i) }
            return (UInt64(v), 5)
        default:  // 0xFF
            guard bytes.count >= 9 else { throw Failure.truncated }
            var v: UInt64 = 0
            for i in 0..<8 { v |= UInt64(bytes[1 + i]) << (8 * i) }
            return (v, 9)
        }
    }

    // MARK: - little-endian byte helpers

    private static func leBytes(_ value: UInt16) -> Data {
        var v = value.littleEndian
        return Data(bytes: &v, count: 2)
    }
    private static func leBytes(_ value: UInt32) -> Data {
        var v = value.littleEndian
        return Data(bytes: &v, count: 4)
    }
    private static func leBytes(_ value: UInt64) -> Data {
        var v = value.littleEndian
        return Data(bytes: &v, count: 8)
    }
}
