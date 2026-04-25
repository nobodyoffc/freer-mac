import Foundation

/// QUIC-style variable-length integer (RFC 9000 §16). Used by FUDP for
/// every length-prefix and frame-type byte inside an encrypted packet
/// payload.
///
/// 2-bit prefix in the first byte selects total encoded length:
/// ```
///   00xxxxxx                                                 → 1 byte  (max 63)
///   01xxxxxx xxxxxxxx                                        → 2 bytes (max 16 383)
///   10xxxxxx xxxxxxxx xxxxxxxx xxxxxxxx                      → 4 bytes (max 1 073 741 823)
///   11xxxxxx xxxxxxxx xxxxxxxx xxxxxxxx xxxxxxxx xxxxxxxx
///                              xxxxxxxx xxxxxxxx             → 8 bytes (max 4 611 686 018 427 387 903)
/// ```
///
/// Big-endian within multi-byte forms.
///
/// Distinct from `VarInt` in `FCCore` (Bitcoin/CompactSize). Different
/// header conventions, different byte orders. The two coexist because
/// FCCore wire-formats use Bitcoin VarInt and FUDP wire-formats use
/// QUIC varint; do not mix them.
public enum FudpVarint {

    public static let max1Byte: UInt64 = 63
    public static let max2Bytes: UInt64 = 16_383
    public static let max4Bytes: UInt64 = 1_073_741_823
    public static let max8Bytes: UInt64 = 4_611_686_018_427_387_903  // 2^62 - 1

    public enum Failure: Error, CustomStringConvertible {
        case truncated
        case valueTooLarge(UInt64)

        public var description: String {
            switch self {
            case .truncated:                return "FudpVarint: input truncated"
            case .valueTooLarge(let v):     return "FudpVarint: value 0x\(String(v, radix: 16)) exceeds 62-bit cap"
            }
        }
    }

    public static func encode(_ value: UInt64) -> Data {
        switch value {
        case 0...max1Byte:
            return Data([UInt8(value)])
        case (max1Byte + 1)...max2Bytes:
            return Data([
                UInt8(((value >> 8) & 0xFF) | 0x40),
                UInt8(value & 0xFF)
            ])
        case (max2Bytes + 1)...max4Bytes:
            return Data([
                UInt8(((value >> 24) & 0xFF) | 0x80),
                UInt8((value >> 16) & 0xFF),
                UInt8((value >> 8) & 0xFF),
                UInt8(value & 0xFF)
            ])
        case (max4Bytes + 1)...max8Bytes:
            return Data([
                UInt8(((value >> 56) & 0xFF) | 0xC0),
                UInt8((value >> 48) & 0xFF),
                UInt8((value >> 40) & 0xFF),
                UInt8((value >> 32) & 0xFF),
                UInt8((value >> 24) & 0xFF),
                UInt8((value >> 16) & 0xFF),
                UInt8((value >> 8) & 0xFF),
                UInt8(value & 0xFF)
            ])
        default:
            // Encode-time errors are programming bugs; fail loudly.
            preconditionFailure("FudpVarint: value too large for QUIC varint: \(value)")
        }
    }

    /// Decode the varint at the start of `data`. Returns the value and the
    /// number of bytes consumed (1, 2, 4, or 8).
    public static func decode(_ data: Data) throws -> (value: UInt64, length: Int) {
        let bytes = [UInt8](data)
        guard !bytes.isEmpty else { throw Failure.truncated }
        let first = bytes[0]
        let prefix = (first >> 6) & 0x03

        switch prefix {
        case 0:
            return (UInt64(first & 0x3F), 1)
        case 1:
            guard bytes.count >= 2 else { throw Failure.truncated }
            let v = (UInt64(first & 0x3F) << 8) | UInt64(bytes[1])
            return (v, 2)
        case 2:
            guard bytes.count >= 4 else { throw Failure.truncated }
            var v: UInt64 = UInt64(first & 0x3F) << 24
            v |= UInt64(bytes[1]) << 16
            v |= UInt64(bytes[2]) << 8
            v |= UInt64(bytes[3])
            return (v, 4)
        default:  // 3
            guard bytes.count >= 8 else { throw Failure.truncated }
            var v: UInt64 = UInt64(first & 0x3F) << 56
            v |= UInt64(bytes[1]) << 48
            v |= UInt64(bytes[2]) << 40
            v |= UInt64(bytes[3]) << 32
            v |= UInt64(bytes[4]) << 24
            v |= UInt64(bytes[5]) << 16
            v |= UInt64(bytes[6]) << 8
            v |= UInt64(bytes[7])
            return (v, 8)
        }
    }
}
