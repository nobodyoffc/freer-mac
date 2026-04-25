import Foundation

/// FUDP packet header — 21 plaintext bytes, big-endian, prepended to
/// every UDP datagram. Layout matches `FC-JDK/src/main/java/fudp/packet/PacketHeader.java`:
///
/// ```
///   offset 0   1 B   flags  (bits 0-1: packetType, bit 4: FIN, bit 5: hasTimestamp, bit 6: hasEpoch)
///          1   4 B   version (BE UInt32; current released format = 1)
///          5   8 B   connectionId  (BE Int64)
///          13  8 B   packetNumber  (BE Int64)
///          21
/// ```
///
/// Per the FUDP v2 repair (F1), this 21-byte serialized header is bound
/// as AEAD AAD on every encrypted data/ACK packet. Mutating any field
/// breaks the GCM tag at the receiver.
public struct PacketHeader: Equatable, Hashable, Sendable {

    public static let size = 21
    public static let currentVersion: UInt32 = 1

    public enum PacketType: UInt8, Sendable, CaseIterable {
        case data    = 0x00
        case ack     = 0x01
        case control = 0x02
        case error   = 0x03
    }

    /// Non-type flag bits. The packet type lives in bits 0-1 of the
    /// wire byte and is stored separately in ``packetType``.
    public struct Flags: OptionSet, Sendable, Hashable {
        public let rawValue: UInt8
        public init(rawValue: UInt8) { self.rawValue = rawValue }

        public static let fin          = Flags(rawValue: 0x10)  // bit 4
        public static let hasTimestamp = Flags(rawValue: 0x20)  // bit 5
        public static let hasEpoch     = Flags(rawValue: 0x40)  // bit 6
    }

    public enum Failure: Error, CustomStringConvertible {
        case truncated(got: Int)
        case unknownPacketType(UInt8)

        public var description: String {
            switch self {
            case let .truncated(got):
                return "PacketHeader: need \(PacketHeader.size) bytes, got \(got)"
            case let .unknownPacketType(bits):
                return String(format: "PacketHeader: unknown packet type bits 0x%02x", bits)
            }
        }
    }

    public var packetType: PacketType
    public var flags: Flags
    public var version: UInt32
    public var connectionId: Int64
    public var packetNumber: Int64

    public init(
        packetType: PacketType = .data,
        flags: Flags = [],
        version: UInt32 = PacketHeader.currentVersion,
        connectionId: Int64,
        packetNumber: Int64
    ) {
        self.packetType = packetType
        self.flags = flags
        self.version = version
        self.connectionId = connectionId
        self.packetNumber = packetNumber
    }

    /// 21-byte big-endian wire encoding. The byte sequence returned here
    /// is the AAD for the AEAD on encrypted packets.
    public func encode() -> Data {
        var out = Data(capacity: PacketHeader.size)
        // Flags byte = (non-type flags) | (type bits 0-1).
        let flagsByte = (flags.rawValue & 0xFC) | (packetType.rawValue & 0x03)
        out.append(flagsByte)
        out.append(beBytes32(version))
        out.append(beBytes64(UInt64(bitPattern: connectionId)))
        out.append(beBytes64(UInt64(bitPattern: packetNumber)))
        return out
    }

    public static func decode(_ data: Data) throws -> PacketHeader {
        let bytes = [UInt8](data)
        guard bytes.count >= size else {
            throw Failure.truncated(got: bytes.count)
        }
        let typeBits = bytes[0] & 0x03
        guard let packetType = PacketType(rawValue: typeBits) else {
            throw Failure.unknownPacketType(typeBits)
        }
        let flags = Flags(rawValue: bytes[0] & 0xFC)
        let version = readBE32(bytes, at: 1)
        let connId = Int64(bitPattern: readBE64(bytes, at: 5))
        let pktNum = Int64(bitPattern: readBE64(bytes, at: 13))
        return PacketHeader(
            packetType: packetType,
            flags: flags,
            version: version,
            connectionId: connId,
            packetNumber: pktNum
        )
    }
}

// MARK: - big-endian byte helpers

@inline(__always)
private func beBytes32(_ value: UInt32) -> Data {
    var v = value.bigEndian
    return Data(bytes: &v, count: 4)
}

@inline(__always)
private func beBytes64(_ value: UInt64) -> Data {
    var v = value.bigEndian
    return Data(bytes: &v, count: 8)
}

@inline(__always)
private func readBE32(_ bytes: [UInt8], at offset: Int) -> UInt32 {
    var v: UInt32 = 0
    for i in 0..<4 { v = (v << 8) | UInt32(bytes[offset + i]) }
    return v
}

@inline(__always)
private func readBE64(_ bytes: [UInt8], at offset: Int) -> UInt64 {
    var v: UInt64 = 0
    for i in 0..<8 { v = (v << 8) | UInt64(bytes[offset + i]) }
    return v
}
