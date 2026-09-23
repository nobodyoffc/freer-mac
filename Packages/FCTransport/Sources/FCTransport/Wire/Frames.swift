import Foundation

/// FUDP frame types. STREAM is a base value (0x08); the lower 3 bits of
/// the on-the-wire type byte encode flags (FIN/LEN/OFF), so any byte in
/// `0x08...0x0F` is a STREAM frame. `0x06`/`0x07` belonged to the
/// removed symkey frames and are not reused.
public enum FrameType: UInt8, Sendable, CaseIterable {
    case padding         = 0x00
    case ack             = 0x01
    case connectionClose = 0x02
    case maxData         = 0x03
    case maxStreamData   = 0x04
    case maxStreams      = 0x05
    case stream          = 0x08
    /// Unreliable application datagram (FUDP7): never retransmitted,
    /// not ACK-eliciting, not counted in bytes in flight.
    case datagram        = 0x10

    public static func parse(typeByte: UInt8) -> FrameType? {
        if (0x08...0x0F).contains(typeByte) { return .stream }
        return FrameType(rawValue: typeByte)
    }
}

/// STREAM frame — the primary application-data carrier.
///
/// Wire layout (all varints are QUIC-style):
/// ```
///   varint typeByte     (0x08 base | FIN(0x01)? | LEN(0x02 always) | OFF(0x04 if offset > 0))
///   varint streamId
///   varint offset       (only if OFF flag set)
///   varint dataLength   (LEN is always set in the released format)
///   raw    data
/// ```
public struct StreamFrame: Equatable, Hashable, Sendable {
    public static let flagFin: UInt64 = 0x01
    public static let flagLen: UInt64 = 0x02
    public static let flagOff: UInt64 = 0x04
    /// Worst-case encoded header: type (1) + stream ID (8) + offset (8)
    /// + length (4). Chunks are sized against this, so a STREAM packet
    /// never outgrows the packet budget whatever its ID and offset.
    public static let maxHeaderSize = 21

    public var streamId: UInt64
    public var offset: UInt64
    public var data: Data
    public var fin: Bool

    public init(streamId: UInt64, offset: UInt64 = 0, data: Data, fin: Bool = false) {
        self.streamId = streamId
        self.offset = offset
        self.data = Data(data)
        self.fin = fin
    }

    public func encode() -> Data {
        var typeByte: UInt64 = UInt64(FrameType.stream.rawValue) | StreamFrame.flagLen
        if fin { typeByte |= StreamFrame.flagFin }
        if offset > 0 { typeByte |= StreamFrame.flagOff }

        var out = Data()
        out.append(FudpVarint.encode(typeByte))
        out.append(FudpVarint.encode(streamId))
        if offset > 0 {
            out.append(FudpVarint.encode(offset))
        }
        out.append(FudpVarint.encode(UInt64(data.count)))
        out.append(data)
        return out
    }
}

/// One range in an ACK frame's range list. The first range in an
/// `AckFrame.ranges` array uses only `length`; its `gap` is implicitly 0
/// and is not encoded on the wire. Subsequent ranges encode both
/// `(gap, length)`.
public struct AckRange: Equatable, Hashable, Sendable {
    public let gap: UInt64
    public let length: UInt64
    public init(gap: UInt64, length: UInt64) {
        self.gap = gap
        self.length = length
    }
}

/// ACK frame — acknowledges packet numbers as ranges.
///
/// Wire layout:
/// ```
///   varint typeByte           (0x01)
///   varint largestAcknowledged
///   varint ackDelay           (microseconds)
///   varint rangeCount
///   varint firstRangeLength   (only if rangeCount > 0)
///   for each subsequent range:
///       varint gap
///       varint length
/// ```
public struct AckFrame: Equatable, Hashable, Sendable {
    public var largestAcknowledged: UInt64
    public var ackDelay: UInt64
    public var ranges: [AckRange]

    public init(largestAcknowledged: UInt64, ackDelay: UInt64, ranges: [AckRange]) {
        self.largestAcknowledged = largestAcknowledged
        self.ackDelay = ackDelay
        self.ranges = ranges
    }

    /// Bytes `encode()` produces.
    public var encodedSize: Int {
        let size = FudpVarint.encodedLength
        var total = size(UInt64(FrameType.ack.rawValue)) + size(largestAcknowledged)
            + size(ackDelay) + size(UInt64(ranges.count))
        if let first = ranges.first {
            total += size(first.length)
            for range in ranges.dropFirst() {
                total += size(range.gap) + size(range.length)
            }
        }
        return total
    }

    public func encode() -> Data {
        var out = Data()
        out.append(FudpVarint.encode(UInt64(FrameType.ack.rawValue)))
        out.append(FudpVarint.encode(largestAcknowledged))
        out.append(FudpVarint.encode(ackDelay))
        out.append(FudpVarint.encode(UInt64(ranges.count)))
        if let first = ranges.first {
            out.append(FudpVarint.encode(first.length))
            for range in ranges.dropFirst() {
                out.append(FudpVarint.encode(range.gap))
                out.append(FudpVarint.encode(range.length))
            }
        }
        return out
    }
}

/// DATAGRAM frame — an unreliable application payload (FUDP7).
///
/// Wire layout:
/// ```
///   varint typeByte   (0x10)
///   varint length
///   raw    data
/// ```
///
/// Encrypted with its packet like any other frame, but never
/// retransmitted, and a packet carrying only DATAGRAM (and ACK/PADDING)
/// frames elicits no ACK and is not counted in bytes in flight. It must
/// fit in one packet: there is no fragmentation and no reassembly.
public struct DatagramFrame: Equatable, Hashable, Sendable {
    public var data: Data

    public init(data: Data) {
        self.data = Data(data)
    }

    /// Encoded size of a DATAGRAM frame carrying `dataLength` bytes.
    public static func encodedSize(dataLength: Int) -> Int {
        FudpVarint.encodedLength(UInt64(FrameType.datagram.rawValue))
            + FudpVarint.encodedLength(UInt64(dataLength))
            + dataLength
    }

    public func encode() -> Data {
        var out = Data(capacity: DatagramFrame.encodedSize(dataLength: data.count))
        out.append(FudpVarint.encode(UInt64(FrameType.datagram.rawValue)))
        out.append(FudpVarint.encode(UInt64(data.count)))
        out.append(data)
        return out
    }
}

/// PADDING frame — single varint type byte (0x00). Used to fill packets
/// to a minimum size for amplification protection.
public enum PaddingFrame {
    public static func encode() -> Data {
        FudpVarint.encode(UInt64(FrameType.padding.rawValue))
    }
}
