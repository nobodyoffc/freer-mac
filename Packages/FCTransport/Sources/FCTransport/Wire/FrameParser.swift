import Foundation

/// One parsed frame off the wire.
public enum ParsedFrame: Equatable, Sendable {
    case padding
    case stream(StreamFrame)
    case ack(AckFrame)
    case datagram(DatagramFrame)
    case connectionClose(errorCode: UInt64, reason: String)
    case maxData(UInt64)
    case maxStreamData(streamId: UInt64, maxData: UInt64)
    case maxStreams(UInt64)

    /// Whether the frame obliges the receiver to acknowledge its packet
    /// (FUDP3 §2.1): everything except ACK, PADDING and DATAGRAM.
    public var isAckEliciting: Bool {
        switch self {
        case .padding, .ack, .datagram: return false
        default:                        return true
        }
    }
}

/// Parses the *frame portion* of a decrypted FUDP payload. The
/// ts/epoch prefix that may sit ahead of the frames is stripped by
/// `FudpPayload.parse` first; this layer only sees frame bytes.
public enum FrameParser {

    public enum Failure: Error, CustomStringConvertible {
        case truncated
        case malformedStreamFrame(String)
        case malformedAckFrame(String)
        case malformedFrame(String)
        case missingLenFlag(typeByte: UInt8)
        case unknownFrameType(UInt64)

        public var description: String {
            switch self {
            case .truncated:                          return "FrameParser: truncated"
            case .malformedStreamFrame(let r):        return "FrameParser: stream frame — \(r)"
            case .malformedAckFrame(let r):           return "FrameParser: ack frame — \(r)"
            case .malformedFrame(let r):              return "FrameParser: \(r)"
            case .missingLenFlag(let t):              return String(format: "FrameParser: STREAM (0x%02x) without LEN flag (0x02)", t)
            case .unknownFrameType(let t):            return "FrameParser: unknown frame type 0x\(String(t, radix: 16))"
            }
        }
    }

    /// Parse every frame, or throw. **An unknown frame type fails the
    /// whole packet**, frames before it included (FUDP1 §Versioning): a
    /// frame carries no length a receiver could skip it by, so nothing
    /// after it can be read, and delivering only the frames before it
    /// would leave the packet half-processed yet still acknowledged.
    public static func parseAll(_ data: Data) throws -> [ParsedFrame] {
        var frames: [ParsedFrame] = []
        var cursor = data
        while !cursor.isEmpty {
            let (typeValue, typeBytes) = try FudpVarint.decode(cursor)
            cursor = cursor.dropFirst(typeBytes)

            switch typeValue {
            case 0x08...0x0F:
                let (frame, consumed) = try parseStreamFrame(typeByte: UInt8(typeValue), after: cursor)
                frames.append(.stream(frame))
                cursor = cursor.dropFirst(consumed)
            case UInt64(FrameType.ack.rawValue):
                let (frame, consumed) = try parseAckFrame(after: cursor)
                frames.append(.ack(frame))
                cursor = cursor.dropFirst(consumed)
            case UInt64(FrameType.padding.rawValue):
                frames.append(.padding)
            case UInt64(FrameType.datagram.rawValue):
                let (length, lb) = try FudpVarint.decode(cursor)
                cursor = cursor.dropFirst(lb)
                guard length <= UInt64(cursor.count) else {
                    throw Failure.malformedFrame("DATAGRAM length \(length) exceeds remaining \(cursor.count)")
                }
                frames.append(.datagram(DatagramFrame(data: Data(cursor.prefix(Int(length))))))
                cursor = cursor.dropFirst(Int(length))
            case UInt64(FrameType.connectionClose.rawValue):
                let (errorCode, eb) = try FudpVarint.decode(cursor)
                cursor = cursor.dropFirst(eb)
                let (reasonLength, rb) = try FudpVarint.decode(cursor)
                cursor = cursor.dropFirst(rb)
                guard reasonLength <= UInt64(cursor.count) else {
                    throw Failure.malformedFrame("CONNECTION_CLOSE reason length \(reasonLength) exceeds remaining \(cursor.count)")
                }
                let reason = String(decoding: cursor.prefix(Int(reasonLength)), as: UTF8.self)
                frames.append(.connectionClose(errorCode: errorCode, reason: reason))
                cursor = cursor.dropFirst(Int(reasonLength))
            case UInt64(FrameType.maxData.rawValue):
                let (value, vb) = try FudpVarint.decode(cursor)
                cursor = cursor.dropFirst(vb)
                frames.append(.maxData(value))
            case UInt64(FrameType.maxStreamData.rawValue):
                let (streamId, sb) = try FudpVarint.decode(cursor)
                cursor = cursor.dropFirst(sb)
                let (value, vb) = try FudpVarint.decode(cursor)
                cursor = cursor.dropFirst(vb)
                frames.append(.maxStreamData(streamId: streamId, maxData: value))
            case UInt64(FrameType.maxStreams.rawValue):
                let (value, vb) = try FudpVarint.decode(cursor)
                cursor = cursor.dropFirst(vb)
                frames.append(.maxStreams(value))
            default:
                throw Failure.unknownFrameType(typeValue)
            }
        }
        return frames
    }

    // MARK: - per-frame parsers

    private static func parseStreamFrame(typeByte: UInt8, after data: Data) throws -> (StreamFrame, consumed: Int) {
        // STREAM type byte format: 0x08 base | bit0 FIN | bit1 LEN | bit2 OFF.
        // LEN is mandatory in v1.
        let fin = (typeByte & UInt8(StreamFrame.flagFin)) != 0
        let hasLen = (typeByte & UInt8(StreamFrame.flagLen)) != 0
        let hasOff = (typeByte & UInt8(StreamFrame.flagOff)) != 0
        guard hasLen else { throw Failure.missingLenFlag(typeByte: typeByte) }

        var cursor = data
        var consumed = 0

        let (streamId, sidBytes) = try FudpVarint.decode(cursor)
        cursor = cursor.dropFirst(sidBytes); consumed += sidBytes

        var offset: UInt64 = 0
        if hasOff {
            let (off, offBytes) = try FudpVarint.decode(cursor)
            offset = off
            cursor = cursor.dropFirst(offBytes); consumed += offBytes
        }

        let (dataLenBig, lenBytes) = try FudpVarint.decode(cursor)
        cursor = cursor.dropFirst(lenBytes); consumed += lenBytes
        let dataLen = Int(dataLenBig)
        guard cursor.count >= dataLen else {
            throw Failure.malformedStreamFrame("declared \(dataLen) bytes, only \(cursor.count) remain")
        }
        let payload = Data(cursor.prefix(dataLen))
        consumed += dataLen

        let frame = StreamFrame(streamId: streamId, offset: offset, data: payload, fin: fin)
        return (frame, consumed)
    }

    private static func parseAckFrame(after data: Data) throws -> (AckFrame, consumed: Int) {
        var cursor = data
        var consumed = 0

        let (largest, b1) = try FudpVarint.decode(cursor)
        cursor = cursor.dropFirst(b1); consumed += b1
        let (delay, b2) = try FudpVarint.decode(cursor)
        cursor = cursor.dropFirst(b2); consumed += b2
        let (rangeCountBig, b3) = try FudpVarint.decode(cursor)
        cursor = cursor.dropFirst(b3); consumed += b3
        let rangeCount = Int(rangeCountBig)

        var ranges: [AckRange] = []
        if rangeCount > 0 {
            let (firstLen, lb) = try FudpVarint.decode(cursor)
            cursor = cursor.dropFirst(lb); consumed += lb
            ranges.append(AckRange(gap: 0, length: firstLen))
            for _ in 1..<rangeCount {
                let (gap, gb) = try FudpVarint.decode(cursor)
                cursor = cursor.dropFirst(gb); consumed += gb
                let (len, lb2) = try FudpVarint.decode(cursor)
                cursor = cursor.dropFirst(lb2); consumed += lb2
                ranges.append(AckRange(gap: gap, length: len))
            }
        }
        let frame = AckFrame(largestAcknowledged: largest, ackDelay: delay, ranges: ranges)
        return (frame, consumed)
    }
}

/// Decoded plaintext payload (the bytes from inside the AsyTwoWay
/// bundle): optional timestamp + optional sessionEpoch + frames.
public struct ParsedPayload: Equatable, Sendable {
    public let timestamp: Int64?
    public let sessionEpoch: Int64?
    public let frames: [ParsedFrame]
}

extension FudpPayload {

    public static func parse(
        _ data: Data,
        hasTimestamp: Bool,
        hasEpoch: Bool
    ) throws -> ParsedPayload {
        var cursor = data
        let bytes = [UInt8](data)

        var prefixOffset = 0
        let timestamp: Int64?
        if hasTimestamp {
            guard bytes.count >= prefixOffset + 8 else { throw FrameParser.Failure.truncated }
            var ts: UInt64 = 0
            for i in 0..<8 { ts = (ts << 8) | UInt64(bytes[prefixOffset + i]) }
            timestamp = Int64(bitPattern: ts)
            prefixOffset += 8
        } else {
            timestamp = nil
        }
        let sessionEpoch: Int64?
        if hasEpoch {
            guard bytes.count >= prefixOffset + 8 else { throw FrameParser.Failure.truncated }
            var ep: UInt64 = 0
            for i in 0..<8 { ep = (ep << 8) | UInt64(bytes[prefixOffset + i]) }
            sessionEpoch = Int64(bitPattern: ep)
            prefixOffset += 8
        } else {
            sessionEpoch = nil
        }
        cursor = cursor.dropFirst(prefixOffset)

        let frames = try FrameParser.parseAll(Data(cursor))
        return ParsedPayload(timestamp: timestamp, sessionEpoch: sessionEpoch, frames: frames)
    }
}
