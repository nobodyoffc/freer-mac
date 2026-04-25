import Foundation

/// One parsed frame off the wire. Frame types we don't yet model are
/// surfaced as `.unknown` so a receive loop can keep going rather than
/// crashing on a frame from a future protocol revision.
public enum ParsedFrame: Equatable, Sendable {
    case padding
    case stream(StreamFrame)
    case ack(AckFrame)
    case unknown(typeByte: UInt8, body: Data)
}

/// Parses the *frame portion* of a decrypted FUDP payload. The
/// ts/epoch prefix that may sit ahead of the frames is stripped by
/// `FudpPayload.parse` first; this layer only sees frame bytes.
public enum FrameParser {

    public enum Failure: Error, CustomStringConvertible {
        case truncated
        case malformedStreamFrame(String)
        case malformedAckFrame(String)
        case missingLenFlag(typeByte: UInt8)

        public var description: String {
            switch self {
            case .truncated:                          return "FrameParser: truncated"
            case .malformedStreamFrame(let r):        return "FrameParser: stream frame — \(r)"
            case .malformedAckFrame(let r):           return "FrameParser: ack frame — \(r)"
            case .missingLenFlag(let t):              return String(format: "FrameParser: STREAM (0x%02x) without LEN flag (0x02)", t)
            }
        }
    }

    public static func parseAll(_ data: Data) throws -> [ParsedFrame] {
        var frames: [ParsedFrame] = []
        var cursor = data
        while !cursor.isEmpty {
            let (typeBig, typeBytes) = try FudpVarint.decode(cursor)
            cursor = cursor.dropFirst(typeBytes)
            let typeByte = UInt8(truncatingIfNeeded: typeBig)

            if (0x08...0x0F).contains(typeByte) {
                let (frame, consumed) = try parseStreamFrame(typeByte: typeByte, after: cursor)
                frames.append(.stream(frame))
                cursor = cursor.dropFirst(consumed)
            } else if typeByte == FrameType.ack.rawValue {
                let (frame, consumed) = try parseAckFrame(after: cursor)
                frames.append(.ack(frame))
                cursor = cursor.dropFirst(consumed)
            } else if typeByte == FrameType.padding.rawValue {
                frames.append(.padding)
            } else {
                // Unknown frame type — without a length we can't safely skip,
                // so we surface remainder as opaque body and stop. This
                // matches the FC-AJDK behaviour on encountering reserved
                // types: don't crash, expose for higher-layer handling.
                let body = Data(cursor)
                frames.append(.unknown(typeByte: typeByte, body: body))
                break
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
