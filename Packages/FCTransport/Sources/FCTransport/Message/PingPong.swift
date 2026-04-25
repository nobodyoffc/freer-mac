import Foundation

/// PING — keepalive / latency probe. Payload is a single 8-byte
/// big-endian Int64 timestamp (millis since epoch on the sender's clock).
public struct PingMessage: Equatable, Sendable {
    public let timestamp: Int64

    public init(timestamp: Int64 = ReplayProtection.currentTimeMillis()) {
        self.timestamp = timestamp
    }

    public func payload() -> Data {
        var ts = UInt64(bitPattern: timestamp).bigEndian
        return Data(bytes: &ts, count: 8)
    }

    public static func parse(payload: Data) throws -> PingMessage {
        guard payload.count >= 8 else {
            throw AppMessageCodec.Failure.truncated(needed: 8, got: payload.count)
        }
        let bytes = [UInt8](payload)
        var ts: UInt64 = 0
        for i in 0..<8 { ts = (ts << 8) | UInt64(bytes[i]) }
        return PingMessage(timestamp: Int64(bitPattern: ts))
    }
}

/// PONG — reply to a PING. Carries:
/// - `echoTimestamp` (8 B BE): the original PING's timestamp, so the
///   sender can compute RTT.
/// - `replyTimestamp` (8 B BE): the responder's clock when it built
///   the PONG, useful for one-way latency hints.
/// - `info` (varint-prefixed bytes): optional opaque data the
///   responder includes when the PING had `FLAG_WANT_PONG_INFO` set.
public struct PongMessage: Equatable, Sendable {
    public let echoTimestamp: Int64
    public let replyTimestamp: Int64
    public let info: Data

    public init(echoTimestamp: Int64, replyTimestamp: Int64, info: Data = Data()) {
        self.echoTimestamp = echoTimestamp
        self.replyTimestamp = replyTimestamp
        self.info = Data(info)
    }

    public func payload() -> Data {
        var out = Data(capacity: 16 + info.count + 4)
        var echoBE = UInt64(bitPattern: echoTimestamp).bigEndian
        out.append(Data(bytes: &echoBE, count: 8))
        var replyBE = UInt64(bitPattern: replyTimestamp).bigEndian
        out.append(Data(bytes: &replyBE, count: 8))
        out.append(FudpVarint.encode(UInt64(info.count)))
        out.append(info)
        return out
    }

    public static func parse(payload: Data) throws -> PongMessage {
        guard payload.count >= 16 else {
            throw AppMessageCodec.Failure.truncated(needed: 16, got: payload.count)
        }
        let bytes = [UInt8](payload)
        var echo: UInt64 = 0
        for i in 0..<8 { echo = (echo << 8) | UInt64(bytes[i]) }
        var reply: UInt64 = 0
        for i in 0..<8 { reply = (reply << 8) | UInt64(bytes[8 + i]) }

        let info: Data
        if payload.count > 16 {
            let rest = payload.advanced(by: 16)
            let (rawLen, consumed) = try FudpVarint.decode(rest)
            let len = Int(rawLen)
            let infoStart = 16 + consumed
            guard payload.count >= infoStart + len else {
                throw AppMessageCodec.Failure.payloadShorterThanLength(
                    declared: len,
                    available: payload.count - infoStart
                )
            }
            info = Data(bytes[infoStart..<(infoStart + len)])
        } else {
            info = Data()
        }

        return PongMessage(
            echoTimestamp: Int64(bitPattern: echo),
            replyTimestamp: Int64(bitPattern: reply),
            info: info
        )
    }
}
