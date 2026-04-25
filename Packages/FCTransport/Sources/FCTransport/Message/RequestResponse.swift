import Foundation

/// REQUEST — application request keyed by service id (e.g. `"node.ping"`).
///
/// Payload format:
/// ```
///   varint  sidLength
///   N B     sid (UTF-8)
///   M B     data (remainder of the payload)
/// ```
public struct RequestMessage: Equatable, Sendable {
    public let sid: String
    public let data: Data

    public init(sid: String, data: Data = Data()) {
        self.sid = sid
        self.data = Data(data)
    }

    public func payload() -> Data {
        let sidBytes = Data(sid.utf8)
        var out = Data()
        out.append(FudpVarint.encode(UInt64(sidBytes.count)))
        out.append(sidBytes)
        out.append(data)
        return out
    }

    public static func parse(payload: Data) throws -> RequestMessage {
        let (sidLen, consumed) = try FudpVarint.decode(payload)
        let len = Int(sidLen)
        guard payload.count >= consumed + len else {
            throw AppMessageCodec.Failure.payloadShorterThanLength(
                declared: len,
                available: payload.count - consumed
            )
        }
        let bytes = [UInt8](payload)
        let sidBytes = Data(bytes[consumed..<(consumed + len)])
        let sid = String(data: sidBytes, encoding: .utf8) ?? ""
        let data = Data(bytes[(consumed + len)..<bytes.count])
        return RequestMessage(sid: sid, data: data)
    }
}

/// RESPONSE — paired with a REQUEST by `messageId`.
///
/// Payload format:
/// ```
///   2 B  statusCode (BE UInt16)
///   N B  data (remainder)
/// ```
///
/// Status codes (mirroring FC-AJDK):
/// - 0   `success`
/// - 1   `error`
/// - 400 `badRequest`
/// - 403 `forbidden` / `overCreditLimit`
/// - 404 `notFound`
/// - 500 `internalError`
public struct ResponseMessage: Equatable, Sendable {
    public enum Status: UInt16, Sendable {
        case success         = 0
        case error           = 1
        case badRequest      = 400
        case forbidden       = 403
        case notFound        = 404
        case internalError   = 500
    }

    public let statusCode: UInt16
    public let data: Data

    public init(statusCode: UInt16, data: Data = Data()) {
        self.statusCode = statusCode
        self.data = Data(data)
    }

    public init(status: Status, data: Data = Data()) {
        self.statusCode = status.rawValue
        self.data = Data(data)
    }

    public var isSuccess: Bool { statusCode == Status.success.rawValue }

    public func payload() -> Data {
        var out = Data(capacity: 2 + data.count)
        var be = statusCode.bigEndian
        out.append(Data(bytes: &be, count: 2))
        out.append(data)
        return out
    }

    public static func parse(payload: Data) throws -> ResponseMessage {
        guard payload.count >= 2 else {
            throw AppMessageCodec.Failure.truncated(needed: 2, got: payload.count)
        }
        let bytes = [UInt8](payload)
        let status = (UInt16(bytes[0]) << 8) | UInt16(bytes[1])
        let data = Data(bytes[2..<bytes.count])
        return ResponseMessage(statusCode: status, data: data)
    }
}
