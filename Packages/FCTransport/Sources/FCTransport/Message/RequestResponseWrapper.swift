import Foundation

/// FUDP-layer REQUEST payload wrapper. Sits **between** the
/// `AppMessageEnvelope` (which carries type / messageId / flags) and
/// the FAPI-level `UnifiedCodec` body. The wire shape mirrors
/// `FC-JDK fudp/message/RequestMessage.java`:
///
/// ```
///   varint  sidLength
///   N B     sid (UTF-8) — service routing key, e.g. "" for the
///                          default service or the sid of a
///                          specific FAPI service
///   M B     data         — UnifiedCodec(FapiRequest) bytes
/// ```
///
/// **Why the extra layer:** the FudpNode dispatches by the FUDP-layer
/// `sid`, and the receiving FAPI server then parses the inner data as
/// UnifiedCodec to get the `FapiRequest`. They serve different
/// purposes — sid is the *transport* address, FapiRequest.api is the
/// *application* method.
///
/// (Phase 5.3 retired this type prematurely on the assumption the
/// wire was just `AppMessage payload = UnifiedCodec`. That was wrong:
/// the live FAPI server expects the wrapper, and skipping it
/// produced a 500 INTERNAL_ERROR. Restored in Phase 7.2.1.)
public struct RequestMessage: Equatable, Sendable {
    public let sid: String
    public let data: Data

    public init(sid: String, data: Data) {
        self.sid = sid
        self.data = Data(data)
    }

    public func encode() -> Data {
        let sidBytes = Data(sid.utf8)
        var out = Data()
        out.append(FudpVarint.encode(UInt64(sidBytes.count)))
        out.append(sidBytes)
        out.append(data)
        return out
    }

    public static func parse(_ data: Data) throws -> RequestMessage {
        let (sidLen, consumed) = try FudpVarint.decode(data)
        let len = Int(sidLen)
        guard data.count >= consumed + len else {
            throw AppMessageCodec.Failure.payloadShorterThanLength(
                declared: len, available: data.count - consumed
            )
        }
        let bytes = [UInt8](data)
        let sidBytes = Data(bytes[consumed..<(consumed + len)])
        let sid = String(data: sidBytes, encoding: .utf8) ?? ""
        let inner = Data(bytes[(consumed + len)..<bytes.count])
        return RequestMessage(sid: sid, data: inner)
    }
}

/// FUDP-layer RESPONSE payload wrapper. Mirrors
/// `FC-JDK fudp/message/ResponseMessage.java`:
///
/// ```
///   2 B   statusCode  (BE UInt16)   — 0=success, 4xx/5xx mirror HTTP
///   N B   data                       — UnifiedCodec(FapiResponse) bytes
/// ```
///
/// `statusCode` is the *transport-level* result. A non-zero value
/// (e.g. 500) means the server couldn't even build a meaningful
/// FapiResponse — common when the request was malformed. Inspect
/// `statusCode` BEFORE trying `UnifiedCodec.decodeResponse(data)`,
/// since on transport errors the inner bytes may be a plain UTF-8
/// error string rather than valid UnifiedCodec.
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

    public func encode() -> Data {
        var out = Data(capacity: 2 + data.count)
        var be = statusCode.bigEndian
        out.append(Data(bytes: &be, count: 2))
        out.append(data)
        return out
    }

    public static func parse(_ data: Data) throws -> ResponseMessage {
        guard data.count >= 2 else {
            throw AppMessageCodec.Failure.truncated(needed: 2, got: data.count)
        }
        let bytes = [UInt8](data)
        let status = (UInt16(bytes[0]) << 8) | UInt16(bytes[1])
        let inner = Data(bytes[2..<bytes.count])
        return ResponseMessage(statusCode: status, data: inner)
    }
}
