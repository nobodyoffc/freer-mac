import Foundation

/// Wire codec for FAPI messages. Mirror of
/// `FC-AJDK/.../fapi/message/UnifiedCodec.java`.
///
/// On the wire (REQUEST or RESPONSE):
/// ```
///   4 B  headerLen   (big-endian Int32)
///   N B  headerJson  (UTF-8, FapiRequest or FapiResponse)
///   M B  binaryData  (optional, remainder of payload)
/// ```
///
/// JSON layer uses `JSONSerialization` rather than `Codable`/`JSONEncoder`
/// for two reasons:
/// - The `params` / `fcdsl` / `data` fields carry **raw, opaque JSON
///   subtrees** that the call site already encoded. We splice them in
///   verbatim and carve them out on decode — Codable can't express
///   "include this raw JSON blob as-is" without custom encoders.
/// - We can request `[.sortedKeys]` for deterministic output, which
///   makes test assertions and on-the-wire diffs sane.
///
/// JSON serialization isn't byte-deterministic across implementations
/// (key order, whitespace, number formatting), so we don't try for
/// byte-exact parity with Java's Gson/Jackson output. What we DO
/// guarantee: the two sides decode each other's JSON correctly.
public enum UnifiedCodec {

    public enum Failure: Error, CustomStringConvertible {
        case truncated(needed: Int, got: Int)
        case invalidHeaderLength(Int)
        case invalidJson(Error)
        case headerNotObject

        public var description: String {
            switch self {
            case let .truncated(needed, got):
                return "UnifiedCodec: truncated (need ≥ \(needed), got \(got))"
            case .invalidHeaderLength(let n):
                return "UnifiedCodec: invalid headerLen \(n)"
            case .invalidJson(let e):
                return "UnifiedCodec: invalid JSON — \(e)"
            case .headerNotObject:
                return "UnifiedCodec: header JSON is not a top-level object"
            }
        }
    }

    public static let headerLengthFieldSize = 4

    // MARK: - request

    public static func encodeRequest(_ request: FapiRequest, binary: Data? = nil) throws -> Data {
        var dict: [String: Any] = [:]
        if let v = request.id        { dict["id"]        = v }
        if let v = request.api       { dict["api"]       = v }
        if let v = request.sid       { dict["sid"]       = v }
        if let v = request.via       { dict["via"]       = v }
        if let v = request.fcdsl     { dict["fcdsl"]     = try parseJsonValue(v) }
        if let v = request.params    { dict["params"]    = try parseJsonValue(v) }
        // dataSize defaults to binary length when binary is supplied,
        // matching the Java helper. An explicit dataSize on the request
        // wins.
        if let v = request.dataSize {
            dict["dataSize"] = v
        } else if let bin = binary, !bin.isEmpty {
            dict["dataSize"] = Int64(bin.count)
        }
        if let v = request.dataHash  { dict["dataHash"]  = v }
        if let v = request.maxCost   { dict["maxCost"]   = v }
        return try encode(headerDict: dict, binary: binary)
    }

    public static func decodeRequest(_ data: Data) throws -> (FapiRequest, binary: Data?) {
        let (headerDict, binary) = try splitHeaderAndBinary(data)
        var req = FapiRequest()
        req.id        = headerDict["id"]        as? String
        req.api       = headerDict["api"]       as? String
        req.sid       = headerDict["sid"]       as? String
        req.via       = headerDict["via"]       as? String
        req.fcdsl     = try reSerialize(headerDict["fcdsl"])
        req.params    = try reSerialize(headerDict["params"])
        req.dataSize  = readInt64(headerDict["dataSize"])
        req.dataHash  = headerDict["dataHash"]  as? String
        req.maxCost   = readInt64(headerDict["maxCost"])
        return (req, binary)
    }

    // MARK: - response

    public static func encodeResponse(_ response: FapiResponse, binary: Data? = nil) throws -> Data {
        var dict: [String: Any] = [:]
        if let v = response.id          { dict["id"]          = v }
        if let v = response.requestId   { dict["requestId"]   = v }
        if let v = response.code        { dict["code"]        = v }
        if let v = response.message     { dict["message"]     = v }
        if let v = response.data        { dict["data"]        = try parseJsonValue(v) }
        if let v = response.got         { dict["got"]         = v }
        if let v = response.total       { dict["total"]       = v }
        if let v = response.last        { dict["last"]        = v }
        if let v = response.bestHeight  { dict["bestHeight"]  = v }
        if let v = response.bestBlockId { dict["bestBlockId"] = v }
        if let v = response.balance     { dict["balance"]     = v }
        if let v = response.balanceSeq  { dict["balanceSeq"]  = v }
        if let v = response.dataSize {
            dict["dataSize"] = v
        } else if let bin = binary, !bin.isEmpty {
            dict["dataSize"] = Int64(bin.count)
        }
        if let v = response.charged     { dict["charged"]     = v }
        return try encode(headerDict: dict, binary: binary)
    }

    public static func decodeResponse(_ data: Data) throws -> (FapiResponse, binary: Data?) {
        let (headerDict, binary) = try splitHeaderAndBinary(data)
        var resp = FapiResponse()
        resp.id          = headerDict["id"]          as? String
        resp.requestId   = headerDict["requestId"]   as? String
        resp.code        = (headerDict["code"]       as? NSNumber)?.intValue
        resp.message     = headerDict["message"]     as? String
        resp.data        = try reSerialize(headerDict["data"])
        resp.got         = readInt64(headerDict["got"])
        resp.total       = readInt64(headerDict["total"])
        resp.last        = headerDict["last"]        as? [String]
        resp.bestHeight  = readInt64(headerDict["bestHeight"])
        resp.bestBlockId = headerDict["bestBlockId"] as? String
        resp.balance     = readInt64(headerDict["balance"])
        resp.balanceSeq  = readInt64(headerDict["balanceSeq"])
        resp.dataSize    = readInt64(headerDict["dataSize"])
        resp.charged     = readInt64(headerDict["charged"])
        return (resp, binary)
    }

    // MARK: - helpers

    private static func encode(headerDict: [String: Any], binary: Data?) throws -> Data {
        let headerBytes: Data
        do {
            headerBytes = try JSONSerialization.data(
                withJSONObject: headerDict,
                options: [.sortedKeys, .withoutEscapingSlashes]
            )
        } catch {
            throw Failure.invalidJson(error)
        }
        var out = Data(capacity: 4 + headerBytes.count + (binary?.count ?? 0))
        var lenBE = UInt32(headerBytes.count).bigEndian
        out.append(Data(bytes: &lenBE, count: 4))
        out.append(headerBytes)
        if let binary, !binary.isEmpty { out.append(binary) }
        return out
    }

    private static func splitHeaderAndBinary(_ data: Data) throws -> (header: [String: Any], binary: Data?) {
        guard data.count >= headerLengthFieldSize else {
            throw Failure.truncated(needed: headerLengthFieldSize, got: data.count)
        }
        let bytes = [UInt8](data)
        let headerLen = Int(
            (UInt32(bytes[0]) << 24) |
            (UInt32(bytes[1]) << 16) |
            (UInt32(bytes[2]) <<  8) |
             UInt32(bytes[3])
        )
        guard headerLen >= 0, headerLen <= bytes.count - 4 else {
            throw Failure.invalidHeaderLength(headerLen)
        }
        let jsonBytes = Data(bytes[4..<(4 + headerLen)])
        let parsed: Any
        do {
            parsed = try JSONSerialization.jsonObject(with: jsonBytes, options: [])
        } catch {
            throw Failure.invalidJson(error)
        }
        guard let dict = parsed as? [String: Any] else {
            throw Failure.headerNotObject
        }
        let binary: Data?
        if bytes.count > 4 + headerLen {
            binary = Data(bytes[(4 + headerLen)..<bytes.count])
        } else {
            binary = nil
        }
        return (dict, binary)
    }

    /// Parse raw JSON bytes into a value usable inside `JSONSerialization`'s
    /// dictionary. Used for the opaque `params` / `fcdsl` / `data` fields.
    private static func parseJsonValue(_ raw: Data) throws -> Any {
        do {
            return try JSONSerialization.jsonObject(with: raw, options: [.fragmentsAllowed])
        } catch {
            throw Failure.invalidJson(error)
        }
    }

    /// Re-serialize a decoded JSON value back to UTF-8 bytes for the
    /// caller to inspect or forward. Returns nil if the field was absent.
    private static func reSerialize(_ value: Any?) throws -> Data? {
        guard let value, !(value is NSNull) else { return nil }
        do {
            return try JSONSerialization.data(
                withJSONObject: value,
                options: [.sortedKeys, .withoutEscapingSlashes, .fragmentsAllowed]
            )
        } catch {
            throw Failure.invalidJson(error)
        }
    }

    /// JSONSerialization gives us NSNumber for numeric values; coerce to
    /// Int64 with rounding-friendly behavior (same as Java's `long` coercion).
    private static func readInt64(_ value: Any?) -> Int64? {
        guard let n = value as? NSNumber else { return nil }
        return n.int64Value
    }
}
