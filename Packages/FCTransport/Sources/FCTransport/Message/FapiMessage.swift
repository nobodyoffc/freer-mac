import Foundation

/// Application-level FAPI request. Wire-compatible with the Java
/// reference at `FC-AJDK/.../fapi/message/FapiRequest.java`.
///
/// `params`, `fcdsl` are kept as raw UTF-8 JSON `Data` rather than typed
/// Codable structs, because they vary per API endpoint and the typing
/// belongs to the call sites. UnifiedCodec splices these in verbatim
/// during encode and carves them out during decode.
///
/// `id` is a string, not the Int64 transport-level `messageId` —
/// FAPI keeps a parallel application-level identifier so audit logs
/// can survive across transport-id reassignments.
public struct FapiRequest: Equatable, Sendable {
    public var id: String?
    public var api: String?
    public var sid: String?
    public var via: String?
    /// Raw JSON for query-style endpoints (search/getByIds/…). Mutually
    /// exclusive with ``params`` per the protocol, but neither side
    /// enforces it — the server just looks at whichever it expects.
    public var fcdsl: Data?
    /// Raw JSON for operation-style endpoints (put/carve/…).
    public var params: Data?
    public var dataSize: Int64?
    public var dataHash: String?
    public var maxCost: Int64?

    public init(
        id: String? = nil,
        api: String? = nil,
        sid: String? = nil,
        via: String? = nil,
        fcdsl: Data? = nil,
        params: Data? = nil,
        dataSize: Int64? = nil,
        dataHash: String? = nil,
        maxCost: Int64? = nil
    ) {
        self.id = id
        self.api = api
        self.sid = sid
        self.via = via
        self.fcdsl = fcdsl
        self.params = params
        self.dataSize = dataSize
        self.dataHash = dataHash
        self.maxCost = maxCost
    }

    /// Generate a request id matching Java's
    /// `"req-" + millis + "-" + hex(int)` format. We don't depend on
    /// this format being byte-stable across implementations — it's only
    /// used for logging/audit — but matching makes server logs readable.
    public static func generateId() -> String {
        let millis = Int64(Date().timeIntervalSince1970 * 1000)
        let r = UInt32.random(in: 0...UInt32.max)
        return "req-\(millis)-\(String(r, radix: 16))"
    }
}

/// Application-level FAPI response. Wire-compatible with the Java
/// reference at `FC-AJDK/.../fapi/message/FapiResponse.java`.
///
/// `data` is the raw JSON value of the `data` field — could be an
/// object, array, string, number, etc. depending on the endpoint.
/// Callers parse the inner shape themselves.
public struct FapiResponse: Equatable, Sendable {
    public var id: String?
    /// Echoes ``FapiRequest/id`` so the client can match by the
    /// app-level identifier. Should equal the request's `id` for
    /// correctly-implemented servers; we surface mismatches as a
    /// dedicated error rather than silently accepting drift.
    public var requestId: String?
    public var code: Int?
    public var message: String?
    public var data: Data?
    public var got: Int64?
    public var total: Int64?
    public var last: [String]?
    public var bestHeight: Int64?
    public var bestBlockId: String?
    public var balance: Int64?
    public var balanceSeq: Int64?
    public var dataSize: Int64?
    public var charged: Int64?

    public init(
        id: String? = nil,
        requestId: String? = nil,
        code: Int? = nil,
        message: String? = nil,
        data: Data? = nil,
        got: Int64? = nil,
        total: Int64? = nil,
        last: [String]? = nil,
        bestHeight: Int64? = nil,
        bestBlockId: String? = nil,
        balance: Int64? = nil,
        balanceSeq: Int64? = nil,
        dataSize: Int64? = nil,
        charged: Int64? = nil
    ) {
        self.id = id
        self.requestId = requestId
        self.code = code
        self.message = message
        self.data = data
        self.got = got
        self.total = total
        self.last = last
        self.bestHeight = bestHeight
        self.bestBlockId = bestBlockId
        self.balance = balance
        self.balanceSeq = balanceSeq
        self.dataSize = dataSize
        self.charged = charged
    }

    public var isSuccess: Bool { code == 0 }
}
