import Foundation
import FCTransport

/// Test double for ``FapiCalling``. Records each outgoing call so
/// assertions can verify the wire shape; replies are produced by a
/// caller-supplied closure so each test stages exactly the response
/// it needs.
///
/// Not `Sendable` enough for true concurrent use across actors —
/// fine for the synchronous test patterns we use here.
final class MockFapiClient: FapiCalling, @unchecked Sendable {

    struct Recorded {
        let api: String
        let params: Data?
        let fcdsl: Data?
        let binary: Data?
        let sid: String?
        let via: String?
        let maxCost: Int64?
        let timeoutMs: Int
    }

    var recorded: [Recorded] = []

    /// Test-supplied responder. Default returns code=0 with empty data.
    /// Override for any api you care about.
    var responder: @Sendable (Recorded) throws -> FapiResponse = { _ in
        FapiResponse(code: 0, message: "ok")
    }

    /// Optional binary trailer per call. Keyed by api name; nil for
    /// calls that don't return binary.
    var binaryByApi: [String: Data] = [:]

    func call(
        api: String,
        params: Data?,
        fcdsl: Data?,
        binary: Data?,
        sid: String?,
        via: String?,
        maxCost: Int64?,
        timeoutMs: Int
    ) async throws -> FapiClient.Reply {
        let r = Recorded(
            api: api, params: params, fcdsl: fcdsl, binary: binary,
            sid: sid, via: via, maxCost: maxCost, timeoutMs: timeoutMs
        )
        recorded.append(r)
        let response = try responder(r)
        return FapiClient.Reply(
            response: response,
            binary: binaryByApi[api],
            messageId: Int64.random(in: 1...Int64.max)
        )
    }
}

/// Helper: build a FapiResponse with `data` set to a JSON-encoded
/// value. Tests use this to stage server replies.
func makeResponse(code: Int = 0, data: Any? = nil, bestHeight: Int64? = nil) throws -> FapiResponse {
    var resp = FapiResponse(code: code, message: code == 0 ? "ok" : "err", bestHeight: bestHeight)
    if let data {
        resp.data = try JSONSerialization.data(
            withJSONObject: data, options: [.sortedKeys, .fragmentsAllowed]
        )
    }
    return resp
}
