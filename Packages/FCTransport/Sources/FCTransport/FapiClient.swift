import Foundation

/// Surface that any FAPI-speaking client exposes. Extracted as a
/// protocol so domain-layer services can be unit-tested with an
/// in-process stub instead of needing a live FUDP server. ``FapiClient``
/// is the production conformance.
///
/// The protocol requirement has no default values (Swift doesn't allow
/// them on protocol requirements). Concrete conformers — like
/// ``FapiClient`` — supply defaults at the call site, so direct calls
/// on a typed `FapiClient` instance still get the friendly form.
/// Protocol-typed callers (`any FapiCalling`) pass everything
/// explicitly.
public protocol FapiCalling: Sendable {
    func call(
        api: String,
        params: Data?,
        fcdsl: Data?,
        binary: Data?,
        sid: String?,
        via: String?,
        maxCost: Int64?,
        timeoutMs: Int
    ) async throws -> FapiClient.Reply
}

/// Application-layer FAPI client. Sits on top of ``FudpClient`` and
/// turns a single `(api, params, …)` call into:
///
/// 1. a fresh transport-level `messageId` (Int64) and FAPI-level `id`
///    (string),
/// 2. a `UnifiedCodec`-encoded REQUEST envelope,
/// 3. a send via FUDP (encrypts + frames + transmits),
/// 4. a wait for the matching RESPONSE envelope by transport
///    `messageId` plus a sanity check that
///    `response.requestId == request.id`.
///
/// **Concurrency:** one in-flight call at a time per `FapiClient` (the
/// underlying `FudpConnection.datagrams` stream is single-consumer).
/// Multiplexing concurrent calls would need a router task fanning out
/// to per-id continuations — added when a real workload demands it.
///
/// **Where to put this class:** sits in FCTransport beside
/// ``FudpClient`` because correlation lives at the wire layer. The
/// FCDomain layer wraps `FapiClient` with typed `WalletService`,
/// `KeysService`, etc. that supply concrete params/data shapes.
public final class FapiClient: FapiCalling {

    public enum Failure: Error, CustomStringConvertible {
        case unexpectedType(MessageType)
        case requestIdMismatch(sent: String, got: String)
        case codec(UnifiedCodec.Failure)
        case underlying(Error)

        public var description: String {
            switch self {
            case .unexpectedType(let t):
                return "FapiClient: expected RESPONSE, got \(t)"
            case let .requestIdMismatch(sent, got):
                return "FapiClient: response.requestId='\(got)' does not echo request.id='\(sent)'"
            case .codec(let inner):
                return "FapiClient: \(inner)"
            case .underlying(let e):
                return "FapiClient: \(e)"
            }
        }
    }

    public struct Reply: Sendable {
        public let response: FapiResponse
        public let binary: Data?
        public let messageId: Int64

        public init(response: FapiResponse, binary: Data?, messageId: Int64) {
            self.response = response
            self.binary = binary
            self.messageId = messageId
        }
    }

    public let fudp: FudpClient

    public init(fudp: FudpClient) {
        self.fudp = fudp
    }

    /// Send a FAPI call and wait for its response.
    ///
    /// - parameters:
    ///   - api: e.g. `"base.search"`, `"disk.put"`. Required by the server.
    ///   - params: opaque JSON for non-query endpoints. Mutually exclusive
    ///     with `fcdsl` per the protocol; nothing here enforces it.
    ///   - fcdsl: opaque JSON for query endpoints.
    ///   - binary: optional binary blob appended after the JSON header.
    ///     `dataSize` is auto-set when `binary` is non-nil.
    ///   - sid / via / maxCost: optional FAPI fields, see
    ///     ``FapiRequest`` for semantics.
    ///   - timeoutMs: how long to wait for the matching RESPONSE.
    @discardableResult
    public func call(
        api: String,
        params: Data? = nil,
        fcdsl: Data? = nil,
        binary: Data? = nil,
        sid: String? = nil,
        via: String? = nil,
        maxCost: Int64? = nil,
        timeoutMs: Int = 5_000
    ) async throws -> Reply {
        let messageId = Int64.random(in: 1...Int64.max)
        let request = FapiRequest(
            id: FapiRequest.generateId(),
            api: api,
            sid: sid,
            via: via,
            fcdsl: fcdsl,
            params: params,
            dataSize: nil,
            dataHash: nil,
            maxCost: maxCost
        )
        return try await call(request: request, binary: binary, messageId: messageId, timeoutMs: timeoutMs)
    }

    /// Lower-level entry point for callers that build the
    /// ``FapiRequest`` themselves (e.g. to set `dataHash` for
    /// integrity-checked uploads). Generates a fresh transport
    /// `messageId` if the caller doesn't supply one.
    @discardableResult
    public func call(
        request: FapiRequest,
        binary: Data? = nil,
        messageId: Int64 = Int64.random(in: 1...Int64.max),
        timeoutMs: Int = 5_000
    ) async throws -> Reply {
        let payload: Data
        do {
            payload = try UnifiedCodec.encodeRequest(request, binary: binary)
        } catch let e as UnifiedCodec.Failure {
            throw Failure.codec(e)
        } catch {
            throw Failure.underlying(error)
        }

        try await fudp.send(AppMessageEnvelope(
            type: .request,
            messageId: messageId,
            payload: payload
        ))

        let envelope = try await fudp.receive(matching: messageId, timeoutMs: timeoutMs)
        guard envelope.type == .response else {
            throw Failure.unexpectedType(envelope.type)
        }

        let response: FapiResponse
        let bin: Data?
        do {
            (response, bin) = try UnifiedCodec.decodeResponse(envelope.payload)
        } catch let e as UnifiedCodec.Failure {
            throw Failure.codec(e)
        } catch {
            throw Failure.underlying(error)
        }

        if let sentId = request.id,
           let gotId = response.requestId,
           gotId != sentId {
            throw Failure.requestIdMismatch(sent: sentId, got: gotId)
        }

        return Reply(response: response, binary: bin, messageId: messageId)
    }
}
