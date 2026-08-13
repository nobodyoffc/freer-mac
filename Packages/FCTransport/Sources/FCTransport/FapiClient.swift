import Foundation
import FCCore

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

    /// Upload streamed from a file on disk (`disk.put` / `disk.carve`).
    /// See ``FapiClient/callUploadingFile(api:params:sid:via:maxCost:fileURL:idleTimeoutMs:progress:)``.
    func callUploadingFile(
        api: String,
        params: Data?,
        sid: String?,
        via: String?,
        maxCost: Int64?,
        fileURL: URL,
        idleTimeoutMs: Int64,
        progress: (@Sendable (Int64, Int64) -> Void)?
    ) async throws -> FapiClient.Reply

    /// Download whose binary body is written straight to a file
    /// (`disk.get`). See
    /// ``FapiClient/callDownloadingToFile(api:params:fcdsl:sid:via:maxCost:outputURL:idleTimeoutMs:progress:)``.
    func callDownloadingToFile(
        api: String,
        params: Data?,
        fcdsl: Data?,
        sid: String?,
        via: String?,
        maxCost: Int64?,
        outputURL: URL,
        idleTimeoutMs: Int64,
        progress: (@Sendable (Int64) -> Void)?
    ) async throws -> FapiClient.Reply
}

extension FapiCalling {
    /// Clients that speak only the JSON call surface — in-process test
    /// stubs, mostly — inherit these and fail loudly rather than
    /// silently pretending a transfer happened.
    public func callUploadingFile(
        api: String,
        params: Data? = nil,
        sid: String? = nil,
        via: String? = nil,
        maxCost: Int64? = nil,
        fileURL: URL,
        idleTimeoutMs: Int64 = FapiClient.transferIdleTimeoutMs,
        progress: (@Sendable (Int64, Int64) -> Void)? = nil
    ) async throws -> FapiClient.Reply {
        throw FapiClient.Failure.fileTransferUnsupported(api: api)
    }

    public func callDownloadingToFile(
        api: String,
        params: Data? = nil,
        fcdsl: Data? = nil,
        sid: String? = nil,
        via: String? = nil,
        maxCost: Int64? = nil,
        outputURL: URL,
        idleTimeoutMs: Int64 = FapiClient.transferIdleTimeoutMs,
        progress: (@Sendable (Int64) -> Void)? = nil
    ) async throws -> FapiClient.Reply {
        throw FapiClient.Failure.fileTransferUnsupported(api: api)
    }
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
        case transportStatus(code: UInt16, body: String)
        case fileTransferUnsupported(api: String)
        case underlying(Error)

        public var description: String {
            switch self {
            case .unexpectedType(let t):
                return "FapiClient: expected RESPONSE, got \(t)"
            case let .requestIdMismatch(sent, got):
                return "FapiClient: response.requestId='\(got)' does not echo request.id='\(sent)'"
            case .codec(let inner):
                return "FapiClient: \(inner)"
            case let .transportStatus(code, body):
                return "FapiClient: transport status \(code) — \(body)"
            case .fileTransferUnsupported(let api):
                return "FapiClient: this client cannot stream files (\(api))"
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
        // Three-layer wire format:
        //   AppMessageEnvelope.payload  =  RequestMessage.encode()
        //   RequestMessage.data         =  UnifiedCodec.encodeRequest(...)
        let unified: Data
        do {
            unified = try UnifiedCodec.encodeRequest(request, binary: binary)
        } catch let e as UnifiedCodec.Failure {
            throw Failure.codec(e)
        } catch {
            throw Failure.underlying(error)
        }
        // FUDP-layer routing sid. Defaults to "" — the server's
        // FapiServer routes by FapiRequest.api anyway, so the outer
        // sid is decorative for single-service deployments. Callers
        // who target a specific sid in a multi-service setup pass
        // it as `request.sid`; we forward that as the wrapper sid.
        let wrapperSid = request.sid ?? ""
        let wrapped = RequestMessage(sid: wrapperSid, data: unified).encode()

        try await fudp.send(AppMessageEnvelope(
            type: .request,
            messageId: messageId,
            payload: wrapped
        ))

        let envelope = try await fudp.receive(matching: messageId, timeoutMs: timeoutMs)
        guard envelope.type == .response else {
            throw Failure.unexpectedType(envelope.type)
        }

        // Unwrap the FUDP-layer status. A non-zero status means the
        // server couldn't build a meaningful FapiResponse — surface
        // it directly without trying to UnifiedCodec.decode the body
        // (which on errors may be a plain string).
        let outer: ResponseMessage
        do {
            outer = try ResponseMessage.parse(envelope.payload)
        } catch {
            throw Failure.underlying(error)
        }
        if !outer.isSuccess {
            let body = String(data: outer.data, encoding: .utf8) ?? "<\(outer.data.count) B binary>"
            throw Failure.transportStatus(code: outer.statusCode, body: body)
        }

        let response: FapiResponse
        let bin: Data?
        do {
            (response, bin) = try UnifiedCodec.decodeResponse(outer.data)
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

// MARK: - file transfer (Phase 8.4.1)

extension FapiClient {

    /// Baseline idle budget for file transfers. The effective budget
    /// grows with the transfer size (1 s per 100 KB, covering
    /// server-side hashing/storing), and is refreshed by ANY sign of
    /// life from the peer — ACKs while the upload drains, response
    /// bytes arriving — so only real silence times out.
    public static let transferIdleTimeoutMs: Int64 = 30_000

    /// Send a binary-operation request (`disk.put` / `disk.carve`)
    /// whose body is streamed from `fileURL` — two sequential passes
    /// over the file (hash, then send), never resident in memory.
    ///
    /// - parameters:
    ///   - progress: cumulative payload bytes handed to the network,
    ///     clamped to the file size.
    @discardableResult
    public func callUploadingFile(
        api: String,
        params: Data? = nil,
        sid: String? = nil,
        via: String? = nil,
        maxCost: Int64? = nil,
        fileURL: URL,
        idleTimeoutMs: Int64 = FapiClient.transferIdleTimeoutMs,
        progress: (@Sendable (Int64, Int64) -> Void)? = nil
    ) async throws -> Reply {
        let attrs: [FileAttributeKey: Any]
        do {
            attrs = try FileManager.default.attributesOfItem(atPath: fileURL.path)
        } catch {
            throw Failure.underlying(error)
        }
        let fileSize = (attrs[.size] as? NSNumber)?.int64Value ?? 0

        // Pass 1: content hash (the server verifies the upload against it).
        let dataHash: String
        do {
            dataHash = try Hash.doubleSha256(fileAt: fileURL)
                .map { String(format: "%02x", $0) }.joined()
        } catch {
            throw Failure.underlying(error)
        }

        let request = FapiRequest(
            id: FapiRequest.generateId(),
            api: api,
            sid: sid,
            via: via,
            params: params,
            dataSize: fileSize,
            dataHash: dataHash,
            maxCost: maxCost
        )

        let unifiedHeader: Data
        do {
            unifiedHeader = try UnifiedCodec.encodeRequestHeaderOnly(request)
        } catch let e as UnifiedCodec.Failure {
            throw Failure.codec(e)
        } catch {
            throw Failure.underlying(error)
        }
        // FUDP-layer wrapper prefix: varint(sidLen) + sid + unified
        // header. The file bytes complete the RequestMessage.data.
        let wrapperPrefix = RequestMessage(sid: request.sid ?? "", data: unifiedHeader).encode()

        let messageId = Int64.random(in: 1...Int64.max)
        let handle: FileHandle
        do {
            handle = try FileHandle(forReadingFrom: fileURL)
        } catch {
            throw Failure.underlying(error)
        }
        defer { try? handle.close() }

        // Pass 2: stream the request. Progress excludes the envelope/
        // header prefix so callers can render sent/total of the file.
        let prefixLen = Int64(wrapperPrefix.count)
        let fileProgress: (@Sendable (Int64) -> Void)?
        if let progress {
            fileProgress = { sent in
                progress(min(max(0, sent - prefixLen), fileSize), fileSize)
            }
        } else {
            fileProgress = nil
        }
        try await fudpSend { fudp in
            try await fudp.sendMessageStreaming(
                type: .request,
                messageId: messageId,
                payloadPrefix: wrapperPrefix,
                fileHandle: handle,
                fileLength: fileSize,
                progress: fileProgress
            )
        }

        // Idle budget scaled by size: base + 1 s per 100 KB.
        let idleBudget = idleTimeoutMs + (fileSize / 102_400) * 1000
        let envelope = try await receiveRefreshedByActivity(
            messageId: messageId, idleTimeoutMs: idleBudget)
        return try decodeReply(envelope: envelope, request: request, messageId: messageId)
    }

    /// Perform a call whose response carries a large binary body
    /// (`disk.get`), writing the binary straight to `outputURL`. The
    /// transport spills oversized responses to a temp file and every
    /// decode layer slices rather than copies, so the content stays
    /// file-backed end to end. Returns the metadata reply (its
    /// `binary` is nil — the body is on disk).
    @discardableResult
    public func callDownloadingToFile(
        api: String,
        params: Data? = nil,
        fcdsl: Data? = nil,
        sid: String? = nil,
        via: String? = nil,
        maxCost: Int64? = nil,
        outputURL: URL,
        idleTimeoutMs: Int64 = FapiClient.transferIdleTimeoutMs,
        progress: (@Sendable (Int64) -> Void)? = nil
    ) async throws -> Reply {
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
        let unified: Data
        do {
            unified = try UnifiedCodec.encodeRequest(request, binary: nil)
        } catch let e as UnifiedCodec.Failure {
            throw Failure.codec(e)
        } catch {
            throw Failure.underlying(error)
        }
        let wrapped = RequestMessage(sid: request.sid ?? "", data: unified).encode()
        let messageId = Int64.random(in: 1...Int64.max)

        // Cumulative-progress adapter over the pump's per-chunk counts.
        if let progress {
            let counter = ByteCounter()
            fudp.setInboundProgressHandler { newBytes in
                progress(counter.add(Int64(newBytes)))
            }
        }
        defer { fudp.setInboundProgressHandler(nil) }

        try await fudpSend { fudp in
            try await fudp.send(AppMessageEnvelope(
                type: .request,
                messageId: messageId,
                payload: wrapped
            ))
        }

        let envelope = try await receiveRefreshedByActivity(
            messageId: messageId, idleTimeoutMs: idleTimeoutMs)
        let reply = try decodeReply(envelope: envelope, request: request, messageId: messageId)

        // Stream the binary body (possibly a file-mapped slice) into
        // the output file in bounded chunks.
        let binary = reply.binary ?? Data()
        do {
            let dir = outputURL.deletingLastPathComponent()
            try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
            FileManager.default.createFile(atPath: outputURL.path, contents: nil)
            let out = try FileHandle(forWritingTo: outputURL)
            defer { try? out.close() }
            try out.truncate(atOffset: 0)
            var idx = binary.startIndex
            let step = 1 << 20
            while idx < binary.endIndex {
                let end = binary.index(idx, offsetBy: step, limitedBy: binary.endIndex) ?? binary.endIndex
                try out.write(contentsOf: binary[idx..<end])
                idx = end
            }
        } catch {
            try? FileManager.default.removeItem(at: outputURL)
            throw Failure.underlying(error)
        }

        return Reply(response: reply.response, binary: nil, messageId: messageId)
    }

    // MARK: - private plumbing

    /// The concrete `FudpClient`, needed for the streaming/progress
    /// surface that `FapiCalling` deliberately doesn't expose.
    private func fudpSend(_ body: (FudpClient) async throws -> Void) async throws {
        do {
            try await body(fudp)
        } catch let e as FudpClient.Failure {
            throw Failure.underlying(e)
        }
    }

    /// Wait for the matching RESPONSE with an idle-based deadline: the
    /// budget measures SILENCE, not wall time. `PeerConnection.touch()`
    /// runs on every valid inbound packet (ACKs included), so a slow
    /// but live transfer never times out mid-flight.
    private func receiveRefreshedByActivity(
        messageId: Int64,
        idleTimeoutMs: Int64
    ) async throws -> AppMessageEnvelope {
        let sliceMs = 1_000
        // The clock starts now — pre-send activity shouldn't count.
        var lastSeen = PeerConnection.currentTimeMillis()
        while true {
            do {
                return try await fudp.receive(matching: messageId, timeoutMs: sliceMs)
            } catch FudpClient.Failure.timeout {
                let activity = fudp.connection.lastActivityMs
                if activity > lastSeen { lastSeen = activity }
                if PeerConnection.currentTimeMillis() - lastSeen >= idleTimeoutMs {
                    throw Failure.underlying(FudpClient.Failure.timeout)
                }
            } catch let e as FudpClient.Failure {
                throw Failure.underlying(e)
            }
        }
    }

    /// Shared response unwrap: transport status → UnifiedCodec →
    /// requestId echo check. Slice-preserving throughout.
    private func decodeReply(
        envelope: AppMessageEnvelope,
        request: FapiRequest,
        messageId: Int64
    ) throws -> Reply {
        guard envelope.type == .response else {
            throw Failure.unexpectedType(envelope.type)
        }
        let outer: ResponseMessage
        do {
            outer = try ResponseMessage.parse(envelope.payload)
        } catch {
            throw Failure.underlying(error)
        }
        if !outer.isSuccess {
            let body = String(data: outer.data, encoding: .utf8) ?? "<\(outer.data.count) B binary>"
            throw Failure.transportStatus(code: outer.statusCode, body: body)
        }
        let response: FapiResponse
        let bin: Data?
        do {
            (response, bin) = try UnifiedCodec.decodeResponse(outer.data)
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

/// Tiny thread-safe accumulator for cumulative progress reporting.
private final class ByteCounter: @unchecked Sendable {
    private let lock = NSLock()
    private var total: Int64 = 0

    func add(_ n: Int64) -> Int64 {
        lock.lock(); defer { lock.unlock() }
        total += n
        return total
    }
}
