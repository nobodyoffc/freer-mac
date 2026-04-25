import Foundation
import Network

/// Async UDP socket built on `Network.framework`. Used by FUDP for both
/// client (talks to one or more servers) and server (listens for any
/// peer) modes — a single `FudpSocket` instance both binds a local port
/// and sends to arbitrary destinations.
///
/// Internally:
/// - One `NWListener` accepts inbound datagrams. Each unique remote
///   endpoint triggers `newConnectionHandler`, after which we loop on
///   `receiveMessage` on the per-source `NWConnection` to drain its
///   datagrams.
/// - Outgoing sends are routed through a cache of `NWConnection`
///   instances keyed by destination endpoint, so we don't create a
///   fresh socket on every datagram.
///
/// The class is `@unchecked Sendable` — internal state is guarded by
/// `NSLock`. Network.framework callbacks run on a private serial queue
/// (`fudp.socket`); the `AsyncStream` of incoming datagrams is fed from
/// that queue.
public final class FudpSocket: @unchecked Sendable {

    /// One inbound datagram plus the endpoint it came from.
    public struct Datagram: Sendable {
        public let data: Data
        public let from: NWEndpoint
    }

    public enum Failure: Error, CustomStringConvertible {
        case alreadyBound
        case notBound
        case invalidPort(UInt16)
        case bindFailed(Error)
        case sendFailed(Error)
        case cancelled

        public var description: String {
            switch self {
            case .alreadyBound:           return "FudpSocket: already bound"
            case .notBound:               return "FudpSocket: not bound (call bind() first)"
            case .invalidPort(let p):     return "FudpSocket: invalid port \(p)"
            case .bindFailed(let e):      return "FudpSocket: bind failed — \(e)"
            case .sendFailed(let e):      return "FudpSocket: send failed — \(e)"
            case .cancelled:              return "FudpSocket: cancelled"
            }
        }
    }

    private let queue = DispatchQueue(label: "fudp.socket", qos: .userInitiated)
    private let stateLock = NSLock()

    private var listener: NWListener?
    private var inboundConnections: [NWConnection] = []
    private var outgoing: [String: NWConnection] = [:]

    /// Stream of incoming datagrams. Iterate with `for await`. The stream
    /// finishes when ``close()`` is called.
    public let datagrams: AsyncStream<Datagram>
    private let datagramContinuation: AsyncStream<Datagram>.Continuation

    public init() {
        var captured: AsyncStream<Datagram>.Continuation!
        self.datagrams = AsyncStream { continuation in
            captured = continuation
        }
        self.datagramContinuation = captured
    }

    /// Resolved local UDP port once `bind` has completed.
    public var localPort: UInt16? {
        stateLock.lock(); defer { stateLock.unlock() }
        return listener?.port?.rawValue
    }

    /// Bind a local UDP port and start receiving. Pass `0` to let the OS
    /// choose an ephemeral port; the chosen port is returned.
    public func bind(localPort: UInt16 = 0) async throws -> UInt16 {
        try checkNotBound()
        let nwPort: NWEndpoint.Port
        if localPort == 0 {
            nwPort = .any
        } else if let p = NWEndpoint.Port(rawValue: localPort) {
            nwPort = p
        } else {
            throw Failure.invalidPort(localPort)
        }

        let params = NWParameters.udp
        params.allowLocalEndpointReuse = true

        let newListener: NWListener
        do {
            newListener = try NWListener(using: params, on: nwPort)
        } catch {
            throw Failure.bindFailed(error)
        }

        newListener.newConnectionHandler = { [weak self] conn in
            self?.handleInbound(conn)
        }

        // Wait for the listener to reach .ready or .failed.
        let resolvedPort: UInt16 = try await withCheckedThrowingContinuation { cont in
            let resumed = ResumeOnce()
            newListener.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    let port = newListener.port?.rawValue ?? 0
                    resumed.fire { cont.resume(returning: port) }
                case .failed(let err):
                    resumed.fire { cont.resume(throwing: Failure.bindFailed(err)) }
                case .cancelled:
                    resumed.fire { cont.resume(throwing: Failure.cancelled) }
                default:
                    break
                }
            }
            newListener.start(queue: queue)
        }

        stateLock.lock()
        self.listener = newListener
        stateLock.unlock()

        return resolvedPort
    }

    /// Send `data` as a UDP datagram to `dest`. Requires `bind()` to have
    /// completed first (we route outbound sends through cached
    /// `NWConnection` instances; binding ensures the listener is alive
    /// for any reply).
    public func send(_ data: Data, to dest: NWEndpoint) async throws {
        try checkBound()
        let conn = try await outgoingConnection(to: dest)
        try await sendOn(conn, data: data)
    }

    /// Stop listening, cancel cached outbound connections, finish the
    /// `datagrams` stream. The instance becomes unusable after this.
    public func close() {
        stateLock.lock()
        let lst = listener
        listener = nil
        let inbound = inboundConnections
        inboundConnections = []
        let outs = outgoing
        outgoing.removeAll()
        stateLock.unlock()

        lst?.cancel()
        for c in inbound { c.cancel() }
        for (_, c) in outs { c.cancel() }
        datagramContinuation.finish()
    }

    // MARK: - private

    private func checkNotBound() throws {
        stateLock.lock(); defer { stateLock.unlock() }
        if listener != nil { throw Failure.alreadyBound }
    }

    private func checkBound() throws {
        stateLock.lock(); defer { stateLock.unlock() }
        if listener == nil { throw Failure.notBound }
    }

    private func handleInbound(_ conn: NWConnection) {
        stateLock.lock()
        inboundConnections.append(conn)
        stateLock.unlock()
        conn.start(queue: queue)
        receiveLoop(on: conn)
    }

    private func receiveLoop(on conn: NWConnection) {
        conn.receiveMessage { [weak self] data, _, isComplete, error in
            guard let self else { return }
            if let data, !data.isEmpty {
                let dg = Datagram(data: data, from: conn.endpoint)
                self.datagramContinuation.yield(dg)
            }
            // For UDP, isComplete usually means "this datagram's done", not
            // "the connection is closed". Keep looping unless we see an
            // error.
            if error == nil {
                self.receiveLoop(on: conn)
            }
            _ = isComplete  // referenced to silence unused warning
        }
    }

    private func outgoingConnection(to dest: NWEndpoint) async throws -> NWConnection {
        let key = endpointKey(dest)

        stateLock.lock()
        if let existing = outgoing[key] {
            stateLock.unlock()
            return existing
        }
        stateLock.unlock()

        let conn = NWConnection(to: dest, using: .udp)
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            let resumed = ResumeOnce()
            conn.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    resumed.fire { cont.resume() }
                case .failed(let err):
                    resumed.fire { cont.resume(throwing: Failure.sendFailed(err)) }
                case .cancelled:
                    resumed.fire { cont.resume(throwing: Failure.cancelled) }
                default:
                    break
                }
            }
            conn.start(queue: queue)
        }

        stateLock.lock()
        // Re-check; another caller may have raced us.
        if let raced = outgoing[key] {
            stateLock.unlock()
            conn.cancel()
            return raced
        }
        outgoing[key] = conn
        stateLock.unlock()
        return conn
    }

    private func sendOn(_ conn: NWConnection, data: Data) async throws {
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            conn.send(content: data, completion: .contentProcessed { error in
                if let error {
                    cont.resume(throwing: Failure.sendFailed(error))
                } else {
                    cont.resume()
                }
            })
        }
    }

    private func endpointKey(_ ep: NWEndpoint) -> String {
        // String form is stable enough for our cache; we never compare
        // endpoints across security domains.
        "\(ep)"
    }
}

// MARK: - tiny helper to ensure a continuation is resumed exactly once

private final class ResumeOnce: @unchecked Sendable {
    private let lock = NSLock()
    private var fired = false

    func fire(_ block: () -> Void) {
        lock.lock()
        if fired { lock.unlock(); return }
        fired = true
        lock.unlock()
        block()
    }
}
