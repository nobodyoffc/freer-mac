import Foundation
import Network

/// Abstraction over a datagram pipe to one peer. `FudpConnection` is
/// the production conformance (UDP via `NWConnection`); tests inject an
/// in-process fake to exercise the client's reliability machinery
/// (ACK processing, retransmission, congestion gating) without sockets.
public protocol DatagramTransport: Sendable {
    var datagrams: AsyncStream<FudpConnection.Datagram> { get }

    /// False once this pipe can no longer carry traffic — the socket
    /// failed, was cancelled, or the OS reports no usable path (the
    /// state a laptop lands in after sleep/wake or a Wi-Fi change).
    /// Callers use it to decide whether to rebuild rather than to keep
    /// writing into a socket whose replies can never come back.
    var isViable: Bool { get }

    func send(_ data: Data) async throws
    func close()
}

extension DatagramTransport {
    /// In-process fakes stay viable for their whole lifetime; only the
    /// real socket has a path underneath it that can go away.
    public var isViable: Bool { true }
}

/// Single-peer UDP connection for client-side use. Wraps an
/// `NWConnection` (not an `NWListener`), so send and receive share one
/// kernel socket and the server's reply arrives on the same UDP flow
/// — unlike `FudpSocket`, where the listener and outgoing-`NWConnection`
/// use different ephemeral source ports and replies miss the listener.
///
/// Use `FudpSocket` when you need to *receive from any peer* (server
/// role). Use `FudpConnection` when you're talking to one known peer
/// (client role) — it's simpler and avoids the source-port asymmetry.
public final class FudpConnection: DatagramTransport, @unchecked Sendable {

    public struct Datagram: Sendable {
        public let data: Data

        public init(data: Data) {
            self.data = data
        }
    }

    public enum Failure: Error, CustomStringConvertible {
        case invalidPort(UInt16)
        case openFailed(Error)
        case openTimedOut(ms: Int)
        case sendFailed(Error)
        case cancelled

        public var description: String {
            switch self {
            case .invalidPort(let p):    return "FudpConnection: invalid port \(p)"
            case .openFailed(let e):     return "FudpConnection: connection open failed — \(e)"
            case .openTimedOut(let ms):  return "FudpConnection: no usable network path after \(ms) ms"
            case .sendFailed(let e):     return "FudpConnection: send failed — \(e)"
            case .cancelled:             return "FudpConnection: cancelled"
            }
        }
    }

    /// How long `init` waits for `.ready` before giving up. Without a
    /// bound the constructor parks forever when the machine has no
    /// route at all — `NWConnection` sits in `.waiting` rather than
    /// failing — which would hang a reconnect attempted a moment too
    /// early after wake.
    public static let defaultConnectTimeoutMs = 5_000

    public let datagrams: AsyncStream<Datagram>

    private let queue = DispatchQueue(label: "fudp.connection", qos: .userInitiated)
    private let connection: NWConnection
    private let continuation: AsyncStream<Datagram>.Continuation

    private let stateLock = NSLock()
    private var _viable = true

    /// See ``DatagramTransport/isViable``.
    public var isViable: Bool {
        stateLock.lock(); defer { stateLock.unlock() }
        return _viable
    }

    /// Open a UDP connection to `host:port`. The constructor returns
    /// once the connection is `.ready`, and throws
    /// ``Failure/openTimedOut(ms:)`` if it never gets there.
    public init(
        host: String,
        port: UInt16,
        connectTimeoutMs: Int = FudpConnection.defaultConnectTimeoutMs
    ) async throws {
        guard let nwPort = NWEndpoint.Port(rawValue: port) else {
            throw Failure.invalidPort(port)
        }
        let endpoint = NWEndpoint.hostPort(host: NWEndpoint.Host(host), port: nwPort)

        var captured: AsyncStream<Datagram>.Continuation!
        self.datagrams = AsyncStream { continuation in
            captured = continuation
        }
        self.continuation = captured

        self.connection = NWConnection(to: endpoint, using: .udp)

        do {
            try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
                let resumed = ResumeOnce()
                self.connection.stateUpdateHandler = { state in
                    switch state {
                    case .ready:
                        resumed.fire { cont.resume() }
                    case .failed(let err):
                        resumed.fire { cont.resume(throwing: Failure.openFailed(err)) }
                    case .cancelled:
                        resumed.fire { cont.resume(throwing: Failure.cancelled) }
                    default:
                        // `.waiting` included: no path yet, but one may
                        // still appear — the timeout below is the bound.
                        break
                    }
                }
                queue.asyncAfter(deadline: .now() + .milliseconds(connectTimeoutMs)) {
                    resumed.fire { cont.resume(throwing: Failure.openTimedOut(ms: connectTimeoutMs)) }
                }
                self.connection.start(queue: queue)
            }
        } catch {
            connection.stateUpdateHandler = nil
            connection.cancel()
            continuation.finish()
            throw error
        }

        observeStateAfterReady()
        receiveLoop()
    }

    public func send(_ data: Data) async throws {
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            connection.send(content: data, completion: .contentProcessed { [weak self] error in
                if let error {
                    // A send error on a datagram socket means the path
                    // is gone, not that this one packet was unlucky.
                    self?.markDead()
                    cont.resume(throwing: Failure.sendFailed(error))
                } else {
                    cont.resume()
                }
            })
        }
    }

    public func close() {
        connection.cancel()
        markDead()
    }

    // MARK: - private

    /// Keep watching the connection *after* the opening handshake. The
    /// original handler only existed to resolve `init`'s continuation,
    /// so every later transition — the `.failed` / `.waiting` a sleep
    /// or Wi-Fi change produces — went unobserved, and the client went
    /// on writing into a socket whose replies could never arrive.
    private func observeStateAfterReady() {
        connection.stateUpdateHandler = { [weak self] state in
            switch state {
            case .failed, .cancelled, .waiting:
                // `.waiting` post-ready is the OS saying there is no
                // usable path. Even if one returns, the NAT mapping
                // this flow depended on is gone, so the flow is dead
                // either way: rebuild rather than wait it out.
                self?.markDead()
            default:
                break
            }
        }
        // Close the gap between `.ready` and installing the handler.
        switch connection.state {
        case .failed, .cancelled, .waiting:
            markDead()
        default:
            break
        }
    }

    /// Mark the pipe unusable and end the datagram stream. Idempotent.
    private func markDead() {
        stateLock.lock()
        let wasViable = _viable
        _viable = false
        stateLock.unlock()
        guard wasViable else { return }
        continuation.finish()
    }

    private func receiveLoop() {
        connection.receiveMessage { [weak self] data, _, _, error in
            guard let self else { return }
            if let data, !data.isEmpty {
                self.continuation.yield(Datagram(data: data))
            }
            if error == nil {
                self.receiveLoop()
            } else {
                self.markDead()
            }
        }
    }
}

/// Tiny re-export so this file is self-contained even though
/// `ResumeOnce` was introduced in `FudpSocket.swift`.
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
