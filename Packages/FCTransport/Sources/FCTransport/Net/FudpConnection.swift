import Foundation
import Network

/// Single-peer UDP connection for client-side use. Wraps an
/// `NWConnection` (not an `NWListener`), so send and receive share one
/// kernel socket and the server's reply arrives on the same UDP flow
/// — unlike `FudpSocket`, where the listener and outgoing-`NWConnection`
/// use different ephemeral source ports and replies miss the listener.
///
/// Use `FudpSocket` when you need to *receive from any peer* (server
/// role). Use `FudpConnection` when you're talking to one known peer
/// (client role) — it's simpler and avoids the source-port asymmetry.
public final class FudpConnection: @unchecked Sendable {

    public struct Datagram: Sendable {
        public let data: Data
    }

    public enum Failure: Error, CustomStringConvertible {
        case invalidPort(UInt16)
        case openFailed(Error)
        case sendFailed(Error)
        case cancelled

        public var description: String {
            switch self {
            case .invalidPort(let p):    return "FudpConnection: invalid port \(p)"
            case .openFailed(let e):     return "FudpConnection: connection open failed — \(e)"
            case .sendFailed(let e):     return "FudpConnection: send failed — \(e)"
            case .cancelled:             return "FudpConnection: cancelled"
            }
        }
    }

    public let datagrams: AsyncStream<Datagram>

    private let queue = DispatchQueue(label: "fudp.connection", qos: .userInitiated)
    private let connection: NWConnection
    private let continuation: AsyncStream<Datagram>.Continuation

    /// Open a UDP connection to `host:port`. The constructor returns
    /// once the connection is `.ready`.
    public init(host: String, port: UInt16) async throws {
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
                    break
                }
            }
            self.connection.start(queue: queue)
        }

        receiveLoop()
    }

    public func send(_ data: Data) async throws {
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            connection.send(content: data, completion: .contentProcessed { error in
                if let error {
                    cont.resume(throwing: Failure.sendFailed(error))
                } else {
                    cont.resume()
                }
            })
        }
    }

    public func close() {
        connection.cancel()
        continuation.finish()
    }

    // MARK: - private

    private func receiveLoop() {
        connection.receiveMessage { [weak self] data, _, _, error in
            guard let self else { return }
            if let data, !data.isEmpty {
                self.continuation.yield(Datagram(data: data))
            }
            if error == nil {
                self.receiveLoop()
            } else {
                self.continuation.finish()
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
