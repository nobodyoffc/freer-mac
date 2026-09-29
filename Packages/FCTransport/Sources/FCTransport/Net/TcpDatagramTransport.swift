import Foundation
import Network

/// FUDP over TCP (FUDP8): the same packets on a TCP stream, each prefixed
/// with its length as a 2-byte big-endian number. For networks that let UDP
/// out but drop what comes back, as some mobile networks do for UDP from
/// abroad; TCP, 443 above all, gets through. A ``FudpClient`` runs over it
/// exactly as over UDP.
public final class TcpDatagramTransport: DatagramTransport, @unchecked Sendable {

    public enum Failure: Error, CustomStringConvertible {
        case invalidPort(UInt16)
        case openFailed(Error)
        case openTimedOut(ms: Int)
        case tooLarge(Int)
        case closed

        public var description: String {
            switch self {
            case .invalidPort(let p): return "TcpDatagramTransport: invalid port \(p)"
            case .openFailed(let e): return "TcpDatagramTransport: connect failed — \(e)"
            case .openTimedOut(let ms): return "TcpDatagramTransport: no connection after \(ms) ms"
            case .tooLarge(let n): return "TcpDatagramTransport: a \(n)-byte packet does not fit a 2-byte length"
            case .closed: return "TcpDatagramTransport: closed"
            }
        }
    }

    public static let defaultConnectTimeoutMs = 5_000

    public let datagrams: AsyncStream<FudpConnection.Datagram>
    private let continuation: AsyncStream<FudpConnection.Datagram>.Continuation
    private let connection: NWConnection
    private let queue = DispatchQueue(label: "fudp.tcp", qos: .userInitiated)
    private let lock = NSLock()
    private var viable = true

    public var isViable: Bool { lock.withLock { viable } }

    public init(host: String, port: UInt16, connectTimeoutMs: Int = TcpDatagramTransport.defaultConnectTimeoutMs) async throws {
        guard let nwPort = NWEndpoint.Port(rawValue: port) else { throw Failure.invalidPort(port) }
        var captured: AsyncStream<FudpConnection.Datagram>.Continuation!
        datagrams = AsyncStream { captured = $0 }
        continuation = captured
        let tcp = NWProtocolTCP.Options()
        tcp.noDelay = true
        connection = NWConnection(to: .hostPort(host: NWEndpoint.Host(host), port: nwPort),
                                  using: NWParameters(tls: nil, tcp: tcp))
        try await open(timeoutMs: connectTimeoutMs)
        readLength()
    }

    private func open(timeoutMs: Int) async throws {
        let once = OnceFlag()
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            connection.stateUpdateHandler = { [weak self] state in
                switch state {
                case .ready:
                    if once.fire() { cont.resume() }
                case .failed(let e), .waiting(let e):
                    if once.fire() { cont.resume(throwing: Failure.openFailed(e)) }
                    self?.markDead()
                case .cancelled:
                    if once.fire() { cont.resume(throwing: Failure.closed) }
                    self?.markDead()
                default:
                    break
                }
            }
            connection.start(queue: queue)
            queue.asyncAfter(deadline: .now() + .milliseconds(timeoutMs)) { [weak self] in
                if once.fire() {
                    cont.resume(throwing: Failure.openTimedOut(ms: timeoutMs))
                    self?.connection.cancel()
                }
            }
        }
    }

    public func send(_ data: Data) async throws {
        guard data.count <= 0xFFFF else { throw Failure.tooLarge(data.count) }
        guard isViable else { throw Failure.closed }
        var framed = Data([UInt8(data.count >> 8), UInt8(data.count & 0xFF)])
        framed.append(data)
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            connection.send(content: framed, completion: .contentProcessed { error in
                if let error { cont.resume(throwing: Failure.openFailed(error)) } else { cont.resume() }
            })
        }
    }

    public func close() {
        connection.cancel()
        markDead()
    }

    private func readLength() {
        connection.receive(minimumIncompleteLength: 2, maximumLength: 2) { [weak self] data, _, complete, error in
            guard let self else { return }
            guard error == nil, let data, data.count == 2 else {
                if complete || error != nil { self.markDead() }
                return
            }
            let n = Int(data[data.startIndex]) << 8 | Int(data[data.startIndex + 1])
            if n == 0 {
                self.readLength()
            } else {
                self.readBody(n)
            }
        }
    }

    private func readBody(_ n: Int) {
        connection.receive(minimumIncompleteLength: n, maximumLength: n) { [weak self] data, _, complete, error in
            guard let self else { return }
            guard error == nil, let data, data.count == n else {
                if complete || error != nil { self.markDead() }
                return
            }
            self.continuation.yield(.init(data: data))
            self.readLength()
        }
    }

    private func markDead() {
        let first = lock.withLock { () -> Bool in
            defer { viable = false }
            return viable
        }
        if first { continuation.finish() }
    }
}

/// True the first time only.
private final class OnceFlag: @unchecked Sendable {
    private let lock = NSLock()
    private var done = false

    func fire() -> Bool {
        lock.withLock {
            defer { done = true }
            return !done
        }
    }
}

public extension FudpDiscovery {
    /// Discovery over any transport: a HELLO, and the PUBLIC_KEY that comes back.
    /// It reads the transport's packets, so use a transport of its own.
    static func discoverPubkey(over transport: any DatagramTransport, timeoutMs: Int = 3_000) async throws -> Data {
        try await transport.send(try buildHelloDatagram())
        return try await withThrowingTaskGroup(of: Data.self) { group in
            group.addTask {
                for await datagram in transport.datagrams {
                    if let pubkey = try? parsePublicKeyDatagram(datagram.data) { return pubkey }
                }
                throw Failure.timeout
            }
            group.addTask {
                try await Task.sleep(nanoseconds: UInt64(timeoutMs) * 1_000_000)
                throw Failure.timeout
            }
            defer { group.cancelAll() }
            return try await group.next()!
        }
    }
}
