import Foundation
import Security
import FCCore
@testable import FCTransport

// Shared helpers for the DATAGRAM (FUDP7) and packet-size tests — the
// Swift counterpart of FC-JDK's `DatagramTestSupport`.
//
// FC-JDK runs two FUDP nodes against each other. The Mac has only the
// client, so a `DatagramTestNode` is a `FudpClient` on a real loopback
// UDP socket, pointed straight at its peer's socket (or at a
// `LossyProxy` between them), plus a small dispatcher that answers every
// request the way FC-JDK's `respondingListener` does: with the request's
// length as a 4-byte big-endian integer.

enum DatagramTestSupport {
    /// What FC-JDK's `createNode` configures.
    static let maxPacketSize = 1400

    /// A UDP port nothing is bound to right now.
    static func freeUdpPort() -> UInt16 {
        let fd = socket(AF_INET, SOCK_DGRAM, 0)
        precondition(fd >= 0)
        defer { Darwin.close(fd) }
        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")
        addr.sin_port = 0
        var len = socklen_t(MemoryLayout<sockaddr_in>.size)
        withUnsafeMutablePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                _ = Darwin.bind(fd, sa, len)
                _ = getsockname(fd, sa, &len)
            }
        }
        return UInt16(bigEndian: addr.sin_port)
    }

    static func randomBytes(_ count: Int) -> Data {
        var data = Data(count: count)
        data.withUnsafeMutableBytes { _ = SecRandomCopyBytes(kSecRandomDefault, count, $0.baseAddress!) }
        return data
    }

    /// Monotonic clock shared by sender and receiver (one process).
    static func nowNanos() -> UInt64 { DispatchTime.now().uptimeNanoseconds }

    /// A datagram carrying a sequence number and its send time, padded to `size`.
    static func stamped(_ seq: Int64, size: Int) -> Data {
        var out = Data(count: max(16, size))
        out.withUnsafeMutableBytes { raw in
            raw.storeBytes(of: UInt64(bitPattern: seq).bigEndian, toByteOffset: 0, as: UInt64.self)
            raw.storeBytes(of: nowNanos().bigEndian, toByteOffset: 8, as: UInt64.self)
        }
        return out
    }

    static func seqOf(_ data: Data) -> Int64 {
        Int64(bitPattern: readBE64(data, at: 0))
    }

    /// Microseconds since the datagram was stamped.
    static func ageMicros(_ data: Data) -> Int64 {
        Int64(nowNanos() - readBE64(data, at: 8)) / 1000
    }

    private static func readBE64(_ data: Data, at offset: Int) -> UInt64 {
        var v: UInt64 = 0
        for b in data.dropFirst(offset).prefix(8) { v = (v << 8) | UInt64(b) }
        return v
    }

    static func percentile(_ sorted: [Int64], _ p: Double) -> Int64 {
        guard !sorted.isEmpty else { return -1 }
        let i = Int((p / 100.0 * Double(sorted.count)).rounded(.up)) - 1
        return sorted[max(0, min(sorted.count - 1, i))]
    }

    /// Two nodes on loopback, connected to each other directly or through
    /// `proxy`, each answering the other's requests.
    static func makePair(
        proxy: LossyProxy? = nil,
        serverPort: UInt16? = nil,
        clientPort: UInt16? = nil,
        onServerDatagram: (@Sendable (String, Int64, Data) -> Void)? = nil
    ) async throws -> (client: DatagramTestNode, server: DatagramTestNode) {
        let server = DatagramTestNode(port: proxy?.serverPort ?? serverPort ?? freeUdpPort())
        let client = DatagramTestNode(port: clientPort ?? freeUdpPort())
        let viaPort = proxy?.port
        try await server.connect(to: client, viaPort: viaPort ?? client.port, onDatagram: onServerDatagram)
        try await client.connect(to: server, viaPort: viaPort ?? server.port, onDatagram: nil)
        return (client, server)
    }

    /// Establish the connection with one request, then enable datagrams
    /// on both ends of it (FC-JDK's `connectWithDatagrams`).
    static func connectWithDatagrams(_ client: DatagramTestNode, _ server: DatagramTestNode) async throws {
        let length = try await client.request(Data(count: 8), timeoutMs: 15_000)
        precondition(length == 8, "warmup request failed")
        client.fudp.enableDatagrams()
        server.fudp.enableDatagrams()
    }
}

/// One end of a loopback FUDP pair.
final class DatagramTestNode: @unchecked Sendable {
    let privkey: Data
    let pubkey: Data
    let fid: String
    let port: UInt16

    private(set) var fudp: FudpClient!
    private var dispatchTask: Task<Void, Never>?
    private let lock = NSLock()
    private var pending: [Int64: CheckedContinuation<AppMessageEnvelope, Error>] = [:]

    init(port: UInt16) {
        var priv: Data
        var pub: Data?
        repeat {
            priv = DatagramTestSupport.randomBytes(32)
            pub = try? Secp256k1.publicKey(fromPrivateKey: priv)
        } while pub == nil
        self.privkey = priv
        self.pubkey = pub!
        self.fid = try! FchAddress(publicKey: pub!).fid
        self.port = port
    }

    func connect(
        to peer: DatagramTestNode,
        viaPort: UInt16,
        onDatagram: (@Sendable (String, Int64, Data) -> Void)?
    ) async throws {
        let transport = try await FudpConnection(host: "127.0.0.1", port: viaPort, localPort: port)
        fudp = try FudpClient(
            transport: transport,
            host: "127.0.0.1",
            port: viaPort,
            peerPubkey: peer.pubkey,
            peerFid: peer.fid,
            localPrivkey: privkey,
            maxPacketSize: DatagramTestSupport.maxPacketSize
        )
        fudp.setDatagramHandler(onDatagram)
        startDispatcher()
    }

    /// Send a request and wait for the peer's answer: the number of
    /// bytes it received.
    func request(_ payload: Data, timeoutMs: Int = 60_000) async throws -> Int {
        let id = Int64.random(in: 1...Int64.max)
        let envelope = AppMessageEnvelope(type: .request, messageId: id, payload: payload)
        let fudp = self.fudp!
        let response: AppMessageEnvelope = try await withCheckedThrowingContinuation { cont in
            lock.lock(); pending[id] = cont; lock.unlock()
            Task {
                do { try await fudp.send(envelope) } catch { self.complete(id, with: .failure(error)) }
            }
            Task {
                await QuietClock.sleep(milliseconds: timeoutMs)
                self.complete(id, with: .failure(FudpClient.Failure.timeout))
            }
        }
        return Int(response.payload.reduce(UInt32(0)) { ($0 << 8) | UInt32($1) })
    }

    func close() {
        dispatchTask?.cancel()
        fudp?.close()
    }

    private func complete(_ id: Int64, with result: Result<AppMessageEnvelope, Error>) {
        lock.lock()
        let cont = pending.removeValue(forKey: id)
        lock.unlock()
        cont?.resume(with: result)
    }

    /// The one consumer of the client's mailbox: answers requests (off
    /// the dispatcher, like a real service) and routes responses.
    private func startDispatcher() {
        let fudp = self.fudp!
        dispatchTask = Task { [weak self] in
            while !Task.isCancelled {
                let envelope: AppMessageEnvelope
                do {
                    envelope = try await fudp.receive(matching: { _ in true }, timeoutMs: 1_000)
                } catch FudpClient.Failure.timeout {
                    continue
                } catch {
                    return
                }
                switch envelope.type {
                case .request:
                    var length = UInt32(envelope.payload.count).bigEndian
                    let reply = AppMessageEnvelope(
                        type: .response,
                        messageId: envelope.messageId,
                        payload: Data(bytes: &length, count: 4)
                    )
                    Task { try? await fudp.send(reply) }
                case .response:
                    self?.complete(envelope.messageId, with: .success(envelope))
                default:
                    break
                }
            }
        }
    }
}

/// UDP forwarder between one client and one server that drops packets
/// with a fixed probability in each direction.
final class LossyProxy: @unchecked Sendable {
    let port: UInt16
    let serverPort: UInt16
    private let fd: Int32
    private let lock = NSLock()
    private var running = true
    private var clientAddr: sockaddr_in?

    private var _dropRate = 0.0
    var dropRate: Double {
        get { lock.lock(); defer { lock.unlock() }; return _dropRate }
        set { lock.lock(); _dropRate = newValue; lock.unlock() }
    }

    private(set) var forwarded = 0
    private(set) var dropped = 0
    /// Largest UDP payload seen in each direction.
    private(set) var maxToServer = 0
    private(set) var maxToClient = 0

    /// Called with every packet after it is forwarded (or dropped).
    var inspect: (@Sendable (_ packet: Data, _ fromServer: Bool) -> Void)?

    init(serverPort: UInt16) {
        self.serverPort = serverPort
        let fd = socket(AF_INET, SOCK_DGRAM, 0)
        precondition(fd >= 0)
        self.fd = fd
        var size: Int32 = 4 * 1024 * 1024
        setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &size, socklen_t(MemoryLayout<Int32>.size))
        setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &size, socklen_t(MemoryLayout<Int32>.size))
        var timeout = timeval(tv_sec: 0, tv_usec: 100_000)
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
        var addr = LossyProxy.loopback(port: 0)
        var len = socklen_t(MemoryLayout<sockaddr_in>.size)
        withUnsafeMutablePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                precondition(Darwin.bind(fd, sa, len) == 0)
                _ = getsockname(fd, sa, &len)
            }
        }
        port = UInt16(bigEndian: addr.sin_port)
        let thread = Thread { [self] in run() }
        thread.name = "dgram-lossy-proxy"
        thread.start()
    }

    func stop() {
        lock.lock(); running = false; lock.unlock()
    }

    private var isRunning: Bool {
        lock.lock(); defer { lock.unlock() }
        return running
    }

    private func run() {
        var buf = [UInt8](repeating: 0, count: 65_535)
        let server = LossyProxy.loopback(port: serverPort)
        while isRunning {
            var from = sockaddr_in()
            var fromLen = socklen_t(MemoryLayout<sockaddr_in>.size)
            let n = withUnsafeMutablePointer(to: &from) { ptr in
                ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                    recvfrom(fd, &buf, buf.count, 0, sa, &fromLen)
                }
            }
            guard n > 0 else { continue }
            let fromServer = from.sin_port == server.sin_port
            let to: sockaddr_in
            if fromServer {
                guard let client = clientAddr else { continue }
                to = client
            } else {
                clientAddr = from
                to = server
            }
            let drop = Double.random(in: 0..<1) < dropRate
            lock.lock()
            if fromServer { maxToClient = max(maxToClient, n) } else { maxToServer = max(maxToServer, n) }
            if drop { dropped += 1 } else { forwarded += 1 }
            lock.unlock()
            if !drop {
                var dest = to
                _ = withUnsafePointer(to: &dest) { ptr in
                    ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                        sendto(fd, buf, n, 0, sa, socklen_t(MemoryLayout<sockaddr_in>.size))
                    }
                }
            }
            inspect?(Data(buf[0..<n]), fromServer)
        }
        Darwin.close(fd)
    }

    private static func loopback(port: UInt16) -> sockaddr_in {
        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")
        addr.sin_port = port.bigEndian
        return addr
    }
}
