import Foundation
import Darwin

/// One UDP port shared by several FUDP connections, as a call's node is on
/// Android (VOICE_SPEC §6.1, §6.2 steps 6-7): the relay connection and a
/// direct connection to the peer go out from, and come back to, the same
/// local port, so the address the relay sees for it — the `map` candidate —
/// is also where the peer can reach this Mac.
///
/// A plain dual-stack BSD socket: `FudpSocket` listens on one port and sends
/// from others, which is exactly what this must not do. Datagrams are routed
/// by their source address to the ``Channel`` opened for it; anything from an
/// address with no channel — a peer's HELLO, a peer opening a connection —
/// goes to ``unclaimed``.
public final class SharedUdpPort: @unchecked Sendable {

    public enum Failure: Error, CustomStringConvertible {
        case socket(Int32), bind(Int32), resolve(String), send(Int32), closed

        public var description: String {
            switch self {
            case .socket(let e): return "SharedUdpPort: socket failed (\(String(cString: strerror(e))))"
            case .bind(let e): return "SharedUdpPort: bind failed (\(String(cString: strerror(e))))"
            case .resolve(let h): return "SharedUdpPort: cannot resolve \(h)"
            case .send(let e): return "SharedUdpPort: send failed (\(String(cString: strerror(e))))"
            case .closed: return "SharedUdpPort: closed"
            }
        }
    }

    /// A numeric address and port, the key datagrams are routed by. IPv4
    /// addresses are kept as dotted quads, never v4-mapped.
    public struct Address: Hashable, Sendable, CustomStringConvertible {
        public let host: String
        public let port: UInt16

        public init(host: String, port: UInt16) {
            self.host = host
            self.port = port
        }

        public var description: String { host.contains(":") ? "[\(host)]:\(port)" : "\(host):\(port)" }
    }

    /// One remote address's traffic, as a ``DatagramTransport`` a
    /// ``FudpClient`` can run on.
    public final class Channel: DatagramTransport, @unchecked Sendable {
        public let remote: Address
        public let datagrams: AsyncStream<FudpConnection.Datagram>
        private let continuation: AsyncStream<FudpConnection.Datagram>.Continuation
        private weak var port: SharedUdpPort?

        init(remote: Address, port: SharedUdpPort) {
            self.remote = remote
            self.port = port
            var captured: AsyncStream<FudpConnection.Datagram>.Continuation!
            datagrams = AsyncStream { captured = $0 }
            continuation = captured
        }

        public var isViable: Bool { port?.isOpen ?? false }

        public func send(_ data: Data) async throws {
            guard let port else { throw Failure.closed }
            try port.send(data, to: remote)
        }

        public func close() {
            port?.release(self)
            continuation.finish()
        }

        /// A datagram that arrived before this channel existed: the first packet of a peer's connection.
        public func inject(_ data: Data) {
            continuation.yield(.init(data: data))
        }

        fileprivate func deliver(_ data: Data) {
            continuation.yield(.init(data: data))
        }

        fileprivate func finish() {
            continuation.finish()
        }
    }

    private let fd: Int32
    public let localPort: UInt16
    private let lock = NSLock()
    private var channels: [Address: Channel] = [:]
    private var open = true
    private var _unclaimed: (@Sendable (Data, Address) -> Void)?

    /// Datagrams from an address with no channel. Called on the receive thread: return quickly.
    public var unclaimed: (@Sendable (Data, Address) -> Void)? {
        get { lock.withLock { _unclaimed } }
        set { lock.withLock { _unclaimed = newValue } }
    }

    public var isOpen: Bool { lock.withLock { open } }

    /// Bind a fresh port on every interface, IPv4 and IPv6.
    public init() throws {
        let s = Darwin.socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)
        guard s >= 0 else { throw Failure.socket(errno) }
        var off: Int32 = 0
        setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, &off, socklen_t(MemoryLayout<Int32>.size))
        var addr = sockaddr_in6()
        addr.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
        addr.sin6_family = sa_family_t(AF_INET6)
        addr.sin6_addr = in6addr_any
        addr.sin6_port = 0
        let bound = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.bind(s, $0, socklen_t(MemoryLayout<sockaddr_in6>.size)) }
        }
        guard bound == 0 else {
            let e = errno
            Darwin.close(s)
            throw Failure.bind(e)
        }
        var got = sockaddr_in6()
        var len = socklen_t(MemoryLayout<sockaddr_in6>.size)
        _ = withUnsafeMutablePointer(to: &got) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(s, $0, &len) }
        }
        // A receive timeout, so the receive thread notices a close.
        var tv = timeval(tv_sec: 0, tv_usec: 250_000)
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        fd = s
        localPort = UInt16(bigEndian: got.sin6_port)
        let t = Thread { [weak self] in self?.receiveLoop() }
        t.name = "shared-udp-port"
        t.qualityOfService = .userInteractive
        t.start()
    }

    deinit {
        close()
    }

    /// The channel for `remote`; datagrams from it go there from now on.
    public func channel(to remote: Address) -> Channel {
        lock.withLock {
            if let c = channels[remote] { return c }
            let c = Channel(remote: remote, port: self)
            channels[remote] = c
            return c
        }
    }

    /// `host` as numeric addresses, IPv4 first: a relay URL may name a host.
    public static func resolve(_ host: String, port: UInt16) throws -> Address {
        var hints = addrinfo()
        hints.ai_family = AF_UNSPEC
        hints.ai_socktype = SOCK_DGRAM
        var res: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(host, String(port), &hints, &res) == 0, let first = res else { throw Failure.resolve(host) }
        defer { freeaddrinfo(first) }
        var found: [Address] = []
        var p: UnsafeMutablePointer<addrinfo>? = first
        while let ai = p {
            if let a = ai.pointee.ai_addr.flatMap({ SharedUdpPort.address(of: $0) }) { found.append(a) }
            p = ai.pointee.ai_next
        }
        guard let pick = found.first(where: { !$0.host.contains(":") }) ?? found.first else { throw Failure.resolve(host) }
        return Address(host: pick.host, port: port)
    }

    public func send(_ data: Data, to remote: Address) throws {
        guard isOpen else { throw Failure.closed }
        var addr = sockaddr_in6()
        addr.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
        addr.sin6_family = sa_family_t(AF_INET6)
        addr.sin6_port = remote.port.bigEndian
        // IPv4 goes out v4-mapped on the dual-stack socket.
        let text = remote.host.contains(":") ? remote.host : "::ffff:" + remote.host
        guard inet_pton(AF_INET6, text, &addr.sin6_addr) == 1 else { throw Failure.resolve(remote.host) }
        let sent = data.withUnsafeBytes { buf in
            withUnsafePointer(to: &addr) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    sendto(fd, buf.baseAddress, buf.count, 0, $0, socklen_t(MemoryLayout<sockaddr_in6>.size))
                }
            }
        }
        if sent < 0 { throw Failure.send(errno) }
    }

    public func close() {
        let all = lock.withLock { () -> [Channel] in
            guard open else { return [] }
            open = false
            defer { channels.removeAll() }
            return Array(channels.values)
        }
        for c in all { c.finish() }
        Darwin.close(fd)
    }

    fileprivate func release(_ c: Channel) {
        lock.withLock {
            if channels[c.remote] === c { channels[c.remote] = nil }
        }
    }

    private func receiveLoop() {
        var buf = [UInt8](repeating: 0, count: 65_536)
        while isOpen {
            var from = sockaddr_storage()
            var len = socklen_t(MemoryLayout<sockaddr_storage>.size)
            let n = withUnsafeMutablePointer(to: &from) { fp in
                fp.withMemoryRebound(to: sockaddr.self, capacity: 1) { recvfrom(fd, &buf, buf.count, 0, $0, &len) }
            }
            if n <= 0 { continue } // timeout, or the socket closing
            let source = withUnsafePointer(to: &from) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { SharedUdpPort.address(of: $0) }
            }
            guard let source else { continue }
            let data = Data(buf[0..<n])
            let (channel, fallback) = lock.withLock { (channels[source], _unclaimed) }
            if let channel { channel.deliver(data) } else { fallback?(data, source) }
        }
    }

    /// An interface's or peer's socket address as numeric host and port.
    public static func address(ofSockaddr sa: UnsafePointer<sockaddr>) -> Address? {
        address(of: sa)
    }

    /// A socket address as numeric host and port; a v4-mapped IPv6 address as plain IPv4.
    static func address(of sa: UnsafePointer<sockaddr>) -> Address? {
        var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
        var serv = [CChar](repeating: 0, count: Int(NI_MAXSERV))
        let len = socklen_t(sa.pointee.sa_len)
        guard getnameinfo(sa, len, &host, socklen_t(host.count), &serv, socklen_t(serv.count),
                          NI_NUMERICHOST | NI_NUMERICSERV) == 0,
              let port = UInt16(String(cString: serv)) else { return nil }
        var h = String(cString: host)
        if let zone = h.firstIndex(of: "%") { h = String(h[..<zone]) }
        if h.hasPrefix("::ffff:"), !h.dropFirst(7).contains(":") { h = String(h.dropFirst(7)) }
        return Address(host: h, port: port)
    }
}
