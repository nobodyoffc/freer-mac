import Foundation
import Darwin
import FCCore
import FCTransport

/// A direct FUDP path to the other side of a 1:1 call (VOICE_SPEC §6.2 steps
/// 6-9), on the call's ``SharedUdpPort`` beside the relay connection that
/// stays joined; a port of Android's `CallDirectPath`.
///
/// Punching: HELLO to every candidate every 100 ms for 3 s, and a PUBLIC_KEY
/// answer to every HELLO; a PUBLIC_KEY that is the peer's transport key marks
/// an address that works. The side with the lower FID then opens the
/// connection there; the other takes it from its first packet. A connection
/// counts only if its key is the peer's transport key, from a delegation
/// already verified (§6.2 step 7). Then probes both ways: once each side has
/// heard the other say it hears it, the path is up. Probes keep going every
/// 500 ms as a keepalive; 2 s without anything from the peer takes the path
/// down for the rest of the call (no second punching).
public final class CallDirectPath: @unchecked Sendable {

    /// A probe datagram: `kind = 0x03, heard`. Never a MediaFrame (0x01) or Attestation (0x02).
    public static let probe: UInt8 = 0x03
    static let punchEveryMs: Int64 = 100, punchForMs: Int64 = 3_000
    /// Punching found nothing, or the connection never came up: give up.
    static let giveUpMs: Int64 = 8_000
    static let probeEveryMs: Int64 = 100, keepaliveEveryMs: Int64 = 500
    static let quietMs: Int64 = 2_000

    public protocol Listener: AnyObject, Sendable {
        /// Probes passed both ways: send on this path now.
        func directUp()
        /// The path went quiet: back to the relay, for good.
        func directDown()
        /// A media frame from the peer on this path.
        func directFrame(_ datagram: Data)
        func directAttestation(_ bytes: Data)
        func directLog(_ what: String)
    }

    /// A candidate endpoint: `t` is lan or map, as in the roster (§6.1).
    public struct Candidate: Equatable, Sendable {
        public let t: String
        public let address: SharedUdpPort.Address

        public static func parse(_ m: [String: Any]) -> Candidate? {
            guard let t = m["t"] as? String, let a = m["a"] as? String, let colon = a.lastIndex(of: ":"),
                  let port = UInt16(a[a.index(after: colon)...]) else { return nil }
            var host = String(a[..<colon])
            if host.hasPrefix("["), host.hasSuffix("]") { host = String(host.dropFirst().dropLast()) }
            guard !host.isEmpty else { return nil }
            return Candidate(t: t, address: .init(host: host, port: port))
        }
    }

    private let port: SharedUdpPort
    private let tPriv: Data
    private let tPub: Data
    private let peerTPub: Data
    private let initiator: Bool
    private let candidates: [Candidate]
    private weak var listener: Listener?
    private let startMs = CallDirectPath.nowMs()

    private let lock = NSLock()
    private var working: SharedUdpPort.Address?
    private var client: FudpClient?
    private var heard = false, heardBack = false, up = false, down = false
    private var lastRxMs: Int64 = 0
    private var ticksUp = 0
    private var ticker: Task<Void, Never>?

    /// - Parameter initiator: true on the side with the lexicographically lower FID, which opens the connection
    public init(port: SharedUdpPort, tPriv: Data, peerTPub: Data, initiator: Bool, candidates: [Candidate],
                listener: Listener) throws {
        self.port = port
        self.tPriv = tPriv
        self.tPub = try Secp256k1.publicKey(fromPrivateKey: tPriv)
        self.peerTPub = peerTPub
        self.initiator = initiator
        self.candidates = candidates
        self.listener = listener
    }

    public var isUp: Bool { lock.withLock { up && !down } }

    public func start() {
        listener?.directLog("punching \(candidates.count) candidate(s) as \(initiator ? "initiator" : "responder")")
        port.unclaimed = { [weak self] data, from in self?.unclaimed(data, from: from) }
        ticker = Task { [weak self] in
            while !Task.isCancelled {
                guard let self else { return }
                await self.tick()
                try? await Task.sleep(nanoseconds: UInt64(CallDirectPath.probeEveryMs) * 1_000_000)
            }
        }
    }

    public func stop() {
        let c = lock.withLock { () -> FudpClient? in
            down = true
            defer { client = nil }
            return client
        }
        ticker?.cancel()
        port.unclaimed = nil
        c?.setDatagramHandler(nil)
        c?.setNotifyHandler(nil)
        c?.close()
    }

    /// A media frame on the direct connection; false before the path is up.
    @discardableResult
    public func send(_ frame: Data) async -> Bool {
        guard let c = lock.withLock({ up && !down ? client : nil }) else { return false }
        return await c.sendDatagram(frame) == .sent
    }

    /// An attestation, reliably, on the direct connection (§5.1).
    public func sendAttestation(_ attestation: Data) async {
        guard let c = lock.withLock({ client }) else { return }
        try? await c.sendNotify(attestation, dataType: 0)
    }

    // MARK: - Internals

    private func tick() async {
        let now = CallDirectPath.nowMs()
        if now - startMs < CallDirectPath.punchForMs { punch() }
        let (w, c) = lock.withLock { (working, client) }
        if initiator, let w, c == nil { open(w) }
        guard let c = lock.withLock({ client }) else {
            if now - startMs > CallDirectPath.giveUpMs { giveUp("no direct connection") }
            return
        }
        // Probe fast until up, then as a keepalive.
        let (probeNow, heardByUs, isUpNow, quietFor) = lock.withLock { () -> (Bool, Bool, Bool, Int64) in
            if up { ticksUp += 1 }
            let due = !up || ticksUp % Int(CallDirectPath.keepaliveEveryMs / CallDirectPath.probeEveryMs) == 0
            return (due, heard, up, now - lastRxMs)
        }
        if probeNow { _ = await c.sendDatagram(Data([CallDirectPath.probe, heardByUs ? 1 : 0])) }
        if isUpNow && quietFor > CallDirectPath.quietMs {
            listener?.directLog("direct path quiet for \(quietFor) ms")
            lock.withLock { down = true }
            ticker?.cancel()
            listener?.directDown()
        } else if !isUpNow && now - startMs > CallDirectPath.giveUpMs {
            giveUp("probes did not pass both ways")
        }
    }

    private func punch() {
        guard let hello = try? FudpDiscovery.buildHelloDatagram() else { return }
        for c in candidates { try? port.send(hello, to: c.address) }
    }

    /// Datagrams from addresses with no connection: HELLOs to answer, the
    /// peer's PUBLIC_KEY, or the first packet of the peer's connection.
    private func unclaimed(_ data: Data, from: SharedUdpPort.Address) {
        guard data.count >= PacketHeader.size, let header = try? PacketHeader.decode(data) else { return }
        let body = Data(data.dropFirst(PacketHeader.size))
        switch header.packetType {
        case .control:
            if body.first == FudpDiscovery.helloTypeByte {
                // Answer anyone during the call: our transport key is in the delegation anyway.
                var reply = PacketHeader(packetType: .control, flags: [], version: PacketHeader.currentVersion,
                                         connectionId: 0, packetNumber: 0).encode()
                reply.append(FudpDiscovery.publicKeyTypeByte)
                reply.append(tPub)
                try? port.send(reply, to: from)
            } else if let pub = try? FudpDiscovery.parsePublicKeyDatagram(data), pub == peerTPub {
                let first = lock.withLock { () -> Bool in
                    guard working == nil else { return false }
                    working = from
                    return true
                }
                if first { listener?.directLog("the peer answered at \(from)") }
            }
        case .data, .ack:
            // §6.2 step 7: only the key the peer's delegation names opens a connection here.
            guard !initiator, AsyTwoWay.senderPubkey(inBundle: body) == peerTPub,
                  lock.withLock({ client == nil && !down }) else { return }
            let ch = port.channel(to: from)
            guard let c = try? adopt(ch, at: from) else { return }
            listener?.directLog("took the peer's direct connection from \(from)")
            _ = c
            ch.inject(data)
        case .error:
            break
        }
    }

    /// The initiator opens the connection at the address that answered; its first packets are probes.
    private func open(_ at: SharedUdpPort.Address) {
        guard let c = try? adopt(port.channel(to: at), at: at) else { return }
        listener?.directLog("opened a direct connection to \(at)")
        Task { _ = try? await c.ping(timeoutMs: 2_000) } // the first encrypted packet opens the peer's side
    }

    private func adopt(_ ch: SharedUdpPort.Channel, at: SharedUdpPort.Address) throws -> FudpClient {
        let c = try FudpClient(over: ch, host: at.host, port: at.port, peerPubkey: peerTPub, localPrivkey: tPriv)
        c.enableDatagrams()
        c.setDatagramHandler { [weak self] _, _, data in self?.onDatagram(data) }
        c.setNotifyHandler { [weak self] type, data in
            guard let self, type == 0 else { return }
            self.lock.withLock { self.lastRxMs = CallDirectPath.nowMs() }
            self.listener?.directAttestation(data)
        }
        let kept = lock.withLock { () -> Bool in
            guard client == nil, !down else { return false }
            client = c
            return true
        }
        guard kept else {
            c.close()
            throw SharedUdpPort.Failure.closed
        }
        return c
    }

    /// A datagram from the peer on the direct connection: a probe, or media (which counts as life).
    private func onDatagram(_ data: Data) {
        let becameUp = lock.withLock { () -> Bool in
            guard !down else { return false }
            lastRxMs = CallDirectPath.nowMs()
            guard data.count == 2, data[data.startIndex] == CallDirectPath.probe else { return false }
            heard = true
            guard data[data.startIndex + 1] == 1, !heardBack else { return false }
            heardBack = true
            guard !up else { return false }
            up = true
            return true
        }
        if data.count == 2 && data.first == CallDirectPath.probe {
            if becameUp {
                listener?.directLog("probes passed both ways after \(CallDirectPath.nowMs() - startMs) ms")
                listener?.directUp()
            }
            return
        }
        listener?.directFrame(data)
    }

    private func giveUp(_ why: String) {
        let first = lock.withLock { () -> Bool in
            guard !down else { return false }
            down = true
            return true
        }
        guard first else { return }
        listener?.directLog("no direct path: \(why); staying on the relay")
        ticker?.cancel()
    }

    static func nowMs() -> Int64 { Int64(Date().timeIntervalSince1970 * 1000) }

    // MARK: - Our own candidates

    /// Private addresses of this Mac's interfaces (RFC 1918, or IPv6 ULA), at
    /// `port`: two devices on one Wi-Fi reach each other there without going
    /// through NAT (§6.1). Never public, loopback or link-local.
    public static func lanCandidates(port: UInt16) -> [[String: String]] {
        var out: [[String: String]] = []
        var ifaddr: UnsafeMutablePointer<ifaddrs>?
        guard port > 0, getifaddrs(&ifaddr) == 0, let first = ifaddr else { return out }
        defer { freeifaddrs(ifaddr) }
        var p: UnsafeMutablePointer<ifaddrs>? = first
        while let ifa = p, out.count < 6 {
            defer { p = ifa.pointee.ifa_next }
            let flags = Int32(ifa.pointee.ifa_flags)
            guard flags & IFF_UP != 0, flags & IFF_LOOPBACK == 0, let sa = ifa.pointee.ifa_addr,
                  let a = SharedUdpPort.address(ofSockaddr: sa) else { continue }
            if isPrivate(a.host) {
                let host = a.host.contains(":") ? "[\(a.host)]" : a.host
                out.append(["t": "lan", "a": "\(host):\(port)"])
            }
        }
        return out
    }

    /// RFC 1918 IPv4, or an IPv6 unique local address (fc00::/7).
    static func isPrivate(_ host: String) -> Bool {
        if host.contains(":") {
            let h = host.lowercased()
            return h.hasPrefix("fc") || h.hasPrefix("fd")
        }
        let o = host.split(separator: ".").compactMap { Int($0) }
        guard o.count == 4 else { return false }
        return o[0] == 10 || (o[0] == 172 && (16...31).contains(o[1])) || (o[0] == 192 && o[1] == 168)
    }
}
