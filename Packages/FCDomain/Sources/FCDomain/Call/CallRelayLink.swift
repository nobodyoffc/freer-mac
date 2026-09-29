import Foundation
import FCCore
import FCTransport

/// One call's or meeting's path to the CALL relay (VOICE_SPEC §6.2, §7.2), a
/// port of Android's `CallRelayLink`: its own FUDP connection under the
/// call's throwaway transport key, so the FID's key never touches it (§4.1),
/// and FAPI requests on it. Media frames go as datagrams, attestations as
/// NOTIFY dataType 0; the relay's notices come back as NOTIFY dataType 1.
public final class CallRelayLink: @unchecked Sendable {

    /// Waits between retries of a 409 join (§6.2 step 4), inside the relay's 10 joins a minute.
    static let joinRetryMs: [UInt64] = [250, 500, 1000, 2000, 2500, 2500, 2500, 2500, 2500]
    static let requestTimeoutMs = 10_000

    public protocol Events: AnyObject {
        /// On the transport's thread: return quickly.
        func frame(_ datagram: Data)
        func attestation(_ bytes: Data)
        /// A relay notice: roster, rekey, muted, kicked, ended, knock, balance, uplink.
        func notice(_ notice: [String: Any])
    }

    /// The relay refused a request; 408 means no answer came, and it may well have taken.
    public struct Refused: Error, CustomStringConvertible {
        public let code: Int
        public let message: String
        public var lostReply: Bool { code == 408 }

        public init(code: Int, message: String) {
            self.code = code
            self.message = message
        }
        public var description: String { "\(code) \(message)" }
    }

    public let callId: String
    private let tPriv: Data
    private let delegation: Delegation?
    private weak var events: Events?
    private var fudp: FudpClient?
    private var fapi: FapiClient?
    public private(set) var relayPubkey: String?
    public private(set) var relaySid: String?
    /// The call's port when a direct path may follow: the relay sees this port, and the peer can reach it.
    public private(set) var sharedPort: SharedUdpPort?

    public init(tPriv: Data, callId: String, delegation: Delegation?, events: Events) {
        self.tPriv = tPriv
        self.callId = callId
        self.delegation = delegation
        self.events = events
    }

    /// How long UDP gets to show the relay answers, before TCP is tried (§11.1).
    static let udpWaitMs = 4_000

    /// TCP ports to try when UDP gets no answer: 443 first, which networks rarely block, then the relay's own.
    static func tcpPorts(_ udpPort: UInt16) -> [UInt16] {
        udpPort == 443 ? [443] : [443, udpPort]
    }

    /// This link reached its relay over TCP (FUDP8), because UDP got no answer.
    public private(set) var overTcp = false

    /// Tests only: behave as on a network that drops every UDP reply.
    nonisolated(unsafe) static var udpBlockedForTesting = false

    /// Relays whose UDP got no answer lately, and when: go straight to TCP for half an hour.
    private static let udpSilent = LockedDates()
    static let tcpFirstSeconds: TimeInterval = 30 * 60

    /// Reach the relay: with its key when an INVITE or card carried it,
    /// otherwise by a HELLO. The service id is sent when known; the relay
    /// routes by method, so it may be left out. With `port`, the connection
    /// leaves from that shared port, so a direct path can use the address
    /// the relay sees (§6.1).
    ///
    /// A connection counts once a request comes back. If nothing does over
    /// UDP, as on networks that let UDP out and drop every reply (§11.1), it
    /// tries FUDP over TCP to the same relay: port 443, then the relay's own.
    public func connect(url: String, pubkeyHex: String?, sid: String?, over port: SharedUdpPort? = nil) async throws {
        guard let (host, portNumber) = FudpUrl.hostPort(url) else { throw Refused(code: 400, message: "not a fudp:// url: \(url)") }
        sharedPort = port
        let given = pubkeyHex.flatMap(Hex.decodeOrNil).flatMap { $0.count == 33 ? $0 : nil }

        let tcpFirst = CallRelayLink.udpBlockedForTesting
            || CallRelayLink.udpSilent.within(url, seconds: CallRelayLink.tcpFirstSeconds)
        var pub = given
        if !tcpFirst {
            if pub == nil { pub = try? await FudpDiscovery.discoverPubkey(host: host, port: portNumber, timeoutMs: 3_000) }
            if let pub, let client = try? await udpClient(host: host, port: portNumber, pub: pub, shared: port) {
                if await answers(client, sid: sid) {
                    adopt(client, pub: pub, sid: sid)
                    CallRelayLink.udpSilent.clear(url)
                    return
                }
                client.close()
            }
        }

        for tcpPort in await CallRelayLink.openTcpPorts(host: host, ports: CallRelayLink.tcpPorts(portNumber)) {
            var key = given ?? pub
            if key == nil, let probe = try? await TcpDatagramTransport(host: host, port: tcpPort) {
                key = try? await FudpDiscovery.discoverPubkey(over: probe)
                probe.close()
            }
            guard let key, let transport = try? await TcpDatagramTransport(host: host, port: tcpPort),
                  let client = try? FudpClient(over: transport, host: host, port: tcpPort, peerPubkey: key,
                                               localPrivkey: tPriv) else { continue }
            if await answers(client, sid: sid) {
                adopt(client, pub: key, sid: sid)
                overTcp = true
                // So the next call on this network does not wait for UDP first.
                if !tcpFirst { CallRelayLink.udpSilent.note(url) }
                return
            }
            client.close()
        }
        if tcpFirst && !CallRelayLink.udpBlockedForTesting {
            // TCP failed too: perhaps this is another network now, where UDP works.
            CallRelayLink.udpSilent.clear(url)
            return try await connect(url: url, pubkeyHex: pubkeyHex, sid: sid, over: port)
        }
        throw Refused(code: 408, message: "relay unreachable over UDP or TCP: \(url)")
    }

    /// Which of `ports` accept a TCP connection, tried all at once: a port whose
    /// packets are dropped costs its whole connect timeout, and should not make
    /// the others wait. In the order given.
    static func openTcpPorts(host: String, ports: [UInt16]) async -> [UInt16] {
        await withTaskGroup(of: (UInt16, Bool).self) { group in
            for p in ports {
                group.addTask {
                    guard let probe = try? await TcpDatagramTransport(host: host, port: p, connectTimeoutMs: 4_000) else {
                        return (p, false)
                    }
                    probe.close()
                    return (p, true)
                }
            }
            var open = Set<UInt16>()
            for await (p, ok) in group where ok { open.insert(p) }
            return ports.filter(open.contains)
        }
    }

    private func udpClient(host: String, port: UInt16, pub: Data, shared: SharedUdpPort?) async throws -> FudpClient {
        if let shared {
            let at = try SharedUdpPort.resolve(host, port: port)
            return try FudpClient(over: shared.channel(to: at), host: at.host, port: at.port, peerPubkey: pub,
                                  localPrivkey: tPriv)
        }
        return try await FudpClient(host: host, port: port, peerPubkey: pub, localPrivkey: tPriv)
    }

    /// Whether the relay answers on `client`: `call.info`, public and cheap, comes back.
    private func answers(_ client: FudpClient, sid: String?) async -> Bool {
        let body = (try? JSONSerialization.data(withJSONObject: ["meetingId": callId])) ?? Data()
        guard let reply = try? await FapiClient(fudp: client).call(api: "call.info", params: body, sid: sid,
                                                                  timeoutMs: CallRelayLink.udpWaitMs) else { return false }
        return reply.response.isSuccess
    }

    private func adopt(_ client: FudpClient, pub: Data, sid: String?) {
        client.setNotifyHandler { [weak self] dataType, data in
            guard let events = self?.events else { return }
            if dataType == 0 {
                events.attestation(data)
            } else if dataType == 1, let n = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] {
                events.notice(n)
            }
        }
        client.setDatagramHandler { [weak self] _, _, data in self?.events?.frame(data) }
        fudp = client
        fapi = FapiClient(fudp: client)
        relayPubkey = Hex.encode(pub)
        relaySid = sid
    }

    // MARK: - Requests (§7.2)

    public func create() async throws {
        var p = base()
        p["kind"] = "p2p"
        _ = try await request("call.create", p)
    }

    /// A meeting's `call.create`, with its admission key; "meeting exists" on a retry means the first took.
    public func createMeeting(authPub: Data) async throws {
        for attempt in 0..<3 {
            var p = base()
            p["kind"] = "meeting"
            p["authPub"] = Hex.encode(authPub)
            do {
                _ = try await request("call.create", p)
                return
            } catch let e as Refused {
                if attempt > 0 && e.code == 409 && e.message.contains("meeting exists") { return }
                if !e.lostReply || attempt == 2 { throw e }
            }
        }
    }

    /// `call.join`: with `authPriv`, an admitSig, retried on 409 while the caller has not
    /// registered yet (§6.2 step 4); without, the host's own join before registration.
    /// - Parameter share: give the relay our direct-path candidates to pass on
    ///   (§6.1): our private addresses, and the address it sees us at. It shows
    ///   our IP to the peer, so only for contacts and never with Always relay
    ///   on (Decision 8). Needs the shared port.
    public func join(ssrc: UInt32, authPriv: Data?, share: Bool = false) async throws -> [String: Any] {
        guard let tPub = delegation?.tPubBytes else { throw Refused(code: 400, message: "no delegation") }
        var attempt = 0
        while true {
            var p = base()
            if share, let shared = sharedPort {
                p["reflexive"] = true
                let lan = CallDirectPath.lanCandidates(port: shared.localPort)
                if !lan.isEmpty { p["candidates"] = lan }
            }
            let ts = UInt64(Date().timeIntervalSince1970 * 1000)
            p["ssrc"] = UInt64(ssrc)
            p["ts"] = ts
            if let authPriv {
                p["admitSig"] = Hex.encode(try CallKeys.admitSig(authPriv: authPriv, meetingId: callId, tPub: tPub, ssrc: ssrc, tsMs: ts))
            }
            do {
                let r = try await request("call.join", p)
                if r["datagram"] as? Bool == true { fudp?.enableDatagrams() } // the §2.3 capability signal
                return r
            } catch let e as Refused {
                // An earlier join took and only its reply was lost: leave, so the next one is the one we hear.
                let tookEarlier = e.code == 409 && e.message.contains("already in a call")
                if tookEarlier { await leave() }
                let retry = e.lostReply || tookEarlier || (e.code == 409 && authPriv != nil)
                guard retry, attempt < CallRelayLink.joinRetryMs.count else { throw e }
                if !tookEarlier { try await Task.sleep(nanoseconds: CallRelayLink.joinRetryMs[attempt] * 1_000_000) }
                attempt += 1
            }
        }
    }

    public func register(authPub: Data) async throws {
        var p = base()
        p["authPub"] = Hex.encode(authPub)
        _ = try await request("call.register", p)
    }

    /// Best effort.
    public func leave() async {
        _ = try? await request("call.leave", base())
    }

    public func info() async throws -> [String: Any] {
        try await request("call.info", ["meetingId": callId])
    }

    /// `target`: a FID, or an ssrc (UInt32); nil for `end`.
    public func control(action: String, target: Any?) async throws {
        var p = base()
        p["action"] = action
        if let ssrc = target as? UInt32 { p["target"] = UInt64(ssrc) } else if let fid = target as? String { p["target"] = fid }
        _ = try await request("call.control", p)
    }

    public func hand(raised: Bool) async throws {
        var p = base()
        p["raised"] = raised
        _ = try await request("call.hand", p)
    }

    public func rekey(symkeyVersion: UInt64, nonce: Data, authPub: Data) async throws -> Int {
        var p = base()
        p["symkeyVersion"] = symkeyVersion
        p["nonce"] = Hex.encode(nonce)
        p["authPub"] = Hex.encode(authPub)
        guard let epoch = (try await request("call.rekey", p))["keyEpoch"] as? NSNumber else {
            throw Refused(code: 500, message: "call.rekey: no keyEpoch")
        }
        return epoch.intValue
    }

    public func prove(keyEpoch: Int, authPriv: Data, ssrc: UInt32) async throws {
        guard let tPub = delegation?.tPubBytes else { return }
        var p = base()
        let ts = UInt64(Date().timeIntervalSince1970 * 1000)
        p["keyEpoch"] = keyEpoch
        p["ts"] = ts
        p["admitSig"] = Hex.encode(try CallKeys.admitSig(authPriv: authPriv, meetingId: callId, tPub: tPub, ssrc: ssrc, tsMs: ts))
        _ = try await request("call.prove", p)
    }

    // MARK: - Media

    /// A sealed media frame, as a datagram.
    @discardableResult
    public func sendFrame(_ frame: Data) async -> Bool {
        guard let fudp else { return false }
        return await fudp.sendDatagram(frame) == .sent
    }

    /// An attestation, reliably (§5.1).
    public func sendAttestation(_ attestation: Data) async {
        try? await fudp?.sendNotify(attestation, dataType: 0)
    }

    public var rttMs: Int64 { -1 }

    public func close() {
        fudp?.setNotifyHandler(nil)
        fudp?.setDatagramHandler(nil)
        fudp?.close()
        fudp = nil
        fapi = nil
    }

    // MARK: - Internals

    private func base() -> [String: Any] {
        var p: [String: Any] = ["meetingId": callId]
        if let d = delegation,
           let obj = try? JSONSerialization.jsonObject(with: Data(d.toJson().utf8)) {
            p["delegation"] = obj
        }
        return p
    }

    private func request(_ api: String, _ params: [String: Any]) async throws -> [String: Any] {
        guard let fapi else { throw Refused(code: 503, message: "\(api): not connected to the relay") }
        let body = try JSONSerialization.data(withJSONObject: params)
        let reply: FapiClient.Reply
        do {
            reply = try await fapi.call(api: api, params: body, sid: relaySid, timeoutMs: CallRelayLink.requestTimeoutMs)
        } catch {
            throw Refused(code: 408, message: "\(api): \(error)")
        }
        let r = reply.response
        guard r.isSuccess else { throw Refused(code: r.code ?? 0, message: r.message ?? "") }
        guard let data = r.data, !data.isEmpty,
              let obj = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else { return [:] }
        return obj
    }

    /// The roster entries of a join result or roster notice.
    public static func roster(_ m: [String: Any]) -> [[String: Any]] {
        m["roster"] as? [[String: Any]] ?? []
    }
}

/// Times per key, from several threads.
final class LockedDates: @unchecked Sendable {
    private let lock = NSLock()
    private var dates: [String: Date] = [:]

    func note(_ key: String) { lock.withLock { dates[key] = Date() } }
    func clear(_ key: String) { lock.withLock { dates[key] = nil } }
    func within(_ key: String, seconds: TimeInterval) -> Bool {
        lock.withLock { dates[key].map { Date().timeIntervalSince($0) < seconds } ?? false }
    }
}
