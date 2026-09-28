import Foundation
import FCCore
import FCDomain
import FCTransport
import FCVoice

/// One 1:1 call (VOICE_SPEC §6.2), the Mac's port of Android's
/// `CallSession`: the signaller's call, its ``CallRelayLink``, ``CallMedia``,
/// and the voice engine. Audio starts on the relay; with a contact, a
/// ``CallDirectPath`` is tried beside it from the same port, and audio moves
/// there once probes pass both ways (§6.2 steps 6-9).
///
/// Caller: connect, `call.create`, join, then ring; once the callee's ACCEPT
/// verifies, register `authPub` and start the audio. Callee, after
/// accepting: connect, join with `admitSig` (retrying while the caller has
/// not registered), start the audio.
final class MacCallSession: CallRelayLink.Events, CallMedia.Listener, CallDirectPath.Listener, @unchecked Sendable {

    enum State: Equatable { case connecting, ringing, connected, ended, failed(String) }

    /// Relayed audio uses 40 ms frames (§9.1).
    static let frameMs = 40
    static let bitrate = 24_000
    static let expectedLoss = 10
    /// A peer gone from the relay this long has hung up.
    static let peerGoneMs: UInt64 = 6_000

    let call: CallSignaller.Call
    private let signaller: CallSignaller
    private let myFid: String
    private let onState: @Sendable (State) -> Void
    private let onUnverified: @Sendable (String) -> Void
    /// Audio moved to the direct path (true), or back to the relay.
    private let onPath: @Sendable (Bool) -> Void
    /// Try a direct path (§6.2 step 6): only with a contact, and never with Always relay on (Decision 8).
    private let allowDirect: Bool
    private let lock = NSLock()
    private var port: SharedUdpPort?
    private var direct: CallDirectPath?
    private var link: CallRelayLink?
    private var media: CallMedia?
    private var mixer: Mixer?
    private var encoder: FrameEncoder?
    private var io: VoiceIO?
    private var ticker: Task<Void, Never>?
    private var routeId: UInt32 = 0
    private var peerSeen = false
    private var lastRoster: [String: Any]?
    private(set) var connectedAtMs: Int64 = -1
    private let ssrc = UInt32.random(in: 0...UInt32.max)
    private var over = false

    init(call: CallSignaller.Call, signaller: CallSignaller, myFid: String, allowDirect: Bool,
         onState: @escaping @Sendable (State) -> Void, onUnverified: @escaping @Sendable (String) -> Void,
         onPath: @escaping @Sendable (Bool) -> Void) {
        self.call = call
        self.signaller = signaller
        self.myFid = myFid
        self.allowDirect = allowDirect
        self.onState = onState
        self.onUnverified = onUnverified
        self.onPath = onPath
    }

    var isDirect: Bool { lock.withLock { direct }?.isUp ?? false }

    // MARK: - Steps

    func startOutgoing() {
        Task {
            do {
                try await openLink()
                try await createRetrying()
                let joined = try await link!.join(ssrc: ssrc, authPriv: nil, share: allowDirect)
                routeId = (joined["routeId"] as? NSNumber)?.uint32Value ?? 0
                signaller.ring(callId: call.callId, relay: .init(url: call.relayUrl ?? "", pubkey: link?.relayPubkey,
                                                                 sid: link?.relaySid))
                onState(.ringing)
            } catch {
                fail("could not open the call on the relay: \(error)")
            }
        }
    }

    /// The callee's ACCEPT verified.
    func onAnswered() {
        Task {
            do {
                guard let secret = signaller.callSecret(callId: call.callId) else { throw CallRelayLink.Refused(code: 0, message: "no call key") }
                try await register(authPub: try CallKeys.authPub(authPriv: CallKeys.authPriv(callSecret: secret)))
                try startMedia(secret: secret)
            } catch {
                fail("could not open the call on the relay: \(error)")
            }
        }
    }

    /// After the signaller sent ACCEPT.
    func startIncoming() {
        Task {
            do {
                guard let secret = signaller.callSecret(callId: call.callId) else { throw CallRelayLink.Refused(code: 0, message: "no call key") }
                try await openLink()
                let joined = try await link!.join(ssrc: ssrc, authPriv: CallKeys.authPriv(callSecret: secret),
                                                  share: allowDirect)
                routeId = (joined["routeId"] as? NSNumber)?.uint32Value ?? 0
                lock.withLock { lastRoster = joined }
                watchPeer(joined)
                try startMedia(secret: secret)
            } catch {
                fail("could not join the call on the relay: \(error)")
            }
        }
    }

    var muted: Bool {
        get { encoder?.muted ?? false }
        set { encoder?.muted = newValue }
    }

    /// Stop everything; HANGUP or CANCEL is the caller's to send.
    func end() {
        Task { await teardown() }
    }

    // MARK: - Internals

    private func openLink() async throws {
        guard let url = call.relayUrl else { throw CallRelayLink.Refused(code: 0, message: "no relay for this call") }
        let l = CallRelayLink(tPriv: call.transportPriv, callId: call.callId, delegation: call.myDelegation, events: self)
        link = l
        // One port for the relay and the peer: the address the relay sees is where the peer can reach us (§6.1).
        let shared = allowDirect ? try? SharedUdpPort() : nil
        lock.withLock { port = shared }
        try await l.connect(url: url, pubkeyHex: call.relayPubkey, sid: call.relaySid, over: shared)
    }

    private func createRetrying() async throws {
        for attempt in 0..<3 {
            do {
                try await link!.create()
                return
            } catch let e as CallRelayLink.Refused {
                if attempt > 0 && e.code == 409 && e.message.contains("meeting exists") { return }
                if !e.lostReply || attempt == 2 { throw e }
            }
        }
    }

    /// `call.register`, retried when its reply is lost; a peer already in the roster means it took.
    private func register(authPub: Data) async throws {
        for attempt in 1...3 {
            do {
                try await link!.register(authPub: authPub)
                return
            } catch let e as CallRelayLink.Refused {
                if !e.lostReply { throw e }
                if lock.withLock({ peerSeen }) || attempt == 3 { return }
            }
        }
    }

    private func startMedia(secret: Data) throws {
        let m = CallMedia(callId: call.callId, callSecret: secret, myFid: myFid, mySsrc: ssrc, tPriv: call.transportPriv)
        m.setOneToOne(true) // a late attestation here is a slow path, not forgery (§5.1)
        m.setRouteId(routeId)
        m.listener = self
        let mix = Mixer()
        let link = self.link
        let enc = try FrameEncoder(ssrc: ssrc, frameMs: MacCallSession.frameMs, bitrate: MacCallSession.bitrate,
                                   expectedLossPercent: MacCallSession.expectedLoss) { [weak self, weak m] f in
            guard let m, let sealed = try? m.seal(seq: f.seq, timestamp: f.timestamp, level: f.level, voiceActive: f.voiceActive,
                                                  afterDtx: f.afterDtx, opus: f.opus, nowMs: MacCallSession.nowMs()) else { return }
            let d = self?.lock.withLock { self?.direct }
            Task {
                if let d, d.isUp { await d.send(sealed) } else { await link?.sendFrame(sealed) }
            }
        }
        let voice = VoiceIO(onCapture: { [weak enc] samples in enc?.push(samples) },
                            render: { [weak mix] now in mix?.renderTick(nowMs: now) ?? [Int16](repeating: 0, count: Mixer.tickSamples) })
        lock.withLock {
            media = m
            mixer = mix
            encoder = enc
            io = voice
        }
        if let roster = lock.withLock({ lastRoster }) { addPeers(roster) }
        try voice.start()
        ticker = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 200_000_000)
                await self?.tick()
            }
        }
        connectedAtMs = MacCallSession.nowMs()
        onState(.connected)
    }

    private func tick() async {
        guard let m = media, let l = link else { return }
        let now = MacCallSession.nowMs()
        // Attestations go the way the frames they cover went.
        let d = lock.withLock { direct }
        for a in m.takeAttestations(nowMs: now) {
            if let d, d.isUp { await d.sendAttestation(a) } else { await l.sendAttestation(a) }
        }
        m.tick(nowMs: now)
    }

    /// Hear a roster entry only if it is the signalled peer, under a delegation that
    /// verifies for this call and names the transport key its INVITE or ACCEPT did.
    private func addPeers(_ roster: [String: Any]) {
        guard let m = media, let signalled = call.peerDelegation else { return }
        for e in CallRelayLink.roster(roster) {
            guard e["fid"] as? String == call.peerFid, let json = e["delegation"] as? String,
                  let d = Delegation.fromJson(json), d.fid == call.peerFid,
                  d.verify(callOrMeetingId: call.callId, nowSec: MacCallSession.nowMs() / 1000) == .ok,
                  d.tPub == signalled.tPub, let tPub = d.tPubBytes,
                  let ssrc = (e["ssrc"] as? NSNumber)?.uint32Value else { continue }
            m.addPeer(fid: call.peerFid, ssrc: ssrc, tPub: tPub)
            tryDirect(e, peerTPub: tPub)
        }
    }

    /// The peer's roster entry, its delegation verified, carries the candidates
    /// it chose to share: punch to them, keeping the relay (§6.2 steps 6-9).
    /// The lower FID opens the connection.
    private func tryDirect(_ entry: [String: Any], peerTPub: Data) {
        guard allowDirect, let list = entry["candidates"] as? [[String: Any]] else { return }
        let candidates = list.compactMap(CallDirectPath.Candidate.parse)
        guard !candidates.isEmpty else { return }
        let started = lock.withLock { () -> CallDirectPath? in
            guard direct == nil, let port,
                  let d = try? CallDirectPath(port: port, tPriv: call.transportPriv, peerTPub: peerTPub,
                                              initiator: myFid < call.peerFid, candidates: candidates, listener: self)
            else { return nil }
            direct = d
            return d
        }
        started?.start()
    }

    /// A peer that was on the relay and left has hung up, even if its HANGUP never reaches us.
    private func watchPeer(_ roster: [String: Any]) {
        let present = CallRelayLink.roster(roster).contains { $0["fid"] as? String == call.peerFid }
        if present {
            lock.withLock { peerSeen = true }
            return
        }
        guard lock.withLock({ peerSeen }) else { return }
        Task { [weak self] in
            try? await Task.sleep(nanoseconds: MacCallSession.peerGoneMs * 1_000_000)
            guard let self else { return }
            let back = self.lock.withLock { self.lastRoster }.map {
                CallRelayLink.roster($0).contains { $0["fid"] as? String == self.call.peerFid }
            } ?? false
            if !back && self.connectedAtMs > 0 { self.signaller.peerLeft(callId: self.call.callId) }
        }
    }

    private func fail(_ why: String) {
        Task {
            await teardown()
            onState(.failed(why))
        }
    }

    private func teardown() async {
        let already = lock.withLock { () -> Bool in
            defer { over = true }
            return over
        }
        guard !already else { return }
        ticker?.cancel()
        io?.stop()
        lock.withLock { direct }?.stop()
        if let m = media, let l = link {
            for a in m.finish(nowMs: MacCallSession.nowMs()) { await l.sendAttestation(a) }
        }
        if let l = link {
            await l.leave()
            l.close()
        }
        let shared = lock.withLock { () -> SharedUdpPort? in
            media = nil
            mixer = nil
            encoder = nil
            io = nil
            link = nil
            direct = nil
            defer { port = nil }
            return port
        }
        shared?.close()
    }

    static func nowMs() -> Int64 { Int64(Date().timeIntervalSince1970 * 1000) }

    // MARK: - CallRelayLink.Events

    func frame(_ datagram: Data) {
        play(datagram, direct: false)
    }

    private func play(_ datagram: Data, direct: Bool) {
        guard let m = media, let mix = mixer,
              let opened = m.open(datagram, nowMs: MacCallSession.nowMs(), fromPeerConnection: direct) else { return }
        let h = opened.header
        mix.onFrame(EncodedFrame(ssrc: h.ssrc, seq: h.seq, timestamp: h.timestamp, level: h.level,
                                 voiceActive: h.flags & MediaFrame.flagVad != 0, afterDtx: h.flags & MediaFrame.flagDtx != 0,
                                 opus: opened.opus),
                    arrivalMs: Int64(DispatchTime.now().uptimeNanoseconds / 1_000_000))
    }

    func attestation(_ bytes: Data) {
        media?.onAttestation(bytes, nowMs: MacCallSession.nowMs())
    }

    func notice(_ n: [String: Any]) {
        switch n["type"] as? String {
        case "roster":
            lock.withLock { lastRoster = n }
            watchPeer(n)
            addPeers(n)
        case "knock":
            guard n["meetingId"] as? String == call.callId, let json = n["delegation"] as? String,
                  let d = Delegation.fromJson(json) else { return }
            signaller.onKnock(callId: call.callId, delegation: d)
        case "kicked":
            fail("removed by the relay: \(n["reason"] ?? "")")
        default:
            break
        }
    }

    // MARK: - CallMedia.Listener

    func unverified(fid: String, ssrc: UInt32) {
        mixer?.silence(ssrc)
        onUnverified(fid)
    }

    func paused(fid: String, ssrc: UInt32, on: Bool) {}

    // MARK: - CallDirectPath.Listener

    func directUp() {
        media?.setRouteId(0) // §5: routeId 0 on a direct path
        step("audio now goes direct")
        onPath(true)
    }

    func directDown() {
        media?.setRouteId(routeId)
        step("back on the relay")
        onPath(false)
    }

    func directFrame(_ datagram: Data) {
        play(datagram, direct: true)
    }

    func directAttestation(_ bytes: Data) {
        media?.onAttestation(bytes, nowMs: MacCallSession.nowMs())
    }

    func directLog(_ what: String) {
        step("direct: \(what)")
    }

    private func step(_ what: String) {
        SystemLog.shared.info(SystemSource.messages, "call \(call.callId.prefix(8)): \(what)")
    }
}
