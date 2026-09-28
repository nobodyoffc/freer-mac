import Foundation
import FCCore
import FCDomain
import FCVoice

/// One 1:1 call through the relay (VOICE_SPEC §6.2), the Mac's port of
/// Android's `CallSession`: the signaller's call, its ``CallRelayLink``,
/// ``CallMedia``, and the voice engine. Relayed only; direct paths come later.
///
/// Caller: connect, `call.create`, join, then ring; once the callee's ACCEPT
/// verifies, register `authPub` and start the audio. Callee, after
/// accepting: connect, join with `admitSig` (retrying while the caller has
/// not registered), start the audio.
final class MacCallSession: CallRelayLink.Events, CallMedia.Listener, @unchecked Sendable {

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
    private let lock = NSLock()
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

    init(call: CallSignaller.Call, signaller: CallSignaller, myFid: String,
         onState: @escaping @Sendable (State) -> Void, onUnverified: @escaping @Sendable (String) -> Void) {
        self.call = call
        self.signaller = signaller
        self.myFid = myFid
        self.onState = onState
        self.onUnverified = onUnverified
    }

    // MARK: - Steps

    func startOutgoing() {
        Task {
            do {
                try await openLink()
                try await createRetrying()
                let joined = try await link!.join(ssrc: ssrc, authPriv: nil)
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
                let joined = try await link!.join(ssrc: ssrc, authPriv: CallKeys.authPriv(callSecret: secret))
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
        try await l.connect(url: url, pubkeyHex: call.relayPubkey, sid: call.relaySid)
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
                                   expectedLossPercent: MacCallSession.expectedLoss) { [weak m] f in
            guard let m, let sealed = try? m.seal(seq: f.seq, timestamp: f.timestamp, level: f.level, voiceActive: f.voiceActive,
                                                  afterDtx: f.afterDtx, opus: f.opus, nowMs: MacCallSession.nowMs()) else { return }
            Task { await link?.sendFrame(sealed) }
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
        for a in m.takeAttestations(nowMs: now) { await l.sendAttestation(a) }
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
        }
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
        if let m = media, let l = link {
            for a in m.finish(nowMs: MacCallSession.nowMs()) { await l.sendAttestation(a) }
        }
        if let l = link {
            await l.leave()
            l.close()
        }
        lock.withLock {
            media = nil
            mixer = nil
            encoder = nil
            io = nil
            link = nil
        }
    }

    static func nowMs() -> Int64 { Int64(Date().timeIntervalSince1970 * 1000) }

    // MARK: - CallRelayLink.Events

    func frame(_ datagram: Data) {
        guard let m = media, let mix = mixer, let opened = m.open(datagram, nowMs: MacCallSession.nowMs()) else { return }
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
}
