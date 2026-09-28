import Foundation
import FCCore
import FCDomain
import FCVoice

/// One join of a meeting in a Room or Team (VOICE_SPEC §8), the Mac's port of
/// Android's `MeetingSession`: the relay link under a throwaway transport key,
/// the call secret from the entity's symkey, ``CallMedia`` for everyone in
/// the roster whose delegation verifies, and the voice engine. Network steps
/// run one at a time, in order; the listener must not block.
///
/// A rekey (§4.5) comes as a relay notice: the session derives the new secret
/// from the named symkey version, asking for it if it lacks it, and proves it
/// within the relay's deadline. Its own frames move to the new key once every
/// roster entry holds it, or at the deadline (Decision 19). As host it also
/// follows the owner's rotations, rekeying when a newer symkey version arrives.
final class MacMeetingSession: CallRelayLink.Events, CallMedia.Listener, @unchecked Sendable {

    enum End: Equatable { case left, endedByHost, kicked, noKey, balance, gone, failed }

    /// Where the entity's symkeys come from, and how to ask for one this device lacks.
    struct Keys: Sendable {
        let symkeys: @Sendable (_ entityId: String, _ version: UInt64) -> [Data]
        let currentVersion: @Sendable (_ entityId: String) -> UInt64
        /// Ask whoever holds it for a version this device lacks (§8).
        let request: @Sendable (_ entityId: String, _ version: UInt64) -> Void
    }

    protocol Listener: AnyObject, Sendable {
        /// Joined, audio flowing.
        func joined()
        /// The roster, a mute, a hand or who is speaking changed.
        func changed()
        /// As host, a rekey took: post the new keys for late joiners (§3.3).
        func rekeyed(_ update: MeetingSignal)
        func ended(_ why: End, _ detail: String?)
    }

    /// One roster entry, as the UI shows it.
    struct Participant: Equatable, Identifiable {
        let fid: String
        let ssrc: UInt32
        let me: Bool
        let host: Bool
        /// "host" or "locked" while the host has muted them (§7.2).
        let mutedByHost: String?
        let hand: Bool
        let verified: Bool
        var id: UInt32 { ssrc }
    }

    static let tickMs: UInt64 = 200
    static let statsEveryMs = 10_000
    static let hostCheckMs = 5_000
    static let rekeyRetryMs: UInt64 = 2_000
    /// A host retries a rekey the relay refused only after this long.
    static let rekeyBackoffMs: Int64 = 30_000
    /// Delegations outlast any meeting, well inside the 24 h cap (§4.1).
    static let delegationSec: Int64 = 12 * 3600
    /// A stream counts as speaking while frames this loud arrived this recently.
    static let speakingWithinMs: Int64 = 400
    static let speakingLevel = 55

    let meeting: MeetingBoard.Meeting
    private let myFid: String
    private let keys: Keys
    private weak var listener: Listener?
    private let creating: Bool
    private let tPriv: Data
    private let myDelegation: Delegation?
    let ssrc = UInt32.random(in: 1...UInt32.max)
    private let startedMs = MacMeetingSession.nowMs()

    private let lock = NSLock()
    private var tail: Task<Void, Never>?
    private var link: CallRelayLink?
    private var media: CallMedia?
    private var mixer: Mixer?
    private var encoder: FrameEncoder?
    private var io: VoiceIO?
    private var ticker: Task<Void, Never>?
    private var ticks = 0
    private var _participants: [Participant] = []
    private var _hostFid: String
    private var routeId: UInt32 = 0
    private var selfMuted = false
    private var _handRaised = false
    private var _mutedByHost: String?
    private var symkeyVersion: UInt64 = 0
    private var rekeyTriedVersion: UInt64 = 0
    private var rekeyTriedAtMs: Int64 = 0
    /// A rekey's epoch that we hold but do not send under yet (Decision 19); -1 if none.
    private var pendingEpoch = -1
    private var over = false
    private var _joinedAtMs: Int64 = -1
    private var unverified = Set<UInt32>()
    private var paused = Set<UInt32>()
    private var fidOfSsrc: [UInt32: String] = [:]
    /// Per sender ssrc: frames that arrived from the relay, and those that opened. For the log.
    private var arrivals: [UInt32: (arrived: Int, opened: Int)] = [:]

    /// - Parameter creating: this device starts the meeting: `call.create` before
    ///   joining, with the newest key set of `meeting`
    init(meeting: MeetingBoard.Meeting, myFid: String, fidPriv: Data, creating: Bool, keys: Keys, listener: Listener) {
        self.meeting = meeting
        self.myFid = myFid
        self.keys = keys
        self.listener = listener
        self.creating = creating
        // Until a roster says otherwise: the relay names the host in each (§7.2).
        self._hostFid = creating ? myFid : meeting.hostFid
        self.tPriv = Data((0..<32).map { _ in UInt8.random(in: 0...255) })
        self.myDelegation = (try? Secp256k1.publicKey(fromPrivateKey: tPriv)).flatMap {
            try? Delegation.sign(fidPriv: fidPriv, callOrMeetingId: meeting.meetingId, tPub: $0,
                                 expiresSec: MacMeetingSession.nowMs() / 1000 + MacMeetingSession.delegationSec)
        }
    }

    var meetingId: String { meeting.meetingId }

    func start() {
        submit { [self] in
            do {
                try await openLink()
                try await join()
            } catch let e as Ended {
                await finish(e.why, e.detail)
            } catch {
                await finish(.failed, "\(error)")
            }
        }
    }

    /// Leave; as host, `endForAll` closes the meeting for everyone first.
    func leave(endForAll: Bool) {
        submit { [self] in
            if endForAll {
                do { try await currentLink()?.control(action: "end", target: nil) } catch { step("end: \(error)") }
            }
            await finish(endForAll ? .endedByHost : .left, nil)
        }
    }

    func setMuted(_ muted: Bool) {
        let liftHostMute = lock.withLock { () -> Bool in
            selfMuted = muted
            return !muted && _mutedByHost == "host"
        }
        applyMute()
        // Unmuting after the host's plain mute asks the relay to let our frames through (§7.2).
        if liftHostMute {
            submit { [self] in
                do { try await currentLink()?.control(action: "unmute", target: ssrc) } catch { step("unmute: \(error)") }
            }
        }
    }

    func setHand(_ raised: Bool) {
        lock.withLock { _handRaised = raised }
        submit { [self] in
            do { try await currentLink()?.hand(raised: raised) } catch { step("hand: \(error)") }
        }
    }

    /// A host control (§7.2). `target` is a FID or an ssrc (UInt32); `done` gets nil or why the relay refused.
    func control(_ action: String, target: Any?, done: @escaping @Sendable (String?) -> Void) {
        nonisolated(unsafe) let target = target
        submit { [self] in
            do {
                try await currentLink()?.control(action: action, target: target)
                done(nil)
            } catch {
                done("\(error)")
            }
        }
    }

    // MARK: - State for the UI

    var participants: [Participant] { lock.withLock { _participants } }
    var hostFid: String { lock.withLock { _hostFid } }
    var isHost: Bool { hostFid == myFid }
    var isMuted: Bool { lock.withLock { selfMuted || _mutedByHost != nil } }
    var mutedByHost: String? { lock.withLock { _mutedByHost } }
    var handRaised: Bool { lock.withLock { _handRaised } }
    var joinedAtMs: Int64 { lock.withLock { _joinedAtMs } }
    var relayPubkey: String? { currentLink()?.relayPubkey }
    var relaySid: String? { currentLink()?.relaySid }

    /// ssrcs heard just now, this device's own included.
    var speaking: Set<UInt32> {
        var out = Set<UInt32>()
        let now = MacMeetingSession.uptimeMs()
        for s in lock.withLock({ mixer })?.snapshot() ?? []
        where now - s.lastArrivalMs < MacMeetingSession.speakingWithinMs && s.level < MacMeetingSession.speakingLevel {
            out.insert(s.ssrc)
        }
        if !isMuted, let enc = lock.withLock({ encoder }), enc.level < MacMeetingSession.speakingLevel { out.insert(ssrc) }
        return out
    }

    /// Streams whose audio is on hold for late attestations (Decision 15).
    var pausedSsrcs: Set<UInt32> { lock.withLock { paused } }

    /// FIDs whose audio could not be verified and is silenced for this join (§5.1).
    var unverifiedFids: [String] { lock.withLock { unverified.compactMap { fidOfSsrc[$0] } } }

    // MARK: - Internals

    /// Refusals that end the session with a reason the UI can say.
    private struct Ended: Error {
        let why: End
        let detail: String?
    }

    private func currentLink() -> CallRelayLink? { lock.withLock { link } }

    private func openLink() async throws {
        let l = CallRelayLink(tPriv: tPriv, callId: meeting.meetingId, delegation: myDelegation, events: self)
        lock.withLock { link = l }
        step("connecting to \(meeting.relay.url)")
        try await l.connect(url: meeting.relay.url, pubkeyHex: meeting.relay.pubkey, sid: meeting.relay.sid)
        step("connected to the relay")
    }

    /// Create (as its starter) and join, with the newest key set this device
    /// can derive; an older one if the relay refuses it, as when a rekey's
    /// update has not reached this device yet (§3.3).
    private func join() async throws {
        guard let link = currentLink() else { throw Ended(why: .failed, detail: "no relay link") }
        var last: Error?
        var anyKey = false
        for k in meeting.keys {
            guard let nonce = Hex.decodeOrNil(k.nonce),
                  let secret = MeetingKeys.secret(symkeys: keys.symkeys(meeting.keyEntity, k.symkeyVersion), nonce: nonce,
                                                  entityId: meeting.keyEntity, version: k.symkeyVersion,
                                                  meetingId: meeting.meetingId, authPubHex: k.authPub) else { continue }
            anyKey = true
            let authPriv = CallKeys.authPriv(callSecret: secret)
            do {
                if creating { try await link.createMeeting(authPub: try CallKeys.authPub(authPriv: authPriv)) }
                let joined = try await link.join(ssrc: ssrc, authPriv: authPriv)
                let epoch = (joined["keyEpoch"] as? NSNumber)?.intValue ?? 0
                lock.withLock {
                    routeId = (joined["routeId"] as? NSNumber)?.uint32Value ?? 0
                    symkeyVersion = k.symkeyVersion
                }
                step("joined at key epoch \(epoch)")
                try startMedia(secret: secret, epoch: epoch)
                onRoster(joined)
                return
            } catch let e as CallRelayLink.Refused {
                last = e
                switch e.code {
                case 404: throw Ended(why: .gone, detail: "the meeting is over")
                case 403: throw Ended(why: .kicked, detail: e.message)
                case 402: throw Ended(why: .balance, detail: e.message)
                case 401: continue // that key is no longer the meeting's: try an older one
                default: throw e
                }
            }
        }
        if !anyKey {
            let newest = meeting.newestKeys
            // A chat's key can be asked for; a chosen-people meeting's key only comes with its invitation.
            if let newest, !meeting.invited { keys.request(meeting.entityId, newest.symkeyVersion) }
            throw Ended(why: .noKey, detail: "no key for symkey version \(newest.map { "\($0.symkeyVersion)" } ?? "?")")
        }
        throw last ?? Ended(why: .failed, detail: "could not join")
    }

    private func startMedia(secret: Data, epoch: Int) throws {
        let m = CallMedia(callId: meeting.meetingId, callSecret: secret, myFid: myFid, mySsrc: ssrc, tPriv: tPriv)
        if epoch != CallMedia.initialEpoch {
            // Joined after a rekey: everyone already holds this epoch.
            m.rekey(secret: secret, keyEpoch: epoch, nowMs: MacMeetingSession.nowMs())
            m.switchSending(nowMs: MacMeetingSession.nowMs())
        }
        m.setRouteId(lock.withLock { routeId })
        m.listener = self
        let mix = Mixer()
        // Relayed audio, and so every meeting, uses 40 ms frames (§9.1).
        let enc = try FrameEncoder(ssrc: ssrc, frameMs: MacCallSession.frameMs, bitrate: MacCallSession.bitrate,
                                   expectedLossPercent: MacCallSession.expectedLoss) { [weak self, weak m] f in
            guard let self, let m, let l = self.currentLink(),
                  let sealed = try? m.seal(seq: f.seq, timestamp: f.timestamp, level: f.level, voiceActive: f.voiceActive,
                                           afterDtx: f.afterDtx, opus: f.opus, nowMs: MacMeetingSession.nowMs()) else { return }
            Task { await l.sendFrame(sealed) }
        }
        let voice = VoiceIO(onCapture: { [weak enc] samples in enc?.push(samples) },
                            render: { [weak mix] now in mix?.renderTick(nowMs: now) ?? [Int16](repeating: 0, count: Mixer.tickSamples) })
        lock.withLock {
            media = m
            mixer = mix
            encoder = enc
            io = voice
        }
        try voice.start()
        applyMute()
        lock.withLock { _joinedAtMs = MacMeetingSession.nowMs() }
        ticker = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: MacMeetingSession.tickMs * 1_000_000)
                await self?.tick()
            }
        }
        step("media started")
        listener?.joined()
    }

    private func tick() async {
        guard let (m, l) = lock.withLock({ media.flatMap { m in link.map { (m, $0) } } }) else { return }
        let now = MacMeetingSession.nowMs()
        for a in m.takeAttestations(nowMs: now) { await l.sendAttestation(a) }
        m.tick(nowMs: now)
        let n = lock.withLock { () -> Int in
            ticks += 1
            return ticks
        }
        if n % (MacMeetingSession.hostCheckMs / Int(MacMeetingSession.tickMs)) == 0 && isHost { followSymkey(now) }
        if n % (MacMeetingSession.statsEveryMs / Int(MacMeetingSession.tickMs)) == 0 { logStats() }
        if n % 5 == 0 { listener?.changed() } // who is speaking
    }

    private func onRelayNotice(_ notice: [String: Any]) {
        switch notice["type"] as? String {
        case "roster":
            onRoster(notice)
        case "muted":
            let how = notice["locked"] as? Bool == true ? "locked" : "host"
            lock.withLock { _mutedByHost = how }
            step("muted by the host (\(how))")
            applyMute()
            listener?.changed()
        case "rekey":
            nonisolated(unsafe) let n = notice
            Task { await self.rekeyAttempt(n, since: MacMeetingSession.nowMs(), asked: false) }
        case "kicked":
            // "rekey": this device could not prove the new key in time (§4.5); "balance": the host's ran out.
            let reason = notice["reason"] as? String ?? ""
            let why: End = reason == "rekey" ? .noKey : reason == "balance" ? .balance : .kicked
            submit { [self] in await finish(why, reason) }
        case "ended":
            submit { [self] in await finish(.endedByHost, nil) }
        case "balance":
            step("the relay says the host's balance is low")
        default:
            break
        }
    }

    /// Hear every roster entry whose delegation verifies for this meeting and
    /// names its FID (§5.1 step 1); a relay that lies in the roster gets no
    /// stream played.
    private func onRoster(_ roster: [String: Any]) {
        let m = lock.withLock { media }
        if let h = roster["host"] as? String { lock.withLock { _hostFid = h } }
        let host = hostFid
        var list: [Participant] = []
        var present = Set<UInt32>()
        var myMute: String?
        let nowSec = MacMeetingSession.nowMs() / 1000
        for e in CallRelayLink.roster(roster) {
            guard let fid = e["fid"] as? String, let n = e["ssrc"] as? NSNumber else { continue }
            let s = n.uint32Value
            let muted = e["muted"] as? String
            let hand = e["hand"] as? Bool == true
            if s == ssrc {
                myMute = muted
                list.append(Participant(fid: fid, ssrc: s, me: true, host: fid == host, mutedByHost: muted, hand: hand, verified: true))
                continue
            }
            var verified = false
            if let json = e["delegation"] as? String, let d = Delegation.fromJson(json), d.fid == fid,
               d.verify(callOrMeetingId: meeting.meetingId, nowSec: nowSec) == .ok, let tPub = d.tPubBytes {
                verified = true
                m?.addPeer(fid: fid, ssrc: s, tPub: tPub)
            }
            present.insert(s)
            lock.withLock { fidOfSsrc[s] = fid }
            list.append(Participant(fid: fid, ssrc: s, me: false, host: fid == host, mutedByHost: muted, hand: hand, verified: verified))
        }
        let pending = lock.withLock { () -> Int in
            for gone in fidOfSsrc.keys where !present.contains(gone) {
                fidOfSsrc[gone] = nil
                arrivals[gone] = nil
                m?.removePeer(ssrc: gone)
            }
            // The host lifted its mute, or never set one; or set one.
            _mutedByHost = myMute
            _participants = list
            return pendingEpoch
        }
        applyMute()
        if pending >= 0 && MacMeetingSession.everyoneHas(roster, pending) { switchSending(pending, why: "everyone has it") }
        listener?.changed()
    }

    /// Every roster entry has proved `epoch`: the relay says so in each entry (§4.5).
    private static func everyoneHas(_ roster: [String: Any], _ epoch: Int) -> Bool {
        let entries = CallRelayLink.roster(roster)
        return !entries.isEmpty && entries.allSatisfy { (($0["keyEpoch"] as? NSNumber)?.intValue ?? -1) >= epoch }
    }

    /// Send under the rekey's epoch from now on, once.
    private func switchSending(_ epoch: Int, why: String) {
        let m = lock.withLock { () -> CallMedia? in
            guard pendingEpoch == epoch, let m = media else { return nil }
            pendingEpoch = -1
            return m
        }
        guard let m else { return }
        m.switchSending(nowMs: MacMeetingSession.nowMs())
        step("sending under key epoch \(epoch): \(why)")
    }

    /// A rekey notice (§4.5): derive the new secret, asking once for a version
    /// this device lacks, and prove it before the relay's deadline. Retried
    /// every 2 s; the relay drops us if it runs out.
    private func rekeyAttempt(_ notice: [String: Any], since: Int64, asked: Bool) async {
        guard !lock.withLock({ over }),
              let version = (notice["symkeyVersion"] as? NSNumber)?.uint64Value,
              let epoch = (notice["keyEpoch"] as? NSNumber)?.intValue,
              let nonceHex = notice["nonce"] as? String, let nonce = Hex.decodeOrNil(nonceHex),
              let authPub = notice["authPub"] as? String else { return }
        let within = ((notice["proveWithinSeconds"] as? NSNumber)?.int64Value ?? 30) * 1000
        let m = lock.withLock { media }
        if let m, m.keyEpoch == (epoch & 0xFF) || m.pendingKeyEpoch == (epoch & 0xFF) { return } // already there
        guard let secret = MeetingKeys.secret(symkeys: keys.symkeys(meeting.keyEntity, version), nonce: nonce,
                                              entityId: meeting.keyEntity, version: version,
                                              meetingId: meeting.meetingId, authPubHex: authPub) else {
            if !asked {
                step("rekeyed to symkey version \(version), which this device lacks: asking for it")
                if !meeting.invited { keys.request(meeting.entityId, version) }
            }
            guard MacMeetingSession.nowMs() - since < within else { return }
            try? await Task.sleep(nanoseconds: MacMeetingSession.rekeyRetryMs * 1_000_000)
            nonisolated(unsafe) let n = notice
            await rekeyAttempt(n, since: since, asked: true)
            return
        }
        let authPriv = CallKeys.authPriv(callSecret: secret)
        if let m {
            // Held, not yet sent under: everyone keeps hearing us until all have the new key,
            // or the relay's deadline drops those who could not get it (Decision 19).
            m.rekey(secret: secret, keyEpoch: epoch, nowMs: MacMeetingSession.nowMs())
            lock.withLock { pendingEpoch = epoch }
            let left = max(0, since + within - MacMeetingSession.nowMs())
            Task { [weak self] in
                try? await Task.sleep(nanoseconds: UInt64(left) * 1_000_000)
                self?.switchSending(epoch, why: "the relay's deadline")
            }
        }
        lock.withLock { symkeyVersion = version }
        submit { [self] in
            for _ in 0..<3 {
                do {
                    try await currentLink()?.prove(keyEpoch: epoch, authPriv: authPriv, ssrc: ssrc)
                    step("proved key epoch \(epoch)")
                    return
                } catch let e as CallRelayLink.Refused where e.lostReply {
                    continue
                } catch {
                    step("prove refused: \(error)")
                    return
                }
            }
        }
    }

    /// As host: the owner rotated the symkey (§4.5), usually to shut out a
    /// member it removed. Rekey the meeting onto the new version; the relay's
    /// rekey notice then moves this device too.
    private func followSymkey(_ now: Int64) {
        guard !meeting.invited else { return } // keyed by its own key, not the chat's: no rotation to follow
        let current = keys.currentVersion(meeting.entityId)
        let go = lock.withLock { () -> Bool in
            guard current > symkeyVersion else { return false }
            if current == rekeyTriedVersion && now - rekeyTriedAtMs < MacMeetingSession.rekeyBackoffMs { return false }
            return true
        }
        guard go, let held = keys.symkeys(meeting.entityId, current).first else { return }
        lock.withLock {
            rekeyTriedVersion = current
            rekeyTriedAtMs = now
        }
        let nonce = Data((0..<32).map { _ in UInt8.random(in: 0...255) })
        guard let secret = try? CallKeys.meetingSecret(symkey: held, nonce: nonce, entityId: meeting.entityId,
                                                       symkeyVersion: current, meetingId: meeting.meetingId),
              let authPub = try? CallKeys.authPub(authPriv: CallKeys.authPriv(callSecret: secret)) else { return }
        submit { [self] in
            do {
                guard let l = currentLink() else { return }
                let epoch = try await l.rekey(symkeyVersion: current, nonce: nonce, authPub: authPub)
                step("rekeyed onto symkey version \(current), key epoch \(epoch)")
                listener?.rekeyed(MeetingSignal.start(meetingId: meeting.meetingId, relay: meeting.relay, nonce: nonce,
                                                      symkeyVersion: current, authPub: authPub, keyEpoch: Int64(epoch),
                                                      title: meeting.title, startedMs: meeting.started))
            } catch {
                step("rekey refused: \(error)")
            }
        }
    }

    private func applyMute() {
        let (enc, muted) = lock.withLock { (encoder, selfMuted || _mutedByHost != nil) }
        enc?.muted = muted
    }

    /// One line for this device, then one per sender: frames that arrived and
    /// opened, and what the jitter buffer made of them.
    private func logStats() {
        let (mix, m, enc, counts, fids, people) = lock.withLock { (mixer, media, encoder, arrivals, fidOfSsrc, _participants.count) }
        step("stats: \(people) in the roster, mic level \(enc?.level ?? 127)\(isMuted ? " (muted)" : ""), "
             + "sent \(enc?.framesSent ?? 0), dtx \(enc?.dtxSkipped ?? 0)")
        for (s, c) in counts {
            let j = mix?.stats(s)
            step("  from \(fids[s] ?? "?") ssrc \(s): arrived \(c.arrived), opened \(c.opened)"
                 + (m?.isPaused(ssrc: s) == true ? ", PAUSED" : "") + (m?.isUnverified(ssrc: s) == true ? ", UNVERIFIED" : "")
                 + (j.map { " | played \($0.played), target \($0.targetMs) ms" } ?? ""))
        }
    }

    private func step(_ what: String) {
        SystemLog.shared.info(SystemSource.messages,
                              "meeting \(meeting.meetingId) +\(MacMeetingSession.nowMs() - startedMs)ms: \(what)")
    }

    /// Network steps, one at a time and in order, like Android's single worker.
    private func submit(_ op: @escaping @Sendable () async -> Void) {
        lock.withLock {
            guard !over else { return }
            let prev = tail
            tail = Task {
                await prev?.value
                await op()
            }
        }
    }

    /// Once: stop everything, erase the transport key, and tell the listener why.
    private func finish(_ why: End, _ detail: String?) async {
        let already = lock.withLock { () -> Bool in
            defer { over = true }
            return over
        }
        guard !already else { return }
        step("over: \(why)\(detail.map { " (\($0))" } ?? "")")
        ticker?.cancel()
        let (m, l, voice) = lock.withLock { (media, link, io) }
        voice?.stop()
        if let m, let l {
            for a in m.finish(nowMs: MacMeetingSession.nowMs()) { await l.sendAttestation(a) }
        }
        if let l {
            if why == .left || why == .failed { await l.leave() }
            l.close()
        }
        lock.withLock {
            media = nil
            mixer = nil
            encoder = nil
            io = nil
            link = nil
        }
        listener?.ended(why, detail)
    }

    static func nowMs() -> Int64 { Int64(Date().timeIntervalSince1970 * 1000) }
    static func uptimeMs() -> Int64 { Int64(DispatchTime.now().uptimeNanoseconds / 1_000_000) }

    // MARK: - CallRelayLink.Events

    func frame(_ datagram: Data) {
        guard let (m, mix) = lock.withLock({ media.flatMap { m in mixer.map { (m, $0) } } }) else { return }
        let h = MediaFrame.Header.parse(datagram)
        if let h { lock.withLock { arrivals[h.ssrc, default: (0, 0)].arrived += 1 } }
        guard let opened = m.open(datagram, nowMs: MacMeetingSession.nowMs()) else { return }
        let oh = opened.header
        lock.withLock { arrivals[oh.ssrc, default: (0, 0)].opened += 1 }
        mix.onFrame(EncodedFrame(ssrc: oh.ssrc, seq: oh.seq, timestamp: oh.timestamp, level: oh.level,
                                 voiceActive: oh.flags & MediaFrame.flagVad != 0, afterDtx: oh.flags & MediaFrame.flagDtx != 0,
                                 opus: opened.opus),
                    arrivalMs: MacMeetingSession.uptimeMs())
    }

    func attestation(_ bytes: Data) {
        lock.withLock { media }?.onAttestation(bytes, nowMs: MacMeetingSession.nowMs())
    }

    func notice(_ n: [String: Any]) {
        guard n["meetingId"] as? String == nil || n["meetingId"] as? String == meeting.meetingId else { return }
        onRelayNotice(n)
    }

    // MARK: - CallMedia.Listener

    func unverified(fid: String, ssrc: UInt32) {
        step("audio claimed to be \(fid)'s could not be verified; silenced")
        let mix = lock.withLock { () -> Mixer? in
            unverified.insert(ssrc)
            paused.remove(ssrc)
            return mixer
        }
        mix?.silence(ssrc)
        listener?.changed()
    }

    func paused(fid: String, ssrc: UInt32, on: Bool) {
        step("\(on ? "paused" : "resumed") \(fid)'s audio")
        lock.withLock {
            if on { paused.insert(ssrc) } else { paused.remove(ssrc) }
        }
        listener?.changed()
    }
}
