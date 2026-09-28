import Foundation
import FCCore

/// The end-to-end layer of one call or meeting (VOICE_SPEC §5, §5.1), a port
/// of Android's `CallMedia`: seals this device's frames under its sender key,
/// opens the others' under theirs, and checks every played frame against its
/// sender's signed attestations.
///
/// In a meeting a sender's audio pauses when its attestations are late and
/// resumes once one vouches for what was held (Decision 15); only a digest
/// that does not match silences it for good. A rekey adds a key epoch;
/// senders move to it once everyone holds it (Decision 19), and the previous
/// epoch's keys open frames for 5 s after that.
///
/// No devices and no network in here. Every method is serialized on one lock.
public final class CallMedia: @unchecked Sendable {

    public static let initialEpoch = 0
    /// Attest at least this often (§5.1).
    static let attestEveryMs: Int64 = 1_000
    /// A played frame no attestation has covered by now pauses its stream (§5.1).
    public static let attestDeadlineMs: Int64 = 3_000
    static let keepPlayedMs: Int64 = 5_000
    static let keepHeldMs: Int64 = 60_000
    public static let previousEpochMs: Int64 = 5_000

    public protocol Listener: AnyObject {
        /// Audio claimed to be from `fid` could not be verified; that stream is now silent.
        func unverified(fid: String, ssrc: UInt32)
        /// A meeting stream paused for late attestations, or resumed once vouched for.
        func paused(fid: String, ssrc: UInt32, on: Bool)
    }

    private struct Played {
        let digest: Data
        let atMs: Int64
        let heard: Bool
    }

    private final class Peer {
        let fid: String
        let ssrc: UInt32
        let tPub: Data
        var keys: [Int: Data] = [:]
        var window = ReplayWindow()
        var played: [UInt64: Played] = [:]
        var unverified = false
        var paused = false

        init(fid: String, ssrc: UInt32, tPub: Data) {
            self.fid = fid
            self.ssrc = ssrc
            self.tPub = tPub
        }
    }

    private let lock = NSLock()
    private let callId: String
    private var secrets: [Int: Data] = [:]
    private let myFid: String
    public let mySsrc: UInt32
    private var myEpoch = CallMedia.initialEpoch
    private var myKey: Data
    private var previousEpoch = -1
    private var previousUntilMs: Int64 = 0
    private var pendingEpoch = -1
    private var pendingKey: Data?
    private let tPriv: Data
    private var peers: [UInt32: Peer] = [:]
    private var routeId: UInt32 = 0
    private var oneToOne = false
    public weak var listener: Listener?

    // Outgoing attestation window: one entry per seq from pendingFirst, nil where not sent.
    private var pending: [Data?] = []
    private var pendingFirst: Int64 = -1
    private var pendingSinceMs: Int64 = 0
    private var ready: [Data] = []

    /// `tPriv` signs the attestations; the caller erases it when the call ends.
    public init(callId: String, callSecret: Data, myFid: String, mySsrc: UInt32, tPriv: Data) {
        self.callId = callId
        self.secrets[CallMedia.initialEpoch] = callSecret
        self.myFid = myFid
        self.mySsrc = mySsrc
        self.myKey = CallKeys.senderKey(callSecret: callSecret, fid: myFid, ssrc: mySsrc, keyEpoch: CallMedia.initialEpoch)
        self.tPriv = tPriv
    }

    /// A 1:1 call: a late attestation silences no one; a mismatch still does (§5.1 step 5).
    public func setOneToOne(_ on: Bool) {
        lock.withLock { oneToOne = on }
    }

    /// The relay's handle for our frames; 0 on a direct path. A change closes the current attestation.
    public func setRouteId(_ id: UInt32) {
        lock.withLock {
            if id != routeId && !pending.isEmpty { flush() }
            routeId = id
        }
    }

    /// Someone we will hear, with a `tPub` whose delegation from `fid` the caller checked.
    public func addPeer(fid: String, ssrc: UInt32, tPub: Data) {
        lock.withLock {
            guard ssrc != mySsrc, peers[ssrc] == nil else { return }
            let p = Peer(fid: fid, ssrc: ssrc, tPub: tPub)
            for (epoch, secret) in secrets {
                p.keys[epoch] = CallKeys.senderKey(callSecret: secret, fid: fid, ssrc: ssrc, keyEpoch: epoch)
            }
            peers[ssrc] = p
        }
    }

    public func removePeer(ssrc: UInt32) {
        lock.withLock { peers[ssrc] = nil }
    }

    // MARK: - Rekeys (§4.5, Decision 19)

    /// A new epoch: everyone's frames open under it now; ours go out under it at `switchSending`.
    public func rekey(secret: Data, keyEpoch: Int, nowMs: Int64) {
        lock.withLock {
            let epoch = keyEpoch & 0xFF
            guard epoch != myEpoch, epoch != pendingEpoch else { return }
            if pendingEpoch >= 0 { switchLocked(nowMs) }
            secrets[epoch] = secret
            for p in peers.values {
                p.keys[epoch] = CallKeys.senderKey(callSecret: secret, fid: p.fid, ssrc: p.ssrc, keyEpoch: epoch)
            }
            pendingEpoch = epoch
            pendingKey = CallKeys.senderKey(callSecret: secret, fid: myFid, ssrc: mySsrc, keyEpoch: epoch)
        }
    }

    public func switchSending(nowMs: Int64) {
        lock.withLock { switchLocked(nowMs) }
    }

    private func switchLocked(_ nowMs: Int64) {
        guard pendingEpoch >= 0, let key = pendingKey else { return }
        dropPreviousEpoch()
        previousEpoch = myEpoch
        previousUntilMs = nowMs + CallMedia.previousEpochMs
        myEpoch = pendingEpoch
        myKey = key
        pendingEpoch = -1
        pendingKey = nil
    }

    public var keyEpoch: Int { lock.withLock { myEpoch } }
    public var pendingKeyEpoch: Int { lock.withLock { pendingEpoch } }

    private func dropPreviousEpoch() {
        guard previousEpoch >= 0 else { return }
        secrets[previousEpoch] = nil
        for p in peers.values { p.keys[previousEpoch] = nil }
        previousEpoch = -1
    }

    // MARK: - Sending

    /// Seal one of our frames, and note it for the next attestation.
    public func seal(seq: UInt64, timestamp: UInt32, level: Int, voiceActive: Bool, afterDtx: Bool, opus: Data,
                     nowMs: Int64) throws -> Data {
        try lock.withLock {
            let flags = (voiceActive ? MediaFrame.flagVad : 0) | (afterDtx ? MediaFrame.flagDtx : 0)
            let frame = try MediaFrame.seal(senderKey: myKey, header: .init(flags: flags, routeId: routeId, ssrc: mySsrc,
                                                                            seq: seq, timestamp: timestamp, level: level,
                                                                            keyEpoch: myEpoch), payload: opus)
            let s = Int64(seq)
            if pendingFirst >= 0 {
                let gap = s - (pendingFirst + Int64(pending.count))
                // Unsent seqs get an all-zero digest; too many of them, or seq going
                // backwards, close this window and start a new one here.
                if gap < 0 || Int64(pending.count) + gap >= Int64(Attestation.maxCount) {
                    flush()
                } else {
                    pending.append(contentsOf: [Data?](repeating: nil, count: Int(gap)))
                }
            }
            if pendingFirst < 0 {
                pendingFirst = s
                pendingSinceMs = nowMs
            }
            pending.append(frame)
            return frame
        }
    }

    /// Attestations to send now, by NOTIFY (dataType 0): one each second (§5.1).
    public func takeAttestations(nowMs: Int64) -> [Data] {
        lock.withLock {
            if !pending.isEmpty && nowMs - pendingSinceMs >= CallMedia.attestEveryMs { flush() }
            defer { ready.removeAll() }
            return ready
        }
    }

    /// The final attestation, before leaving or hanging up.
    public func finish(nowMs: Int64) -> [Data] {
        lock.withLock {
            flush()
            defer { ready.removeAll() }
            return ready
        }
    }

    private func flush() {
        while let last = pending.last, last == nil { pending.removeLast() } // trailing unsent seqs claim nothing
        if !pending.isEmpty, let a = try? Attestation.sign(tPriv: tPriv, callOrMeetingId: callId, routeId: routeId,
                                                          ssrc: mySsrc, firstSeq: UInt64(pendingFirst), frames: pending) {
            ready.append(a.bytes)
        }
        pending.removeAll()
        pendingFirst = -1
    }

    // MARK: - Receiving

    public struct Opened: Sendable {
        public let header: MediaFrame.Header
        public let opus: Data
    }

    /// The frame to play, or nil: not a media frame, an unknown or silenced ssrc,
    /// a key epoch we hold no key for, failed authentication, a replay, or paused.
    /// `fromPeerConnection`: on the direct connection, which attributes it itself (§5.1).
    public func open(_ datagram: Data, nowMs: Int64, fromPeerConnection: Bool = false) -> Opened? {
        lock.withLock {
            guard let h = MediaFrame.Header.parse(datagram), let p = peers[h.ssrc], !p.unverified,
                  let key = p.keys[h.keyEpoch], let payload = MediaFrame.open(senderKey: key, frame: datagram),
                  p.window.accept(h.seq) else { return nil }
            if !fromPeerConnection {
                p.played[h.seq] = Played(digest: Attestation.digest(datagram), atMs: nowMs, heard: !p.paused)
            }
            return p.paused ? nil : Opened(header: h, opus: payload)
        }
    }

    /// A sender's attestation: signed by the roster's tPub for that ssrc, then every
    /// frame we played in its range must match. The signature check is outside the lock.
    public func onAttestation(_ bytes: Data, nowMs: Int64) {
        guard let a = Attestation.parse(bytes) else { return }
        let tPub: Data? = lock.withLock {
            guard let p = peers[a.ssrc], !p.unverified else { return nil }
            return p.tPub
        }
        guard let tPub, a.verify(tPub: tPub, callOrMeetingId: callId) else { return }
        var events: [(Peer, Bool?)] = [] // (peer, nil = unverified, true/false = paused)
        lock.withLock {
            guard let p = peers[a.ssrc], !p.unverified else { return }
            for seq in p.played.keys where seq >= a.firstSeq && seq <= a.lastSeq {
                let claimed = a.digests[Int(seq - a.firstSeq)]
                if claimed != p.played[seq]!.digest {
                    markUnverified(p)
                    events.append((p, nil))
                    return
                }
                p.played[seq] = nil // vouched for
            }
            if p.paused && !overdue(p, nowMs) {
                p.paused = false
                events.append((p, false))
            }
        }
        report(events)
    }

    /// About once a second: a meeting stream with a frame played 3 s ago and still unattested pauses.
    public func tick(nowMs: Int64) {
        var events: [(Peer, Bool?)] = []
        lock.withLock {
            if previousEpoch >= 0 && nowMs >= previousUntilMs { dropPreviousEpoch() }
            for p in peers.values where !p.unverified {
                if !oneToOne && !p.paused && overdue(p, nowMs) {
                    p.paused = true
                    events.append((p, true))
                }
                if p.paused {
                    p.played = p.played.filter { $0.value.heard || nowMs - $0.value.atMs <= CallMedia.keepHeldMs }
                } else {
                    p.played = p.played.filter { nowMs - $0.value.atMs <= CallMedia.keepPlayedMs }
                }
            }
        }
        report(events)
    }

    private func overdue(_ p: Peer, _ nowMs: Int64) -> Bool {
        p.played.values.contains { nowMs - $0.atMs >= CallMedia.attestDeadlineMs }
    }

    private func markUnverified(_ p: Peer) {
        p.unverified = true
        p.paused = false
        p.played.removeAll()
    }

    private func report(_ events: [(Peer, Bool?)]) {
        guard let l = listener else { return }
        for (p, e) in events {
            if let on = e { l.paused(fid: p.fid, ssrc: p.ssrc, on: on) } else { l.unverified(fid: p.fid, ssrc: p.ssrc) }
        }
    }

    public func isUnverified(ssrc: UInt32) -> Bool {
        lock.withLock { peers[ssrc]?.unverified ?? false }
    }

    public func isPaused(ssrc: UInt32) -> Bool {
        lock.withLock { peers[ssrc]?.paused ?? false }
    }
}
