import Foundation
import FCCore

/// Signalling for 1:1 calls on one device (VOICE_SPEC §3.2), a port of
/// Android's `CallSignaller`: the INVITE / ACCEPT / REJECT / CANCEL / HANGUP
/// state machine, each call's throwaway transport key and delegation, and the
/// local call records the chat shows.
///
/// No UI and no IM in here: signals go out through `outbox` and come in
/// through `onSignal`, after the IM layer has decoded them, checked the
/// FIMP signature and applied the stranger gate. Every method is serialized
/// on one lock; the listener is called with it held, so it must not block.
public final class CallSignaller: @unchecked Sendable {

    /// A delegation lasts this long: longer than any call, well inside the 24 h cap (§4.1).
    static let delegationSec: Int64 = 12 * 3600
    /// Message ids remembered for deduplication across channels (§6.3).
    static let seenLimit = 512

    public protocol Listener: AnyObject {
        /// Ring.
        func incoming(_ call: Call)
        /// The callee answered; `callSecret` now works on both sides.
        func answered(_ call: Call)
        /// The call is over, or never started.
        func ended(_ call: Call, _ reason: End)
    }

    public enum End: Equatable, Sendable {
        case declined, busy, unsupported, wrongRelay, cancelled, noAnswer, missed, answeredElsewhere, hungUp, localHangup
    }

    public enum State: Equatable, Sendable { case preparing, ringingOut, ringingIn, active, ended }

    /// What the chat shows for a call (§10).
    public struct CallRecord: Equatable, Sendable {
        public enum Kind: String, Sendable { case ENDED, MISSED, DECLINED, NO_ANSWER, BUSY, CANCELLED, ANSWERED_ELSEWHERE }
        public let kind: Kind
        public let outgoing: Bool
        public let atMs: Int64
        public let durationMs: Int64
        public let callId: String

        public init(kind: Kind, outgoing: Bool, atMs: Int64, durationMs: Int64, callId: String) {
            self.kind = kind
            self.outgoing = outgoing
            self.atMs = atMs
            self.durationMs = durationMs
            self.callId = callId
        }

        /// The record's JSON, as Android writes it into the chat.
        public var json: String {
            "{\"record\":\"\(kind.rawValue)\",\"outgoing\":\(outgoing),\"duration\":\(durationMs),\"callId\":\"\(callId)\"}"
        }
    }

    public final class Call: @unchecked Sendable {
        public let callId: String
        public let peerFid: String
        public let outgoing: Bool
        fileprivate var tPriv: Data
        public let tPub: Data
        public let myDelegation: Delegation
        public let relayUrl: String?
        public fileprivate(set) var relayPubkey: String?
        public fileprivate(set) var relaySid: String?
        fileprivate var peerTPub: Data?
        public fileprivate(set) var peerDelegation: Delegation?
        fileprivate var expiresMs: Int64 = .max
        fileprivate var answeredAtMs: Int64 = -1
        public fileprivate(set) var state: State

        fileprivate init(callId: String, peerFid: String, outgoing: Bool, tPriv: Data, delegation: Delegation,
                         relayUrl: String?, state: State) throws {
            self.callId = callId
            self.peerFid = peerFid
            self.outgoing = outgoing
            self.tPriv = tPriv
            self.tPub = try Secp256k1.publicKey(fromPrivateKey: tPriv)
            self.myDelegation = delegation
            self.relayUrl = relayUrl
            self.state = state
        }

        /// The transport key the call's link runs under (§4.1). Wiped when the call ends.
        public var transportPriv: Data { tPriv }
    }

    private let lock = NSLock()
    private let myFid: String
    private let fidPriv: Data
    private let outbox: (String, CallSignal) -> Void
    private let records: (String, CallRecord) -> Void
    private let clock: () -> Int64
    /// Which relays I answer on: my own home.CALL (§6.2). Anything, until set.
    public var relayPolicy: (CallSignal.Relay?) -> Bool = { _ in true }
    /// Busy for another reason, such as a meeting (§3.2).
    public var alsoBusy: () -> Bool = { false }
    private var calls: [String: Call] = [:]
    private var seen: [String] = []
    private var seenSet = Set<String>()
    public weak var listener: Listener?

    public init(myFid: String, fidPriv: Data, outbox: @escaping (String, CallSignal) -> Void,
                records: @escaping (String, CallRecord) -> Void, clock: @escaping () -> Int64) {
        self.myFid = myFid
        self.fidPriv = fidPriv
        self.outbox = outbox
        self.records = records
        self.clock = clock
    }

    // MARK: - Outgoing

    /// A call's keys and delegation, with nothing sent: the caller reaches its relay first.
    /// `relayPubkey` and `relaySid` are the callee's CALL service as named on chain, so the
    /// link takes no other relay at that address.
    public func prepare(peerFid: String, relayUrl: String?, relayPubkey: String? = nil,
                        relaySid: String? = nil) throws -> Call {
        try lock.withLock {
            guard !busyLocked(except: nil) else { throw CallKeys.Failure.badCallId }
            let now = clock()
            let callId = Hex.encode(Data((0..<16).map { _ in UInt8.random(in: 0...255) }))
            let tPriv = CallSignaller.newKey()
            let d = try Delegation.sign(fidPriv: fidPriv, callOrMeetingId: callId,
                                        tPub: try Secp256k1.publicKey(fromPrivateKey: tPriv),
                                        expiresSec: now / 1000 + CallSignaller.delegationSec)
            let c = try Call(callId: callId, peerFid: peerFid, outgoing: true, tPriv: tPriv, delegation: d,
                             relayUrl: relayUrl, state: .preparing)
            c.relayPubkey = relayPubkey
            c.relaySid = relaySid
            calls[callId] = c
            return c
        }
    }

    /// Send the INVITE of a prepared call; its 45 s ring starts now.
    public func ring(callId: String, relay: CallSignal.Relay?) {
        lock.withLock {
            guard let c = calls[callId], c.state == .preparing else { return }
            let now = clock()
            c.state = .ringingOut
            c.expiresMs = now + CallSignal.ringMs
            c.relayPubkey = relay?.pubkey
            c.relaySid = relay?.sid
            outbox(c.peerFid, CallSignal.invite(callId: callId, tPub: c.tPub, delegation: c.myDelegation, relay: relay,
                                                nowMs: now))
        }
    }

    public func cancel(callId: String) {
        lock.withLock {
            guard let c = calls[callId], c.outgoing, c.state == .ringingOut || c.state == .preparing else { return }
            if c.state == .ringingOut { outbox(c.peerFid, CallSignal.cancel(callId: callId, reason: CallSignal.cancelCancelled)) }
            end(c, .cancelled, .CANCELLED)
        }
    }

    // MARK: - Incoming

    @discardableResult
    public func accept(callId: String) -> Call? {
        lock.withLock {
            guard let c = calls[callId], !c.outgoing, c.state == .ringingIn else { return nil }
            c.state = .active
            c.answeredAtMs = clock()
            outbox(c.peerFid, CallSignal.accept(callId: callId, tPub: c.tPub, delegation: c.myDelegation))
            return c
        }
    }

    public func reject(callId: String) {
        lock.withLock {
            guard let c = calls[callId], !c.outgoing, c.state == .ringingIn else { return }
            outbox(c.peerFid, CallSignal.reject(callId: callId, reason: CallSignal.rejectDeclined))
            end(c, .declined, .DECLINED)
        }
    }

    public func hangup(callId: String) {
        lock.withLock {
            guard let c = calls[callId], c.state == .active else { return }
            outbox(c.peerFid, CallSignal.hangup(callId: callId, durationMs: clock() - c.answeredAtMs))
            end(c, .localHangup, .ENDED)
        }
    }

    /// The relay shows the ringing call settled without this device (§6.3).
    public func settledElsewhere(callId: String, answered: Bool) {
        lock.withLock {
            guard let c = calls[callId], !c.outgoing, c.state == .ringingIn else { return }
            if answered { end(c, .answeredElsewhere, .ANSWERED_ELSEWHERE) } else { end(c, .missed, .MISSED) }
        }
    }

    /// The peer left the relay and did not come back: it hung up.
    public func peerLeft(callId: String) {
        lock.withLock {
            guard let c = calls[callId], c.state == .active else { return }
            end(c, .hungUp, .ENDED)
        }
    }

    /// The relay says the callee is waiting to join, with the delegation it joined under (§6.2 step 3).
    public func onKnock(callId: String, delegation d: Delegation) {
        lock.withLock {
            guard let tPub = d.tPubBytes else { return }
            onAccept(d.fid, CallSignal.accept(callId: callId, tPub: tPub, delegation: d))
        }
    }

    // MARK: - Received

    /// A decoded, signature-checked CALL message from an accepted peer.
    public func onSignal(from senderFid: String, messageId: String, _ s: CallSignal) {
        lock.withLock {
            guard senderFid != myFid else { return }
            // The same signal arrives by several channels (§6.3).
            let key = senderFid + "|" + messageId
            guard !seenSet.contains(key) else { return }
            seenSet.insert(key)
            seen.append(key)
            if seen.count > CallSignaller.seenLimit { seenSet.remove(seen.removeFirst()) }
            switch s.op {
            case .INVITE: onInvite(senderFid, s)
            case .ACCEPT: onAccept(senderFid, s)
            case .REJECT: onReject(senderFid, s)
            case .CANCEL: onCancel(senderFid, s)
            case .HANGUP: onHangup(senderFid, s)
            }
        }
    }

    private func onInvite(_ caller: String, _ s: CallSignal) {
        guard calls[s.callId] == nil, delegationHolds(s, caller), let expires = s.expires else { return }
        let now = clock()
        // The DOCK copy of an INVITE usually arrives after it expired: a missed call, no ring.
        if expires <= now {
            records(caller, CallRecord(kind: .MISSED, outgoing: false, atMs: now, durationMs: 0, callId: s.callId))
            return
        }
        if !relayPolicy(s.relay) {
            outbox(caller, CallSignal.reject(callId: s.callId, reason: CallSignal.rejectRelay))
            records(caller, CallRecord(kind: .MISSED, outgoing: false, atMs: now, durationMs: 0, callId: s.callId))
            return
        }
        if busyLocked(except: s.callId) {
            outbox(caller, CallSignal.reject(callId: s.callId, reason: CallSignal.rejectBusy))
            records(caller, CallRecord(kind: .MISSED, outgoing: false, atMs: now, durationMs: 0, callId: s.callId))
            return
        }
        let tPriv = CallSignaller.newKey()
        guard let tPub = try? Secp256k1.publicKey(fromPrivateKey: tPriv),
              let mine = try? Delegation.sign(fidPriv: fidPriv, callOrMeetingId: s.callId, tPub: tPub,
                                              expiresSec: now / 1000 + CallSignaller.delegationSec),
              let c = try? Call(callId: s.callId, peerFid: caller, outgoing: false, tPriv: tPriv, delegation: mine,
                                relayUrl: s.relay?.url, state: .ringingIn) else { return }
        c.relayPubkey = s.relay?.pubkey
        c.relaySid = s.relay?.sid
        c.peerTPub = s.transportPubBytes
        c.peerDelegation = s.delegation
        c.expiresMs = expires
        calls[s.callId] = c
        listener?.incoming(c)
    }

    private func onAccept(_ callee: String, _ s: CallSignal) {
        guard let c = calls[s.callId], c.outgoing, c.state == .ringingOut, c.peerFid == callee,
              delegationHolds(s, callee) else { return }
        c.peerTPub = s.transportPubBytes
        c.peerDelegation = s.delegation
        c.state = .active
        c.answeredAtMs = clock()
        // The callee's other devices are still ringing.
        outbox(callee, CallSignal.cancel(callId: s.callId, reason: CallSignal.cancelAnsweredElsewhere))
        listener?.answered(c)
    }

    private func onReject(_ callee: String, _ s: CallSignal) {
        guard let c = calls[s.callId], c.outgoing, c.state == .ringingOut, c.peerFid == callee else { return }
        switch s.reason {
        case CallSignal.rejectBusy: end(c, .busy, .BUSY)
        case CallSignal.rejectUnsupported: end(c, .unsupported, .DECLINED)
        case CallSignal.rejectRelay: end(c, .wrongRelay, .NO_ANSWER)
        default: end(c, .declined, .DECLINED)
        }
    }

    private func onCancel(_ caller: String, _ s: CallSignal) {
        guard let c = calls[s.callId], !c.outgoing, c.peerFid == caller, c.state == .ringingIn else { return }
        if s.reason == CallSignal.cancelAnsweredElsewhere { end(c, .answeredElsewhere, .ANSWERED_ELSEWHERE) } else { end(c, .missed, .MISSED) }
    }

    private func onHangup(_ peer: String, _ s: CallSignal) {
        guard let c = calls[s.callId], c.state == .active, c.peerFid == peer else { return }
        end(c, .hungUp, .ENDED)
    }

    /// About once a second: an unanswered INVITE expires after 45 s on both sides.
    public func tick() {
        lock.withLock {
            let now = clock()
            for c in calls.values {
                if c.state == .ringingOut && now >= c.expiresMs {
                    outbox(c.peerFid, CallSignal.cancel(callId: c.callId, reason: CallSignal.cancelTimeout))
                    end(c, .noAnswer, .NO_ANSWER)
                } else if c.state == .ringingIn && now >= c.expiresMs {
                    end(c, .missed, .MISSED)
                }
            }
            calls = calls.filter { $0.value.state != .ended }
        }
    }

    // MARK: - Keys (§4.2)

    /// The call's forward-secret key, once both transport keys are known.
    public func callSecret(callId: String) -> Data? {
        lock.withLock {
            guard let c = calls[callId], let peer = c.peerTPub, c.state != .ended else { return nil }
            return try? CallKeys.p2pSecret(tPrivSelf: c.tPriv, tPubPeer: peer, callIdHex: callId, fidA: myFid, fidB: c.peerFid)
        }
    }

    public func call(_ callId: String) -> Call? {
        lock.withLock { calls[callId] }
    }

    public func busy(except: String?) -> Bool {
        lock.withLock { busyLocked(except: except) }
    }

    private func busyLocked(except: String?) -> Bool {
        if alsoBusy() { return true }
        return calls.values.contains { $0.state != .ended && $0.callId != except }
    }

    // MARK: - Helpers

    /// The signal's delegation is from `fid`, for this call, for the transport key it names (§4.1).
    private func delegationHolds(_ s: CallSignal, _ fid: String) -> Bool {
        guard let d = s.delegation, d.fid == fid, let named = s.transportPubBytes else { return false }
        return d.verify(callOrMeetingId: s.callId, nowSec: clock() / 1000) == .ok && d.tPubBytes == named
    }

    private func end(_ c: Call, _ reason: End, _ kind: CallRecord.Kind) {
        let now = clock()
        let duration = c.answeredAtMs >= 0 ? now - c.answeredAtMs : 0
        c.state = .ended
        c.tPriv = Data(count: c.tPriv.count) // §4.1: gone at hang-up; this is what makes 1:1 forward secret
        records(c.peerFid, CallRecord(kind: kind, outgoing: c.outgoing, atMs: now, durationMs: duration, callId: c.callId))
        listener?.ended(c, reason)
    }

    private static func newKey() -> Data {
        Data((0..<32).map { _ in UInt8.random(in: 0...255) })
    }
}
