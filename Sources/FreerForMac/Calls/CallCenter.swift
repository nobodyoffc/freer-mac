import Foundation
import AppKit
import AVFoundation
import FCCore
import FCDomain
import FCTransport

/// The Mac's one call at a time (VOICE_SPEC §10, §11.2), as `CallManager`
/// is on Android: places and answers calls, rings for incoming ones while
/// the app runs, runs the ``MacCallSession``, and gives the call view one
/// state to show. Everything the UI reads changes on the main actor.
@MainActor
@Observable
final class CallCenter {

    enum Phase: Equatable { case idle, calling, ringingIn, connecting, connected, ended }

    static let homeKey = ServiceName.call
    /// A relay to call through, and to answer on, before a CALL service is on chain: for testing.
    static let testRelayKey = "callTestRelay"
    /// Never try a direct path: the peer never learns this Mac's address (Decision 8).
    static let alwaysRelayKey = "callAlwaysRelay"

    private(set) var phase: Phase = .idle
    private(set) var peerFid: String?
    private(set) var connectedAtMs: Int64 = -1
    private(set) var endReason: String?
    private(set) var unverifiedFid: String?
    private(set) var relayHost: String?
    /// Audio goes on a direct path rather than the relay.
    private(set) var direct = false
    /// The call failed rather than ended: the card stays until closed, so the reason can be read.
    private(set) var failed = false
    var muted = false {
        didSet { callSession?.muted = muted }
    }

    @ObservationIgnored private var active: ActiveSession?
    @ObservationIgnored private var signaller: CallSignaller?
    @ObservationIgnored private var events: SignallerEvents?
    @ObservationIgnored private var call: CallSignaller.Call?
    @ObservationIgnored private var callSession: MacCallSession?
    @ObservationIgnored private var ticker: Task<Void, Never>?
    @ObservationIgnored private var ringtone: Task<Void, Never>?
    /// My own home.CALL, read by the signaller's thread for its relay policy.
    @ObservationIgnored private let ownCallRelay = LockedValue<String?>(nil)
    /// Where meeting messages go, set by ``MeetingCenter``; read on the courier's thread.
    @ObservationIgnored let meetingInbox = LockedValue<MeetingInbox?>(nil)
    /// A meeting is running or joining: one call or meeting at a time (§3.2).
    @ObservationIgnored let meetingBusy = LockedValue(false)
    /// An incoming call is about to ring.
    @ObservationIgnored var onIncoming: () -> Void = {}

    var alwaysRelay: Bool {
        get { UserDefaults.standard.bool(forKey: Self.alwaysRelayKey) }
        set { UserDefaults.standard.set(newValue, forKey: Self.alwaysRelayKey) }
    }

    var testRelay: String {
        get { UserDefaults.standard.string(forKey: Self.testRelayKey) ?? "" }
        set { UserDefaults.standard.set(newValue.trimmingCharacters(in: .whitespaces), forKey: Self.testRelayKey) }
    }

    // MARK: - Session

    /// An identity has loaded: calls for it can ring.
    func attach(_ session: ActiveSession) {
        detach()
        guard let fidPriv = try? session.livePrikey() else { return }
        active = session
        let s = CallSignaller(
            myFid: session.liveFid, fidPriv: fidPriv,
            outbox: { [weak session] fid, signal in try? session?.sendCallSignal(to: fid, json: signal.toJson()) },
            records: { [weak session] fid, record in try? session?.recordCall(peerFid: fid, record) },
            clock: { Int64(Date().timeIntervalSince1970 * 1000) })
        let own = ownCallRelay
        s.relayPolicy = { relay in
            guard let url = relay?.url else { return false }
            let test = UserDefaults.standard.string(forKey: CallCenter.testRelayKey) ?? ""
            if !test.isEmpty && FudpUrl.sameEndpoint(test, url) { return true }
            return FudpUrl.sameEndpoint(own.value, url) // my own home.CALL, and no other (§6.2)
        }
        let busy = meetingBusy
        s.alsoBusy = { busy.value }
        let ev = SignallerEvents(center: self)
        s.listener = ev
        events = ev
        signaller = s
        let meetings = meetingInbox
        session.callInbox.handler = { [weak session, weak s] message, liveFid in
            if meetings.value?.take(message) == true { return }
            guard let session, let s else {
                SystemLog.shared.warning(SystemSource.messages, "A CALL message arrived with no identity to take it")
                return
            }
            guard let sender = message.senderId, message.type == .p2p,
                  let content = message.content, let signal = CallSignal.fromJson(content) else {
                SystemLog.shared.warning(SystemSource.messages,
                    "A CALL message from \(CallCenter.short(message.senderId ?? "?")) was not understood",
                    detail: "type \(message.type.map { "\($0)" } ?? "?"), "
                        + (message.content.map { "content: \($0.prefix(200))" } ?? "still sealed"))
                return
            }
            let gate = session.callGate(sender: sender)
            SystemLog.shared.info(SystemSource.messages,
                "Call signal \(signal.op.rawValue) for call \(signal.callId) from \(CallCenter.short(sender)): \(gate)")
            switch gate {
            case .ring:
                s.onSignal(from: sender, messageId: message.id ?? UUID().uuidString, signal)
            case .missed where signal.op == .INVITE:
                // A stranger's call rings nowhere; it is a missed call to see (§3.2).
                try? session.recordCall(peerFid: sender, .init(kind: .MISSED, outgoing: false,
                    atMs: message.timestamp ?? Int64(Date().timeIntervalSince1970 * 1000), durationMs: 0, callId: signal.callId))
            default:
                break
            }
        }
        ticker = Task { [weak s] in
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 1_000_000_000)
                s?.tick()
            }
        }
        Task {
            own.value = await Self.callRelay(of: session.liveFid, in: session)
        }
    }

    func detach() {
        active?.callInbox.handler = nil
        ticker?.cancel()
        if let c = call { signaller?.hangup(callId: c.callId) }
        callSession?.end()
        signaller = nil
        active = nil
        reset()
        phase = .idle
    }

    // MARK: - Actions

    /// Ring `fid`: its home.CALL, and no other (§6.2); a test relay when set.
    func placeCall(to fid: String) {
        guard let session = active, let signaller, phase == .idle || phase == .ended else { return }
        reset()
        if meetingBusy.value {
            phase = .calling
            peerFid = fid
            finish("You are in a meeting.")
            return
        }
        phase = .calling
        peerFid = fid
        Task {
            let test = testRelay
            let url = test.isEmpty ? await Self.callRelay(of: fid, in: session) : test
            guard phase == .calling, call == nil else { return }
            guard let url, !url.isEmpty else {
                finish("\(Self.short(fid)) has no CALL service in their home, so they cannot be called.")
                return
            }
            guard await Self.microphoneAllowed() else {
                finish("Calls need the microphone. Allow it in System Settings → Privacy & Security.")
                return
            }
            // Calling someone accepts them, as writing to them does: their calls back must ring.
            session.chat.acceptPeer(fid, as: session.liveFid)
            do {
                let c = try signaller.prepare(peerFid: fid, relayUrl: url)
                call = c
                relayHost = Self.host(url)
                let cs = newSession(c)
                callSession = cs
                cs.startOutgoing()
            } catch {
                finish("You are already in a call.")
            }
        }
    }

    func answer() {
        guard phase == .ringingIn, let c = call, let signaller else { return }
        stopRinging()
        Task {
            guard await Self.microphoneAllowed() else {
                decline()
                finish("Calls need the microphone. Allow it in System Settings → Privacy & Security.")
                return
            }
            guard signaller.accept(callId: c.callId) != nil else { return }
            phase = .connecting
            let cs = newSession(c)
            callSession = cs
            cs.startIncoming()
        }
    }

    func decline() {
        if phase == .ringingIn, let c = call { signaller?.reject(callId: c.callId) }
    }

    /// Cancel an unanswered call, or hang up an answered one.
    func hangup() {
        guard let c = call, let signaller else {
            if phase == .calling { finish("Call ended") }
            return
        }
        switch phase {
        case .calling: signaller.cancel(callId: c.callId)
        case .ringingIn: signaller.reject(callId: c.callId)
        case .connecting, .connected: signaller.hangup(callId: c.callId)
        default: break
        }
    }

    func dismiss() {
        if phase == .ended { phase = .idle }
    }

    // MARK: - Signalling events

    fileprivate func incoming(_ c: CallSignaller.Call) {
        guard phase == .idle || phase == .ended else { return }
        reset()
        call = c
        peerFid = c.peerFid
        relayHost = c.relayUrl.map(Self.host)
        phase = .ringingIn
        onIncoming()
        ring()
    }

    fileprivate func answered(_ c: CallSignaller.Call) {
        guard call === c, let cs = callSession else { return }
        phase = .connecting
        cs.onAnswered()
    }

    fileprivate func ended(_ c: CallSignaller.Call, _ reason: CallSignaller.End) {
        guard call === c, phase != .ended else { return }
        finish(Self.describe(reason))
    }

    // MARK: - Internals

    private func newSession(_ c: CallSignaller.Call) -> MacCallSession {
        // A direct path shows each side's IP to the other: only with a contact,
        // and never with Always relay on (§6.1, Decision 8).
        let isContact = ((try? active?.contacts.get(fid: c.peerFid)) ?? nil) != nil
        return MacCallSession(call: c, signaller: signaller!, myFid: active?.liveFid ?? "",
                              allowDirect: isContact && !alwaysRelay, onState: { [weak self] state in
            Task { @MainActor in self?.sessionState(state, for: c) }
        }, onUnverified: { [weak self] fid in
            Task { @MainActor in self?.unverifiedFid = fid }
        }, onPath: { [weak self] direct in
            Task { @MainActor in if self?.call === c { self?.direct = direct } }
        })
    }

    private func sessionState(_ state: MacCallSession.State, for c: CallSignaller.Call) {
        guard call === c else { return }
        switch state {
        case .connected:
            phase = .connected
            connectedAtMs = Int64(Date().timeIntervalSince1970 * 1000)
        case .failed(let why):
            hangup() // the media path failed: end the call for the peer too
            SystemLog.shared.error(SystemSource.messages, "A call failed", detail: why)
            failed = true
            finish("The call failed: \(why)")
        default:
            break
        }
    }

    private func finish(_ reason: String) {
        stopRinging()
        callSession?.end()
        callSession = nil
        call = nil
        phase = .ended
        endReason = reason
    }

    private func reset() {
        call = nil
        callSession = nil
        connectedAtMs = -1
        endReason = nil
        failed = false
        unverifiedFid = nil
        relayHost = nil
        direct = false
        muted = false
    }

    /// Rings only while the app runs (§11.2): brings it forward and plays until answered.
    private func ring() {
        NSApp.activate(ignoringOtherApps: true)
        ringtone?.cancel()
        ringtone = Task {
            while !Task.isCancelled {
                NSSound(named: "Submarine")?.play()
                try? await Task.sleep(nanoseconds: 2_000_000_000)
            }
        }
    }

    private func stopRinging() {
        ringtone?.cancel()
        ringtone = nil
    }

    static func describe(_ reason: CallSignaller.End) -> String {
        switch reason {
        case .declined: return "Declined"
        case .busy: return "Busy"
        case .unsupported: return "Their app cannot take calls"
        case .wrongRelay: return "They answer only on their own CALL service"
        case .noAnswer: return "No answer"
        case .missed: return "Missed call"
        case .answeredElsewhere: return "Answered on another device"
        case .cancelled, .hungUp, .localHangup: return "Call ended"
        }
    }

    /// `fid`'s home.CALL, resolved to a URL; nil if it has none.
    static func callRelay(of fid: String, in session: ActiveSession) async -> String? {
        guard let freer = try? await DirectoryService(fapi: session.fapi).freer(byId: fid),
              let value = freer.home?[homeKey], !value.isEmpty else { return nil }
        return await session.homeServices.resolve(value)
    }

    static func microphoneAllowed() async -> Bool {
        switch AVCaptureDevice.authorizationStatus(for: .audio) {
        case .authorized: return true
        case .notDetermined: return await AVCaptureDevice.requestAccess(for: .audio)
        default: return false
        }
    }

    static func host(_ url: String) -> String {
        FudpUrl.hostPort(url).map { "\($0.host):\($0.port)" } ?? url
    }

    nonisolated static func short(_ fid: String) -> String {
        fid.count > 14 ? String(fid.prefix(6)) + "…" + String(fid.suffix(6)) : fid
    }
}

/// A value read and written from several threads.
final class LockedValue<T>: @unchecked Sendable {
    private let lock = NSLock()
    private var _value: T

    init(_ value: T) {
        _value = value
    }

    var value: T {
        get { lock.withLock { _value } }
        set { lock.withLock { _value = newValue } }
    }
}

/// The signaller calls its listener with its lock held: hop to the main actor.
private final class SignallerEvents: CallSignaller.Listener, @unchecked Sendable {
    weak var center: CallCenter?

    init(center: CallCenter) {
        self.center = center
    }

    func incoming(_ call: CallSignaller.Call) {
        Task { @MainActor [weak center] in center?.incoming(call) }
    }

    func answered(_ call: CallSignaller.Call) {
        Task { @MainActor [weak center] in center?.answered(call) }
    }

    func ended(_ call: CallSignaller.Call, _ reason: CallSignaller.End) {
        Task { @MainActor [weak center] in center?.ended(call, reason) }
    }
}
