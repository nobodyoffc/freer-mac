import Foundation
import FCCore
import FCDomain

/// The Mac's one meeting at a time (VOICE_SPEC §8, §10), as `MeetingManager`
/// is on Android: starts and joins meetings in Rooms and Teams, keeps the
/// ``MeetingBoard`` the chat's cards come from, runs the
/// ``MacMeetingSession``, and gives the meeting view one state to show. A
/// meeting and a 1:1 call never run at once. Everything the UI reads changes
/// on the main actor.
@MainActor
@Observable
final class MeetingCenter {

    enum Phase: Equatable { case idle, connecting, inMeeting, ended }

    /// A member's MEETING_END is checked with the relay after the relay would have closed an empty meeting (§7.6).
    static let confirmEndAfterNs: UInt64 = 70_000_000_000

    private(set) var phase: Phase = .idle
    private(set) var meeting: MeetingBoard.Meeting?
    private(set) var endReason: String?
    /// The meeting's Room or Team name.
    private(set) var entityName: String?
    /// Bumped whenever the session's state changes: the view redraws from the session.
    private(set) var revision = 0
    /// Bumped when a card opened, changed or ended: the chat reloads.
    private(set) var cardsRevision = 0
    /// Shown by the meeting view until closed.
    var visible = false

    @ObservationIgnored private(set) var session: MacMeetingSession?
    @ObservationIgnored private(set) var board: MeetingBoard?
    @ObservationIgnored private var active: ActiveSession?
    @ObservationIgnored private var endForAllRequested = false
    @ObservationIgnored private let calls: CallCenter
    /// Keep a meeting's DOCKs on the fast lane while it runs; nil, nil when it ends.
    @ObservationIgnored var meetingDocks: (ImType?, String?) -> Void = { _, _ in }

    init(calls: CallCenter) {
        self.calls = calls
    }

    var isActive: Bool { phase == .connecting || phase == .inMeeting }
    var myFid: String? { active?.liveFid }

    /// The meeting's title, or its Room or Team's name.
    var title: String {
        guard let m = meeting else { return "" }
        if let t = m.title, !t.isEmpty { return t }
        return entityName ?? m.entityId
    }

    var relayHost: String? { meeting.map { CallCenter.host($0.relay.url) } }

    // MARK: - Session

    /// An identity has loaded: its meetings' cards can come in.
    func attach(_ s: ActiveSession) {
        detach()
        active = s
        let b = s.meetingBoard()
        board = b
        calls.meetingInbox.value = MeetingInbox(session: s, board: b, center: self)
        cardsRevision += 1
    }

    func detach() {
        calls.meetingInbox.value = nil
        session?.leave(endForAll: false)
        session = nil
        active = nil
        board = nil
        setPhase(.idle)
    }

    // MARK: - Actions

    /// Start a meeting in a Room or Team (§8): the entity's newest symkey, or,
    /// with `invitees`, a key of the meeting's own that only they get (Decision
    /// 20); `call.create` and join on the relay, then the card. Returns why it
    /// cannot start, or nil once connecting.
    func start(type: ImType, entityId: String, title: String?, invitees: [String]?) async -> String? {
        if let busy = busyReason() { return busy }
        guard let s = active, let fidPriv = try? s.livePrikey() else { return "This identity cannot sign, so it cannot hold meetings." }
        setPhase(.connecting)
        endReason = nil
        guard let relayUrl = await relay(for: type, entityId: entityId, in: s), !relayUrl.isEmpty else {
            setPhase(.idle)
            return "Neither this chat nor you have a CALL service in your home, so there is no relay to meet on."
        }
        guard await CallCenter.microphoneAllowed() else {
            setPhase(.idle)
            return "Meetings need the microphone. Allow it in System Settings → Privacy & Security."
        }
        guard phase == .connecting, session == nil else { return nil }
        let version = s.meetingSymkeyVersion(entityId: entityId)
        let held = version == 0 ? [] : s.meetingSymkeys(entityId: entityId, version: version)
        if invitees == nil && held.isEmpty {
            setPhase(.idle)
            return "This device has no key for this chat yet, so it cannot start a meeting in it."
        }
        let meetingId = MeetingSignal.idPrefix + Hex.encode(MeetingCenter.random(12))
        let nonce = MeetingCenter.random(32)
        let keyVersion: UInt64
        let secret: Data
        do {
            if invitees != nil {
                // Its own key, stored as the symkey of an entity named by the meeting (§4.2).
                keyVersion = MeetingSignal.invitedVersion
                let key = MeetingCenter.random(32)
                try s.storeMeetingKey(key, keyEntity: meetingId, version: keyVersion)
                secret = try CallKeys.meetingSecret(symkey: key, nonce: nonce, entityId: meetingId,
                                                    symkeyVersion: keyVersion, meetingId: meetingId)
            } else {
                keyVersion = version
                secret = try CallKeys.meetingSecret(symkey: held[0], nonce: nonce, entityId: entityId,
                                                    symkeyVersion: version, meetingId: meetingId)
            }
        } catch {
            setPhase(.idle)
            return "Could not make the meeting's key: \(error)"
        }
        guard let authPub = try? CallKeys.authPub(authPriv: CallKeys.authPriv(callSecret: secret)) else {
            setPhase(.idle)
            return "Could not make the meeting's key."
        }
        let m = MeetingBoard.Meeting(
            meetingId: meetingId, entityId: entityId, entityType: type == .team ? "TEAM" : "ROOM", hostFid: s.liveFid,
            relay: .init(url: relayUrl), title: (title?.isEmpty ?? true) ? nil : title,
            started: MacMeetingSession.nowMs(),
            keys: [.init(nonce: Hex.encode(nonce), symkeyVersion: keyVersion, authPub: Hex.encode(authPub), keyEpoch: 0)],
            invited: invitees != nil, invitees: invitees ?? [])
        run(m, creating: true, fidPriv: fidPriv)
        return nil
    }

    /// Join a meeting from its card. Returns why not, or nil once connecting.
    func join(meetingId: String) async -> String? {
        guard let m = board?.get(meetingId) else { return "This device does not know that meeting." }
        if isActive, meeting?.meetingId == meetingId {
            visible = true // already in it: just show it
            return nil
        }
        if m.ended { return "The meeting is over." }
        if let busy = busyReason() { return busy }
        guard let s = active, let fidPriv = try? s.livePrikey() else { return "This identity cannot sign, so it cannot join meetings." }
        guard await CallCenter.microphoneAllowed() else {
            return "Meetings need the microphone. Allow it in System Settings → Privacy & Security."
        }
        guard !isActive else { return busyReason() }
        run(m, creating: false, fidPriv: fidPriv)
        return nil
    }

    func leave() {
        if let session {
            session.leave(endForAll: false)
        } else if phase == .connecting {
            setPhase(.idle) // still finding the relay: nothing to leave yet
        }
    }

    /// Host only: close the meeting for everyone, and say so in the chat (§8).
    func endForAll() {
        guard let session, session.isHost else { return }
        endForAllRequested = true
        session.leave(endForAll: true)
    }

    func setMuted(_ muted: Bool) {
        session?.setMuted(muted)
        revision += 1
    }

    func setHand(_ raised: Bool) {
        session?.setHand(raised)
        revision += 1
    }

    /// A host control; `done` gets nil or the relay's refusal, on the main actor.
    func control(_ action: String, target: Any?, done: @escaping @MainActor (String?) -> Void) {
        session?.control(action, target: target) { error in
            Task { @MainActor in done(error) }
        }
    }

    func close() {
        visible = false
        if phase == .ended { setPhase(.idle) }
    }

    /// Host of a chosen-people meeting: invite more members to it (Decision 20).
    func invite(_ fids: [String]) {
        guard var m = meeting, m.invited, let s = session, s.isHost else { return }
        let fresh = fids.filter { !m.invitees.contains($0) }
        guard !fresh.isEmpty else { return }
        m.invitees += fresh
        meeting = m
        board?.put(m)
        sendInvites(m, to: fresh)
    }

    /// Members of the meeting's Room or Team not yet invited, for the picker.
    func invitable() -> [String] {
        guard let m = meeting, let s = active, let type = ActiveSession.meetingImType(m.entityType) else { return [] }
        return s.entityMembers(type: type, entityId: m.entityId).filter { $0 != s.liveFid && !m.invitees.contains($0) }
    }

    // MARK: - From the inbox

    fileprivate func cardsChanged() {
        cardsRevision += 1
    }

    /// Another member says a meeting ended: believe it only once its relay
    /// no longer knows it, after it would have closed an empty meeting.
    fileprivate func confirmEndLater(_ meetingId: String) {
        Task { [weak self] in
            try? await Task.sleep(nanoseconds: MeetingCenter.confirmEndAfterNs)
            guard let self, let b = self.board, let m = b.get(meetingId), !m.ended else { return }
            if await MeetingCenter.probeOpen(m) == false, b.markEnded(meetingId, durationMs: 0) { self.cardsRevision += 1 }
        }
    }

    /// `call.info` on a throwaway key (§7.2): open, or nil if the relay could not be asked.
    private static func probeOpen(_ m: MeetingBoard.Meeting) async -> Bool? {
        final class Deaf: CallRelayLink.Events {
            func frame(_ datagram: Data) {}
            func attestation(_ bytes: Data) {}
            func notice(_ notice: [String: Any]) {}
        }
        let deaf = Deaf()
        let l = CallRelayLink(tPriv: random(32), callId: m.meetingId, delegation: nil, events: deaf)
        defer { l.close() }
        do {
            try await l.connect(url: m.relay.url, pubkeyHex: m.relay.pubkey, sid: m.relay.sid)
            return try await l.info()["open"] as? Bool == true
        } catch {
            return nil
        }
    }

    // MARK: - Internals

    /// Why a meeting cannot start or be joined now, or nil.
    private func busyReason() -> String? {
        if isActive { return "You are already in a meeting." }
        if calls.phase != .idle && calls.phase != .ended { return "You are in a call." }
        return nil
    }

    private func setPhase(_ p: Phase) {
        phase = p
        calls.meetingBusy.value = isActive
        revision += 1
    }

    private func run(_ m: MeetingBoard.Meeting, creating: Bool, fidPriv: Data) {
        guard let s = active else { return }
        meeting = m
        entityName = ActiveSession.meetingImType(m.entityType).flatMap { s.entityName(type: $0, entityId: m.entityId) }
        endReason = nil
        endForAllRequested = false
        let keys = MacMeetingSession.Keys(
            symkeys: { [weak s] entity, version in s?.meetingSymkeys(entityId: entity, version: version) ?? [] },
            currentVersion: { [weak s] entity in s?.meetingSymkeyVersion(entityId: entity) ?? 0 },
            // The host holds whatever the meeting is keyed with; the owner holds every version.
            request: { [weak s] entity, version in
                guard let s else { return }
                s.requestMeetingSymkey(entityId: entity, version: version, from: m.hostFid)
            })
        let events = SessionEvents(center: self, meetingId: m.meetingId, creating: creating)
        let ms = MacMeetingSession(meeting: m, myFid: s.liveFid, fidPriv: fidPriv, creating: creating, keys: keys,
                                   listener: events)
        sessionEvents = events
        session = ms
        visible = true
        setPhase(.connecting)
        if let type = ActiveSession.meetingImType(m.entityType) { meetingDocks(type, m.entityId) }
        ms.start()
    }

    @ObservationIgnored private var sessionEvents: SessionEvents?

    fileprivate func joined(_ meetingId: String, creating: Bool) {
        guard let s = session, s.meetingId == meetingId, var m = meeting else { return }
        setPhase(.inMeeting)
        guard creating, let active else { return }
        // The card, once the meeting is open on the relay: with its key and service id, to spare joiners discovery.
        if let pub = s.relayPubkey { m.relay = .init(url: m.relay.url, pubkey: pub, sid: s.relaySid) }
        meeting = m
        board?.put(m)
        guard let type = ActiveSession.meetingImType(m.entityType), let k = m.newestKeys,
              let nonce = Hex.decodeOrNil(k.nonce), let authPub = Hex.decodeOrNil(k.authPub) else { return }
        if m.invited {
            // Only the chosen: each gets the key in an invitation sealed to them alone (Decision 20).
            sendInvites(m, to: m.invitees)
            if let inv = invitation(m) {
                try? active.storeMeetingCard(type: type, entityId: m.entityId, hostFid: active.liveFid, card: inv.withoutKey)
            }
        } else {
            let start = MeetingSignal.start(meetingId: m.meetingId, relay: m.relay, nonce: nonce, symkeyVersion: k.symkeyVersion,
                                            authPub: authPub, keyEpoch: k.keyEpoch, title: m.title, startedMs: m.started)
            _ = board?.onStart(entityId: m.entityId, entityType: m.entityType, senderFid: active.liveFid, start)
            do {
                try active.postMeetingSignal(type: type, entityId: m.entityId, start)
            } catch {
                SystemLog.shared.error(SystemSource.messages, "Could not post the meeting's card", detail: "\(error)")
            }
        }
        cardsRevision += 1
    }

    fileprivate func rekeyed(_ meetingId: String, _ update: MeetingSignal) {
        guard let m = meeting, m.meetingId == meetingId, let active,
              let type = ActiveSession.meetingImType(m.entityType) else { return }
        // Late joiners need the new keys (§3.3); the board takes them as any member's post.
        _ = board?.onStart(entityId: m.entityId, entityType: m.entityType, senderFid: active.liveFid, update)
        try? active.postMeetingSignal(type: type, entityId: m.entityId, update)
    }

    fileprivate func ended(_ meetingId: String, _ why: MacMeetingSession.End, _ detail: String?) {
        guard let m = meeting, m.meetingId == meetingId else { return }
        let joinedAt = session?.joinedAtMs ?? -1
        let duration = joinedAt > 0 ? MacMeetingSession.nowMs() - joinedAt : 0
        if why == .endedByHost || why == .gone {
            board?.markEnded(m.meetingId, durationMs: duration)
            // The host who closed it says so; members learn it from there (§8).
            if endForAllRequested, let active, let type = ActiveSession.meetingImType(m.entityType) {
                var end = MeetingSignal.end(meetingId: m.meetingId, durationMs: duration)
                if m.invited {
                    end.entityId = m.entityId
                    end.entityType = m.entityType
                    for fid in m.invitees where fid != active.liveFid { try? active.sendMeetingDirect(to: fid, end) }
                } else {
                    try? active.postMeetingSignal(type: type, entityId: m.entityId, end)
                }
            }
            if m.invited { active?.forgetMeetingKey(keyEntity: m.meetingId) } // over: its key has no further use
            cardsRevision += 1
        }
        session = nil
        sessionEvents = nil
        meetingDocks(nil, nil)
        endReason = switch why {
        case .left: "You left the meeting."
        case .endedByHost, .gone: "The meeting is over."
        case .kicked: "The host removed you from the meeting."
        case .noKey: "This device lacks the meeting's key; it has asked for it. Try again in a moment."
        case .balance: "The host's balance on the relay ran out."
        case .failed: "The meeting failed: \(detail ?? "")"
        }
        if why == .failed { SystemLog.shared.error(SystemSource.messages, "A meeting failed", detail: detail ?? "") }
        setPhase(.ended)
    }

    fileprivate func changed() {
        revision += 1
    }

    /// The invitation, with the key read back from where it is kept; nil if this device lacks it.
    private func invitation(_ m: MeetingBoard.Meeting) -> MeetingSignal? {
        guard let s = active, let k = m.newestKeys, let nonce = Hex.decodeOrNil(k.nonce),
              let authPub = Hex.decodeOrNil(k.authPub),
              let key = s.meetingSymkeys(entityId: m.meetingId, version: MeetingSignal.invitedVersion).first else { return nil }
        return MeetingSignal.invite(meetingId: m.meetingId, entityId: m.entityId, entityType: m.entityType, relay: m.relay,
                                    nonce: nonce, authPub: authPub, key: key, title: m.title, startedMs: m.started)
    }

    private func sendInvites(_ m: MeetingBoard.Meeting, to fids: [String]) {
        guard let s = active, let inv = invitation(m) else { return }
        for fid in fids where fid != s.liveFid {
            do {
                try s.sendMeetingDirect(to: fid, inv)
            } catch {
                SystemLog.shared.warning(SystemSource.messages, "Could not invite \(CallCenter.short(fid)) to the meeting",
                                         detail: "\(error)")
            }
        }
    }

    /// The entity's home.CALL, else my own (§8); the test relay wins, as for 1:1 calls.
    private func relay(for type: ImType, entityId: String, in s: ActiveSession) async -> String? {
        let test = calls.testRelay
        if !test.isEmpty { return test }
        if let value = s.entityHome(type: type, entityId: entityId)?[CallCenter.homeKey], !value.isEmpty,
           let url = await s.homeServices.resolve(value) {
            return url
        }
        return await CallCenter.callRelay(of: s.liveFid, in: s)
    }

    static func random(_ n: Int) -> Data {
        Data((0..<n).map { _ in UInt8.random(in: 0...255) })
    }
}

/// The session's listener, from its own tasks: hop to the main actor.
private final class SessionEvents: MacMeetingSession.Listener, @unchecked Sendable {
    weak var center: MeetingCenter?
    let meetingId: String
    let creating: Bool

    init(center: MeetingCenter, meetingId: String, creating: Bool) {
        self.center = center
        self.meetingId = meetingId
        self.creating = creating
    }

    func joined() {
        Task { @MainActor [weak center, meetingId, creating] in center?.joined(meetingId, creating: creating) }
    }

    func changed() {
        Task { @MainActor [weak center] in center?.changed() }
    }

    func rekeyed(_ update: MeetingSignal) {
        Task { @MainActor [weak center, meetingId] in center?.rekeyed(meetingId, update) }
    }

    func ended(_ why: MacMeetingSession.End, _ detail: String?) {
        Task { @MainActor [weak center, meetingId] in center?.ended(meetingId, why, detail) }
    }
}

/// Meeting messages from the courier, on its thread (VOICE_SPEC §3.3,
/// Decision 20): a Room or Team chat's cards and ends, and 1:1 invitations
/// to chosen-people meetings and their ends. Only a member's count.
final class MeetingInbox: @unchecked Sendable {
    private let session: ActiveSession
    private let board: MeetingBoard
    private weak var center: MeetingCenter?

    init(session: ActiveSession, board: MeetingBoard, center: MeetingCenter) {
        self.session = session
        self.board = board
        self.center = center
    }

    /// True if `message` was about a meeting, whatever came of it.
    func take(_ message: ImMessage) -> Bool {
        guard let content = message.content, let s = MeetingSignal.fromJson(content),
              let sender = message.senderId else { return false }
        switch message.type {
        case .room?, .team?:
            chat(message, s, sender: sender)
            return true
        case .p2p? where s.entityId != nil:
            if sender != session.liveFid { direct(message, s, sender: sender) }
            return true
        default:
            return false
        }
    }

    /// A meeting signal in a Room or Team chat, opened with its symkey. A new
    /// meeting's MEETING_START becomes its card; everything else changes the card.
    private func chat(_ message: ImMessage, _ s: MeetingSignal, sender: String) {
        guard let type = message.type, let entityId = message.targetId else { return }
        guard session.isEntityMember(type: type, entityId: entityId, fid: sender) else {
            log("Meeting signal \(s.op.rawValue) in \(CallCenter.short(entityId)) from \(CallCenter.short(sender)), who is not a member: dropped")
            return
        }
        let entityType = type == .team ? "TEAM" : "ROOM"
        let r: MeetingBoard.Result
        switch s.op {
        case .MEETING_START: r = board.onStart(entityId: entityId, entityType: entityType, senderFid: sender, s)
        case .MEETING_END: r = board.onEnd(entityId: entityId, senderFid: sender, s)
        case .MEETING_INVITE: r = .unchanged // only ever 1:1
        }
        log("Meeting signal \(s.op.rawValue) for \(s.meetingId) in \(CallCenter.short(entityId)) from \(CallCenter.short(sender)): \(r)")
        if r == .new && !ActiveSession.isMeetingControl(s) { try? session.fileMeetingCard(message) }
        notify(r, meetingId: s.meetingId)
    }

    /// A 1:1 invitation to a chosen-people meeting, or its end. It counts only
    /// from a member of the Room or Team it names, and only if this identity
    /// is one too. The key goes into the symkey store; the card only into this
    /// device's copy of the chat.
    private func direct(_ message: ImMessage, _ s: MeetingSignal, sender: String) {
        guard session.callGate(sender: sender) != .drop,
              let entityId = s.entityId, let type = s.entityType.flatMap(ActiveSession.meetingImType) else { return }
        guard session.isEntityMember(type: type, entityId: entityId, fid: sender),
              session.isEntityMember(type: type, entityId: entityId, fid: session.liveFid) else {
            log("Meeting \(s.op.rawValue) for \(CallCenter.short(entityId)) from \(CallCenter.short(sender)): not both members; dropped")
            return
        }
        if s.op == .MEETING_INVITE {
            guard let key = s.keyBytes,
                  (try? session.storeMeetingKey(key, keyEntity: s.meetingId,
                                                version: s.symkeyVersion ?? MeetingSignal.invitedVersion)) != nil else { return }
        }
        let r = s.op == .MEETING_INVITE ? board.onInvite(hostFid: sender, s) : board.onEnd(entityId: entityId, senderFid: sender, s)
        if s.op == .MEETING_END && r == .updated { session.forgetMeetingKey(keyEntity: s.meetingId) }
        log("Meeting \(s.op.rawValue) for \(s.meetingId) in \(CallCenter.short(entityId)) from \(CallCenter.short(sender)): \(r)")
        if s.op == .MEETING_INVITE && r == .new {
            try? session.storeMeetingCard(type: type, entityId: entityId, hostFid: sender, card: s.withoutKey,
                                          timestampMs: message.timestamp)
        }
        notify(r, meetingId: s.meetingId)
    }

    private func notify(_ r: MeetingBoard.Result, meetingId: String) {
        switch r {
        case .new, .updated: Task { @MainActor [weak center] in center?.cardsChanged() }
        case .confirm: Task { @MainActor [weak center] in center?.confirmEndLater(meetingId) }
        case .unchanged: break
        }
    }

    private func log(_ line: String) {
        SystemLog.shared.info(SystemSource.messages, line)
    }
}
