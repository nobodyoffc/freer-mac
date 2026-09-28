import Foundation
import FCCore

/// What this identity knows of the meetings in its Rooms and Teams (VOICE_SPEC
/// §3.3), a port of Android's `MeetingBoard`: who started each, where it
/// runs, the key sets its host has posted, and whether it has ended. The
/// chat shows one card per meeting from it, and joining reads the keys from it.
///
/// A host that rekeys posts `MEETING_START` again with a higher `keyEpoch`;
/// each is kept, newest first, so a late joiner can still prove the key.
/// Updates are taken from any member, since the host role can pass on; one
/// that does not work only costs the joiner a failed attempt.
///
/// Persists through the `load` and `save` it is given. Thread-safe.
public final class MeetingBoard: @unchecked Sendable {

    /// Meetings remembered; the oldest are forgotten past this.
    static let limit = 200

    /// One key set of a meeting (§4.2): what a member derives the call secret from.
    public struct Keys: Codable, Sendable, Equatable {
        public var nonce: String
        public var symkeyVersion: UInt64
        public var authPub: String
        public var keyEpoch: Int64

        public init(nonce: String, symkeyVersion: UInt64, authPub: String, keyEpoch: Int64) {
            self.nonce = nonce
            self.symkeyVersion = symkeyVersion
            self.authPub = authPub
            self.keyEpoch = keyEpoch
        }
    }

    public struct Meeting: Codable, Sendable, Equatable {
        public var meetingId: String
        public var entityId: String
        /// TEAM or ROOM.
        public var entityType: String
        public var hostFid: String
        public var relay: CallSignal.Relay
        public var title: String?
        public var started: Int64
        /// Newest key epoch first.
        public var keys: [Keys]
        public var ended = false
        public var duration: Int64 = 0
        /// Only chosen people (Decision 20): keyed by its own random key, not the entity's symkey.
        public var invited = false
        /// Whom the host invited, for its own board.
        public var invitees: [String] = []

        public init(meetingId: String, entityId: String, entityType: String, hostFid: String, relay: CallSignal.Relay,
                    title: String?, started: Int64, keys: [Keys], invited: Bool = false, invitees: [String] = []) {
            self.meetingId = meetingId
            self.entityId = entityId
            self.entityType = entityType
            self.hostFid = hostFid
            self.relay = relay
            self.title = title
            self.started = started
            self.keys = keys
            self.invited = invited
            self.invitees = invitees
        }

        public var newestKeys: Keys? { keys.first }

        /// Whose symkey the call secret comes from: the Room or Team, or, for a
        /// chosen-people meeting, the pseudo-entity its meetingId names (§4.2).
        public var keyEntity: String { invited ? meetingId : entityId }
    }

    public enum Result: Sendable, Equatable {
        /// A meeting not seen before: show its card.
        case new
        /// Known, and this changed it: redraw the card.
        case updated
        /// Nothing new.
        case unchanged
        /// A MEETING_END from someone other than its host: ask the relay before believing it.
        case confirm
    }

    private let lock = NSLock()
    private let saveData: (Data) -> Void
    private var meetings: [String: Meeting] = [:]

    public init(load: () -> Data?, save: @escaping (Data) -> Void) {
        saveData = save
        // An unreadable board is an empty one: the chat still has the messages.
        if let data = load(), let saved = try? JSONDecoder().decode([String: Meeting].self, from: data) {
            meetings = saved
        }
    }

    public func get(_ meetingId: String?) -> Meeting? {
        guard let meetingId else { return nil }
        return lock.withLock { meetings[meetingId] }
    }

    public func isEnded(_ meetingId: String) -> Bool {
        get(meetingId)?.ended == true
    }

    /// Open meetings of one Room or Team, newest first.
    public func open(entityId: String) -> [Meeting] {
        lock.withLock { meetings.values.filter { !$0.ended && $0.entityId == entityId } }
            .sorted { $0.started > $1.started }
    }

    /// A `MEETING_START` from `senderFid`, a member of the entity: the caller
    /// has checked that, as FIMP requires (§3.3).
    public func onStart(entityId: String, entityType: String, senderFid: String, _ s: MeetingSignal) -> Result {
        guard s.op == .MEETING_START, let relay = s.relay, let nonce = s.nonce, let authPub = s.authPub,
              let version = s.symkeyVersion else { return .unchanged }
        let k = Keys(nonce: nonce, symkeyVersion: version, authPub: authPub, keyEpoch: s.keyEpochOrZero)
        return lock.withLock {
            guard var m = meetings[s.meetingId] else {
                meetings[s.meetingId] = Meeting(meetingId: s.meetingId, entityId: entityId, entityType: entityType,
                                                hostFid: senderFid, relay: relay, title: s.title, started: s.started ?? 0,
                                                keys: [k])
                trimLocked()
                saveLocked()
                return .new
            }
            // The same meeting id in another entity is not this meeting.
            guard m.entityId == entityId, !m.keys.contains(where: { $0.authPub == k.authPub }) else { return .unchanged }
            m.keys.append(k)
            m.keys.sort { $0.keyEpoch > $1.keyEpoch }
            meetings[s.meetingId] = m
            saveLocked()
            return .updated
        }
    }

    /// A `MEETING_INVITE` to a chosen-people meeting (Decision 20), from
    /// `hostFid`, a member of the entity: the caller has checked that and
    /// stored the key. The card it makes is only on this device.
    public func onInvite(hostFid: String, _ s: MeetingSignal) -> Result {
        guard s.op == .MEETING_INVITE, let relay = s.relay, let nonce = s.nonce, let authPub = s.authPub,
              let entityId = s.entityId, let entityType = s.entityType else { return .unchanged }
        return lock.withLock {
            guard meetings[s.meetingId] == nil else { return .unchanged }
            meetings[s.meetingId] = Meeting(
                meetingId: s.meetingId, entityId: entityId, entityType: entityType, hostFid: hostFid, relay: relay,
                title: s.title, started: s.started ?? 0,
                keys: [Keys(nonce: nonce, symkeyVersion: s.symkeyVersion ?? MeetingSignal.invitedVersion,
                            authPub: authPub, keyEpoch: 0)],
                invited: true)
            trimLocked()
            saveLocked()
            return .new
        }
    }

    /// Put a meeting this device hosts: a new one, or its relay or invitees changed.
    public func put(_ m: Meeting) {
        lock.withLock {
            meetings[m.meetingId] = m
            trimLocked()
            saveLocked()
        }
    }

    /// A `MEETING_END`: from the host who started it, the meeting is over;
    /// from anyone else, only once the relay confirms it (§3.3).
    public func onEnd(entityId: String?, senderFid: String, _ s: MeetingSignal) -> Result {
        let verdict: Result? = lock.withLock {
            guard let m = meetings[s.meetingId], !m.ended, m.entityId == entityId else { return .unchanged }
            return m.hostFid == senderFid ? nil : .confirm
        }
        if let verdict { return verdict }
        return markEnded(s.meetingId, durationMs: s.duration ?? 0) ? .updated : .unchanged
    }

    /// The meeting is over: its host said so, or the relay confirmed it. False if already known.
    @discardableResult
    public func markEnded(_ meetingId: String, durationMs: Int64) -> Bool {
        lock.withLock {
            guard var m = meetings[meetingId], !m.ended else { return false }
            m.ended = true
            m.duration = max(0, durationMs)
            meetings[meetingId] = m
            saveLocked()
            return true
        }
    }

    private func trimLocked() {
        guard meetings.count > MeetingBoard.limit else { return }
        let oldest = meetings.values.sorted { $0.started < $1.started }.prefix(meetings.count - MeetingBoard.limit)
        for m in oldest { meetings[m.meetingId] = nil }
    }

    private func saveLocked() {
        // Kept in memory if it cannot be written; the chat messages remain the record.
        if let data = try? JSONEncoder().encode(meetings) { saveData(data) }
    }
}

/// A meeting's call secret from the entity's symkey (VOICE_SPEC §4.2). A
/// member may hold two keys at one version (FIMP2 §7.1): the right one is the
/// one whose admission key matches the `authPub` the host posted, which says
/// which without sending the key or its hash.
public enum MeetingKeys {

    /// The call secret among `symkeys` (the keys held at `version`) whose
    /// authPub is `authPubHex`, or nil if none gives it: this member lacks that key version.
    public static func secret(symkeys: [Data], nonce: Data, entityId: String, version: UInt64, meetingId: String,
                              authPubHex: String) -> Data? {
        guard let want = Hex.decodeOrNil(authPubHex) else { return nil }
        for symkey in symkeys {
            guard let secret = try? CallKeys.meetingSecret(symkey: symkey, nonce: nonce, entityId: entityId,
                                                           symkeyVersion: version, meetingId: meetingId) else { continue }
            if (try? CallKeys.authPub(authPriv: CallKeys.authPriv(callSecret: secret))) == want { return secret }
        }
        return nil
    }
}
