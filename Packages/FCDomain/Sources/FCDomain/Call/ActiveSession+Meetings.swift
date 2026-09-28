import Foundation
import FCCore
import FCStorage

/// What meetings need from this identity (VOICE_SPEC §3.3, §8), the Mac's
/// `ImManager.MeetingHooks`: posting cards into a Room or Team chat, the
/// local card of a chosen-people meeting, membership, and the symkeys the
/// call secret comes from.
public extension ActiveSession {

    /// The live identity's meetings, kept in the vault's encrypted store: which
    /// Rooms hold meetings, and where they run, is nobody else's business.
    func meetingBoard() -> MeetingBoard {
        let storage = self.storage
        let key = liveFid
        return MeetingBoard(load: { try? storage.get(Data.self, namespace: "meetings", key: key) },
                            save: { try? storage.put($0, namespace: "meetings", key: key) })
    }

    /// `entityType` is "ROOM" or "TEAM".
    static func meetingImType(_ entityType: String) -> ImType? {
        switch entityType {
        case "ROOM": return .room
        case "TEAM": return .team
        default: return nil
        }
    }

    /// A MEETING_END, or a host's re-post of a rekeyed meeting's keys: they
    /// change a card, and are no chat row of their own.
    static func isMeetingControl(_ s: MeetingSignal) -> Bool {
        s.op == .MEETING_END || s.keyEpochOrZero > 0
    }

    /// Owner or member of the Room or Team, as this device knows it.
    func isEntityMember(type: ImType, entityId: String, fid: String) -> Bool {
        switch type {
        case .room:
            guard let room = (try? rooms.get(id: entityId)) ?? nil else { return false }
            return room.isOwner(fid) || room.isMember(fid)
        case .team:
            guard let team = (try? teams.get(id: entityId)) ?? nil else { return false }
            return team.isOwner(fid) || team.isMember(fid)
        default:
            return false
        }
    }

    /// The Room's or Team's members, owner included, as this device knows them.
    func entityMembers(type: ImType, entityId: String) -> [String] {
        var out: [String] = []
        switch type {
        case .room:
            if let room = (try? rooms.get(id: entityId)) ?? nil {
                out = (room.owner.map { [$0] } ?? []) + (room.members ?? [])
            }
        case .team:
            if let team = (try? teams.get(id: entityId)) ?? nil {
                out = (team.owner.map { [$0] } ?? []) + (team.members ?? [])
            }
        default:
            break
        }
        var seen = Set<String>()
        return out.filter { !$0.isEmpty && seen.insert($0).inserted }
    }

    func entityName(type: ImType, entityId: String) -> String? {
        switch type {
        case .room: return ((try? rooms.get(id: entityId)) ?? nil)?.name
        case .team: return ((try? teams.get(id: entityId)) ?? nil)?.stdName
        default: return nil
        }
    }

    /// The Room's or Team's home, for its CALL service.
    func entityHome(type: ImType, entityId: String) -> [String: String]? {
        switch type {
        case .room: return ((try? rooms.get(id: entityId)) ?? nil)?.home
        case .team: return ((try? teams.get(id: entityId)) ?? nil)?.home
        default: return nil
        }
    }

    /// Post a meeting signal into the Room or Team chat, sealed under its
    /// symkey, and send it now. A new card is filed as a row; a control
    /// message (an end, a rekey's re-post) is only sent.
    @discardableResult
    func postMeetingSignal(type: ImType, entityId: String, _ signal: MeetingSignal, now: Date = Date()) throws -> ImMessage {
        var m = ImMessage.make(type: type, from: liveFid, to: entityId, contentType: .call, now: now).named()
        m.content = signal.toJson()
        let conversationId = Conversation.id(type: type, targetId: entityId)
        let sent: ImMessage
        if Self.isMeetingControl(signal) {
            var outgoing = m
            _ = try symkeys.seal(&outgoing, for: entityId)
            try outbox.enqueue(outgoing, in: conversationId, now: now)
            sent = m
        } else {
            guard let conversation = try conversations.get(id: conversationId) else {
                throw ChatService.Failure.noSuchConversation(conversationId)
            }
            sent = try chat.send(m, in: conversation, as: liveFid, now: now)
        }
        drainMeetingOutbox()
        return sent
    }

    /// A 1:1 meeting signal: an invitation or its end, out at once (§6.3).
    func sendMeetingDirect(to fid: String, _ signal: MeetingSignal) throws {
        try sendCallSignal(to: fid, json: signal.toJson())
    }

    /// A meeting card in this device's copy of a Room or Team chat; sent to no one.
    func storeMeetingCard(type: ImType, entityId: String, hostFid: String, card: MeetingSignal,
                          timestampMs: Int64? = nil) throws {
        var m = ImMessage.make(type: type, from: hostFid, to: entityId, contentType: .call).named()
        m.content = card.toJson()
        m.timestamp = timestampMs ?? Int64(Date().timeIntervalSince1970 * 1000)
        m.status = hostFid == liveFid ? .sent : .delivered
        m.unread = hostFid != liveFid
        try messages.put(m, in: Conversation.id(type: type, targetId: entityId))
        try conversations.record(m, myFid: liveFid)
    }

    /// A member's MEETING_START that the board took as new: its card, filed in the chat.
    func fileMeetingCard(_ message: ImMessage) throws {
        guard let type = message.type, let entityId = message.targetId else { return }
        var m = message
        m.body = nil
        m.status = .delivered
        m.unread = message.senderId != liveFid
        try messages.put(m, in: Conversation.id(type: type, targetId: entityId))
        try conversations.record(m, myFid: liveFid)
    }

    // MARK: - Keys

    func meetingSymkeys(entityId: String, version: UInt64) -> [Data] {
        (try? symkeys.keys(for: entityId, version: Int64(version))) ?? []
    }

    /// The newest version held, or 0 for none.
    func meetingSymkeyVersion(entityId: String) -> UInt64 {
        UInt64(max(0, (try? symkeys.currentVersion(for: entityId)) ?? 0))
    }

    /// Ask `fid`, who holds it, for a version of the entity's key this device lacks (§8).
    func requestMeetingSymkey(entityId: String, version: UInt64, from fid: String, now: Date = Date()) {
        guard fid != liveFid, version >= UInt64(SymkeyStore.minimumVersion),
              let allowed = try? keyAsks.askable([fid], entityId: entityId, version: Int64(version), now: now).allowed,
              !allowed.isEmpty else { return }
        let request = KeyExchange.request(entityId: entityId, version: Int64(version), from: liveFid, to: fid, now: now)
        guard let requestId = request.id else { return }
        do {
            try outbox.enqueue(request, in: Conversation.id(type: .p2p, targetId: fid), now: now)
            try keyAsks.record(entityId: entityId, version: Int64(version), kind: .symkey,
                               sent: [(fid: fid, requestId: requestId)], now: now)
            drainMeetingOutbox()
        } catch {
            SystemLog.shared.warning(SystemSource.messages, "Could not ask for a meeting key", detail: "\(error)")
        }
    }

    /// A chosen-people meeting's key, kept as the symkey of `keyEntity` and encrypted like any (Decision 20).
    func storeMeetingKey(_ key: Data, keyEntity: String, version: UInt64) throws {
        try symkeys.store(key, for: keyEntity, version: Int64(version))
    }

    func forgetMeetingKey(keyEntity: String) {
        _ = try? symkeys.removeAll(for: keyEntity)
    }

    private func drainMeetingOutbox() {
        let courier = self.courier
        let from = liveFid
        Task { _ = try? await courier.drainOutbox(as: from) }
    }
}
