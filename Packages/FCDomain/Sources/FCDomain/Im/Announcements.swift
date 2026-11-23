import Foundation
import FCStorage

/// A team's or a room's announcement: a notice from whoever runs the group
/// that every member is asked to open and confirm.
///
/// **Text on the wire**, as Android's team notices are: an ordinary group
/// text whose content starts with ``prefix``. It is sealed, filed and
/// shown like any other message, and a client that has never heard of
/// announcements shows it as a line beginning `[ANNOUNCEMENT]` — the words
/// still arrive.
///
/// **Who may post one is the receiver's to check.** Anybody in the group
/// can type the prefix. The sender of a group message is proven by its
/// signature (FIMP0V3 §3.5), so what remains is whether that sender runs
/// the group: a team's owner or one of its managers, on the chain; a
/// room's owner, who is the only one a room has. An announcement from
/// anyone else is a plain message.
///
/// The rules are Android's `Announcements` too, case for case — see
/// `AnnouncementsTests` and `AnnouncementsTest`.
public enum Announcements {

    public static let prefix = "[ANNOUNCEMENT]"

    /// The wire text for an announcement saying `body`.
    public static func text(_ body: String) -> String {
        prefix + body.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    /// What an announcement says, or nil when `content` is not one — or
    /// is one that says nothing.
    public static func body(of content: String?) -> String? {
        guard let content, content.hasPrefix(prefix) else { return nil }
        let body = content.dropFirst(prefix.count).trimmingCharacters(in: .whitespacesAndNewlines)
        return body.isEmpty ? nil : body
    }

    /// Whether `message` is shaped as an announcement: a team or room text
    /// with the prefix and something after it, still standing. Says
    /// nothing about whether its sender may post one.
    public static func isAnnouncement(_ message: ImMessage) -> Bool {
        (message.type == .team || message.type == .room)
            && message.contentType == .text
            && !message.isWithdrawn && message.deleted != true
            && body(of: message.content) != nil
    }

    /// Whether `fid` may announce in a team: its owner or a manager.
    public static func mayPost(_ fid: String?, team: Team?) -> Bool {
        team?.isManager(fid) ?? false
    }

    /// Whether `fid` may announce in a room: its owner. A room has no
    /// managers.
    public static func mayPost(_ fid: String?, room: Room?) -> Bool {
        room?.isOwner(fid) ?? false
    }
}

/// Which announcements a conversation holds, and which of them this
/// identity has confirmed.
///
/// An index, not a copy: the words stay in ``MessagesStore``, and a row
/// here whose message is gone, withdrawn or no longer an announcement is
/// passed over when read. It exists because an unconfirmed announcement
/// can be weeks and a thousand messages old, and finding it by reading
/// every transcript back to the start each time a badge is drawn would
/// cost exactly that.
///
/// Rows are keyed as messages are, `<timestamp>-<id>`, so they list in
/// the order they were said.
public struct AnnouncementsStore {

    public static let namespacePrefix = "im.announcements.v1."

    public struct Entry: Codable, Equatable, Sendable {
        public var id: String
        public var senderId: String?
        public var timestamp: Int64?
        /// When this identity confirmed it. Our own are confirmed as sent.
        public var confirmedAt: Int64?

        public var isConfirmed: Bool { confirmedAt != nil }
    }

    private let kv: EncryptedKVStore

    public init(kv: EncryptedKVStore) {
        self.kv = kv
    }

    private func store(_ conversationId: String) -> TypedStore<Entry> {
        TypedStore(kv: kv, namespace: Self.namespacePrefix + conversationId)
    }

    private static func key(_ timestamp: Int64?, _ id: String) -> String {
        String(format: "%019lld", max(0, timestamp ?? 0)) + "-" + id
    }

    /// File `message` if it is an announcement. A row already here keeps
    /// its confirmation; `confirmed` only ever adds one.
    public func note(_ message: ImMessage, in conversationId: String, confirmed: Bool, now: Date = Date()) throws {
        guard Announcements.isAnnouncement(message), let id = message.id else { return }
        let at = Int64(now.timeIntervalSince1970 * 1000)
        _ = try store(conversationId).mutate(Self.key(message.timestamp, id)) { existing in
            var entry = existing ?? Entry(id: id, senderId: message.senderId, timestamp: message.timestamp)
            if confirmed, entry.confirmedAt == nil { entry.confirmedAt = at }
            return entry
        }
    }

    /// Every announcement filed in a conversation, oldest first.
    public func entries(in conversationId: String) throws -> [Entry] {
        try store(conversationId).all().sorted { $0.key < $1.key }.map(\.value)
    }

    /// Whether any announcement is filed in a conversation — read off the
    /// keys, so nothing is decrypted to say no.
    public func isEmpty(_ conversationId: String) throws -> Bool {
        try store(conversationId).keys().isEmpty
    }

    /// Mark one confirmed. Returns whether it was not already.
    @discardableResult
    public func confirm(_ entry: Entry, in conversationId: String, now: Date = Date()) throws -> Bool {
        var changed = false
        _ = try store(conversationId).mutate(Self.key(entry.timestamp, entry.id)) { existing in
            var e = existing ?? entry
            if e.confirmedAt == nil {
                e.confirmedAt = Int64(now.timeIntervalSince1970 * 1000)
                changed = true
            }
            return e
        }
        return changed
    }

    public func deleteConversation(_ conversationId: String) throws {
        let s = store(conversationId)
        for key in try s.keys() { try s.delete(key) }
    }
}

/// An announcement as a pane shows it: the message, where it was said,
/// and whether this identity has confirmed it.
public struct GroupAnnouncement: Identifiable, Sendable {
    public var id: String { conversation.id + "|" + (message.id ?? "") }
    public let conversation: Conversation
    public let message: ImMessage
    public let entry: AnnouncementsStore.Entry

    /// What it says, without the prefix.
    public var body: String { Announcements.body(of: message.content) ?? "" }
    public var isConfirmed: Bool { entry.isConfirmed }
}

extension ActiveSession {

    public var announcementIndex: AnnouncementsStore { AnnouncementsStore(kv: messages.kv) }

    /// Whether this identity may post an announcement in `conversation`.
    public func mayAnnounce(in conversation: Conversation) -> Bool {
        mayAnnounce(liveFid, in: conversation)
    }

    private func mayAnnounce(_ fid: String?, in conversation: Conversation) -> Bool {
        switch conversation.type {
        case .team: return Announcements.mayPost(fid, team: (try? teams.get(id: conversation.targetId)) ?? nil)
        case .room: return Announcements.mayPost(fid, room: (try? rooms.get(id: conversation.targetId)) ?? nil)
        case .p2p, .square: return false
        }
    }

    /// Every announcement in `conversation` from somebody who may post
    /// one, newest first — its history, confirmed or not.
    ///
    /// Whether the sender may is asked of the group as it stands now, so
    /// a manager's announcements go when they are dismissed — the same
    /// reading every member's device makes of the same chain.
    public func announcements(in conversation: Conversation) -> [GroupAnnouncement] {
        guard conversation.type == .team || conversation.type == .room else { return [] }
        let entries = (try? announcementIndex.entries(in: conversation.id)) ?? []
        guard !entries.isEmpty else { return [] }
        var found: [GroupAnnouncement] = []
        for entry in entries.reversed() {
            guard mayAnnounce(entry.senderId, in: conversation),
                  let message = (try? messages.get(messageId: entry.id, in: conversation.id)) ?? nil,
                  Announcements.isAnnouncement(message)
            else { continue }
            found.append(GroupAnnouncement(conversation: conversation, message: message, entry: entry))
        }
        return found
    }

    /// Announcements not yet confirmed here, oldest first — the order to
    /// read them in — across every team and room, or one flavour.
    public func unconfirmedAnnouncements(type: ImType? = nil) -> [GroupAnnouncement] {
        let types = type.map { [$0] } ?? [.team, .room]
        var found: [GroupAnnouncement] = []
        for type in types where type == .team || type == .room {
            for conversation in (try? conversations.visible(type: type)) ?? [] {
                guard conversation.leftGroup != true,
                      (try? announcementIndex.isEmpty(conversation.id)) == false
                else { continue }
                found += announcements(in: conversation).filter { !$0.isConfirmed }
            }
        }
        return found.sorted { ($0.message.timestamp ?? 0) < ($1.message.timestamp ?? 0) }
    }

    /// The member has read it and says so: it leaves the list of things to
    /// confirm, and stays in the group's history.
    public func confirmAnnouncement(_ announcement: GroupAnnouncement) {
        _ = try? announcementIndex.confirm(announcement.entry, in: announcement.conversation.id)
        if let id = announcement.message.id {
            _ = try? messages.markRead(messageId: id, in: announcement.conversation.id)
            try? conversations.rebuild(id: announcement.conversation.id, from: messages, myFid: liveFid)
        }
    }

    /// File any announcement the index has not seen — one that came in a
    /// shared history file, or before this device kept the index. Reads
    /// the whole transcript, so it is for opening a history, not for a
    /// badge. What it finds is filed as confirmed when it is history
    /// (imported) or our own, and as waiting when it is still unread.
    public func indexAnnouncements(in conversation: Conversation) {
        guard conversation.type == .team || conversation.type == .room else { return }
        guard let all = try? messages.messages(in: conversation.id, since: 0, before: Int64.max) else { return }
        for message in all where Announcements.isAnnouncement(message) {
            let settled = message.isOutgoing(from: liveFid) || message.status == .imported || message.unread != true
            try? announcementIndex.note(message, in: conversation.id, confirmed: settled)
        }
    }
}
