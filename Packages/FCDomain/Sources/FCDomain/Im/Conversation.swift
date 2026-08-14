import Foundation

/// One chat thread as the conversation list shows it, mirroring
/// `FC-AJDK/.../data/fcData/Conversation.java`.
///
/// Everything here is a **cache of the messages**, not a source of
/// truth: the last-message preview, the unread count, the display name.
/// It exists so opening the app does not mean paging every conversation's
/// history to draw one screen — ``MessagesStore`` holds the messages
/// themselves and is the only thing that can contradict this.
///
/// Unlike ``ImMessage``, ``Mail`` and ``Hat``, this type has **no
/// byte-level parity obligation**. Those three are serialized into
/// something another client reads — a carve, a history file — so their
/// field order is part of the format. A conversation is local display
/// state that never leaves the device, so it is a plain `Codable` and
/// the Java field order is followed for readability only.
public struct Conversation: Codable, Equatable, Sendable, Identifiable {

    /// `"<TYPE>_<targetId>"` — Java's `Conversation.fromMessage`
    /// derivation, kept identical so a log line from either client names
    /// the same thread.
    public var id: String

    public var targetId: String
    public var type: ImType
    /// CID, room name, team name — whatever the pane should show.
    public var displayName: String?
    public var avatarDid: String?

    // Last-message preview
    public var lastMessageId: String?
    /// The **preview**, not the message: ``preview(for:)`` renders
    /// non-text kinds as a placeholder. Android stores the same thing in
    /// the same field.
    public var lastMessageContent: String?
    public var lastMessageSenderId: String?
    public var lastMessageSenderName: String?
    public var lastMessageType: ContentType?
    public var lastMessageTime: Int64?

    public var unreadCount: Int?

    public var pinned: Bool?
    public var muted: Bool?
    public var archived: Bool?

    public var lastActiveAt: Int64?
    public var createdAt: Int64?

    // Team / room encryption state
    public var symkeyVersion: Int64?
    public var hasSymkey: Bool?

    // P2P presence
    public var isOnline: Bool?
    public var lastSeenAt: Int64?

    /// Square/team membership: we were a member and are not any more.
    public var leftGroup: Bool?

    // Group metrics, as the on-chain entity reports them
    public var memberNum: Int64?
    public var tCdd: Int64?
    public var tRate: Double?

    public init(
        id: String,
        targetId: String,
        type: ImType,
        displayName: String? = nil,
        avatarDid: String? = nil,
        lastMessageId: String? = nil,
        lastMessageContent: String? = nil,
        lastMessageSenderId: String? = nil,
        lastMessageSenderName: String? = nil,
        lastMessageType: ContentType? = nil,
        lastMessageTime: Int64? = nil,
        unreadCount: Int? = nil,
        pinned: Bool? = nil,
        muted: Bool? = nil,
        archived: Bool? = nil,
        lastActiveAt: Int64? = nil,
        createdAt: Int64? = nil,
        symkeyVersion: Int64? = nil,
        hasSymkey: Bool? = nil,
        isOnline: Bool? = nil,
        lastSeenAt: Int64? = nil,
        leftGroup: Bool? = nil,
        memberNum: Int64? = nil,
        tCdd: Int64? = nil,
        tRate: Double? = nil
    ) {
        self.id = id
        self.targetId = targetId
        self.type = type
        self.displayName = displayName
        self.avatarDid = avatarDid
        self.lastMessageId = lastMessageId
        self.lastMessageContent = lastMessageContent
        self.lastMessageSenderId = lastMessageSenderId
        self.lastMessageSenderName = lastMessageSenderName
        self.lastMessageType = lastMessageType
        self.lastMessageTime = lastMessageTime
        self.unreadCount = unreadCount
        self.pinned = pinned
        self.muted = muted
        self.archived = archived
        self.lastActiveAt = lastActiveAt
        self.createdAt = createdAt
        self.symkeyVersion = symkeyVersion
        self.hasSymkey = hasSymkey
        self.isOnline = isOnline
        self.lastSeenAt = lastSeenAt
        self.leftGroup = leftGroup
        self.memberNum = memberNum
        self.tCdd = tCdd
        self.tRate = tRate
    }

    // MARK: - identity

    /// The thread id for a conversation of `type` with `targetId`.
    ///
    /// For P2P the target is the *other* FID, which is why building one
    /// from a message needs to know who we are — see
    /// ``ImMessage/conversationId(for:)``.
    public static func id(type: ImType, targetId: String) -> String {
        "\(type.rawValue)_\(targetId)"
    }

    /// A new thread opened by `message`, from `myFid`'s point of view.
    /// Returns nil for a message with no routing — a half-decoded frame
    /// names no conversation and must not open an empty one.
    public static func opened(by message: ImMessage, myFid: String) -> Conversation? {
        guard let type = message.type,
              let targetId = message.conversationTargetId(for: myFid)
        else { return nil }

        var conv = Conversation(id: id(type: type, targetId: targetId), targetId: targetId, type: type)
        conv.unreadCount = 0
        conv.createdAt = message.timestamp
        conv.update(with: message, myFid: myFid)
        return conv
    }

    // MARK: - updating

    /// Fold `message` into the preview fields, and count it unread if it
    /// came from someone else.
    ///
    /// Ordering is checked first: a message that is *older* than the one
    /// already summarized here leaves the preview alone. Delivery is not
    /// ordered — a DOCK-stored message can land minutes after a direct
    /// one that was sent later — and without this guard picking up an
    /// offline backlog would leave every conversation showing whichever
    /// message happened to arrive last.
    public mutating func update(with message: ImMessage, myFid: String) {
        if message.contentType?.isDisplayable == true, !message.isOutgoing(from: myFid) {
            unreadCount = (unreadCount ?? 0) + 1
        }
        // Above the recency guard on purpose: a backfilled older message
        // does not touch the preview, but it does move the thread's
        // birthday back, and it is still something we have not read.
        if let born = message.timestamp, born < (createdAt ?? .max) {
            createdAt = born
        }

        guard isNewerThanPreview(message) else { return }
        lastMessageId = message.id
        lastMessageContent = Self.preview(for: message)
        lastMessageSenderId = message.senderId
        lastMessageSenderName = message.senderName
        lastMessageType = message.contentType
        lastMessageTime = message.timestamp
        lastActiveAt = message.timestamp
    }

    private func isNewerThanPreview(_ message: ImMessage) -> Bool {
        guard let existing = lastMessageTime else { return true }
        guard let incoming = message.timestamp else { return false }
        if incoming != existing { return incoming > existing }
        // Same millisecond: fall back to the id, which is how
        // MessagesStore breaks the tie too, so the list and the
        // transcript agree on which one is last.
        return (message.id ?? "") >= (lastMessageId ?? "")
    }

    public mutating func markRead() { unreadCount = 0 }

    /// Port of Java's `getPreviewContent`. The bracketed placeholders are
    /// Android's own strings, kept verbatim: the value is *stored*, so
    /// the two clients showing a thread differently would be a visible
    /// disagreement about the same cached field.
    public static func preview(for message: ImMessage) -> String? {
        guard let contentType = message.contentType else { return message.content }
        switch contentType {
        case .text:     return message.content
        case .hat:      return "[File]"
        case .stream:   return "[Stream]"
        case .symkey:   return "[Symmetric Key]"
        case .members:  return "[Members]"
        case .history:  return "[History]"
        case .request:  return "[Request]"
        case .response: return "[Response]"
        case .typing:   return "typing..."
        case .receipt:  return ""
        case .presence: return ""
        case .reaction: return "[Reaction]"
        case .edit:     return message.content
        case .delete:   return "[Deleted]"
        case .forward:  return "[Forwarded] " + (message.content ?? "")
        case .voice:    return "[Voice]"
        case .roomInfo, .roomLeave, .roomAccept, .roomDisband, .roomRemoved:
            return ""
        }
    }

    // MARK: - ordering

    /// Pinned threads first, then most recently active. Ties break on
    /// id so the list never reshuffles between two equal rows.
    public static func listOrder(_ a: Conversation, _ b: Conversation) -> Bool {
        if (a.pinned == true) != (b.pinned == true) { return a.pinned == true }
        let ta = a.lastActiveAt ?? 0, tb = b.lastActiveAt ?? 0
        if ta != tb { return ta > tb }
        return a.id < b.id
    }

    /// Case-insensitive match over what a conversation list can search:
    /// the name, the target id, and the cached preview.
    public func matches(query: String) -> Bool {
        let needle = query.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !needle.isEmpty else { return false }
        func hit(_ s: String?) -> Bool { s?.lowercased().contains(needle) ?? false }
        return hit(displayName) || hit(targetId) || hit(lastMessageContent)
    }
}

public extension ContentType {

    /// Whether a message of this kind is a thing the user *said* — one
    /// that earns a row in the transcript, bumps its conversation up the
    /// list, and counts as unread.
    ///
    /// This is our judgment, not a port: Android decides case by case at
    /// each call site in `ImManager`. Everything excluded here is either
    /// a signal (typing, receipt, presence), protocol traffic (symkey,
    /// members, request/response, the room notifications), or an
    /// operation *on* another message (reaction, edit, delete) — and the
    /// one that matters is `typing`, since counting it would let a peer
    /// hold a conversation at the top of the list by doing nothing.
    var isDisplayable: Bool {
        switch self {
        case .text, .hat, .stream, .voice, .forward:
            return true
        case .symkey, .members, .history, .request, .response, .typing, .receipt,
             .presence, .reaction, .edit, .delete, .roomInfo, .roomLeave,
             .roomAccept, .roomDisband, .roomRemoved:
            return false
        }
    }
}

public extension ImMessage {

    /// The other end of this message's conversation, from `myFid`'s
    /// point of view: the partner FID for P2P, the group id otherwise.
    /// Same as ``conversationPartnerId(for:)`` but nil when the message
    /// names no route at all.
    func conversationTargetId(for myFid: String) -> String? {
        guard type != nil else { return nil }
        guard let partner = conversationPartnerId(for: myFid), !partner.isEmpty else { return nil }
        return partner
    }

    /// The ``Conversation`` id this message belongs to, from `myFid`'s
    /// point of view — which is also its ``MessagesStore`` namespace.
    func conversationId(for myFid: String) -> String? {
        guard let type, let targetId = conversationTargetId(for: myFid) else { return nil }
        return Conversation.id(type: type, targetId: targetId)
    }
}
