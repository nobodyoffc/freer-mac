import Foundation

/// Delivery and read receipts: the small P2P messages that turn a
/// sender's `SENT` into `DELIVERED` and then `READ`.
///
/// A receipt is **always P2P**, whatever kind of conversation the
/// message it refers to was in, because it is addressed to that one
/// sender rather than to a group — see ``ImMessage/receipt(from:to:originalMessageId:read:)``.
/// It names its subject in ``ImMessage/requestId`` and says which kind
/// it is in ``ImMessage/content``, as the literal strings `"delivered"`
/// and `"read"` that Android writes.
public enum Receipt {

    public enum Kind: String, Equatable, Sendable {
        case delivered
        case read

        /// The status this receipt proves the message reached.
        public var status: MessageStatus {
            switch self {
            case .delivered: return .delivered
            case .read: return .read
            }
        }
    }

    /// The kind of receipt this message is, or nil if it is not one.
    public static func kind(of message: ImMessage) -> Kind? {
        guard message.contentType == .receipt else { return nil }
        return Kind(rawValue: message.content ?? "")
    }

    /// The conversation the *subject* of a receipt lives in, from our
    /// point of view: the P2P thread with whoever sent the receipt.
    ///
    /// A receipt for a message we sent into a room would not be found
    /// this way — the original is filed under the room, not under the
    /// person. Android only ever tracks P2P receipts, and rather than
    /// guess at a room id this returns the one thread it can name and
    /// lets ``apply(_:in:messages:)`` take an explicit conversation when
    /// the caller knows better.
    public static func originConversationId(for receipt: ImMessage) -> String? {
        guard let senderId = receipt.senderId, !senderId.isEmpty else { return nil }
        return Conversation.id(type: .p2p, targetId: senderId)
    }

    /// Apply a receipt to the message it refers to.
    ///
    /// Returns the updated message, or nil when the receipt names
    /// something we do not have, is not a receipt, or would move the
    /// message *backwards*.
    ///
    /// That last case is not hypothetical. Delivery is unordered: a
    /// `delivered` receipt can arrive after the `read` receipt that
    /// followed it, and applying it in arrival order would flip a
    /// message the recipient has already read back to merely delivered.
    /// So a receipt only ever advances the status, never retracts it.
    @discardableResult
    public static func apply(
        _ receipt: ImMessage,
        in conversationId: String,
        messages: MessagesStore
    ) throws -> ImMessage? {
        guard let kind = kind(of: receipt),
              let subjectId = receipt.requestId, !subjectId.isEmpty
        else { return nil }

        var applied = false
        let updated = try messages.mutate(messageId: subjectId, in: conversationId) { message in
            guard advances(from: message.status, to: kind.status) else { return }
            message.status = kind.status
            switch kind {
            case .delivered:
                message.deliveredAt = message.deliveredAt ?? receipt.timestamp
            case .read:
                // A read receipt implies delivery, and may be the only
                // one that arrives — a peer that read the message on
                // first sight sends one receipt, not two.
                message.deliveredAt = message.deliveredAt ?? receipt.timestamp
                message.readAt = receipt.timestamp
            }
            applied = true
        }
        return applied ? updated : nil
    }

    /// Whether `next` is further along the lifecycle than `current`.
    /// `pending → sent → delivered → read`; `failed` is not on the line
    /// at all, and a receipt overrides it — a message we gave up on that
    /// turns out to have arrived did arrive.
    static func advances(from current: MessageStatus?, to next: MessageStatus) -> Bool {
        rank(next) > rank(current)
    }

    private static func rank(_ status: MessageStatus?) -> Int {
        switch status {
        case .none: return 0
        case .quarantined, .imported: return 0
        case .failed: return 0
        case .pending: return 1
        case .sent: return 2
        case .delivered: return 3
        case .read: return 4
        }
    }
}
