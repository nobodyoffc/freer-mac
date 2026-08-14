import Foundation
import FCStorage

/// The conversation list: one row per thread, keyed by
/// ``Conversation/id``.
///
/// This is the index over ``MessagesStore``, and unlike the messages
/// themselves it *is* human-scale — a person has tens of chats, not tens
/// of thousands — so it loads whole and sorts in memory like every other
/// store in the app.
///
/// Being an index makes it a **cache, and cheap to lose**. Every field on
/// a ``Conversation`` can be rebuilt from the messages it summarizes
/// (see ``rebuild(id:from:)``), which is what makes it safe to update
/// optimistically on the delivery path and repair later, rather than
/// keeping the two in lockstep on every write.
public struct ConversationsStore {

    public static let namespace = "im.conversations.v1"

    private let inner: TypedStore<Conversation>

    public init(kv: EncryptedKVStore) {
        self.inner = TypedStore(kv: kv, namespace: Self.namespace)
    }

    // MARK: - reading

    public func get(id: String) throws -> Conversation? {
        try inner.get(id)
    }

    public func get(type: ImType, targetId: String) throws -> Conversation? {
        try get(id: Conversation.id(type: type, targetId: targetId))
    }

    /// Every thread, pinned first then most recently active.
    public func all() throws -> [Conversation] {
        try inner.all().map(\.value).sorted(by: Conversation.listOrder)
    }

    /// The list as the sidebar shows it — archived threads left out.
    public func visible() throws -> [Conversation] {
        try all().filter { $0.archived != true }
    }

    /// Unread across every thread, for a dock badge. Muted threads still
    /// count here: muting silences a notification, it does not make
    /// messages disappear.
    public func totalUnread() throws -> Int {
        try all().reduce(0) { $0 + ($1.unreadCount ?? 0) }
    }

    public func search(_ query: String) throws -> [Conversation] {
        let needle = query.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !needle.isEmpty else { return try all() }
        return try all().filter { $0.matches(query: needle) }
    }

    // MARK: - writing

    public func upsert(_ conversation: Conversation) throws {
        try inner.put(conversation, key: conversation.id)
    }

    /// Fold a message into its thread, opening the thread if this is the
    /// first thing we have seen in it. Returns the updated conversation,
    /// or nil when the message names no route (see
    /// ``ImMessage/conversationId(for:)``).
    ///
    /// Signals and protocol traffic still land here, and still cannot
    /// disturb the list: ``Conversation/update(with:myFid:)`` counts only
    /// displayable messages as unread, and a typing indicator that
    /// arrives before any real message opens a thread with an empty
    /// preview rather than one that claims someone said "typing...".
    @discardableResult
    public func record(_ message: ImMessage, myFid: String) throws -> Conversation? {
        guard let id = message.conversationId(for: myFid) else { return nil }
        guard var conversation = try get(id: id) else {
            guard let opened = Conversation.opened(by: message, myFid: myFid) else { return nil }
            try upsert(opened)
            return opened
        }
        conversation.update(with: message, myFid: myFid)
        try upsert(conversation)
        return conversation
    }

    /// Zero the unread count. The messages' own `unread` flags are
    /// ``MessagesStore/markAllRead(in:at:)``'s business — a pane opening
    /// a thread does both, and they are separate so that marking a
    /// notification read does not have to walk the transcript.
    @discardableResult
    public func markRead(id: String) throws -> Bool {
        guard var conversation = try get(id: id), conversation.unreadCount ?? 0 != 0 else { return false }
        conversation.markRead()
        try upsert(conversation)
        return true
    }

    /// Apply a change to one thread, if it exists.
    @discardableResult
    public func mutate(id: String, _ change: (inout Conversation) -> Void) throws -> Conversation? {
        guard var conversation = try get(id: id) else { return nil }
        change(&conversation)
        try upsert(conversation)
        return conversation
    }

    @discardableResult
    public func remove(id: String) throws -> Bool {
        guard try inner.exists(id) else { return false }
        try inner.delete(id)
        return true
    }

    // MARK: - repair

    /// Rebuild one thread's cached summary from the messages themselves.
    ///
    /// Used when the index and the transcript disagree — after an
    /// interrupted write, or for a conversation ``MessagesStore`` knows
    /// about and this store does not. Unread is recounted from the
    /// messages' own flags, which is the only place that survives losing
    /// this row.
    ///
    /// Walks the whole conversation, so it is repair, not routine.
    @discardableResult
    public func rebuild(id: String, from messages: MessagesStore, myFid: String) throws -> Conversation? {
        var page = try messages.page(in: id, limit: 500)
        guard !page.messages.isEmpty else { return nil }

        var rebuilt: Conversation?
        var unread = 0
        while true {
            for message in page.messages {
                if rebuilt == nil {
                    rebuilt = Conversation.opened(by: message, myFid: myFid)
                } else {
                    rebuilt?.update(with: message, myFid: myFid)
                }
                if message.unread == true { unread += 1 }
            }
            guard let cursor = page.olderCursor else { break }
            page = try messages.page(in: id, before: cursor, limit: 500)
            if page.messages.isEmpty { break }
        }

        guard var conversation = rebuilt else { return nil }
        // `update` counted every incoming message as unread, which is
        // right for a live message and wrong for a replay of history.
        // The messages' own flags are the surviving record of what has
        // actually been read, so they win.
        conversation.unreadCount = unread
        // Carry over the preferences, which are this store's own and are
        // not recoverable from any message.
        if let existing = try get(id: id) {
            conversation.displayName = existing.displayName
            conversation.avatarDid = existing.avatarDid
            conversation.pinned = existing.pinned
            conversation.muted = existing.muted
            conversation.archived = existing.archived
            conversation.symkeyVersion = existing.symkeyVersion
            conversation.hasSymkey = existing.hasSymkey
        }
        try upsert(conversation)
        return conversation
    }
}
