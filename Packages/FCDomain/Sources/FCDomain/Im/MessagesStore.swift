import Foundation
import FCStorage

/// Message history — the first collection in this app with no ceiling.
///
/// Every other store here (contacts, secrets, mails, hats) is
/// human-scale, so it can sit in one namespace and answer `all()`. A
/// chat cannot: one busy room outlives the patience of any `all()`, and
/// `TypedStore` says as much in its own doc comment. So this store is
/// shaped around never loading what it is not showing:
///
/// - **One namespace per conversation.** `EncryptedKVStore` keys on
///   `(namespace, key)`, so `listKeys` on `im.messages.v1.ROOM_abc…`
///   returns that room's keys and nobody else's. Opening one chat never
///   touches another's rows.
/// - **The key sorts chronologically.** `listKeys` is `ORDER BY key`, so
///   a key of zero-padded timestamp + message id makes SQLite's ordering
///   the transcript's ordering, and paging is a slice of a string array
///   — no ciphertext is touched until a row is actually wanted.
///
/// The cost of that shape is that "find by message id" is a scan of the
/// conversation's *keys* (never its values), which is cheap and bounded
/// but is not an index. If receipts ever need it per packet rather than
/// per user action, that is the moment to add one.
///
/// **Bodies are stored open when they could be opened.** This is the
/// opposite of ``MailsStore``, deliberately. A mail's ``Mail/cipher`` is
/// what came off the chain and can always be reopened with the identity
/// key, so storing it sealed costs nothing. An IM cipher is an ephemeral
/// transport wrapper whose symkey version may be rotated away — keeping
/// it would mean holding a blob that becomes unreadable while the
/// plaintext beside it stays fine. So ``put(_:in:)`` drops ``ImMessage/cipher``
/// once ``ImMessage/content`` is present, and keeps the cipher only for a
/// message we could *not* open, where it is the sole copy and a later
/// key might still recover it. The store itself is encrypted at rest
/// either way.
public struct MessagesStore {

    /// Namespaces are `"\(namespacePrefix)\(conversationId)"`.
    public static let namespacePrefix = "im.messages.v1."

    private let kv: EncryptedKVStore

    public init(kv: EncryptedKVStore) {
        self.kv = kv
    }

    // MARK: - keys

    /// `<19-digit timestamp>-<message id>`.
    ///
    /// 19 digits is `Int64.max`, so every timestamp pads to the same
    /// width and lexicographic order is numeric order. A negative
    /// timestamp — a bug, or a peer lying about when it spoke — clamps
    /// to 0 rather than sorting after everything by wrapping into a
    /// shorter string; the id keeps the key unique either way.
    static func key(timestamp: Int64?, id: String) -> String {
        String(format: "%019lld", max(0, timestamp ?? 0)) + "-" + id
    }

    static func namespace(_ conversationId: String) -> String {
        namespacePrefix + conversationId
    }

    private func store(_ conversationId: String) -> TypedStore<ImMessage> {
        TypedStore(kv: kv, namespace: Self.namespace(conversationId))
    }

    // MARK: - writing

    /// Store `message` in `conversationId`, replacing any earlier copy of
    /// the same message.
    ///
    /// The replacement is not just a `put`: the key encodes the
    /// timestamp, so a message whose timestamp was corrected would
    /// otherwise land beside its old self as a duplicate. The old key is
    /// found and removed first.
    ///
    /// Throws when the message has no id — this store will not invent
    /// one. An id is the FUDP layer's to assign (see
    /// ``ImMessage/setId(fudpId:)``), and a message keyed by something
    /// this store made up would not be findable by the receipt that
    /// names it.
    public func put(_ message: ImMessage, in conversationId: String) throws {
        guard let id = message.id, !id.isEmpty else { throw Failure.messageHasNoId }

        var stored = message
        if stored.content != nil || stored.data != nil { stored.body = nil }

        let s = store(conversationId)
        let newKey = Self.key(timestamp: stored.timestamp, id: id)
        if let existing = try key(forMessageId: id, in: conversationId), existing != newKey {
            try s.delete(existing)
        }
        try s.put(stored, key: newKey)
    }

    /// Read-modify-write one message. Returns the updated message, or
    /// nil when there is no such message here.
    ///
    /// This is the general form the delivery layer needs — status,
    /// `deliveredAt`, `dockId`, `roadIds` all change after the fact —
    /// and ``markRead(messageId:in:)`` is the one case common enough to
    /// have its own name.
    @discardableResult
    public func mutate(
        messageId: String,
        in conversationId: String,
        _ change: (inout ImMessage) -> Void
    ) throws -> ImMessage? {
        let s = store(conversationId)
        guard let key = try key(forMessageId: messageId, in: conversationId),
              var message = try s.get(key)
        else { return nil }
        change(&message)
        // Deliberately re-put under the *original* key: a mutation must
        // not move a message in the transcript, whatever it does to the
        // timestamp field.
        try s.put(message, key: key)
        return message
    }

    /// Marks one message read. Returns false when it was already read or
    /// is not here.
    @discardableResult
    public func markRead(messageId: String, in conversationId: String, at: Date = Date()) throws -> Bool {
        var changed = false
        _ = try mutate(messageId: messageId, in: conversationId) { message in
            guard message.unread != false || message.readAt == nil else { return }
            message.unread = false
            message.readAt = Int64(at.timeIntervalSince1970 * 1000)
            changed = true
        }
        return changed
    }

    /// Clears the unread flag on every message in one conversation,
    /// returning the ones that were actually flipped.
    ///
    /// This is the one method that walks a whole conversation, and it
    /// does so because opening a chat means exactly that. It is a user
    /// action on a thread they are looking at, not something a sync loop
    /// should call.
    ///
    /// The return is the messages rather than a count so a caller can
    /// tell the senders: a read receipt is owed for each one from
    /// somebody else, and only the ones that changed are owed one.
    @discardableResult
    public func markAllRead(in conversationId: String, at: Date = Date()) throws -> [ImMessage] {
        let s = store(conversationId)
        let stamp = Int64(at.timeIntervalSince1970 * 1000)
        var changed: [ImMessage] = []
        for key in try s.keys() {
            guard var message = try s.get(key), message.unread == true else { continue }
            message.unread = false
            message.readAt = stamp
            try s.put(message, key: key)
            changed.append(message)
        }
        return changed
    }

    // MARK: - reading

    public func get(messageId: String, in conversationId: String) throws -> ImMessage? {
        guard let key = try key(forMessageId: messageId, in: conversationId) else { return nil }
        return try store(conversationId).get(key)
    }

    /// One screenful, oldest-first, ending at `before` (exclusive).
    ///
    /// Pass no cursor for the newest page, then feed
    /// ``Page/olderCursor`` back as `before` to walk backwards — which
    /// is the direction a chat view scrolls. A nil `olderCursor` means
    /// the beginning of the conversation, so it doubles as "no more".
    public func page(in conversationId: String, before: String? = nil, limit: Int = 50) throws -> Page {
        guard limit > 0 else { return Page(messages: [], olderCursor: before) }
        let s = store(conversationId)
        var keys = try s.keys()
        if let before { keys = keys.filter { $0 < before } }

        let window = Array(keys.suffix(limit))
        let messages = try window.compactMap { try s.get($0) }
        let older = keys.count > window.count ? window.first : nil
        return Page(messages: messages, olderCursor: older)
    }

    /// The newest message, for a conversation-list preview that has to
    /// be rebuilt. Reads exactly one row.
    public func latest(in conversationId: String) throws -> ImMessage? {
        guard let key = try store(conversationId).keys().last else { return nil }
        return try store(conversationId).get(key)
    }

    /// How many messages the conversation holds. Counts keys, so no
    /// ciphertext is touched.
    public func count(in conversationId: String) throws -> Int {
        try store(conversationId).keys().count
    }

    /// Conversation ids this store holds messages for, taken from the
    /// keys themselves rather than from ``ConversationsStore``. Its
    /// purpose is repair: the conversation index is a cache, and this is
    /// how you find a thread the cache has lost.
    public func conversationIds() throws -> [String] {
        try kv.listNamespaces()
            .filter { $0.hasPrefix(Self.namespacePrefix) }
            .map { String($0.dropFirst(Self.namespacePrefix.count)) }
    }

    // MARK: - deleting

    @discardableResult
    public func delete(messageId: String, in conversationId: String) throws -> Bool {
        guard let key = try key(forMessageId: messageId, in: conversationId) else { return false }
        try store(conversationId).delete(key)
        return true
    }

    /// Drops an entire conversation's history. Returns how many messages
    /// went. The ``ConversationsStore`` row is a separate concern —
    /// leaving a thread and erasing what was said in it are different
    /// decisions.
    @discardableResult
    public func deleteConversation(_ conversationId: String) throws -> Int {
        let s = store(conversationId)
        let keys = try s.keys()
        for key in keys { try s.delete(key) }
        return keys.count
    }

    // MARK: - internals

    /// The storage key for a message id, or nil. Scans keys — see the
    /// type's note on why there is no index.
    private func key(forMessageId id: String, in conversationId: String) throws -> String? {
        let suffix = "-" + id
        return try store(conversationId).keys().first { $0.hasSuffix(suffix) }
    }

    /// One page of transcript.
    public struct Page: Equatable, Sendable {
        /// Oldest first — the order a chat view lays rows out in.
        public let messages: [ImMessage]
        /// Cursor for the page *before* this one, or nil at the start of
        /// the conversation.
        public let olderCursor: String?

        public init(messages: [ImMessage], olderCursor: String?) {
            self.messages = messages
            self.olderCursor = olderCursor
        }

        public var hasOlder: Bool { olderCursor != nil }
    }

    public enum Failure: Error, CustomStringConvertible {
        case messageHasNoId

        public var description: String {
            switch self {
            case .messageHasNoId:
                return "MessagesStore: the message has no id — the FUDP layer assigns it"
            }
        }
    }
}
