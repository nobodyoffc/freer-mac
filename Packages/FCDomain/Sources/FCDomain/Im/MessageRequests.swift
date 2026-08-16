import Foundation
import FCStorage

/// One stranger, and what they have said so far.
///
/// The index exists so the pane can show "3 requests" without opening
/// three conversations' worth of ciphertext. Everything in it is
/// recoverable from the held messages themselves, which is what makes it
/// safe to rebuild or drop.
public struct MessageRequest: Codable, Equatable, Sendable, Identifiable {

    public var fid: String
    /// How many of their messages are being held.
    public var count: Int
    /// The most recent one, for the list. Never the whole message.
    public var lastPreview: String?
    public var firstSeenAt: Int64
    public var lastAt: Int64

    public var id: String { fid }

    public init(
        fid: String,
        count: Int = 0,
        lastPreview: String? = nil,
        firstSeenAt: Int64 = 0,
        lastAt: Int64 = 0
    ) {
        self.fid = fid
        self.count = count
        self.lastPreview = lastPreview
        self.firstSeenAt = firstSeenAt
        self.lastAt = lastAt
    }
}

/// Messages from people this identity has not agreed to hear from.
///
/// **Held, not delivered and not dropped.** A held message is stored in
/// the sender's own conversation namespace with
/// ``MessageStatus/quarantined``, and — this is the part that makes it
/// work — ``ConversationsStore`` is never told about it. No thread row,
/// no unread count, no preview anywhere: the sender cannot put anything
/// on screen until someone here says yes. Accepting them re-files what
/// was held through the ordinary path, so a conversation that starts
/// from a request opens with its history intact rather than as an empty
/// thread that lost the message that caused it.
///
/// There is a **cap per sender** (Android's
/// `MAX_QUARANTINE_PER_STRANGER`), and it is a real defence rather than
/// tidiness: without it anyone with our FID could fill this device's
/// disk by writing to a queue we have not agreed to read.
public struct MessageRequests {

    /// How many messages one stranger may leave waiting.
    public static let maxHeldPerSender = 20

    private let requests: MessageRequestsStore
    private let messages: MessagesStore
    private let conversations: ConversationsStore

    public init(
        requests: MessageRequestsStore,
        messages: MessagesStore,
        conversations: ConversationsStore
    ) {
        self.requests = requests
        self.messages = messages
        self.conversations = conversations
    }

    /// The conversation a sender's messages are filed under — the same
    /// id their thread will have if they are ever accepted, which is
    /// what lets promotion be a status change rather than a move.
    static func conversationId(for sender: String) -> String {
        Conversation.id(type: .p2p, targetId: sender)
    }

    // MARK: - holding

    /// File one message as a request. Returns false when this sender has
    /// already left as many as they are allowed to, in which case the
    /// message is discarded and nothing is recorded.
    @discardableResult
    public func hold(
        _ message: ImMessage, from sender: String, now: Date = Date()
    ) throws -> Bool {
        var row = try requests.get(fid: sender) ?? MessageRequest(fid: sender)
        guard row.count < Self.maxHeldPerSender else { return false }

        var held = message
        held.status = .quarantined
        held.unread = true
        try messages.put(held, in: Self.conversationId(for: sender))

        let stamp = message.timestamp ?? Int64(now.timeIntervalSince1970 * 1000)
        row.count += 1
        row.lastPreview = Conversation.preview(for: held)
        row.lastAt = stamp
        if row.firstSeenAt == 0 { row.firstSeenAt = stamp }
        try requests.upsert(row)
        return true
    }

    // MARK: - reading

    public func pending() throws -> [MessageRequest] {
        try requests.all()
    }

    public func count(from sender: String) throws -> Int {
        try requests.get(fid: sender)?.count ?? 0
    }

    /// Every held message from one sender, oldest first.
    ///
    /// Walks back from the newest page until a page holds nothing
    /// quarantined. Held messages only ever land at the tail — once a
    /// sender is allowed through nothing more is held, and once they are
    /// blocked nothing is kept — so this terminates immediately for a
    /// stranger and after one page for someone with history.
    public func held(from sender: String) throws -> [ImMessage] {
        let conversationId = Self.conversationId(for: sender)
        var found: [ImMessage] = []
        var cursor: String?

        while true {
            let page = try messages.page(in: conversationId, before: cursor, limit: 50)
            let quarantined = page.messages.filter { $0.status == .quarantined }
            found.insert(contentsOf: quarantined, at: 0)
            guard quarantined.count == page.messages.count,
                  let older = page.olderCursor
            else { break }
            cursor = older
        }
        return found
    }

    // MARK: - deciding

    /// Accept a sender: their held messages become ordinary delivered
    /// ones and their thread appears, with everything they said in it.
    ///
    /// The conversation row is **rebuilt from the messages** rather than
    /// assembled here, so the preview, the unread count and the thread's
    /// birthday all come from the same place they would have come from
    /// if the messages had never been held.
    @discardableResult
    public func promote(_ sender: String, as liveFid: String, now: Date = Date()) throws -> Int {
        let conversationId = Self.conversationId(for: sender)
        let waiting = try held(from: sender)
        guard !waiting.isEmpty else {
            _ = try requests.remove(fid: sender)
            return 0
        }

        for message in waiting {
            guard let id = message.id else { continue }
            _ = try messages.mutate(messageId: id, in: conversationId) { held in
                held.status = .delivered
                held.deliveredAt = Int64(now.timeIntervalSince1970 * 1000)
                held.unread = true
            }
        }
        _ = try conversations.rebuild(id: conversationId, from: messages, myFid: liveFid)
        _ = try requests.remove(fid: sender)
        return waiting.count
    }

    /// Turn a sender down: the held messages go, and so does the row.
    ///
    /// Deliberately *not* the same as blocking. Refusing this batch says
    /// nothing about the next one, which is why the caller decides
    /// separately whether to blacklist — and why rejecting somebody who
    /// simply wrote to the wrong FID does not make them unreachable
    /// forever.
    @discardableResult
    public func reject(_ sender: String) throws -> Int {
        let conversationId = Self.conversationId(for: sender)
        let waiting = try held(from: sender)
        for message in waiting {
            guard let id = message.id else { continue }
            _ = try messages.delete(messageId: id, in: conversationId)
        }
        _ = try requests.remove(fid: sender)
        return waiting.count
    }
}

/// The request index. Human-scale — one row per waiting stranger.
public struct MessageRequestsStore {

    public static let namespace = "im.requests.v1"

    private let inner: TypedStore<MessageRequest>

    public init(kv: EncryptedKVStore) {
        self.inner = TypedStore(kv: kv, namespace: Self.namespace)
    }

    public func get(fid: String) throws -> MessageRequest? {
        try inner.get(fid)
    }

    public func upsert(_ request: MessageRequest) throws {
        try inner.put(request, key: request.fid)
    }

    /// Newest first: the one that just arrived is the one being asked
    /// about.
    public func all() throws -> [MessageRequest] {
        try inner.all().map(\.value).sorted { $0.lastAt > $1.lastAt }
    }

    public func total() throws -> Int {
        try all().reduce(0) { $0 + $1.count }
    }

    @discardableResult
    public func remove(fid: String) throws -> Bool {
        guard try inner.exists(fid) else { return false }
        try inner.delete(fid)
        return true
    }
}
