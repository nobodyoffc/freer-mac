import Foundation
import FCCore

/// Sending and receiving a message, with everything that has to happen
/// around it: sealing it the way its conversation requires, filing it in
/// the transcript, updating the thread summary, and — on the way out —
/// putting it in the outbox.
///
/// This is the seam the chat pane calls and the seam 9.2.4b's transport
/// will call, and it is deliberately the *same* seam. A message that
/// arrives over FUDP and a message the user just typed differ only in
/// direction; everything else about how they are stored, counted and
/// displayed is the same, and writing that twice is how the two drift
/// apart.
///
/// **Sealing is decided by the conversation, not by the caller.** P2P
/// goes AsyTwoWay so the sender can reread it, team and room go under
/// the group's current symkey, and a square goes in the clear because it
/// has no membership to keep anyone out of. Handing that choice to the
/// call site would make "forgot to encrypt" a possible bug; here it is
/// not expressible.
public struct ChatService {

    private let messages: MessagesStore
    private let conversations: ConversationsStore
    private let symkeys: SymkeyStore
    private let outbox: MessageQueue

    public init(
        messages: MessagesStore,
        conversations: ConversationsStore,
        symkeys: SymkeyStore,
        outbox: MessageQueue
    ) {
        self.messages = messages
        self.conversations = conversations
        self.symkeys = symkeys
        self.outbox = outbox
    }

    /// The key material a send needs, which depends on where it is
    /// going. Group sends need nothing here — the key comes from
    /// ``SymkeyStore`` — so the P2P fields are optional and their
    /// absence is caught at the point it matters.
    public struct Keys: Sendable {
        public var privkey: Data?
        public var recipientPubkey: Data?

        public init(privkey: Data? = nil, recipientPubkey: Data? = nil) {
            self.privkey = privkey
            self.recipientPubkey = recipientPubkey
        }

        public static let none = Keys()
    }

    // MARK: - outbound

    /// Compose, seal, file and enqueue one text message.
    ///
    /// Returns the message **as stored** — plaintext in `content`, since
    /// we can obviously read our own, and the sealed copy is what the
    /// outbox carries. That difference is the point of ``MessagesStore``
    /// storing bodies open.
    @discardableResult
    public func sendText(
        _ text: String,
        in conversationId: String,
        as liveFid: String,
        keys: Keys = .none,
        now: Date = Date()
    ) throws -> ImMessage {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { throw Failure.emptyMessage }
        guard let conversation = try conversations.get(id: conversationId) else {
            throw Failure.noSuchConversation(conversationId)
        }

        var draft = ImMessage.text(
            type: conversation.type,
            from: liveFid,
            to: conversation.targetId,
            trimmed,
            now: now
        )
        draft.setId(fudpId: Self.newMessageId())
        return try send(draft, in: conversation, as: liveFid, keys: keys, now: now)
    }

    /// Seal, file and enqueue a message that has already been composed —
    /// the path a voice note, a file share or a protocol message takes.
    ///
    /// The message is named here if it has no id yet, for the same
    /// reason ``MessagesStore`` refuses to invent one: everything
    /// downstream refers to a message by it.
    @discardableResult
    public func send(
        _ draft: ImMessage,
        in conversation: Conversation,
        as liveFid: String,
        keys: Keys = .none,
        now: Date = Date()
    ) throws -> ImMessage {
        var stored = draft
        if stored.id == nil { stored.setId(fudpId: Self.newMessageId()) }
        stored.senderId = liveFid
        stored.targetId = conversation.targetId
        stored.type = conversation.type
        if stored.timestamp == nil { stored.timestamp = Self.millis(now) }

        // What goes on the wire is sealed; what we keep is not.
        var outgoing = stored
        try seal(&outgoing, for: conversation, keys: keys)

        // The stored copy keeps the plaintext and **not** the cipher —
        // the rule ``MessagesStore`` enforces anyway, applied here so
        // what this returns is what the store holds. The key version is
        // not ciphertext and is worth keeping: it records which key the
        // message went out under.
        stored.symkeyVersion = outgoing.symkeyVersion
        stored.cipher = nil
        stored.status = .pending
        stored.unread = false

        try messages.put(stored, in: conversation.id)
        try conversations.record(stored, myFid: liveFid)
        try outbox.enqueue(outgoing, in: conversation.id, now: now)
        return stored
    }

    /// Seal a body the way `conversation` requires. Throws rather than
    /// falling back to plaintext: the alternative to a thrown error here
    /// is a private message on the wire in the clear.
    private func seal(_ message: inout ImMessage, for conversation: Conversation, keys: Keys) throws {
        switch conversation.type {
        case .square:
            // Nothing to seal. Anyone may join a square, so a key shared
            // with everyone who asks would imply a privacy it does not
            // have.
            return
        case .team, .room:
            try symkeys.seal(&message, for: conversation.targetId)
        case .p2p:
            guard let privkey = keys.privkey, let pubkey = keys.recipientPubkey else {
                throw Failure.noRecipientKey(conversation.targetId)
            }
            try message.sealBody(privkey: privkey, recipientPubkey: pubkey)
        }
    }

    // MARK: - inbound

    /// What arriving traffic turned into.
    public enum Received: Equatable, Sendable {
        /// A message for a conversation, filed and counted.
        case message(ImMessage)
        /// A receipt that advanced one of our own messages.
        case receipt(ImMessage)
        /// Something we filed but could not open — the cue to ask for
        /// the key version it names.
        case sealed(ImMessage, symkeyVersion: Int64?)
        /// Nothing to do with a transcript: a typing indicator, a
        /// presence ping, a room notification. The caller routes these.
        case signal(ImMessage)
        case ignored(reason: String)
    }

    /// File one inbound message.
    ///
    /// A body we cannot open is **kept sealed and flagged**, not
    /// dropped. After a key rotation a batch will contain some of these,
    /// and each is a row to show as locked and a key to go and ask for —
    /// throwing them away would silently lose messages that become
    /// readable minutes later.
    @discardableResult
    public func receive(
        _ message: ImMessage,
        as liveFid: String,
        privkey: Data? = nil,
        now: Date = Date()
    ) throws -> Received {
        guard message.hasFudpId else { return .ignored(reason: "unnamed message") }
        guard let type = message.type,
              let conversationId = message.conversationId(for: liveFid)
        else { return .ignored(reason: "no route") }

        if message.contentType == .receipt {
            guard let origin = Receipt.originConversationId(for: message),
                  let updated = try Receipt.apply(message, in: origin, messages: messages)
            else { return .ignored(reason: "receipt matched nothing") }
            return .receipt(updated)
        }
        guard message.contentType?.isDisplayable == true else {
            return .signal(message)
        }

        var stored = message
        stored.status = .delivered
        stored.deliveredAt = Self.millis(now)
        stored.unread = !message.isOutgoing(from: liveFid)

        var opened = true
        if stored.isSealed {
            switch type {
            case .team, .room:
                opened = (try? symkeys.open(&stored, for: stored.targetId ?? "")) ?? false
            case .p2p:
                opened = privkey.map { stored.openBody(privkey: $0) } ?? false
            case .square:
                opened = false
            }
            // Same rule as the send path: once the plaintext is beside
            // it the cipher is redundant, and the store drops it — so
            // drop it here too, and return what was actually stored.
            if opened { stored.cipher = nil }
        }

        try messages.put(stored, in: conversationId)
        try conversations.record(stored, myFid: liveFid)
        return opened ? .message(stored) : .sealed(stored, symkeyVersion: stored.symkeyVersion)
    }

    // MARK: - reading

    /// One screenful of a conversation, oldest first.
    public func page(
        _ conversationId: String, before: String? = nil, limit: Int = 50
    ) throws -> MessagesStore.Page {
        try messages.page(in: conversationId, before: before, limit: limit)
    }

    /// Opening a thread: clear its unread count and the messages' own
    /// flags. The two are separate stores and separate facts — see
    /// ``ConversationsStore/markRead(id:)``.
    @discardableResult
    public func markRead(_ conversationId: String, now: Date = Date()) throws -> Int {
        try conversations.markRead(id: conversationId)
        return try messages.markAllRead(in: conversationId, at: now)
    }

    // MARK: - helpers

    /// A fresh 64-bit message id.
    ///
    /// The FUDP layer names messages in the finished system, and this is
    /// the same thing its `generateMessageId` does — the transport picks
    /// a random 64-bit number and both ends refer to the message by it.
    /// Nothing about the *value* is FUDP-specific, which is why the pane
    /// can name a message today and 9.2.4b can hand the job to the node
    /// without anything downstream noticing.
    public static func newMessageId() -> Int64 {
        Int64.random(in: 1...Int64.max)
    }

    static func millis(_ date: Date) -> Int64 {
        Int64(date.timeIntervalSince1970 * 1000)
    }

    public enum Failure: Error, Equatable, CustomStringConvertible {
        case emptyMessage
        case noSuchConversation(String)
        case noRecipientKey(String)

        public var description: String {
            switch self {
            case .emptyMessage:
                return "ChatService: nothing to send"
            case .noSuchConversation(let id):
                return "ChatService: no conversation \(id)"
            case .noRecipientKey(let fid):
                return "\(fid) has never published a public key, so there is nothing to encrypt a message to. They need to spend from that FID at least once."
            }
        }
    }
}
