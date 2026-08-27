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

    /// The stranger gate. Optional because the gate is a property of a
    /// configured session and not of the send/receive machinery: the
    /// tests that exercise sealing and filing have no policy and want
    /// none, and a nil here means every sender is let through, which is
    /// what this seam did before the gate existed.
    private let policy: ContactPolicyStore?
    private let requests: MessageRequests?
    /// Asked whether a sender is in the address book. Supplied rather
    /// than reached for, so ``ContactPolicy`` and this service both stay
    /// out of ``ContactsStore``.
    private let isContact: (@Sendable (String) -> Bool)?

    public init(
        messages: MessagesStore,
        conversations: ConversationsStore,
        symkeys: SymkeyStore,
        outbox: MessageQueue,
        policy: ContactPolicyStore? = nil,
        requests: MessageRequests? = nil,
        isContact: (@Sendable (String) -> Bool)? = nil
    ) {
        self.messages = messages
        self.conversations = conversations
        self.symkeys = symkeys
        self.outbox = outbox
        self.policy = policy
        self.requests = requests
        self.isContact = isContact
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
        stored.body = nil
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
        /// From someone this identity has not agreed to hear from. It is
        /// stored, but under no conversation — see ``MessageRequests``.
        /// `prompt` asks the UI to raise it now rather than badge it.
        case held(ImMessage, prompt: Bool)
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

        // **Open first.** Every branch below asks what the body says —
        // a receipt reads `content` to learn whether it means delivered
        // or read, a signal is routed on its payload — and a sealed body
        // says nothing until it is opened.
        //
        // Doing this after the receipt branch is why delivery and read
        // receipts silently did nothing: they arrive sealed like any
        // other P2P message, `Receipt.kind(of:)` read a nil `content`,
        // and every receipt was discarded as "matched nothing". The
        // sender's message then sat at `sent` forever. Android opens
        // before its own RECEIPT branch for exactly this reason.
        var stored = message
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
            // it the sealed body is redundant, and the store drops it —
            // so drop it here too, and return what was actually stored.
            if opened { stored.body = nil }
        }

        if stored.contentType == .receipt {
            // A receipt we cannot open is not a receipt we can act on,
            // and there is nothing to file: it names someone else's
            // message and carries no transcript content of its own.
            guard opened else { return .ignored(reason: "receipt still sealed") }
            guard let origin = Receipt.originConversationId(for: stored),
                  let updated = try Receipt.apply(stored, in: origin, messages: messages)
            else { return .ignored(reason: "receipt matched nothing") }
            return .receipt(updated)
        }
        guard stored.contentType?.isDisplayable == true else {
            return .signal(stored)
        }

        // **The stranger gate**, and it sits exactly here on purpose.
        //
        // Android puts it earlier, in front of everything inbound, which
        // also quarantines control traffic — a receipt, a room
        // invitation, a key share — from anyone not yet accepted. That
        // is the wrong place for two reasons: those messages carry no
        // transcript content to show in a request list, and each already
        // has a gate of its own that is stricter than this one (a room
        // notification is checked against the room's owner, a key
        // against the entity's). Filtering them by sender as well would
        // hold half a protocol exchange in a queue nobody can act on.
        //
        // So the gate guards the one thing it is actually for: whether a
        // stranger may put a row in the thread list.
        if let verdict = try strangerVerdict(for: stored, as: liveFid, now: now) {
            return verdict
        }

        stored.status = .delivered
        stored.deliveredAt = Self.millis(now)
        stored.unread = !message.isOutgoing(from: liveFid)

        try messages.put(stored, in: conversationId)
        try conversations.record(stored, myFid: liveFid)
        return opened ? .message(stored) : .sealed(stored, symkeyVersion: stored.symkeyVersion)
    }

    /// Ask the policy about an inbound message, and act on the answer.
    ///
    /// Returns nil when the message should go on to be filed normally —
    /// which is every case except a stranger's, and every case at all
    /// when no policy is configured.
    ///
    /// **Only P2P.** A square is open by definition, and being in a team
    /// or a room already means the conversation was accepted; running
    /// group traffic through a per-sender gate would quarantine a group
    /// chat one member at a time.
    private func strangerVerdict(
        for stored: ImMessage,
        as liveFid: String,
        now: Date
    ) throws -> Received? {
        guard let policy, let requests else { return nil }
        guard stored.type == .p2p else { return nil }
        guard let sender = stored.senderId, sender != liveFid else { return nil }
        guard !stored.isOutgoing(from: liveFid) else { return nil }

        let current = try policy.load(liveFid: liveFid)
        switch current.decide(sender: sender, isContact: isContact?(sender) ?? false) {
        case .deliver:
            return nil

        case .acceptAndDeliver:
            // Remembering them is the point: the *next* message from
            // this sender must not ask the same question again.
            try policy.mutate(liveFid: liveFid) { $0.allow(sender) }
            return nil

        case .hold(let prompt):
            // Over the cap, `hold` keeps nothing and says so. Reporting
            // that as ignored rather than held is deliberate: there is
            // no new request to show, and a count that kept climbing
            // would promise messages this device no longer has.
            guard try requests.hold(stored, from: sender, now: now) else {
                return .ignored(reason: "message request cap reached for \(sender)")
            }
            return .held(stored, prompt: prompt)

        case .drop:
            return .ignored(reason: "blocked sender \(sender)")
        }
    }

    // MARK: - receipts

    /// Acknowledge someone else's message: build a receipt, seal it, and
    /// put it in the outbox.
    ///
    /// A receipt is **not filed in the transcript**, which is why this
    /// does not go through ``send(_:in:as:keys:now:)``. It carries no
    /// content of its own — ``Conversation/preview(for:)`` renders it as
    /// the empty string — so filing one would blank the thread's preview
    /// and count a message that is not a message.
    ///
    /// Always P2P, whatever kind of conversation the subject was in: a
    /// receipt is addressed to the one sender, not to a group.
    ///
    /// Returns nil when there is nothing to acknowledge — our own
    /// message, an unnamed one, or a sender we cannot address.
    @discardableResult
    public func acknowledge(
        _ message: ImMessage,
        kind: Receipt.Kind,
        as liveFid: String,
        keys: Keys,
        now: Date = Date()
    ) throws -> ImMessage? {
        guard let subjectId = message.id, !subjectId.isEmpty else { return nil }
        guard let senderId = message.senderId, !senderId.isEmpty else { return nil }
        // Acknowledging ourselves would be a message to nobody, and for
        // self-chat it would be a message to ourselves in a loop.
        guard senderId != liveFid else { return nil }

        var receipt = ImMessage.receipt(
            from: liveFid, to: senderId,
            originalMessageId: subjectId, read: kind == .read, now: now
        )
        receipt.setId(fudpId: Self.newMessageId())

        // Sealed like any other P2P body. A receipt naming a message id
        // is not nothing to an observer, and the rule is the same one
        // the send path follows: fail rather than fall back to plaintext.
        guard let privkey = keys.privkey, let pubkey = keys.recipientPubkey else {
            throw Failure.noRecipientKey(senderId)
        }
        try receipt.sealBody(privkey: privkey, recipientPubkey: pubkey)

        _ = try outbox.enqueue(receipt, in: Conversation.id(type: .p2p, targetId: senderId), now: now)
        return receipt
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
    ///
    /// Returns the messages that were actually flipped to read. Each one
    /// from someone else is a read receipt we now owe them — see
    /// ``acknowledge(_:kind:as:keys:now:)``.
    @discardableResult
    public func markRead(_ conversationId: String, now: Date = Date()) throws -> [ImMessage] {
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
        ImMessage.newFudpId()
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
