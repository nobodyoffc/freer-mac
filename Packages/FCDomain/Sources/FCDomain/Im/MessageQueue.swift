import Foundation
import FCStorage

/// How an attempt to deliver a message turned out — the port of
/// Android's `MessageQueue.SendResult`.
///
/// The distinction that earns this type is transient versus permanent. A
/// peer being offline and a target FID being nonsense both look like
/// "it didn't send", and treating them the same means either giving up
/// on someone who is merely asleep, or retrying a malformed message
/// every fifteen minutes forever.
public enum SendResult: String, Codable, Equatable, Sendable {
    /// Delivered. Leaves the queue.
    case success
    /// Network glitch, peer offline, no route right now. Try later.
    case retryTransient
    /// Nothing about waiting will help — no target, nothing to send.
    /// Fails immediately.
    case failPermanent
}

/// A message waiting to be delivered, with its retry bookkeeping.
public struct QueuedMessage: Codable, Equatable, Sendable, Identifiable {

    public var message: ImMessage
    /// The conversation the message belongs to, so a status update can
    /// find it in ``MessagesStore`` without re-deriving it from a FID
    /// the queue does not know.
    public var conversationId: String
    /// How many *failed* attempts have been made.
    public var retryCount: Int
    /// Milliseconds since the epoch. Attempts before this are not due.
    public var nextRetryAt: Int64
    public var createdAt: Int64
    /// What went wrong last time, for a UI that wants to say so.
    public var lastError: String?

    public var id: String { message.id ?? "" }

    public init(
        message: ImMessage,
        conversationId: String,
        retryCount: Int = 0,
        nextRetryAt: Int64 = 0,
        createdAt: Int64 = 0,
        lastError: String? = nil
    ) {
        self.message = message
        self.conversationId = conversationId
        self.retryCount = retryCount
        self.nextRetryAt = nextRetryAt
        self.createdAt = createdAt
        self.lastError = lastError
    }
}

/// The durable outbox: messages we have accepted from the user but not
/// yet got rid of.
///
/// It is a *store*, not a loop. Android's `MessageQueue` owns two
/// executors and a 30-second ticker; here the scheduling belongs to
/// whoever drives the transport, and this type answers exactly two
/// questions — what is due, and what does this outcome mean — so both
/// are testable without a clock or a network.
///
/// **Everything here survives a restart**, which is the entire point.
/// The alternative is that quitting the app between "send" and "sent"
/// silently drops the message, and the user has no way to know.
public struct MessageQueue {

    public static let namespace = "im.queue.v1"

    /// Attempts, after which a message is declared failed. Android's
    /// `MAX_RETRIES`.
    public static let maxRetries = 5

    /// Backoff, in milliseconds: 5 s, 15 s, 1 min, 5 min, 15 min.
    ///
    /// **We use the first entry and Android does not.** Its
    /// `RETRY_DELAYS_MS[min(retryCount, len-1)]` reads the array *after*
    /// incrementing the count, so the first retry waits 15 s and the 5 s
    /// entry is dead code (logged as Android issue C11). Nothing on the
    /// wire depends on the schedule, so this uses the one the array
    /// plainly describes: a first retry that is quick enough to ride out
    /// a moment of bad signal.
    public static let retryDelaysMs: [Int64] = [5_000, 15_000, 60_000, 300_000, 900_000]

    private let inner: TypedStore<QueuedMessage>

    public init(kv: EncryptedKVStore) {
        self.inner = TypedStore(kv: kv, namespace: Self.namespace)
    }

    // MARK: - enqueueing

    /// Accept a message for delivery. Due immediately.
    ///
    /// Throws without an id for the same reason ``MessagesStore`` does:
    /// the queue is keyed by it, and a receipt naming a message we filed
    /// under a made-up id would never find it.
    @discardableResult
    public func enqueue(
        _ message: ImMessage, in conversationId: String, now: Date = Date()
    ) throws -> QueuedMessage {
        guard let id = message.id, !id.isEmpty else { throw Failure.messageHasNoId }
        let stamp = Int64(now.timeIntervalSince1970 * 1000)
        let queued = QueuedMessage(
            message: message,
            conversationId: conversationId,
            retryCount: 0,
            nextRetryAt: stamp,
            createdAt: stamp
        )
        try inner.put(queued, key: id)
        return queued
    }

    // MARK: - reading

    public func get(id: String) throws -> QueuedMessage? {
        try inner.get(id)
    }

    /// Everything still waiting, oldest first — the order it should be
    /// attempted in, so a conversation does not arrive backwards.
    public func all() throws -> [QueuedMessage] {
        try inner.all().map(\.value).sorted { $0.createdAt < $1.createdAt }
    }

    /// What is due to be attempted now.
    public func due(now: Date = Date()) throws -> [QueuedMessage] {
        let stamp = Int64(now.timeIntervalSince1970 * 1000)
        return try all().filter { $0.nextRetryAt <= stamp }
    }

    public func count() throws -> Int {
        try inner.keys().count
    }

    // MARK: - outcomes

    /// Apply the outcome of one delivery attempt.
    ///
    /// Returns what became of the message, which is what a UI needs to
    /// hear: it left the queue, it will be tried again at some time, or
    /// it is not going to be delivered.
    ///
    /// The retry counter is not reset by anything. A message that has
    /// exhausted its attempts stays failed until the user resends it —
    /// ``retryNow(id:now:)`` exists for exactly that and is deliberately
    /// something only a person triggers.
    @discardableResult
    public func record(
        _ result: SendResult,
        for id: String,
        error: String? = nil,
        now: Date = Date()
    ) throws -> Outcome {
        guard var queued = try get(id: id) else { return .unknown }

        switch result {
        case .success:
            try inner.delete(id)
            return .sent

        case .failPermanent:
            try inner.delete(id)
            return .failed(reason: error ?? "delivery permanently failed")

        case .retryTransient:
            let attempts = queued.retryCount + 1
            if attempts >= Self.maxRetries {
                try inner.delete(id)
                return .failed(reason: error ?? "max retries exceeded")
            }
            let delay = Self.retryDelaysMs[min(attempts - 1, Self.retryDelaysMs.count - 1)]
            queued.retryCount = attempts
            queued.nextRetryAt = Int64(now.timeIntervalSince1970 * 1000) + delay
            queued.lastError = error
            try inner.put(queued, key: id)
            return .retrying(attempt: attempts, at: queued.nextRetryAt)
        }
    }

    /// Make a queued message due again — the user tapping "retry".
    @discardableResult
    public func retryNow(id: String, now: Date = Date()) throws -> Bool {
        guard var queued = try get(id: id) else { return false }
        queued.nextRetryAt = Int64(now.timeIntervalSince1970 * 1000)
        try inner.put(queued, key: id)
        return true
    }

    @discardableResult
    public func cancel(id: String) throws -> Bool {
        guard try inner.exists(id) else { return false }
        try inner.delete(id)
        return true
    }

    @discardableResult
    public func clearAll() throws -> Int {
        let keys = try inner.keys()
        for key in keys { try inner.delete(key) }
        return keys.count
    }

    /// What happened to a message after an attempt.
    public enum Outcome: Equatable, Sendable {
        case sent
        case retrying(attempt: Int, at: Int64)
        case failed(reason: String)
        /// No such message in the queue — it was cancelled, or already
        /// delivered by an attempt that overlapped this one.
        case unknown

        /// The ``MessageStatus`` to stamp on the message itself, or nil
        /// when the outcome says nothing new about it.
        public var messageStatus: MessageStatus? {
            switch self {
            case .sent: return .sent
            case .failed: return .failed
            case .retrying: return .pending
            case .unknown: return nil
            }
        }
    }

    public enum Failure: Error, Equatable, CustomStringConvertible {
        case messageHasNoId

        public var description: String {
            switch self {
            case .messageHasNoId:
                return "MessageQueue: the message has no id — the FUDP layer assigns it"
            }
        }
    }
}
