import Foundation
import FCStorage

/// Editing and withdrawing a message you sent: the rules, independent of
/// transport, store or UI. The port of Android's `MessageAmend.java`, with
/// the same test cases (`MessageAmendTests` / `MessageAmendTest`).
///
/// **Wire.** An amendment is an ordinary signed message from the original's
/// author, sent to the same thread:
/// - `EDIT` — `content` is the new text.
/// - `DELETE`, shown as *withdraw* — `content` is a short human line that
///   only a client predating this feature reads.
///
/// Both name the original in `requestId`, as a receipt does. An edit always
/// names the **original**, never an earlier edit, so the versions form a
/// flat list and arrival order does not matter.
///
/// **What a withdraw cannot do.** It is a request to well-behaved clients:
/// a recipient that already holds the message keeps whatever it chooses
/// to. The author's client also deletes the DOCK item where it can, which
/// is the only real erasure — it stops delivery to whoever has not fetched
/// it yet. An item our own DOCK *forwarded* is filed under the forwarding
/// server's identity, so that one stays.
///
/// **The window** is measured between the two *signed* timestamps, never
/// against a receiver's clock: a recipient that was offline for a day
/// fetches the original and its edit together. An author can forge their
/// own timestamps, but that only lets them amend their own message late,
/// which is no worse than sending a new one.
public enum MessageAmend {

    /// How long after sending its author may edit or withdraw a message.
    public static let windowMs: Int64 = 10 * 60_000

    /// Bound on versions kept per message.
    public static let maxVersions = 20

    public enum Outcome: Equatable, Sendable {
        /// The original changed: persist it and redraw it.
        case applied
        /// Already applied, or the original is withdrawn.
        case duplicate
        /// Not a valid amendment of this original.
        case rejected
    }

    public static func isAmend(_ m: ImMessage) -> Bool {
        m.contentType == .edit || m.contentType == .delete
    }

    public static func target(of op: ImMessage) -> String? {
        isAmend(op) ? op.requestId : nil
    }

    /// Only text can be edited; anything can be withdrawn.
    public static func isEditable(_ original: ImMessage) -> Bool {
        original.contentType == .text
    }

    /// Whether `fid` may still edit or withdraw `original` at `nowMs`.
    public static func canAmend(_ original: ImMessage, as fid: String, nowMs: Int64) -> Bool {
        guard original.isOutgoing(from: fid), !original.isWithdrawn, !isAmend(original),
              original.hasFudpId, let ts = original.timestamp
        else { return false }
        if original.status == .pending || original.status == .failed { return false }
        let age = nowMs - ts
        return age >= 0 && age <= windowMs
    }

    public static func edit(of original: ImMessage, text: String, nowMs: Int64) -> ImMessage {
        var op = base(original, .edit, nowMs)
        op.content = text
        return op
    }

    public static func withdraw(of original: ImMessage, fallbackText: String, nowMs: Int64) -> ImMessage {
        var op = base(original, .delete, nowMs)
        op.content = fallbackText
        return op
    }

    private static func base(_ original: ImMessage, _ ct: ContentType, _ nowMs: Int64) -> ImMessage {
        ImMessage(
            type: original.type,
            senderId: original.senderId,
            targetId: original.targetId,
            timestamp: nowMs,
            contentType: ct,
            requestId: original.id,
            status: .pending,
            unread: false
        )
    }

    /// Same author (the envelope signature already proved who wrote `op`),
    /// same thread, signed within the window.
    public static func isValid(_ op: ImMessage, for original: ImMessage) -> Bool {
        guard isAmend(op), !isAmend(original),
              let id = original.id, id == op.requestId,
              let author = original.senderId, author == op.senderId,
              op.type == original.type,
              let target = op.targetId, target == original.targetId,
              let t0 = original.timestamp, let t1 = op.timestamp
        else { return false }
        let gap = t1 - t0
        guard gap >= 0, gap <= windowMs else { return false }
        if op.contentType == .edit {
            guard isEditable(original),
                  let text = op.content,
                  !text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            else { return false }
        }
        return true
    }

    /// Apply `op` to `original` in place. A withdraw wins over everything;
    /// edits merge by signed timestamp, so a late older edit lands in the
    /// history instead of overwriting a newer one.
    @discardableResult
    public static func apply(_ op: ImMessage, to original: inout ImMessage) -> Outcome {
        guard isValid(op, for: original) else { return .rejected }
        if original.isWithdrawn { return .duplicate }

        if op.contentType == .delete {
            original.withdrawn = true
            original.withdrawnAt = op.timestamp
            original.content = nil
            original.data = nil
            original.body = nil
            original.editHistory = nil
            original.editId = nil
            return .applied
        }

        var versions = original.editHistory ?? []
        versions.append(.init(
            content: original.content,
            at: original.editedAt ?? original.timestamp,
            editId: original.editId
        ))
        if let opId = op.id, versions.contains(where: { $0.editId == opId }) { return .duplicate }
        if versions.count >= maxVersions { return .rejected }
        versions.append(.init(content: op.content, at: op.timestamp, editId: op.id))

        // The original (nil editId) sorts first at equal times; ties between
        // edits go by id. Same order as Android's comparator.
        versions.sort { a, b in
            let ta = a.at ?? 0, tb = b.at ?? 0
            if ta != tb { return ta < tb }
            return (a.editId ?? "") < (b.editId ?? "")
        }
        let latest = versions.removeLast()
        original.content = latest.content
        original.editId = latest.editId
        original.editedAt = latest.editId == nil ? nil : latest.at
        original.editHistory = versions.isEmpty ? nil : versions
        return .applied
    }
}

/// Amendments that arrived before they could be applied: the original
/// has not arrived yet, or the edit (or its original) is still sealed.
///
/// Keyed `<originalId>-<opId>` within a conversation, so everything
/// waiting for one message is a prefix scan away.
public struct AmendmentsStore {

    public static let namespacePrefix = "im.amends.v1."

    private let kv: EncryptedKVStore

    public init(kv: EncryptedKVStore) {
        self.kv = kv
    }

    private func store(_ conversationId: String) -> TypedStore<ImMessage> {
        TypedStore(kv: kv, namespace: Self.namespacePrefix + conversationId)
    }

    public func hold(_ op: ImMessage, in conversationId: String) throws {
        guard let target = MessageAmend.target(of: op), let id = op.id else { return }
        try store(conversationId).put(op, key: target + "-" + id)
    }

    /// Everything waiting for `originalId`.
    public func held(for originalId: String, in conversationId: String) throws -> [(key: String, op: ImMessage)] {
        let s = store(conversationId)
        return try s.keys()
            .filter { $0.hasPrefix(originalId + "-") }
            .compactMap { key in try s.get(key).map { (key, $0) } }
    }

    /// Everything waiting in a conversation, for opening sealed edits.
    public func all(in conversationId: String) throws -> [(key: String, op: ImMessage)] {
        try store(conversationId).all().map { ($0.key, $0.value) }
    }

    public func replace(_ op: ImMessage, key: String, in conversationId: String) throws {
        try store(conversationId).put(op, key: key)
    }

    public func drop(key: String, in conversationId: String) throws {
        try store(conversationId).delete(key)
    }

    /// Apply what has been waiting for `message`, in place. Returns whether
    /// anything changed. A sealed original takes only a withdraw; its edits
    /// keep waiting for its text, and a sealed edit waits for its key.
    @discardableResult
    public func applyHeld(to message: inout ImMessage, in conversationId: String) throws -> Bool {
        guard let id = message.id else { return false }
        var changed = false
        for (key, op) in try held(for: id, in: conversationId) {
            if op.contentType == .edit && (op.isSealed || message.isSealed) { continue }
            if MessageAmend.apply(op, to: &message) == .applied { changed = true }
            try drop(key: key, in: conversationId)
        }
        if message.isWithdrawn {
            // Nothing else can ever apply to it.
            for (key, _) in try held(for: id, in: conversationId) { try drop(key: key, in: conversationId) }
        }
        return changed
    }
}
