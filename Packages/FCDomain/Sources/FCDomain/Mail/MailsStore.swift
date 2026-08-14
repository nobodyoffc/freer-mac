import Foundation
import FCStorage

/// Per-identity mailbox. Keyed by ``Mail/id`` — the carve txid for an
/// on-chain mail, the derived hash for a local draft — so a chain sync
/// merging by id is idempotent.
///
/// Bodies are stored sealed (``Mail/cipher``, never ``Mail/content``), so
/// this store can be read without a key; that is also why ``search(_:)``
/// cannot see message text. A pane that has decrypted its rows filters
/// them in memory with ``Mail/matches(query:)`` instead.
public struct MailsStore {

    public static let namespace = "mails.v1"

    /// The `lastHeight` Android stamps on a mail it has broadcast but not
    /// yet seen confirmed (`Constants.MaX_HEIGHT`). Sorting by height
    /// descending therefore floats just-sent mail to the top, where the
    /// user is looking for it, and a real height replaces it on the next
    /// sync.
    public static let unconfirmedHeight: Int64 = 999_999_999

    private let inner: TypedStore<Mail>

    public init(kv: EncryptedKVStore) {
        self.inner = TypedStore(kv: kv, namespace: Self.namespace)
    }

    /// Store a mail, deriving its id first if it has none. The plaintext
    /// body is dropped on the way in — a stored mail is always sealed,
    /// whatever the caller happened to be holding.
    ///
    /// ``Mail/decrypted`` **is** kept. It is not plaintext but a fact
    /// about key availability: whether the body opened the last time
    /// anyone tried. Persisting it is what lets a list distinguish "not
    /// opened yet" from "needs a key this identity doesn't have", and it
    /// saves an ECDH per row on the next sync. Read it as a statement
    /// about the key, never as "content is loaded" — that is
    /// ``Mail/content`` being non-nil, which for a stored row it never
    /// is.
    public func upsert(_ mail: Mail) throws {
        var m = mail
        m.checkIdWithCreate()
        guard let id = m.id else { return }
        if m.cipher != nil {
            m.content = nil
        }
        try inner.put(m, key: id)
    }

    public func get(id: String) throws -> Mail? {
        try inner.get(id)
    }

    @discardableResult
    public func remove(id: String) throws -> Bool {
        guard try inner.exists(id) else { return false }
        try inner.delete(id)
        return true
    }

    public func removeAll(ids: [String]) throws -> Int {
        try ids.reduce(0) { try $0 + (remove(id: $1) ? 1 : 0) }
    }

    /// Every mail, newest first — `lastHeight` descending then id
    /// descending, matching `MailManager.makeFcdsl`'s sort so local and
    /// server order agree. Mails with no height (a draft that was never
    /// carved) sort as unconfirmed, i.e. at the top.
    public func all() throws -> [Mail] {
        try inner.all().map(\.value).sorted(by: Self.newestFirst)
    }

    /// Mails that have not been deleted — the inbox/sent view.
    public func active() throws -> [Mail] {
        try all().filter { !$0.isDeleted }
    }

    /// Mails whose newest carve was a `delete` op — the Deleted view.
    /// They are kept, not dropped: a delete is recoverable on chain, so
    /// throwing the local row away would make Recover a blind operation.
    public func deleted() throws -> [Mail] {
        try all().filter(\.isDeleted)
    }

    public func unreadCount() throws -> Int {
        try all().filter { $0.unread == true && !$0.isDeleted }.count
    }

    /// The highest `lastHeight` we hold, ignoring the not-yet-confirmed
    /// sentinel — the watermark an incremental sync resumes from.
    public func highestKnownHeight() throws -> Int64? {
        try all()
            .compactMap(\.lastHeight)
            .filter { $0 != Self.unconfirmedHeight }
            .max()
    }

    @discardableResult
    public func markRead(id: String) throws -> Bool {
        guard var mail = try get(id: id), mail.unread == true else { return false }
        mail.unread = false
        try inner.put(mail, key: id)
        return true
    }

    /// Marks every unread mail read. Returns how many changed.
    @discardableResult
    public func markAllRead() throws -> Int {
        var changed = 0
        for mail in try all() where mail.unread == true {
            guard let id = mail.id else { continue }
            var m = mail
            m.unread = false
            try inner.put(m, key: id)
            changed += 1
        }
        return changed
    }

    /// Substring search over the fields that survive at rest: the two
    /// FIDs, their cached names, and the id. **Not** the body — see the
    /// type's note.
    public func search(_ query: String) throws -> [Mail] {
        let needle = query.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !needle.isEmpty else { return try all() }
        return try all().filter { $0.matches(query: needle) }
    }

    static func newestFirst(_ a: Mail, _ b: Mail) -> Bool {
        let ha = a.lastHeight ?? unconfirmedHeight
        let hb = b.lastHeight ?? unconfirmedHeight
        if ha != hb { return ha > hb }
        return (a.id ?? "") > (b.id ?? "")
    }
}
