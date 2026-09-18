import Foundation
import FCStorage

/// Per-identity cache of statements and local drafts, keyed by
/// ``Statement/id``.
///
/// **The one Publish store with nothing to update.** A statement cannot
/// be edited, deleted or recovered once carved, so this has no flag to
/// flip and no edition to bump — a cached row is a permanent fact, and
/// the only mutable thing in here is a draft nobody has paid for yet.
public struct StatementsStore {

    public static let namespace = "statements.v1"

    /// `birthHeight` for a carve that has been broadcast but not yet
    /// confirmed, so it sorts above every real height. Statements have
    /// no `lastHeight` — nothing ever touches them again — so it is
    /// birth that stands in for both.
    public static let unconfirmedHeight: Int64 = Int64(Int32.max)

    private let inner: TypedStore<Statement>

    public init(kv: EncryptedKVStore) {
        self.inner = TypedStore(kv: kv, namespace: Self.namespace)
    }

    public func upsert(_ statement: Statement) throws {
        var s = statement
        s.updatedAt = Date()
        try inner.put(s, key: s.id)
    }

    public func get(id: String) throws -> Statement? {
        try inner.get(id)
    }

    @discardableResult
    public func remove(id: String) throws -> Bool {
        guard try inner.exists(id) else { return false }
        try inner.delete(id)
        return true
    }

    /// Every row, newest first — by `birthHeight`, which for a
    /// statement is the only height there is.
    public func all() throws -> [Statement] {
        try inner.all().map(\.value).sorted { a, b in
            let ah = a.birthHeight ?? (a.onChain == false ? 0 : Self.unconfirmedHeight)
            let bh = b.birthHeight ?? (b.onChain == false ? 0 : Self.unconfirmedHeight)
            if ah != bh { return ah > bh }
            return a.addedAt > b.addedAt
        }
    }

    /// Composed here, never carved — and, for this record, the only
    /// thing anyone can still change their mind about.
    public func drafts() throws -> [Statement] {
        try all().filter { $0.onChain == false }
    }

    /// Replace the cached chain rows with `statements`, leaving drafts
    /// alone.
    ///
    /// **`complete` is the caller saying it saw everything.** A refresh
    /// that fetched only the first page has not: the rows it did not
    /// ask for are absent from `statements` for the same reason a deleted
    /// row is, and pruning on that could not tell the two apart — a
    /// shelf of three hundred records became the latest twenty-five,
    /// every refresh. Pass `false` whenever more pages remain and the
    /// call merges without dropping anything.
    ///
    /// **A broadcast-unconfirmed row is never dropped.** `onChain` nil
    /// means the carve is paid for and waiting for a block, so the
    /// indexer has nothing to return yet and absence proves nothing.
    /// Pruning those meant the record the user had just published
    /// disappeared from under them on the refresh that followed the
    /// broadcast. Only a row the chain has confirmed and now omits is
    /// stale enough to remove.
    @discardableResult
    public func replaceChainRows(with statements: [Statement], complete: Bool = true) throws -> Int {
        let incoming = Dictionary(statements.map { ($0.id, $0) }, uniquingKeysWith: { a, _ in a })
        if complete {
            for existing in try all() where existing.onChain == true {
                if incoming[existing.id] == nil {
                    try remove(id: existing.id)
                }
            }
        }
        for var statement in statements {
            if let existing = try get(id: statement.id) {
                statement.addedAt = existing.addedAt
            }
            try upsert(statement)
        }
        return statements.count
    }

    /// Merge chain rows in without dropping anything — for a browse of
    /// the whole chain, where the page is a window rather than the
    /// truth about this identity.
    @discardableResult
    public func mergeChainRows(_ statements: [Statement]) throws -> Int {
        for var statement in statements {
            if let existing = try get(id: statement.id) {
                statement.addedAt = existing.addedAt
            }
            try upsert(statement)
        }
        return statements.count
    }

    /// Promote a draft to a carved statement: the txid becomes the id,
    /// so the row is deleted and re-inserted under its new key.
    ///
    /// Stamped broadcast-unconfirmed (`onChain` nil) rather than
    /// on-chain — no block has seen it yet.
    @discardableResult
    public func promoteDraft(id draftId: String, toTxid txid: String) throws -> Statement? {
        guard var draft = try get(id: draftId) else { return nil }
        try remove(id: draftId)
        draft.id = txid
        draft.onChain = nil
        draft.birthHeight = Self.unconfirmedHeight
        draft.birthTime = draft.birthTime ?? Int64(Date().timeIntervalSince1970)
        try upsert(draft)
        return draft
    }
}
