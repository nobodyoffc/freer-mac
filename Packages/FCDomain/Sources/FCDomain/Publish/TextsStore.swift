import Foundation
import FCStorage

/// Per-identity cache of text records and local drafts, keyed by
/// ``TextRecord/id`` so a chain fetch merging by record id is
/// idempotent.
///
/// **Two kinds of row share this namespace**, as in ``ProofsStore``: a
/// *draft* is a work composed but never carved (`onChain == false`, id
/// derived locally), which no sync will ever produce or remove; a
/// *cached* row is a copy of a chain record, kept so the pane has
/// something to show while offline. ``replaceChainRows(with:)`` may
/// drop stale chain copies wholesale and must never touch a draft.
public struct TextsStore {

    public static let namespace = "texts.v1"

    /// `lastHeight` for a carve that has been broadcast but not yet
    /// confirmed, so it sorts above every real height. Matches Java's
    /// `Constants.MaX_HEIGHT`.
    public static let unconfirmedHeight: Int64 = Int64(Int32.max)

    private let inner: TypedStore<TextRecord>

    public init(kv: EncryptedKVStore) {
        self.inner = TypedStore(kv: kv, namespace: Self.namespace)
    }

    public func upsert(_ record: TextRecord) throws {
        var r = record
        r.updatedAt = Date()
        try inner.put(r, key: r.id)
    }

    public func get(id: String) throws -> TextRecord? {
        try inner.get(id)
    }

    @discardableResult
    public func remove(id: String) throws -> Bool {
        guard try inner.exists(id) else { return false }
        try inner.delete(id)
        return true
    }

    /// Every row, newest activity first. A broadcast-but-unconfirmed
    /// carve carries ``unconfirmedHeight`` and so sits at the top,
    /// which is where the user just put it.
    public func all() throws -> [TextRecord] {
        try inner.all().map(\.value).sorted { a, b in
            let ah = a.lastHeight ?? (a.onChain == false ? 0 : Self.unconfirmedHeight)
            let bh = b.lastHeight ?? (b.onChain == false ? 0 : Self.unconfirmedHeight)
            if ah != bh { return ah > bh }
            return a.addedAt > b.addedAt
        }
    }

    /// Composed here, never carved — the rows no sync would restore.
    public func drafts() throws -> [TextRecord] {
        try all().filter { $0.onChain == false }
    }

    /// Replace the cached chain rows with `records`, leaving drafts
    /// alone.
    ///
    /// Chain copies are replaced rather than merged because the chain
    /// is the authority for every field on them — a merge would let a
    /// stale `deleted` or `tRate` survive the refresh that exists to
    /// update it. Rows still present keep their original `addedAt`, so
    /// "when did this first appear here" stays meaningful.
    @discardableResult
    public func replaceChainRows(with records: [TextRecord]) throws -> Int {
        let incoming = Dictionary(records.map { ($0.id, $0) }, uniquingKeysWith: { a, _ in a })
        for existing in try all() where existing.onChain != false {
            if incoming[existing.id] == nil {
                try remove(id: existing.id)
            }
        }
        for var record in records {
            if let existing = try get(id: record.id) {
                record.addedAt = existing.addedAt
            }
            try upsert(record)
        }
        return records.count
    }

    /// Merge chain rows in without dropping anything — for a browse of
    /// somebody else's shelf, where the page is a window on the chain
    /// rather than the whole truth about this identity.
    @discardableResult
    public func mergeChainRows(_ records: [TextRecord]) throws -> Int {
        for var record in records {
            if let existing = try get(id: record.id) {
                record.addedAt = existing.addedAt
            }
            try upsert(record)
        }
        return records.count
    }

    /// Promote a draft to a carved record: the txid becomes the id, so
    /// the row is deleted and re-inserted under its new key rather than
    /// updated in place.
    ///
    /// Called right after a broadcast, which is why the result is
    /// stamped broadcast-unconfirmed (`onChain` nil) rather than
    /// on-chain — no block has seen it yet. ``TextRecord/ver`` becomes
    /// `"1"` because that is what the indexer will assign to a first
    /// edition.
    @discardableResult
    public func promoteDraft(id draftId: String, toTxid txid: String) throws -> TextRecord? {
        guard var draft = try get(id: draftId) else { return nil }
        try remove(id: draftId)
        draft.id = txid
        draft.onChain = nil
        draft.ver = "1"
        draft.lastTxId = txid
        draft.lastHeight = Self.unconfirmedHeight
        draft.lastTime = Int64(Date().timeIntervalSince1970)
        draft.birthTime = draft.birthTime ?? Int64(Date().timeIntervalSince1970)
        try upsert(draft)
        return draft
    }
}
