import Foundation
import FCStorage

/// Per-identity cache of one media kind's records and local drafts,
/// keyed by ``MediaRecord/id``. The same shape as ``TextsStore``, over
/// whichever of the `image` / `sound` / `video` indices ``kind`` names.
///
/// **One store per kind, not one store with a kind column.** Each is a
/// separate ``MediaKind/namespace``, so a refresh of the video shelf
/// cannot drop a row from the image shelf — ``replaceChainRows(with:)``
/// deletes what the chain no longer returns, and a shared namespace
/// would have it delete every other kind on every refresh.
///
/// **Two kinds of row share this namespace**, as in ``ProofsStore``: a
/// *draft* is an image composed but never carved (`onChain == false`, id
/// derived locally), which no sync will ever produce or remove; a
/// *cached* row is a copy of a chain record, kept so the pane has
/// something to show while offline. ``replaceChainRows(with:)`` may
/// drop stale chain copies wholesale and must never touch a draft.
public struct MediaStore {


    /// `lastHeight` for a carve that has been broadcast but not yet
    /// confirmed, so it sorts above every real height. Matches Java's
    /// `Constants.MaX_HEIGHT`.
    public static let unconfirmedHeight: Int64 = Int64(Int32.max)

    public let kind: MediaKind
    private let inner: TypedStore<MediaRecord>

    public init(kv: EncryptedKVStore, kind: MediaKind) {
        self.kind = kind
        self.inner = TypedStore(kv: kv, namespace: kind.namespace)
    }

    public func upsert(_ record: MediaRecord) throws {
        var r = record
        // The namespace is the authority on kind: a row filed here is
        // this kind whatever the caller believed, and a mismatch would
        // otherwise survive a save/reload as a row in the wrong pane.
        r.kind = kind
        r.updatedAt = Date()
        try inner.put(r, key: r.id)
    }

    public func get(id: String) throws -> MediaRecord? {
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
    public func all() throws -> [MediaRecord] {
        try inner.all().map(\.value).sorted { a, b in
            let ah = a.lastHeight ?? (a.onChain == false ? 0 : Self.unconfirmedHeight)
            let bh = b.lastHeight ?? (b.onChain == false ? 0 : Self.unconfirmedHeight)
            if ah != bh { return ah > bh }
            return a.addedAt > b.addedAt
        }
    }

    /// Composed here, never carved — the rows no sync would restore.
    public func drafts() throws -> [MediaRecord] {
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
    public func replaceChainRows(with records: [MediaRecord]) throws -> Int {
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
    public func mergeChainRows(_ records: [MediaRecord]) throws -> Int {
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
    /// on-chain — no block has seen it yet. ``MediaRecord/ver`` becomes
    /// `"1"` because that is what the indexer will assign to a first
    /// edition.
    @discardableResult
    public func promoteDraft(id draftId: String, toTxid txid: String) throws -> MediaRecord? {
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
