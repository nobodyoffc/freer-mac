import Foundation
import FCStorage

/// Per-identity proof cache and local drafts, keyed by ``Proof/id`` so
/// a chain fetch merging by record id is idempotent.
///
/// **Two kinds of row share this namespace.** A *draft* is a proof
/// composed but never carved (`onChain == false`, id derived locally);
/// it exists only here, and no sync will ever produce or remove it. A
/// *cached* row is a copy of a chain record, kept so the pane has
/// something to show while offline. The distinction is what
/// ``replaceChainRows(with:)`` turns on: it may drop stale chain copies
/// wholesale, and must never touch a draft, because a draft is the only
/// copy of work the user has not yet paid to publish.
public struct ProofsStore {

    public static let namespace = "proofs.v1"

    /// `lastHeight` for a carve that has been broadcast but not yet
    /// confirmed, so it sorts above every real height. Matches Java's
    /// `Constants.MaX_HEIGHT`, which Android stamps for the same reason.
    public static let unconfirmedHeight: Int64 = Int64(Int32.max)

    private let inner: TypedStore<Proof>

    public init(kv: EncryptedKVStore) {
        self.inner = TypedStore(kv: kv, namespace: Self.namespace)
    }

    public func upsert(_ proof: Proof) throws {
        var p = proof
        p.updatedAt = Date()
        try inner.put(p, key: p.id)
    }

    public func get(id: String) throws -> Proof? {
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
    public func all() throws -> [Proof] {
        try inner.all().map(\.value).sorted { a, b in
            let ah = a.lastHeight ?? (a.onChain == false ? 0 : Self.unconfirmedHeight)
            let bh = b.lastHeight ?? (b.onChain == false ? 0 : Self.unconfirmedHeight)
            if ah != bh { return ah > bh }
            return a.addedAt > b.addedAt
        }
    }

    /// Composed here, never carved — the rows no sync will restore if
    /// they are dropped.
    public func drafts() throws -> [Proof] {
        try all().filter { $0.onChain == false }
    }

    /// Replace the cached chain rows with `proofs`, leaving drafts
    /// alone.
    ///
    /// Chain copies are replaced rather than merged because the chain
    /// is the authority for every field on them: a merge would let a
    /// stale local `cosignersSigned` survive a refresh that exists
    /// precisely to update it. Rows whose id is in `proofs` keep their
    /// original ``Proof/addedAt`` so "when did this first appear here"
    /// stays meaningful across refreshes.
    @discardableResult
    public func replaceChainRows(with proofs: [Proof]) throws -> Int {
        let incoming = Dictionary(proofs.map { ($0.id, $0) }, uniquingKeysWith: { a, _ in a })
        for existing in try all() where existing.onChain != false {
            if incoming[existing.id] == nil {
                try remove(id: existing.id)
            }
        }
        for var proof in proofs {
            if let existing = try get(id: proof.id) {
                proof.addedAt = existing.addedAt
            }
            try upsert(proof)
        }
        return proofs.count
    }

    /// Promote a draft to a carved proof: the txid becomes the id, so
    /// the row is deleted and re-inserted under its new key rather than
    /// updated in place.
    ///
    /// Called right after a broadcast, which is why the result is
    /// stamped broadcast-unconfirmed (``Proof/onChain`` nil) rather than
    /// on-chain — no block has seen it yet.
    @discardableResult
    public func promoteDraft(id draftId: String, toTxid txid: String) throws -> Proof? {
        guard var draft = try get(id: draftId) else { return nil }
        try remove(id: draftId)
        draft.id = txid
        draft.onChain = nil
        draft.lastTxId = txid
        draft.lastHeight = Self.unconfirmedHeight
        draft.lastTime = Int64(Date().timeIntervalSince1970)
        draft.birthTime = draft.birthTime ?? Int64(Date().timeIntervalSince1970)
        try upsert(draft)
        return draft
    }
}
