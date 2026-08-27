import Foundation
import FCStorage

/// Local code drafts, the cached registry window, and the hidden list —
/// Android's `CODE_LIST` entity DB plus its local-deleted list, in one
/// store. The same shape as ``ProtocolsStore``, over the `code` index.
///
/// **Drafts and cache do not share a namespace, and that is the point.**
/// ``ProofsStore`` keeps both in one keyspace and tells them apart by
/// ``Proof/onChain``, which works because a proof list is *yours*: every
/// row in it is one you have a stake in, so the cache is bounded by your
/// own activity. The code registry is chain-wide — the window is a slice
/// of everything anybody ever published, and it is truncated on every
/// save. A draft sharing that keyspace would be one truncation away from
/// deletion, and a draft is the only copy of work the user has not yet
/// paid to publish. So drafts get their own keyed namespace and the
/// window is one bounded blob.
///
/// **Hidden is not stopped and not closed.** Hiding is a local decision
/// to stop showing a row on this device; the record carries on existing
/// and another device still shows it. Nothing here is ever carved.
public struct CodesStore {

    /// Drafts, keyed by ``Code/id``.
    public static let draftNamespace = "codes.drafts.v1"
    /// The single cache row: the registry window and the hidden ids.
    public static let cacheNamespace = "codes.cache.v1"
    public static let cacheKey = "window"

    /// How much of the window survives a restart. Bounded because the
    /// cache is one blob that is read and written whole; the chain can
    /// rebuild anything past the cut.
    public static let maxCachedCodes = 200

    /// `lastHeight` for a carve that has been broadcast but not yet
    /// confirmed, so it sorts above every real height. Matches Java's
    /// `Constants.MaX_HEIGHT`, which Android stamps for the same reason.
    public static let unconfirmedHeight: Int64 = Int64(Int32.max)

    /// What the pane shows while offline, plus what the user has hidden.
    public struct Cache: Codable, Equatable, Sendable {
        /// The registry window, as displayed.
        public var codes: [Code]
        /// Record ids the user has hidden from the list.
        public var hiddenIds: [String]
        /// When the window was written, seconds since the epoch — what
        /// an offline pane shows so a stale list says it is stale.
        public var savedAt: Int64?

        public init(
            codes: [Code] = [],
            hiddenIds: [String] = [],
            savedAt: Int64? = nil
        ) {
            self.codes = codes
            self.hiddenIds = hiddenIds
            self.savedAt = savedAt
        }
    }

    private let draftStore: TypedStore<Code>
    private let cache: TypedStore<Cache>

    public init(kv: EncryptedKVStore) {
        self.draftStore = TypedStore(kv: kv, namespace: Self.draftNamespace)
        self.cache = TypedStore(kv: kv, namespace: Self.cacheNamespace)
    }

    // MARK: - drafts

    public func upsertDraft(_ code: Code) throws {
        var c = code
        c.updatedAt = Date()
        try draftStore.put(c, key: c.id)
    }

    public func draft(id: String) throws -> Code? {
        try draftStore.get(id)
    }

    @discardableResult
    public func removeDraft(id: String) throws -> Bool {
        guard try draftStore.exists(id) else { return false }
        try draftStore.delete(id)
        return true
    }

    /// Every draft, most recently worked on first. Drafts have no height
    /// and no chain time, so ``Code/updatedAt`` is the only ordering
    /// that means anything here.
    public func drafts() throws -> [Code] {
        try draftStore.all().map(\.value).sorted { $0.updatedAt > $1.updatedAt }
    }

    /// Promote a draft to a carved record: the txid becomes the id, so
    /// the row is deleted from the draft namespace rather than updated
    /// in place — it is no longer a draft.
    ///
    /// Called right after a broadcast, which is why the result is
    /// stamped broadcast-unconfirmed (``Code/onChain`` nil) rather than
    /// on-chain — no block has seen it yet. The promoted row is returned
    /// rather than written to the window: the window is a slice of the
    /// chain, and this record is not on the chain until a block says so.
    /// ``rememberBroadcast(_:)`` is what puts it in front of the user in
    /// the meantime.
    @discardableResult
    public func promoteDraft(id draftId: String, toTxid txid: String) throws -> Code? {
        guard var draft = try draft(id: draftId) else { return nil }
        try removeDraft(id: draftId)
        let now = Int64(Date().timeIntervalSince1970)
        draft.id = txid
        draft.onChain = nil
        draft.lastTxId = txid
        draft.lastHeight = Self.unconfirmedHeight
        draft.lastTime = now
        draft.birthTime = draft.birthTime ?? now
        draft.updatedAt = Date()
        return draft
    }

    // MARK: - the cache blob

    /// The cached window, or an empty one on a first run.
    public func load() throws -> Cache {
        try cache.get(Self.cacheKey) ?? Cache()
    }

    private func mutate(_ body: (inout Cache) -> Void) throws {
        var c = try load()
        body(&c)
        c.savedAt = Int64(Date().timeIntervalSince1970)
        try cache.put(c, key: Self.cacheKey)
    }

    /// Save the registry window, in the order given, truncated to
    /// ``maxCachedCodes``.
    ///
    /// The order is the caller's — the window is what the pane last
    /// displayed, and re-sorting it here would make the offline view
    /// disagree with the online one it is standing in for.
    public func saveWindow(_ codes: [Code]) throws {
        try mutate { c in
            // Rows carried over keep their original `addedAt`, so "when
            // did this first appear here" survives a refresh.
            let firstSeen = Dictionary(
                c.codes.map { ($0.id, $0.addedAt) }, uniquingKeysWith: { a, _ in a }
            )
            c.codes = codes.prefix(Self.maxCachedCodes).map { row in
                var copy = row
                if let seen = firstSeen[row.id] { copy.addedAt = seen }
                copy.updatedAt = Date()
                return copy
            }
        }
    }

    /// The cached window.
    public func window() throws -> [Code] {
        try load().codes
    }

    /// The cached window minus the hidden rows.
    public func visibleWindow() throws -> [Code] {
        let c = try load()
        let hidden = Set(c.hiddenIds)
        return c.codes.filter { !hidden.contains($0.id) }
    }

    /// Put a just-broadcast record at the head of the window so the
    /// carve the user just paid for is visible before a block confirms
    /// it.
    ///
    /// Keyed by id like everything else, so the row is replaced rather
    /// than duplicated when the same id arrives again from a real fetch
    /// — at which point the chain's copy wins, which is the right way
    /// round.
    public func rememberBroadcast(_ code: Code) throws {
        try mutate { c in
            c.codes.removeAll { $0.id == code.id }
            var row = code
            row.updatedAt = Date()
            c.codes.insert(row, at: 0)
            c.codes = Array(c.codes.prefix(Self.maxCachedCodes))
        }
    }

    /// Apply a local state change to the cached copy of a record, so a
    /// stop / recover / close shows immediately instead of after the
    /// next block.
    ///
    /// **The chain is still the authority.** This edits the *cache*, and
    /// the next refresh overwrites it wholesale with what the indexer
    /// says. That is the intended lifetime: long enough that the button
    /// the user pressed has a visible effect, short enough that a carve
    /// which never confirms does not leave a lie on screen.
    public func markLocally(
        ids: [String], active: Bool? = nil, closed: Bool? = nil, closeStatement: String? = nil
    ) throws {
        let targets = Set(ids)
        guard !targets.isEmpty else { return }
        try mutate { c in
            c.codes = c.codes.map { row in
                guard targets.contains(row.id) else { return row }
                var copy = row
                if let active { copy.active = active }
                if let closed { copy.closed = closed }
                if let closeStatement, !closeStatement.isEmpty {
                    copy.closeStatement = closeStatement
                }
                copy.lastTime = Int64(Date().timeIntervalSince1970)
                copy.updatedAt = Date()
                return copy
            }
        }
    }

    // MARK: - hiding

    public func hiddenIds() throws -> Set<String> {
        Set(try load().hiddenIds)
    }

    /// Hide records from the list. Idempotent, and order is preserved so
    /// the hidden-list view reads in the order things were hidden.
    public func hide(ids: [String]) throws {
        try mutate { c in
            var seen = Set(c.hiddenIds)
            for id in ids where !id.isEmpty && seen.insert(id).inserted {
                c.hiddenIds.append(id)
            }
        }
    }

    public func unhide(ids: [String]) throws {
        let drop = Set(ids)
        try mutate { c in c.hiddenIds.removeAll { drop.contains($0) } }
    }

    /// The hidden records themselves, for the view that offers to
    /// un-hide them. A hidden id whose row has fallen out of the window
    /// is missing from the result but **not** dropped from the hidden
    /// list: the row may come back on the next refresh, and forgetting
    /// the decision would silently un-hide it.
    public func hidden() throws -> [Code] {
        let c = try load()
        let hidden = Set(c.hiddenIds)
        return c.codes.filter { hidden.contains($0.id) }
    }
}
