import Foundation
import FCStorage

/// The cached token window, the cached holdings, the history window and
/// the two hidden lists — Android's `TOKEN_LIST`, the `TokenHolder`
/// entity DB, `TOKEN_HISTORY_LIST`, `HIDDEN_TOKEN_LIST` and the
/// local-deleted holder list, in one store.
///
/// **Everything here is a cache except the hidden lists.** Tokens,
/// holdings and history are chain state: dropping any of it costs one
/// refresh. The two hidden lists are the user's own decisions about
/// what to stop looking at, no chain fetch will ever restore them, and
/// that asymmetry is what ``replaceHolders(with:)`` and
/// ``saveTokenWindow(_:)`` are careful about.
///
/// **Hidden is not closed and not destroyed.** Hiding is a local
/// decision to stop showing a row on this device; the token carries on
/// existing, the balance carries on being spendable, and another
/// device will still show it. Nothing here is ever carved.
public struct TokensStore {

    /// Holdings, keyed by ``TokenHolder/id``.
    public static let holderNamespace = "tokens.holders.v1"
    /// The single cache row: token window, history window, hidden ids.
    public static let cacheNamespace = "tokens.cache.v1"
    public static let cacheKey = "window"

    /// How much of each window survives a restart. Bounded because the
    /// cache is one blob that is read and written whole; the chain can
    /// rebuild anything past the cut.
    public static let maxCachedTokens = 200
    public static let maxCachedHistory = 200

    /// What the pane shows while offline, plus what the user has hidden.
    public struct Cache: Codable, Equatable, Sendable {
        /// The chain-wide token window, as displayed.
        public var tokens: [Token]
        /// The history window, newest first.
        public var history: [TokenHistory]
        /// Token ids the user has hidden from the chain-wide list.
        public var hiddenTokenIds: [String]
        /// Holder-row ids the user has hidden from their holdings list.
        /// Ids rather than token ids, because a holding is a (FID,
        /// token) pair and hiding one identity's dust should not hide
        /// another identity's stake in the same token.
        public var hiddenHolderIds: [String]
        /// When the windows were written, seconds since the epoch — what
        /// an offline pane shows so a stale list says it is stale.
        public var savedAt: Int64?

        public init(
            tokens: [Token] = [],
            history: [TokenHistory] = [],
            hiddenTokenIds: [String] = [],
            hiddenHolderIds: [String] = [],
            savedAt: Int64? = nil
        ) {
            self.tokens = tokens
            self.history = history
            self.hiddenTokenIds = hiddenTokenIds
            self.hiddenHolderIds = hiddenHolderIds
            self.savedAt = savedAt
        }
    }

    private let holders: TypedStore<TokenHolder>
    private let cache: TypedStore<Cache>

    public init(kv: EncryptedKVStore) {
        self.holders = TypedStore(kv: kv, namespace: Self.holderNamespace)
        self.cache = TypedStore(kv: kv, namespace: Self.cacheNamespace)
    }

    // MARK: - holdings

    public func upsertHolder(_ holder: TokenHolder) throws {
        var h = holder
        h.updatedAt = Date()
        try holders.put(h, key: h.id)
    }

    public func holder(id: String) throws -> TokenHolder? {
        try holders.get(id)
    }

    public func holder(fid: String, tokenId: String) throws -> TokenHolder? {
        try holders.get(TokenHolder.id(fid: fid, tokenId: tokenId))
    }

    @discardableResult
    public func removeHolder(id: String) throws -> Bool {
        guard try holders.exists(id) else { return false }
        try holders.delete(id)
        return true
    }

    /// Every cached holding, newest activity first.
    public func allHolders() throws -> [TokenHolder] {
        try holders.all().map(\.value).sorted { a, b in
            let ah = a.lastHeight ?? 0
            let bh = b.lastHeight ?? 0
            if ah != bh { return ah > bh }
            return a.addedAt > b.addedAt
        }
    }

    /// Cached holdings minus the ones the user hid.
    public func visibleHolders() throws -> [TokenHolder] {
        let hidden = Set(try load().hiddenHolderIds)
        return try allHolders().filter { !hidden.contains($0.id) }
    }

    /// Replace the cached holdings with `rows`.
    ///
    /// Replaced rather than merged because the chain is the authority
    /// for every field on a holder row: a merge would let a stale
    /// balance survive a refresh that exists precisely to update it.
    /// Rows whose id is in `rows` keep their original
    /// ``TokenHolder/addedAt``, so "when did this first appear here"
    /// stays meaningful across refreshes.
    ///
    /// **A row dropping out of the fetch is deleted.** A holder record
    /// the chain no longer returns is one this FID no longer has, and
    /// keeping the last copy on screen would show a balance that cannot
    /// be spent. Hidden ids are left alone — hiding is about the *list*,
    /// and un-hiding a row that has since been refetched should bring
    /// the row back, not a fossil.
    @discardableResult
    public func replaceHolders(with rows: [TokenHolder]) throws -> Int {
        let incoming = Dictionary(rows.map { ($0.id, $0) }, uniquingKeysWith: { a, _ in a })
        for existing in try allHolders() where incoming[existing.id] == nil {
            try removeHolder(id: existing.id)
        }
        for var row in rows {
            if let existing = try holder(id: row.id) {
                row.addedAt = existing.addedAt
            }
            try upsertHolder(row)
        }
        return rows.count
    }

    /// Merge a page of holdings in without dropping anything — what
    /// paging uses, where the fetch is a *slice* rather than the whole
    /// set and ``replaceHolders(with:)`` would delete every row above
    /// the cursor.
    @discardableResult
    public func mergeHolders(_ rows: [TokenHolder]) throws -> Int {
        for var row in rows {
            if let existing = try holder(id: row.id) {
                row.addedAt = existing.addedAt
            }
            try upsertHolder(row)
        }
        return rows.count
    }

    // MARK: - the cache blob

    /// The cached windows, or an empty set on a first run.
    public func load() throws -> Cache {
        try cache.get(Self.cacheKey) ?? Cache()
    }

    private func mutate(_ body: (inout Cache) -> Void) throws {
        var c = try load()
        body(&c)
        c.savedAt = Int64(Date().timeIntervalSince1970)
        try cache.put(c, key: Self.cacheKey)
    }

    /// Save the chain-wide token window, newest first, truncated to
    /// ``maxCachedTokens``.
    public func saveTokenWindow(_ tokens: [Token]) throws {
        try mutate { $0.tokens = Array(tokens.prefix(Self.maxCachedTokens)) }
    }

    /// The cached token window.
    public func tokenWindow() throws -> [Token] {
        try load().tokens
    }

    /// The cached token window minus the hidden ones.
    public func visibleTokenWindow() throws -> [Token] {
        let c = try load()
        let hidden = Set(c.hiddenTokenIds)
        return c.tokens.filter { !hidden.contains($0.id) }
    }

    public func saveHistoryWindow(_ history: [TokenHistory]) throws {
        try mutate { $0.history = Array(history.prefix(Self.maxCachedHistory)) }
    }

    public func historyWindow() throws -> [TokenHistory] {
        try load().history
    }

    // MARK: - hiding

    public func hiddenTokenIds() throws -> Set<String> {
        Set(try load().hiddenTokenIds)
    }

    public func hiddenHolderIds() throws -> Set<String> {
        Set(try load().hiddenHolderIds)
    }

    /// Hide tokens from the chain-wide list. Idempotent, and order is
    /// preserved so the hidden-list view reads in the order things were
    /// hidden.
    public func hideTokens(ids: [String]) throws {
        try mutate { c in
            var seen = Set(c.hiddenTokenIds)
            for id in ids where !id.isEmpty && seen.insert(id).inserted {
                c.hiddenTokenIds.append(id)
            }
        }
    }

    public func unhideTokens(ids: [String]) throws {
        let drop = Set(ids)
        try mutate { c in c.hiddenTokenIds.removeAll { drop.contains($0) } }
    }

    public func hideHolders(ids: [String]) throws {
        try mutate { c in
            var seen = Set(c.hiddenHolderIds)
            for id in ids where !id.isEmpty && seen.insert(id).inserted {
                c.hiddenHolderIds.append(id)
            }
        }
    }

    public func unhideHolders(ids: [String]) throws {
        let drop = Set(ids)
        try mutate { c in c.hiddenHolderIds.removeAll { drop.contains($0) } }
    }

    /// The hidden holdings themselves, for the pane that offers to
    /// un-hide them. A hidden id whose row is no longer cached is
    /// dropped from the result but **not** from the hidden list: the
    /// row may come back on the next refresh, and forgetting the
    /// decision would silently un-hide it.
    public func hiddenHolders() throws -> [TokenHolder] {
        let hidden = try hiddenHolderIds()
        return try allHolders().filter { hidden.contains($0.id) }
    }

    /// The hidden tokens themselves, same contract as
    /// ``hiddenHolders()``.
    public func hiddenTokens() throws -> [Token] {
        let c = try load()
        let hidden = Set(c.hiddenTokenIds)
        return c.tokens.filter { hidden.contains($0.id) }
    }
}
