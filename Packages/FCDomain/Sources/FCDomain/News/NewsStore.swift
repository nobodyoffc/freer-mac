import Foundation
import FCStorage

/// The cached feed window plus the watermark that decides what counts
/// as new — Android's `NEWS_LIST` list and `LAST_HEIGHT_OF_NEWS` state
/// value, in one row.
///
/// **One blob, not one row per item.** Every other store here is keyed
/// by entity id because callers query it — a mail by txid, a contact by
/// FID. Nothing ever asks for a single news item: the pane wants "the
/// window I was looking at" and nothing else, the window is bounded by
/// ``maxCachedNews``, and the feed is a cache the chain can rebuild. A
/// keyed namespace would buy pruning work and a deletion-ordering
/// question in exchange for a lookup nobody makes.
///
/// **The cache is public data; the watermark is not.** The feed itself
/// is the same for every identity, but "what have I already seen" is
/// personal, and this store lives on the per-main encrypted DB, so both
/// halves stay with the identity that read them.
public struct NewsCache: Codable, Equatable, Sendable {
    /// Newest first, as displayed.
    public var news: [News]
    /// Chain tip as of the last successful fetch. Anything above it on
    /// the next fetch is new to this device.
    public var lastSeenHeight: Int64?
    /// When the window was written, seconds since the epoch — what an
    /// offline pane shows so a stale feed says it is stale.
    public var savedAt: Int64?

    public init(news: [News] = [], lastSeenHeight: Int64? = nil, savedAt: Int64? = nil) {
        self.news = news
        self.lastSeenHeight = lastSeenHeight
        self.savedAt = savedAt
    }
}

public struct NewsStore {

    public static let namespace = "news.v1"
    /// The single row. Named, not empty, so a later addition to this
    /// namespace has somewhere to go.
    public static let windowKey = "window"

    /// How much of the feed survives a restart. Generous compared with
    /// Android's 40 — that number is a phone inflating a view per row,
    /// and a `LazyVStack` has no such ceiling — but still bounded, so
    /// one blob stays a reasonable thing to read and write whole.
    public static let maxCachedNews = 200

    private let inner: TypedStore<NewsCache>

    public init(kv: EncryptedKVStore) {
        self.inner = TypedStore(kv: kv, namespace: Self.namespace)
    }

    /// The cached window, or an empty one on a first run.
    public func load() throws -> NewsCache {
        try inner.get(Self.windowKey) ?? NewsCache()
    }

    /// Replace the window, and advance the watermark to `bestHeight`.
    ///
    /// The watermark only ever moves forward: a reply from a lagging
    /// server must not re-light items this device has already shown.
    /// ``News/isNew`` is stripped on the way in — a dot means "arrived
    /// since you last looked", which is a fact about a session, not
    /// something to reload three days later.
    public func save(news: [News], bestHeight: Int64? = nil) throws {
        var cache = try load()
        cache.news = Array(news.prefix(Self.maxCachedNews)).map { item in
            var copy = item
            copy.isNew = nil
            return copy
        }
        if let bestHeight, bestHeight > (cache.lastSeenHeight ?? Int64.min) {
            cache.lastSeenHeight = bestHeight
        }
        cache.savedAt = Int64(Date().timeIntervalSince1970)
        try inner.put(cache, key: Self.windowKey)
    }

    /// The watermark on its own — read before a fetch, to mark that
    /// fetch's arrivals.
    public func lastSeenHeight() throws -> Int64? {
        try load().lastSeenHeight
    }

    public func clear() throws {
        try inner.delete(Self.windowKey)
    }
}
