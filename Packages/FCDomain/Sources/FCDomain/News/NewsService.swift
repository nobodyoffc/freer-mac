import Foundation
import FCCore
import FCTransport

/// The chain-wide activity feed — the read half of Android's
/// `FcObjectManager` news wrappers (`fetchNewsFromAPI`,
/// `searchNewsFromApi`), behind `base.search` on the `news` index.
///
/// **Nothing here needs a key.** Every field is public chain data, so
/// this is the one sync path in the app that works identically for a
/// watch-only identity — no privkey, no decrypt, no per-row ECDH. That
/// also means it is not per-identity data: two mains on the same Mac
/// see the same feed. The *watermark* that decides what is new is
/// per-identity, and lives in ``NewsStore``.
///
/// Stateless, like ``DirectoryService``: the caller owns the window it
/// is showing and persists it.
public struct NewsService {

    public enum Failure: Error, CustomStringConvertible {
        case fapiNonZeroCode(api: String, code: Int, message: String?)
        case underlying(Error)

        public var description: String {
            switch self {
            case let .fapiNonZeroCode(api, code, message):
                return "NewsService: \(api) returned code=\(code) message=\(message ?? "<nil>")"
            case .underlying(let e):
                return "NewsService: \(e)"
            }
        }
    }

    /// One page of the feed.
    public struct Page: Sendable {
        /// Records in server order — descending by time except for
        /// ``Direction/newer``, which reads forwards.
        public let news: [News]
        /// The server's own cursor for the next page. Prefer this over
        /// rebuilding one from the last row: it matches whatever sort
        /// the query actually used.
        public let last: [String]?
        /// Total matches server-side, when reported — the "on-chain N"
        /// half of the statistics line.
        public let total: Int64?
        /// Chain tip as of this reply. What the new-item watermark is
        /// set from.
        public let bestHeight: Int64?

        public init(news: [News], last: [String]?, total: Int64?, bestHeight: Int64?) {
            self.news = news
            self.last = last
            self.total = total
            self.bestHeight = bestHeight
        }
    }

    /// Which way to walk the time-ordered feed.
    public enum Direction: Sendable {
        /// The newest records, from the tip. No cursor.
        case newest
        /// Further back in time, continuing past the oldest record
        /// held. Descending, so the page appends to the bottom.
        case older
        /// Forwards from the newest record held — the refresh path.
        /// Ascending, so the page is reversed before it is prepended.
        case newer
    }

    public static let index = "news"

    public let fapi: any FapiCalling

    public init(fapi: any FapiCalling) {
        self.fapi = fapi
    }

    // MARK: - browse

    /// One page of the plain feed, sorted `time, id`.
    ///
    /// `reference` is the row the walk continues from: the oldest held
    /// for ``Direction/older``, the newest held for
    /// ``Direction/newer``, ignored for ``Direction/newest``. A
    /// reference with no `time`/`id` pair simply starts from the tip
    /// rather than erroring — a record the index gave us without a
    /// cursor is a server problem, not a reason to break the pane.
    public func fetch(
        _ direction: Direction,
        reference: News? = nil,
        size: Int = 25,
        timeoutMs: Int = 15_000
    ) async throws -> Page {
        let order = (direction == .newer) ? "asc" : "desc"
        var dict: [String: Any] = [
            "entity": Self.index,
            "sort": [
                ["field": "time", "order": order],
                ["field": "id",   "order": order]
            ],
            "size": String(size)
        ]
        if direction != .newest, let cursor = reference?.cursor {
            dict["after"] = cursor
        }
        return try await run(dict, timeoutMs: timeoutMs)
    }

    // MARK: - search

    /// Server-side search — `match` over one field, or over all six
    /// searchable fields when `inField` is nil.
    ///
    /// Paging is by the server's `last` cursor rather than a rebuilt
    /// `[time, id]`, because `sortField` may be any of
    /// ``News/sortableFields`` and `search_after` only compares against
    /// the sort keys in play.
    public func search(
        query: String,
        inField: News.Field? = nil,
        sortField: News.Field? = nil,
        ascending: Bool = false,
        after: [String]? = nil,
        size: Int = 25,
        timeoutMs: Int = 15_000
    ) async throws -> Page {
        let fields = inField.map { [$0.name] } ?? News.searchableFields.map(\.name)
        let order = ascending ? "asc" : "desc"
        let sorted = sortField ?? News.timeField

        var sorts: [[String: String]] = [["field": sorted.name, "order": order]]
        // The id tiebreaker keeps the sort total, which is what makes
        // the cursor stable. Skip it when it *is* the sort field.
        if sorted.name != News.idField.name {
            sorts.append(["field": News.idField.name, "order": order])
        }

        var dict: [String: Any] = [
            "entity": Self.index,
            "query": ["match": ["fields": fields, "value": query]],
            "sort": sorts,
            "size": String(size)
        ]
        if let after, !after.isEmpty { dict["after"] = after }
        return try await run(dict, timeoutMs: timeoutMs)
    }

    // MARK: - new-item marking

    /// Flag the records the local watermark has not seen.
    ///
    /// `sinceHeight` nil means this device has no watermark yet — a
    /// first run, or a cleared cache. Android marks *everything* new in
    /// that case, which lights up the whole first page; here the first
    /// load establishes the watermark silently and the dots start
    /// meaning something from the second load on.
    public static func markingNew(_ items: [News], sinceHeight: Int64?) -> [News] {
        guard let sinceHeight else { return items }
        return items.map { item in
            var copy = item
            if let h = item.height, h > sinceHeight { copy.isNew = true }
            return copy
        }
    }

    // MARK: - the one call

    private func run(_ fcdsl: [String: Any], timeoutMs: Int) async throws -> Page {
        let body: Data
        do {
            body = try JSONSerialization.data(withJSONObject: fcdsl, options: [.sortedKeys])
        } catch {
            throw Failure.underlying(error)
        }
        let reply = try await fapi.call(
            api: "base.search",
            params: nil, fcdsl: body, binary: nil,
            sid: nil, via: nil, maxCost: nil,
            timeoutMs: timeoutMs
        )
        let resp = reply.response
        // 404 is the server's "nothing matched" — an empty page, and
        // for the feed's oldest end the normal way a walk terminates.
        if let code = resp.code, code != 0 {
            if code == 404 {
                return Page(news: [], last: nil, total: 0, bestHeight: resp.bestHeight)
            }
            throw Failure.fapiNonZeroCode(
                api: "base.search", code: code, message: resp.message
            )
        }
        guard let data = resp.data else {
            return Page(news: [], last: resp.last, total: resp.total, bestHeight: resp.bestHeight)
        }
        do {
            let page = try JSONDecoder().decode([News].self, from: data)
            return Page(
                news: page,
                last: resp.last,
                total: resp.total,
                bestHeight: resp.bestHeight
            )
        } catch {
            throw Failure.underlying(error)
        }
    }
}
