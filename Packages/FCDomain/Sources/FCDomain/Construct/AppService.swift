import Foundation
import FCCore
import FCTransport

/// On-chain app-registry reads — the port of Android's `AppManager`'s
/// API half, over `base.search` against the `app` index.
///
/// The write half — publish, update, stop, recover, close — lives on
/// ``ActiveSession`` next to the other carves, because it goes through
/// the wallet's send pipeline rather than this client.
///
/// **This index is chain-wide.** A proof query is scoped to your FID; a
/// registry is worth having for the opposite reason — the point is to
/// look up apps *other people* published. So the browse is unscoped by
/// default and `owner` is a filter you opt into.
///
/// **No key is needed to read.** Every field of a published app record
/// is public, which makes this a path that works fully on a watch-only
/// identity. What you cannot do from there is publish one.
public struct AppService {

    /// The index this reads. Java's `IndicesNames.APP`.
    public static let index = "app"

    public enum Failure: Error, CustomStringConvertible {
        case fapiNonZeroCode(api: String, code: Int, message: String?)
        case underlying(Error)

        public var description: String {
            switch self {
            case let .fapiNonZeroCode(api, code, message):
                return "AppService: \(api) returned code=\(code) message=\(message ?? "<nil>")"
            case .underlying(let e):
                return "AppService: \(e)"
            }
        }
    }

    /// A field the `app` index can be searched or sorted on. The two
    /// sets differ — you can search the description but not sort by it —
    /// so ``searchable`` and ``sortable`` name them separately,
    /// mirroring Java's `getSearchableFields` / `getSortableFields`.
    public enum Field: String, CaseIterable, Sendable, Identifiable {
        case stdName
        case localNames
        case types
        case desc
        case ver
        case waiters
        case protocols
        case codes
        case services
        case owner
        case birthTime
        case lastTime
        case lastHeight
        case tCdd
        case tRate
        case id

        public var id: String { rawValue }

        /// The wire name — what goes in the fcdsl.
        public var wire: String { rawValue }

        /// Display label. English only for now; Phase 11 localises.
        public var label: String {
            switch self {
            case .stdName:    return "Name"
            case .localNames: return "Local name"
            case .types:      return "Type"
            case .desc:       return "Description"
            case .ver:        return "Version"
            case .waiters:    return "Waiter"
            case .protocols:  return "Protocol"
            case .codes:      return "Code"
            case .services:   return "Service"
            case .owner:      return "Owner"
            case .birthTime:  return "Published"
            case .lastTime:   return "Time"
            case .lastHeight: return "Height"
            case .tCdd:       return "CDD"
            case .tRate:      return "Rating"
            case .id:         return "AID"
            }
        }

        /// Java's `getSearchableFields`, minus `home` — a map of
        /// label→URL that a `match` clause has no sensible way to score
        /// — plus `id`, so pasting an AID finds its row.
        ///
        /// **`downloads` is not searchable and that is the index's
        /// choice, not ours.** Java does not list it either: it is a
        /// list of objects, and the fcdsl `match` clause scores text
        /// fields. ``AppRecord/matches(query:)`` does reach into it, so
        /// a download link is findable among rows already loaded — just
        /// not chain-wide.
        public static let searchable: [Field] = [
            .stdName, .localNames, .types, .desc,
            .waiters, .protocols, .codes, .services, .owner, .id
        ]

        /// Java's `getSortableFields`, minus the two booleans (`active`
        /// and `closed` sort a list into two undifferentiated blocks,
        /// which is a filter wearing a sort's clothes — the state
        /// filters do that job properly), plus `lastHeight`, which is
        /// what the default browse actually pages on.
        public static let sortable: [Field] =
            [.lastHeight, .lastTime, .birthTime, .stdName, .owner, .tCdd, .tRate, .id]
    }

    /// One page of results plus what is needed to ask for the next.
    public struct Page: Sendable {
        public let apps: [AppRecord]
        /// The server's own cursor for the page after this one. Feed it
        /// straight back as `after` — see ``search`` for why this rather
        /// than a locally rebuilt key pair.
        public let last: [String]?
        public let total: Int64?
        public let bestHeight: Int64?

        public init(
            apps: [AppRecord], last: [String]?,
            total: Int64?, bestHeight: Int64?
        ) {
            self.apps = apps
            self.last = last
            self.total = total
            self.bestHeight = bestHeight
        }
    }

    public let fapi: any FapiCalling

    public init(fapi: any FapiCalling) {
        self.fapi = fapi
    }

    // MARK: - browse

    /// One page of the registry, newest first.
    ///
    /// `owner` nil browses every app on the chain; passing a FID narrows
    /// it to that publisher's. `type` narrows to apps that declare one
    /// kind — a filter on the `types` *list*, which is why it is a
    /// `terms` clause rather than an equality on a scalar.
    /// `active` and `closed` are three-valued: nil leaves the state out
    /// of the query entirely, which is how the All filter sees stopped
    /// and closed records alongside live ones.
    public func fetchApps(
        owner: String? = nil,
        ofType type: String? = nil,
        active: Bool? = nil,
        closed: Bool? = nil,
        ascending: Bool = false,
        after: [String]? = nil,
        size: Int = 25,
        timeoutMs: Int = 15_000
    ) async throws -> Page {
        let order = ascending ? "asc" : "desc"
        var query: [String: Any] = [:]
        if let owner, !owner.isEmpty {
            query["equals"] = ["fields": [Field.owner.wire], "values": [owner]]
        }
        let state = Self.stateClauses(active: active, closed: closed, type: type)
        if let terms = state.queryTerms { query["terms"] = terms }

        var dict: [String: Any] = [
            "entity": Self.index,
            "sort": [
                ["field": Field.lastHeight.wire, "order": order],
                ["field": Field.id.wire,         "order": order]
            ],
            "size": String(size)
        ]
        if !query.isEmpty { dict["query"] = query }
        if let filter = state.filter { dict["filter"] = filter }
        if let except = state.except { dict["except"] = except }
        if let after, !after.isEmpty { dict["after"] = after }
        return try await run(dict, timeoutMs: timeoutMs)
    }

    // MARK: - search

    /// Full-text search over the registry.
    ///
    /// **Pages from the server's cursor.** Android rebuilds `after` as
    /// `[lastHeight, id]` for every search regardless of what it sorted
    /// by, so any search on another key pages against keys it is not
    /// sorted on (**Android issue C17**, the same defect as News, Proof,
    /// Protocol, Code and Service). Passing ``Page/last`` back is
    /// correct for every sort.
    public func search(
        query text: String,
        inField: Field? = nil,
        sortField: Field? = nil,
        ascending: Bool = false,
        owner: String? = nil,
        ofType type: String? = nil,
        active: Bool? = nil,
        closed: Bool? = nil,
        after: [String]? = nil,
        size: Int = 25,
        timeoutMs: Int = 15_000
    ) async throws -> Page {
        let fields = inField.map { [$0.wire] } ?? Field.searchable.map(\.wire)
        let order = ascending ? "asc" : "desc"
        let sorted = sortField ?? .lastHeight

        var sorts: [[String: String]] = [["field": sorted.wire, "order": order]]
        if sorted != .id {
            sorts.append(["field": Field.id.wire, "order": order])
        }

        var query: [String: Any] = [
            "match": ["fields": fields, "value": text]
        ]
        if let owner, !owner.isEmpty {
            query["equals"] = ["fields": [Field.owner.wire], "values": [owner]]
        }
        let state = Self.stateClauses(active: active, closed: closed, type: type)
        if let terms = state.queryTerms { query["terms"] = terms }

        var dict: [String: Any] = [
            "entity": Self.index,
            "query": query,
            "sort": sorts,
            "size": String(size)
        ]
        if let filter = state.filter { dict["filter"] = filter }
        if let except = state.except { dict["except"] = except }
        if let after, !after.isEmpty { dict["after"] = after }
        return try await run(dict, timeoutMs: timeoutMs)
    }

    /// The lifecycle flags and the type narrowing, as fcdsl clauses.
    ///
    /// **`active` and `closed` cannot share one `terms`.** A single
    /// clause naming two fields and two values matches either value in
    /// either field, so asking for `active=true, closed=false` that way
    /// would also return `active=false, closed=true` — precisely the
    /// rows being excluded. So `active` goes in the query and `closed`
    /// in a top-level clause, which is a sibling of `query` in the
    /// fcdsl (Java's `Fcdsl.filter` / `Fcdsl.except`), not a member of
    /// it. A filter nested inside the query is silently ignored, and a
    /// state filter that does nothing looks exactly like one that
    /// worked on a chain where every record happens to be live.
    ///
    /// **`closed = false` is asked as an `except`, not a `filter`.**
    /// This index is not like the other three: the FEIP parser's app
    /// publish path sets `active = true` and *never sets `closed` at
    /// all* — `protocol`, `code` and `service` all set `closed = false`
    /// beside it, `app` alone does not (**indexer issue: no
    /// `app.setClosed(false)` in `ConstructParser`**). Elasticsearch
    /// does not index a field that was never written, so a
    /// `filter.terms closed=false` — a `bool.filter`, and thus a must —
    /// matches *no app document on the chain*, and the whole Live
    /// registry comes back empty with a code of 0 and no error to show
    /// for it. `except.terms closed=true` is a `bool.must_not`, which
    /// is the same question asked the way this index can answer it: a
    /// record with no `closed` field is not closed.
    ///
    /// The type rides in the filter, the same way ``ServiceRegistry``
    /// carries its component, and now has that filter to itself.
    private static func stateClauses(
        active: Bool?, closed: Bool?, type: String? = nil
    ) -> (queryTerms: [String: Any]?, filter: [String: Any]?, except: [String: Any]?) {
        let queryTerms: [String: Any]? = active.map {
            ["fields": ["active"], "values": [$0 ? "true" : "false"]]
        }
        var filter: [String: Any] = [:]
        if let type, !type.isEmpty {
            filter["terms"] = ["fields": [Field.types.wire], "values": [type]]
        }
        var except: [String: Any]?
        if let closed {
            let clause: [String: Any] = ["fields": ["closed"], "values": ["true"]]
            if closed {
                // Closed records do carry the flag — `close` writes it.
                filter[filter["terms"] == nil ? "terms" : "equals"] = clause
            } else {
                except = ["terms": clause]
            }
        }
        return (queryTerms, filter.isEmpty ? nil : filter, except)
    }

    // MARK: - by id

    /// Fetch specific app records by AID.
    ///
    /// The path for the two things a browse cannot do: read back a
    /// record you only have the AID of, and confirm a carve you just
    /// broadcast — the record appears here once a block includes it,
    /// which is what flips a row from broadcast-unconfirmed to on-chain.
    ///
    /// **Not `base.search`.** By-ids is its own endpoint
    /// (``DirectoryService/getByIdsApi``) and its `data` is a *map* from
    /// id to record, not an array. Ids absent from the reply simply have
    /// no record yet.
    public func fetchAppsByIds(
        _ ids: [String],
        timeoutMs: Int = 15_000
    ) async throws -> [String: AppRecord] {
        guard !ids.isEmpty else { return [:] }
        var found: [String: AppRecord] = [:]
        // The endpoint caps how many ids one call may name; page the
        // list rather than sending an unbounded one.
        for start in stride(from: 0, to: ids.count, by: 100) {
            let chunk = Array(ids[start..<min(start + 100, ids.count)])
            let body: Data
            do {
                body = try JSONSerialization.data(
                    withJSONObject: ["entity": Self.index, "ids": chunk],
                    options: [.sortedKeys]
                )
            } catch {
                throw Failure.underlying(error)
            }
            let reply = try await fapi.call(
                api: DirectoryService.getByIdsApi,
                params: nil, fcdsl: body, binary: nil,
                sid: nil, via: nil, maxCost: nil,
                timeoutMs: timeoutMs
            )
            let resp = reply.response
            if let code = resp.code, code != 0 {
                if code == 404 { continue }
                throw Failure.fapiNonZeroCode(
                    api: DirectoryService.getByIdsApi, code: code, message: resp.message
                )
            }
            guard let data = resp.data else { continue }
            let page: [String: AppRecord]
            do {
                page = try JSONDecoder().decode([String: AppRecord].self, from: data)
            } catch {
                throw Failure.underlying(error)
            }
            for (key, row) in page {
                var copy = row
                // The map key is authoritative: a record whose body
                // omits its own id still has one here.
                if copy.id.isEmpty { copy.id = key }
                copy.onChain = true
                found[key] = copy
            }
        }
        return found
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
        // 404 is the server's "nothing matched" — an empty page, and for
        // a filter nothing satisfies, the normal reply.
        if let code = resp.code, code != 0 {
            if code == 404 {
                return Page(apps: [], last: nil, total: 0, bestHeight: resp.bestHeight)
            }
            throw Failure.fapiNonZeroCode(
                api: "base.search", code: code, message: resp.message
            )
        }
        guard let data = resp.data else {
            return Page(
                apps: [], last: resp.last,
                total: resp.total, bestHeight: resp.bestHeight
            )
        }
        do {
            let decoded = try JSONDecoder().decode([AppRecord].self, from: data)
            // Chain rows are on-chain by definition; the wire may or may
            // not carry the flag, and the pane's whole layout keys off
            // it, so stamp it rather than trusting the field to be there.
            let apps = decoded
                .filter { !$0.id.isEmpty }
                .map { row -> AppRecord in
                    var copy = row
                    copy.onChain = true
                    return copy
                }
            return Page(
                apps: apps,
                last: resp.last,
                total: resp.total,
                bestHeight: resp.bestHeight
            )
        } catch {
            throw Failure.underlying(error)
        }
    }
}
