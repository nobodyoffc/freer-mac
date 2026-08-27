import Foundation
import FCCore
import FCTransport

/// On-chain service-registry reads — the port of Android's
/// `ServiceManager`'s API half, over `base.search` against the
/// `service` index.
///
/// **Why `ServiceRegistry` and not `ServiceService`.** The other two
/// Construct readers are ``ProtocolService`` and ``CodeService``, so the
/// pattern would name this one twice. It is also not the only reader of
/// this index: ``DirectoryService`` has read it since long before the
/// Construct phase, for SID→URL discovery on the IM path. The two do
/// different jobs on the same rows — discovery asks "which live service
/// offers a DOCK", the registry asks "show me every service record and
/// let me manage mine" — and keeping them apart means the message path
/// cannot be broken by a change to a browse query.
///
/// The write half — publish, update, stop, recover, close — lives on
/// ``ActiveSession`` next to the other carves, because it goes through
/// the wallet's send pipeline rather than this client.
///
/// **No key is needed to read.** Every field of a published service
/// record is public. What a watch-only identity cannot do is publish
/// one.
public struct ServiceRegistry {

    /// The index this reads. Java's `IndicesNames.SERVICE`, and the same
    /// string ``DirectoryService/serviceIndex`` uses.
    public static let index = DirectoryService.serviceIndex

    public enum Failure: Error, CustomStringConvertible {
        case fapiNonZeroCode(api: String, code: Int, message: String?)
        case underlying(Error)

        public var description: String {
            switch self {
            case let .fapiNonZeroCode(api, code, message):
                return "ServiceRegistry: \(api) returned code=\(code) message=\(message ?? "<nil>")"
            case .underlying(let e):
                return "ServiceRegistry: \(e)"
            }
        }
    }

    /// A field the `service` index can be searched or sorted on,
    /// mirroring Java's `getSearchableFields` / `getSortableFields`.
    public enum Field: String, CaseIterable, Sendable, Identifiable {
        case stdName
        case localNames
        case type
        case desc
        case components
        case ver
        case waiters
        case protocols
        case codes
        case services
        case owner
        case dealer
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
            case .type:       return "Type"
            case .desc:       return "Description"
            case .components: return "Component"
            case .ver:        return "Version"
            case .waiters:    return "Waiter"
            case .protocols:  return "Protocol"
            case .codes:      return "Code"
            case .services:   return "Service"
            case .owner:      return "Owner"
            case .dealer:     return "Dealer"
            case .birthTime:  return "Published"
            case .lastTime:   return "Time"
            case .lastHeight: return "Height"
            case .tCdd:       return "CDD"
            case .tRate:      return "Rating"
            case .id:         return "SID"
            }
        }

        /// Java's `getSearchableFields`, minus `home` — a map of
        /// label→URL that a `match` clause has no sensible way to score
        /// — plus `id`, so pasting a SID finds its row.
        ///
        /// ``localNames`` stays in, unlike ``CodeService``'s treatment
        /// of `home`: it is a map too, but a map of *names*, and
        /// ``DirectoryService/searchServices(offering:matching:after:size:timeoutMs:)``
        /// has been matching on it in production since the DOCK picker
        /// shipped.
        public static let searchable: [Field] = [
            .stdName, .localNames, .type, .desc, .components,
            .waiters, .protocols, .codes, .services, .owner, .id
        ]

        /// Java's `getSortableFields`, minus the two booleans (`active`
        /// and `closed` sort a list into two undifferentiated blocks,
        /// which is a filter wearing a sort's clothes), plus
        /// `lastHeight`, which is what the default browse pages on.
        public static let sortable: [Field] =
            [.lastHeight, .lastTime, .birthTime, .stdName, .owner, .tCdd, .tRate, .id]
    }

    /// One page of results plus what is needed to ask for the next.
    public struct Page: Sendable {
        public let services: [Service]
        /// The server's own cursor for the page after this one — feed it
        /// straight back as `after`.
        public let last: [String]?
        public let total: Int64?
        public let bestHeight: Int64?

        public init(
            services: [Service], last: [String]?,
            total: Int64?, bestHeight: Int64?
        ) {
            self.services = services
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
    /// `owner` nil browses every service on the chain; passing a FID
    /// narrows it to that operator's. `component` narrows to services
    /// that actually *offer* something — the same `terms` clause
    /// ``DirectoryService/searchServices(offering:matching:after:size:timeoutMs:)``
    /// uses, and the reason it is a filter rather than a query on
    /// `type`: one server publishes one record listing everything it
    /// runs, so asking on `type` matches every FC service on the chain.
    public func fetchServices(
        owner: String? = nil,
        offering component: String? = nil,
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
        let state = Self.stateClauses(active: active, closed: closed, component: component)
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
    /// Protocol and Code). Passing ``Page/last`` back is correct for
    /// every sort.
    public func search(
        query text: String,
        inField: Field? = nil,
        sortField: Field? = nil,
        ascending: Bool = false,
        owner: String? = nil,
        offering component: String? = nil,
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
        let state = Self.stateClauses(active: active, closed: closed, component: component)
        if let terms = state.queryTerms { query["terms"] = terms }

        var dict: [String: Any] = [
            "entity": Self.index,
            "query": query,
            "sort": sorts,
            "size": String(size)
        ]
        if let filter = state.filter { dict["filter"] = filter }
        if let after, !after.isEmpty { dict["after"] = after }
        return try await run(dict, timeoutMs: timeoutMs)
    }

    /// The lifecycle flags and the component narrowing, as fcdsl
    /// clauses.
    ///
    /// **`active` and `closed` cannot share one `terms`.** A single
    /// clause naming two fields and two values matches either value in
    /// either field, so asking for `active=true, closed=false` that way
    /// would also return `active=false, closed=true` — precisely the
    /// rows being excluded. So `active` goes in the query and `closed`
    /// in the top-level `filter`, which is a sibling of `query` in the
    /// fcdsl (Java's `Fcdsl.filter`), not a member of it. A filter
    /// nested inside the query is silently ignored, and a state filter
    /// that does nothing looks exactly like one that worked on a chain
    /// where every record happens to be live.
    ///
    /// The component rides in the filter alongside `closed` for the same
    /// reason: it is a third field, and folding it into the query's
    /// `terms` would make it interchangeable with `active`.
    private static func stateClauses(
        active: Bool?, closed: Bool?, component: String? = nil
    ) -> (queryTerms: [String: Any]?, filter: [String: Any]?) {
        let queryTerms: [String: Any]? = active.map {
            ["fields": ["active"], "values": [$0 ? "true" : "false"]]
        }
        var filter: [String: Any] = [:]
        if let component, !component.isEmpty {
            // `terms` against the component list, which is what
            // ``DirectoryService`` has used for the DOCK and DISK
            // pickers since they shipped — a list field matched by
            // exact value.
            filter["terms"] = ["fields": [Field.components.wire], "values": [component]]
        }
        if let closed {
            let clause = ["fields": ["closed"], "values": [closed ? "true" : "false"]]
            // One filter holds one clause of each kind, so `closed`
            // takes `terms` when it is alone and `equals` when the
            // component has claimed it. Java's `Filter extends FcQuery`,
            // so both keys exist here and both are exact-value clauses —
            // this is a slot conflict, not a semantic choice.
            filter[filter["terms"] == nil ? "terms" : "equals"] = clause
        }
        return (queryTerms, filter.isEmpty ? nil : filter)
    }

    // MARK: - by id

    /// Fetch specific service records by SID.
    ///
    /// The path for the two things a browse cannot do: read back a
    /// record you only have the SID of, and confirm a carve you just
    /// broadcast — the record appears here once a block includes it,
    /// which is what flips a row from broadcast-unconfirmed to on-chain.
    ///
    /// **Not `base.search`.** By-ids is its own endpoint
    /// (``DirectoryService/getByIdsApi``) and its `data` is a *map* from
    /// id to record, not an array. Ids absent from the reply simply have
    /// no record yet.
    ///
    /// ``DirectoryService/serviceByIds(_:timeoutMs:)`` reads the same
    /// endpoint for the resolver; this one chunks, stamps ``onChain``
    /// and backfills the id from the map key, which the resolver has no
    /// use for.
    public func fetchServicesByIds(
        _ ids: [String],
        timeoutMs: Int = 15_000
    ) async throws -> [String: Service] {
        guard !ids.isEmpty else { return [:] }
        var found: [String: Service] = [:]
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
            let page: [String: Service]
            do {
                page = try JSONDecoder().decode([String: Service].self, from: data)
            } catch {
                throw Failure.underlying(error)
            }
            for (key, row) in page {
                var copy = row
                // The map key is authoritative: a record whose body
                // omits its own id still has one here.
                if copy.sid.isEmpty { copy.id = key }
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
                return Page(services: [], last: nil, total: 0, bestHeight: resp.bestHeight)
            }
            throw Failure.fapiNonZeroCode(
                api: "base.search", code: code, message: resp.message
            )
        }
        guard let data = resp.data else {
            return Page(
                services: [], last: resp.last,
                total: resp.total, bestHeight: resp.bestHeight
            )
        }
        do {
            let decoded = try JSONDecoder().decode([Service].self, from: data)
            // Chain rows are on-chain by definition; the wire may or may
            // not carry the flag, and the pane's whole layout keys off
            // it, so stamp it rather than trusting the field to be there.
            let services = decoded
                .filter { !$0.sid.isEmpty }
                .map { row -> Service in
                    var copy = row
                    copy.onChain = true
                    return copy
                }
            return Page(
                services: services,
                last: resp.last,
                total: resp.total,
                bestHeight: resp.bestHeight
            )
        } catch {
            throw Failure.underlying(error)
        }
    }
}
