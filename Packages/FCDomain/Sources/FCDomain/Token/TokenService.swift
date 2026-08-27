import Foundation
import FCCore
import FCTransport

/// On-chain token reads — the port of Android's `TokenManager`'s API
/// half (`fetchTokensFromAPI` / `searchTokensFromApi` /
/// `fetchTokenHoldersFromAPI` / `searchTokenHoldersFromApi` /
/// `fetchTokenHistoryFromAPI` / `fetchTokensByIds`), over `base.search`
/// against three indices: `token`, `token_holder` and `token_history`.
///
/// The write half — deploy, issue, transfer, destroy, close — lives on
/// ``ActiveSession`` next to the other carves, because it goes through
/// the wallet's send pipeline rather than this client.
///
/// **No key is needed to read.** Token ledgers are public, so this
/// works fully on a watch-only identity: you can watch a balance from a
/// FID you cannot sign with. What you cannot do from there is move it.
///
/// **Three indices, three shapes, one paging rule.** Tokens and holders
/// sort by `lastHeight` + `id`; history sorts by `time` + `id`. Every
/// one of them pages by feeding ``Page/last`` straight back as `after`
/// rather than rebuilding the cursor locally — see ``searchTokens``.
public struct TokenService {

    /// The three indices this reads. Java's `IndicesNames.TOKEN`,
    /// `TOKEN_HOLDER` and `TOKEN_HISTORY`.
    public static let tokenIndex = "token"
    public static let holderIndex = "token_holder"
    public static let historyIndex = "token_history"

    public enum Failure: Error, CustomStringConvertible {
        case fapiNonZeroCode(api: String, code: Int, message: String?)
        case underlying(Error)

        public var description: String {
            switch self {
            case let .fapiNonZeroCode(api, code, message):
                return "TokenService: \(api) returned code=\(code) message=\(message ?? "<nil>")"
            case .underlying(let e):
                return "TokenService: \(e)"
            }
        }
    }

    // MARK: - fields

    /// A field the `token` index can be searched or sorted on. The two
    /// sets differ — you can search the description but not sort by it
    /// — so ``searchable`` and ``sortable`` name them separately,
    /// mirroring Java's `Token.getSearchableFields` /
    /// `getSortableFields`.
    public enum TokenField: String, CaseIterable, Sendable, Identifiable {
        case name
        case desc
        case consensusId
        case deployer
        case circulating
        case birthTime
        case lastHeight
        case lastTime
        case id

        public var id: String { rawValue }
        /// The wire name — what goes in the fcdsl.
        public var wire: String { rawValue }

        /// Display label. English only for now; Phase 11 localises.
        public var label: String {
            switch self {
            case .name:        return "Name"
            case .desc:        return "Description"
            case .consensusId: return "Consensus ID"
            case .deployer:    return "Deployer"
            case .circulating: return "Circulating"
            case .birthTime:   return "Created"
            case .lastHeight:  return "Height"
            case .lastTime:    return "Time"
            case .id:          return "ID"
            }
        }

        public static let searchable: [TokenField] =
            [.name, .desc, .consensusId, .deployer, .id]
        public static let sortable: [TokenField] =
            [.lastHeight, .lastTime, .name, .deployer, .circulating, .birthTime, .id]
    }

    /// A field the `token_holder` index can be searched or sorted on.
    public enum HolderField: String, CaseIterable, Sendable, Identifiable {
        case fid
        case tokenId
        case balance
        case firstHeight
        case lastHeight
        case id

        public var id: String { rawValue }
        public var wire: String { rawValue }

        public var label: String {
            switch self {
            case .fid:         return "FID"
            case .tokenId:     return "Token ID"
            case .balance:     return "Balance"
            case .firstHeight: return "First height"
            case .lastHeight:  return "Height"
            case .id:          return "ID"
            }
        }

        public static let searchable: [HolderField] = [.tokenId, .id]
        public static let sortable: [HolderField] = [.lastHeight, .balance, .firstHeight, .id]
    }

    /// A field the `token_history` index is queried on. History is not
    /// full-text searched anywhere — Android only ever filters it by
    /// token or by party — so there is no searchable/sortable split.
    public enum HistoryField: String, Sendable {
        case tokenId
        case signer
        case recipient
        case time
        case height
        case id

        public var wire: String { rawValue }
    }

    // MARK: - pages

    /// One page of results plus what is needed to ask for the next.
    public struct Page<Row: Sendable>: Sendable {
        public let rows: [Row]
        /// The server's own cursor for the page after this one. Feed it
        /// straight back as `after`.
        public let last: [String]?
        public let total: Int64?
        public let bestHeight: Int64?

        public init(rows: [Row], last: [String]?, total: Int64?, bestHeight: Int64?) {
            self.rows = rows
            self.last = last
            self.total = total
            self.bestHeight = bestHeight
        }

        static func empty(bestHeight: Int64? = nil) -> Page<Row> {
            Page(rows: [], last: nil, total: 0, bestHeight: bestHeight)
        }
    }

    public let fapi: any FapiCalling

    public init(fapi: any FapiCalling) {
        self.fapi = fapi
    }

    // MARK: - tokens

    /// Every token on the chain, newest activity first — the chain-wide
    /// browse behind the Tokens tab.
    ///
    /// **Unscoped, and that is the feature.** Unlike proofs or mail,
    /// there is no "your tokens" query here: you find a token to hold
    /// by looking at the ones that exist. What you hold is a different
    /// index — see ``fetchHolders(for:ascending:after:size:timeoutMs:)``.
    public func fetchTokens(
        ascending: Bool = false,
        after: [String]? = nil,
        size: Int = 25,
        timeoutMs: Int = 15_000
    ) async throws -> Page<Token> {
        let order = ascending ? "asc" : "desc"
        var dict: [String: Any] = [
            "entity": Self.tokenIndex,
            "sort": [
                ["field": TokenField.lastHeight.wire, "order": order],
                ["field": TokenField.id.wire,         "order": order]
            ],
            "size": String(size)
        ]
        if let after, !after.isEmpty { dict["after"] = after }
        return try await runTokens(dict, timeoutMs: timeoutMs)
    }

    /// Full-text search across every token on the chain.
    ///
    /// **Pages from the server's cursor.** Android rebuilds `after` as
    /// `[lastHeight, id]` for every search regardless of what it sorted
    /// by, and `search_after` compares positionally against the sort
    /// keys actually used — so its name-, deployer- and
    /// circulating-sorted searches page wrong (the same defect as News
    /// and Proof, **Android issue C17**). Passing ``Page/last`` back is
    /// correct for every sort.
    public func searchTokens(
        query text: String,
        inField: TokenField? = nil,
        sortField: TokenField? = nil,
        ascending: Bool = false,
        after: [String]? = nil,
        size: Int = 25,
        timeoutMs: Int = 15_000
    ) async throws -> Page<Token> {
        let fields = inField.map { [$0.wire] } ?? TokenField.searchable.map(\.wire)
        let order = ascending ? "asc" : "desc"
        let sorted = sortField ?? .lastHeight

        var sorts: [[String: String]] = [["field": sorted.wire, "order": order]]
        if sorted != .id { sorts.append(["field": TokenField.id.wire, "order": order]) }

        var dict: [String: Any] = [
            "entity": Self.tokenIndex,
            "query": ["match": ["fields": fields, "value": text]],
            "sort": sorts,
            "size": String(size)
        ]
        if let after, !after.isEmpty { dict["after"] = after }
        return try await runTokens(dict, timeoutMs: timeoutMs)
    }

    /// Fetch specific tokens by record id — Android's `fetchTokensByIds`.
    ///
    /// This is the path a holdings list depends on: a ``TokenHolder``
    /// row carries a `tokenId` and a balance and nothing else — no
    /// name, no decimal scale, no closed flag — so a balance cannot even
    /// be *formatted*, let alone spent, until its token is resolved
    /// here.
    ///
    /// **Not `base.search`.** By-ids is its own endpoint
    /// (``DirectoryService/getByIdsApi``) and its `data` is a *map* from
    /// id to record, not an array — the shape mismatch that made every
    /// SID unresolvable when service lookups went to the wrong endpoint.
    public func fetchTokensByIds(
        _ ids: [String],
        timeoutMs: Int = 15_000
    ) async throws -> [String: Token] {
        try await byIds(entity: Self.tokenIndex, ids: ids, timeoutMs: timeoutMs) { row, key in
            var copy = row
            if copy.id.isEmpty { copy.id = key }
            return copy
        }
    }

    // MARK: - holders

    /// What `fid` holds — one page of ``TokenHolder`` rows, newest
    /// activity first.
    ///
    /// A row can legitimately have a zero balance: the chain keeps a
    /// holder record once it has existed, so a fully spent holding
    /// stays visible rather than vanishing. Filtering those out is the
    /// caller's decision, not this one's.
    public func fetchHolders(
        for fid: String,
        ascending: Bool = false,
        after: [String]? = nil,
        size: Int = 25,
        timeoutMs: Int = 15_000
    ) async throws -> Page<TokenHolder> {
        let order = ascending ? "asc" : "desc"
        var dict: [String: Any] = [
            "entity": Self.holderIndex,
            "query": ["terms": ["fields": [HolderField.fid.wire], "values": [fid]]],
            "sort": [
                ["field": HolderField.lastHeight.wire, "order": order],
                ["field": HolderField.id.wire,         "order": order]
            ],
            "size": String(size)
        ]
        if let after, !after.isEmpty { dict["after"] = after }
        return try await runHolders(dict, timeoutMs: timeoutMs)
    }

    /// Search within `fid`'s own holdings.
    ///
    /// Scoped by the `terms` clause on `fid`, exactly as Android scopes
    /// it: the index holds everybody's balances, and a search box on a
    /// pane titled "your tokens" that quietly returned strangers'
    /// holdings would be a different feature wearing this one's UI.
    public func searchHolders(
        for fid: String,
        query text: String,
        inField: HolderField? = nil,
        sortField: HolderField? = nil,
        ascending: Bool = false,
        after: [String]? = nil,
        size: Int = 25,
        timeoutMs: Int = 15_000
    ) async throws -> Page<TokenHolder> {
        let fields = inField.map { [$0.wire] } ?? HolderField.searchable.map(\.wire)
        let order = ascending ? "asc" : "desc"
        let sorted = sortField ?? .lastHeight

        var sorts: [[String: String]] = [["field": sorted.wire, "order": order]]
        if sorted != .id { sorts.append(["field": HolderField.id.wire, "order": order]) }

        var dict: [String: Any] = [
            "entity": Self.holderIndex,
            "query": [
                "terms": ["fields": [HolderField.fid.wire], "values": [fid]],
                "match": ["fields": fields, "value": text]
            ],
            "sort": sorts,
            "size": String(size)
        ]
        if let after, !after.isEmpty { dict["after"] = after }
        return try await runHolders(dict, timeoutMs: timeoutMs)
    }

    /// Who holds `tokenId`, biggest balance first — the deployer's view
    /// of their own token's distribution.
    ///
    /// Not in Android, which only ever scopes this index to the live
    /// FID. It is the same index and the same query with the `fid`
    /// clause swapped for a `tokenId` one, and without it the person
    /// who deployed a token has no way to see where it went.
    public func fetchHolders(
        ofToken tokenId: String,
        after: [String]? = nil,
        size: Int = 25,
        timeoutMs: Int = 15_000
    ) async throws -> Page<TokenHolder> {
        var dict: [String: Any] = [
            "entity": Self.holderIndex,
            "query": ["terms": ["fields": [HolderField.tokenId.wire], "values": [tokenId]]],
            "sort": [
                ["field": HolderField.balance.wire, "order": "desc"],
                ["field": HolderField.id.wire,      "order": "desc"]
            ],
            "size": String(size)
        ]
        if let after, !after.isEmpty { dict["after"] = after }
        return try await runHolders(dict, timeoutMs: timeoutMs)
    }

    /// One holder row by its derived id, or nil if the chain has never
    /// seen this pairing. See ``TokenHolder/id(fid:tokenId:)`` — the id
    /// is computable, so this needs no prior fetch.
    ///
    /// The freshest possible answer to "what can I actually spend",
    /// which is why the send form re-reads the balance through this
    /// rather than trusting the row the list was drawn from.
    public func fetchHolder(
        fid: String, tokenId: String, timeoutMs: Int = 15_000
    ) async throws -> TokenHolder? {
        let id = TokenHolder.id(fid: fid, tokenId: tokenId)
        let found = try await byIds(
            entity: Self.holderIndex, ids: [id], timeoutMs: timeoutMs
        ) { (row: TokenHolder, key: String) -> TokenHolder in
            var copy = row
            if copy.id.isEmpty { copy.id = key }
            if copy.fid == nil { copy.fid = fid }
            if copy.tokenId == nil { copy.tokenId = tokenId }
            return copy
        }
        return found[id]
    }

    // MARK: - history

    /// The op stream, filtered by token or by party.
    ///
    /// **The two filters are exclusive, matching Android.** Passing a
    /// `tokenId` gives that token's whole history including other
    /// people's ops; passing a `fid` gives everything that FID signed or
    /// received across every token. Passing both applies only the
    /// token filter — the index's `terms` clause is a disjunction, so
    /// combining them would widen the result rather than narrow it,
    /// which is the opposite of what a caller asking for both means.
    /// Passing neither gives the chain's whole token history.
    ///
    /// Sorted by `time`, not `lastHeight`: history rows are events, and
    /// the two ops in one block are ordered by ``TokenHistory/index``
    /// rather than by a height they share.
    public func fetchHistory(
        tokenId: String? = nil,
        fid: String? = nil,
        ascending: Bool = false,
        after: [String]? = nil,
        size: Int = 25,
        timeoutMs: Int = 15_000
    ) async throws -> Page<TokenHistory> {
        let order = ascending ? "asc" : "desc"
        var dict: [String: Any] = [
            "entity": Self.historyIndex,
            "sort": [
                ["field": HistoryField.time.wire, "order": order],
                ["field": HistoryField.id.wire,   "order": order]
            ],
            "size": String(size)
        ]
        if let tokenId, !tokenId.isEmpty {
            dict["query"] = ["terms": ["fields": [HistoryField.tokenId.wire], "values": [tokenId]]]
        } else if let fid, !fid.isEmpty {
            dict["query"] = [
                "terms": [
                    "fields": [HistoryField.signer.wire, HistoryField.recipient.wire],
                    "values": [fid]
                ]
            ]
        }
        if let after, !after.isEmpty { dict["after"] = after }
        return try await runHistory(dict, timeoutMs: timeoutMs)
    }

    // MARK: - the calls

    private func runTokens(_ fcdsl: [String: Any], timeoutMs: Int) async throws -> Page<Token> {
        try await run(fcdsl, timeoutMs: timeoutMs) { (rows: [Token]) in
            rows.filter { !$0.id.isEmpty }
        }
    }

    private func runHolders(_ fcdsl: [String: Any], timeoutMs: Int) async throws -> Page<TokenHolder> {
        try await run(fcdsl, timeoutMs: timeoutMs) { (rows: [TokenHolder]) in
            // A holder row's id is derivable from fid+tokenId, and
            // `init(from:)` fills it in — so a row is only unusable when
            // it carries neither the id nor both parts.
            rows.filter { !$0.id.isEmpty }
        }
    }

    private func runHistory(_ fcdsl: [String: Any], timeoutMs: Int) async throws -> Page<TokenHistory> {
        try await run(fcdsl, timeoutMs: timeoutMs) { (rows: [TokenHistory]) in
            rows.filter { !$0.id.isEmpty }
        }
    }

    private func run<Row: Decodable & Sendable>(
        _ fcdsl: [String: Any],
        timeoutMs: Int,
        clean: ([Row]) -> [Row]
    ) async throws -> Page<Row> {
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
        // a FID that has never touched a token, the normal reply.
        if let code = resp.code, code != 0 {
            if code == 404 { return .empty(bestHeight: resp.bestHeight) }
            throw Failure.fapiNonZeroCode(api: "base.search", code: code, message: resp.message)
        }
        guard let data = resp.data else {
            return Page(rows: [], last: resp.last, total: resp.total, bestHeight: resp.bestHeight)
        }
        do {
            let decoded = try JSONDecoder().decode([Row].self, from: data)
            return Page(
                rows: clean(decoded),
                last: resp.last,
                total: resp.total,
                bestHeight: resp.bestHeight
            )
        } catch {
            throw Failure.underlying(error)
        }
    }

    /// The shared by-ids path. Chunked because the endpoint caps how
    /// many ids one call may name.
    private func byIds<Row: Decodable & Sendable>(
        entity: String,
        ids: [String],
        timeoutMs: Int,
        fix: (Row, String) -> Row
    ) async throws -> [String: Row] {
        guard !ids.isEmpty else { return [:] }
        var found: [String: Row] = [:]
        for start in stride(from: 0, to: ids.count, by: 100) {
            let chunk = Array(ids[start..<min(start + 100, ids.count)])
            let body: Data
            do {
                body = try JSONSerialization.data(
                    withJSONObject: ["entity": entity, "ids": chunk], options: [.sortedKeys]
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
            let page: [String: Row]
            do {
                page = try JSONDecoder().decode([String: Row].self, from: data)
            } catch {
                throw Failure.underlying(error)
            }
            // The map key is authoritative: a record whose body omits
            // its own id still has one here.
            for (key, row) in page { found[key] = fix(row, key) }
        }
        return found
    }
}
