import Foundation
import FCCore
import FCTransport

/// On-chain reads for the Publish family — `base.search` and
/// `base.getByIds` over the `text` and `remark` indices.
///
/// **One client for both indices, unlike the Construct four.** Protocol,
/// Code, Service and App each got a service of their own because each
/// has its own field set, its own filters and its own idea of what a
/// state is. Text and Remark have one field set and one lifecycle
/// between them; two clients would have been the same query written
/// twice, and the second copy is where the sort keys drift apart.
///
/// The write half — publish, update, delete, recover — lives on
/// ``ActiveSession`` next to the other carves, because it goes through
/// the wallet's send pipeline rather than this client.
///
/// **No key is needed to read.** Everything a published record holds is
/// public, so this works fully on a watch-only identity: you can browse
/// and read anyone's work from a FID you cannot sign with. What you
/// cannot do from there is publish or remark.
public struct PublishService {

    /// Java's `IndicesNames.TEXT`, `REMARK` and `STATEMENT`. The three
    /// media indices come from ``MediaKind/index``.
    public static let textIndex = "text"
    public static let remarkIndex = "remark"
    public static let statementIndex = "statement"

    /// The fields a publisher clause on the `statement` index has to
    /// name — **both of them**.
    ///
    /// `equals` compiles to an Elasticsearch `terms` query, which is
    /// unanalysed: it matches the token as indexed. The other five
    /// publish mappings declare `publisher` as `wildcard`, so the FID
    /// is stored whole and an exact match works. The `statement`
    /// mapping never declared `publisher` at all — it declared `owner`,
    /// `active` and `lastHeight`, none of which the parser writes — so
    /// on every index built from it `publisher` arrives through dynamic
    /// mapping as **analysed text**, whose indexed token is lowercased.
    /// A `terms` query for a mixed-case FID therefore matched nothing,
    /// and "Mine" came back empty on a FID with statements in it.
    ///
    /// Naming both fields is a bool-should across them, so this matches
    /// whichever exists: `publisher.keyword` on an index with the old
    /// dynamic mapping, `publisher` on one built from the corrected
    /// mapping. A `terms` query against a field the mapping does not
    /// have matches nothing rather than erroring, so carrying both
    /// costs nothing and survives the reindex in either direction.
    static let statementPublisherFields = ["publisher", "publisher.keyword"]

    public enum Failure: Error, CustomStringConvertible {
        case fapiNonZeroCode(api: String, code: Int, message: String?)
        case underlying(Error)

        public var description: String {
            switch self {
            case let .fapiNonZeroCode(api, code, message):
                return "PublishService: \(api) returned code=\(code) message=\(message ?? "<nil>")"
            case .underlying(let e):
                return "PublishService: \(e)"
            }
        }
    }

    /// A field the two indices can be searched or sorted on.
    ///
    /// **The two sets are not the same, and getting them wrong fails
    /// differently at each end.** `title` and `summary` are analysed
    /// text — searchable, and *not* sortable, because Elasticsearch
    /// refuses to sort on an analysed field. `did`, `lang` and the rest
    /// are keywords: sortable, and only exact-matchable. `onDid` exists
    /// on `remark` alone.
    public enum Field: String, CaseIterable, Sendable, Identifiable {
        case title
        /// Statements only — the one Publish record whose body is on
        /// the chain rather than behind a `did`.
        case content
        case summary
        case publisher
        case authors
        case type
        case lang
        case did
        case onDid
        case ver
        case birthTime
        case tRate
        case tCdd
        case birthHeight
        case lastHeight
        case lastTime
        case id

        public var id: String { rawValue }

        /// The wire name — what goes in the fcdsl.
        public var name: String { rawValue }

        /// Display label. English only for now; Phase 11 localises.
        public var label: String {
            switch self {
            case .title:       return "Title"
            case .content:     return "Content"
            case .summary:     return "Summary"
            case .publisher:   return "Publisher"
            case .authors:     return "Author"
            case .type:        return "Type"
            case .lang:        return "Language"
            case .did:         return "Document"
            case .onDid:       return "Target"
            case .ver:         return "Edition"
            case .tRate:       return "Rating"
            case .tCdd:        return "Rating weight"
            case .birthTime:   return "Published"
            case .birthHeight: return "Height"
            case .lastHeight:  return "Height"
            case .lastTime:    return "Time"
            case .id:          return "ID"
            }
        }

        public static let searchable: [Field] =
            [.title, .summary, .publisher, .authors, .type, .lang, .id]
        /// Remarks have no `type`; everything else is shared.
        public static let searchableForRemark: [Field] =
            [.title, .summary, .publisher, .authors, .lang, .id]
        /// Nor do the three media protocols — each is FEIP21 minus
        /// that one field, and asking an index to match a field its
        /// mapping does not have is how a search comes back empty for
        /// no visible reason.
        public static let searchableForMedia: [Field] =
            [.title, .summary, .publisher, .authors, .lang, .id]
        public static let sortable: [Field] =
            [.lastHeight, .lastTime, .birthHeight, .tRate, .id]
        /// A statement has a birth and nothing else: no edition, no
        /// rating, and no `lastHeight`, because nothing ever touches it
        /// again. Sorting one by `lastHeight` would sort every row on a
        /// field the parser never writes.
        public static let searchableForStatement: [Field] =
            [.title, .content, .publisher, .id]
        public static let sortableForStatement: [Field] =
            [.birthHeight, .birthTime, .id]
    }

    /// One page of results plus the cursor for the next.
    public struct Page<Row: Sendable>: Sendable {
        public let rows: [Row]
        /// The server's own cursor for the page after this one. Feed it
        /// straight back as `after` — Android rebuilds `[lastHeight,
        /// id]` regardless of what it sorted by, which pages wrong for
        /// every other sort (**Android issue C17**).
        public let last: [String]?
        public let total: Int64?
        public let bestHeight: Int64?

        public init(rows: [Row], last: [String]?, total: Int64?, bestHeight: Int64?) {
            self.rows = rows
            self.last = last
            self.total = total
            self.bestHeight = bestHeight
        }
    }

    public let fapi: any FapiCalling

    public init(fapi: any FapiCalling) {
        self.fapi = fapi
    }

    // MARK: - texts

    /// One page of text records, newest first.
    ///
    /// `publisher` nil browses the whole chain — the discovery view;
    /// naming a FID gives that FID's shelf. `deleted` false is the
    /// normal list, true the retired one, nil both.
    public func fetchTexts(
        publisher: String? = nil,
        deleted: Bool? = false,
        ascending: Bool = false,
        after: [String]? = nil,
        size: Int = 25,
        timeoutMs: Int = 15_000
    ) async throws -> Page<TextRecord> {
        let dict = browseRequest(
            index: Self.textIndex, publisher: publisher, deleted: deleted,
            ascending: ascending, after: after, size: size
        )
        return try await run(dict, timeoutMs: timeoutMs, as: TextRecord.self)
    }

    /// Full-text search over text records.
    ///
    /// Unscoped by publisher unless one is given: a published work is
    /// meant to be found by strangers, which is the difference between
    /// this and ``ProofService/search(for:query:inField:sortField:ascending:destroyed:after:size:timeoutMs:)``.
    public func searchTexts(
        query text: String,
        inField: Field? = nil,
        publisher: String? = nil,
        sortField: Field? = nil,
        ascending: Bool = false,
        deleted: Bool? = false,
        after: [String]? = nil,
        size: Int = 25,
        timeoutMs: Int = 15_000
    ) async throws -> Page<TextRecord> {
        let dict = searchRequest(
            index: Self.textIndex, text: text, inField: inField,
            fields: Field.searchable, publisher: publisher, deleted: deleted,
            sortField: sortField, ascending: ascending, after: after, size: size
        )
        return try await run(dict, timeoutMs: timeoutMs, as: TextRecord.self)
    }

    /// Fetch specific text records by id — the path for reading back a
    /// work somebody sent you the id of, and for confirming a carve you
    /// just broadcast: the record appears here once a block includes
    /// it, which is what flips a row from broadcast-unconfirmed to
    /// on-chain.
    public func textsByIds(
        _ ids: [String], timeoutMs: Int = 15_000
    ) async throws -> [String: TextRecord] {
        try await byIds(index: Self.textIndex, ids: ids, timeoutMs: timeoutMs, as: TextRecord.self)
    }

    // MARK: - media

    /// One page of image, sound or video records, newest first. Same
    /// arguments and same meaning as ``fetchTexts(publisher:deleted:ascending:after:size:timeoutMs:)``
    /// — `publisher` nil browses the whole chain.
    ///
    /// Rows come back stamped with `kind`, which no server row carries:
    /// the index asked is what knows, and that is here.
    public func fetchMedia(
        kind: MediaKind,
        publisher: String? = nil,
        deleted: Bool? = false,
        ascending: Bool = false,
        after: [String]? = nil,
        size: Int = 25,
        timeoutMs: Int = 15_000
    ) async throws -> Page<MediaRecord> {
        let dict = browseRequest(
            index: kind.index, publisher: publisher, deleted: deleted,
            ascending: ascending, after: after, size: size
        )
        return try await run(dict, timeoutMs: timeoutMs, as: MediaRecord.self).stamped(kind)
    }

    public func searchMedia(
        kind: MediaKind,
        query text: String,
        inField: Field? = nil,
        publisher: String? = nil,
        sortField: Field? = nil,
        ascending: Bool = false,
        deleted: Bool? = false,
        after: [String]? = nil,
        size: Int = 25,
        timeoutMs: Int = 15_000
    ) async throws -> Page<MediaRecord> {
        let dict = searchRequest(
            index: kind.index, text: text, inField: inField,
            fields: Field.searchableForMedia, publisher: publisher, deleted: deleted,
            sortField: sortField, ascending: ascending, after: after, size: size
        )
        return try await run(dict, timeoutMs: timeoutMs, as: MediaRecord.self).stamped(kind)
    }

    public func mediaByIds(
        kind: MediaKind, _ ids: [String], timeoutMs: Int = 15_000
    ) async throws -> [String: MediaRecord] {
        let found = try await byIds(
            index: kind.index, ids: ids, timeoutMs: timeoutMs, as: MediaRecord.self
        )
        return found.mapValues { row in
            var copy = row
            copy.kind = kind
            return copy
        }
    }

    // MARK: - statements

    /// One page of statements, newest first.
    ///
    /// **Sorted and filtered on `birthHeight`, not `lastHeight`.** A
    /// statement is written once and never touched, so the parser never
    /// writes a `lastHeight`; asking the index to sort on it would sort
    /// every row on a field none of them have.
    ///
    /// There is no `deleted` argument because there is no such flag —
    /// nothing can retire a statement.
    public func fetchStatements(
        publisher: String? = nil,
        ascending: Bool = false,
        after: [String]? = nil,
        size: Int = 25,
        timeoutMs: Int = 15_000
    ) async throws -> Page<Statement> {
        let order = ascending ? "asc" : "desc"
        var dict: [String: Any] = [
            "entity": Self.statementIndex,
            "sort": [
                ["field": Field.birthHeight.name, "order": order],
                ["field": Field.id.name, "order": order]
            ],
            "size": String(size)
        ]
        if let publisher, !publisher.isEmpty {
            dict["query"] = [
                "equals": ["fields": Self.statementPublisherFields, "values": [publisher]]
            ]
        }
        if let after, !after.isEmpty { dict["after"] = after }
        return try await run(dict, timeoutMs: timeoutMs, as: Statement.self)
    }

    /// Full-text search over statements — `content` included, because
    /// for this one record the body really is in the index.
    public func searchStatements(
        query text: String,
        inField: Field? = nil,
        publisher: String? = nil,
        sortField: Field? = nil,
        ascending: Bool = false,
        after: [String]? = nil,
        size: Int = 25,
        timeoutMs: Int = 15_000
    ) async throws -> Page<Statement> {
        let names = inField.map { [$0.name] } ?? Field.searchableForStatement.map(\.name)
        let order = ascending ? "asc" : "desc"
        let sorted = sortField ?? .birthHeight

        var sorts: [[String: String]] = [["field": sorted.name, "order": order]]
        if sorted != .id {
            sorts.append(["field": Field.id.name, "order": order])
        }

        var query: [String: Any] = ["match": ["fields": names, "value": text]]
        if let publisher, !publisher.isEmpty {
            query["equals"] = ["fields": Self.statementPublisherFields, "values": [publisher]]
        }
        var dict: [String: Any] = [
            "entity": Self.statementIndex,
            "query": query,
            "sort": sorts,
            "size": String(size)
        ]
        if let after, !after.isEmpty { dict["after"] = after }
        return try await run(dict, timeoutMs: timeoutMs, as: Statement.self)
    }

    public func statementsByIds(
        _ ids: [String], timeoutMs: Int = 15_000
    ) async throws -> [String: Statement] {
        try await byIds(
            index: Self.statementIndex, ids: ids, timeoutMs: timeoutMs, as: Statement.self
        )
    }

    // MARK: - remarks

    /// The remarks anchored to one published record — the thread under
    /// a work.
    ///
    /// Matches `onDid` against the target's **record id**, which is what
    /// this app carves there; see ``Remark``. Ascending by default,
    /// because a thread reads oldest-first while a shelf reads
    /// newest-first.
    public func fetchRemarks(
        on targetId: String,
        deleted: Bool? = false,
        ascending: Bool = true,
        after: [String]? = nil,
        size: Int = 50,
        timeoutMs: Int = 15_000
    ) async throws -> Page<Remark> {
        let order = ascending ? "asc" : "desc"
        var query: [String: Any] = [
            "terms": ["fields": [Field.onDid.name], "values": [targetId]]
        ]
        if let deleted {
            query["equals"] = ["fields": ["deleted"], "values": [deleted ? "true" : "false"]]
        }
        var dict: [String: Any] = [
            "entity": Self.remarkIndex,
            "query": query,
            "sort": [
                ["field": Field.lastHeight.name, "order": order],
                ["field": Field.id.name, "order": order]
            ],
            "size": String(size)
        ]
        if let after, !after.isEmpty { dict["after"] = after }
        return try await run(dict, timeoutMs: timeoutMs, as: Remark.self)
    }

    /// One page of remark records, newest first — a publisher's own
    /// annotations, or the whole chain's.
    public func fetchRemarks(
        publisher: String? = nil,
        deleted: Bool? = false,
        ascending: Bool = false,
        after: [String]? = nil,
        size: Int = 25,
        timeoutMs: Int = 15_000
    ) async throws -> Page<Remark> {
        let dict = browseRequest(
            index: Self.remarkIndex, publisher: publisher, deleted: deleted,
            ascending: ascending, after: after, size: size
        )
        return try await run(dict, timeoutMs: timeoutMs, as: Remark.self)
    }

    public func searchRemarks(
        query text: String,
        inField: Field? = nil,
        publisher: String? = nil,
        sortField: Field? = nil,
        ascending: Bool = false,
        deleted: Bool? = false,
        after: [String]? = nil,
        size: Int = 25,
        timeoutMs: Int = 15_000
    ) async throws -> Page<Remark> {
        let dict = searchRequest(
            index: Self.remarkIndex, text: text, inField: inField,
            fields: Field.searchableForRemark, publisher: publisher, deleted: deleted,
            sortField: sortField, ascending: ascending, after: after, size: size
        )
        return try await run(dict, timeoutMs: timeoutMs, as: Remark.self)
    }

    public func remarksByIds(
        _ ids: [String], timeoutMs: Int = 15_000
    ) async throws -> [String: Remark] {
        try await byIds(index: Self.remarkIndex, ids: ids, timeoutMs: timeoutMs, as: Remark.self)
    }

    // MARK: - request shapes

    private func browseRequest(
        index: String, publisher: String?, deleted: Bool?,
        ascending: Bool, after: [String]?, size: Int
    ) -> [String: Any] {
        let order = ascending ? "asc" : "desc"
        var query: [String: Any] = [:]
        if let publisher, !publisher.isEmpty {
            query["equals"] = ["fields": [Field.publisher.name], "values": [publisher]]
        }
        // `deleted` takes the `terms` slot when `equals` is spoken for:
        // one filter holds one clause of each kind, the same slot
        // conflict `ServiceRegistry` documents.
        if let deleted {
            let clause = ["fields": ["deleted"], "values": [deleted ? "true" : "false"]]
            query[query.keys.contains("equals") ? "terms" : "equals"] = clause
        }
        var dict: [String: Any] = [
            "entity": index,
            "sort": [
                ["field": Field.lastHeight.name, "order": order],
                ["field": Field.id.name, "order": order]
            ],
            "size": String(size)
        ]
        if !query.isEmpty { dict["query"] = query }
        if let after, !after.isEmpty { dict["after"] = after }
        return dict
    }

    private func searchRequest(
        index: String, text: String, inField: Field?, fields: [Field],
        publisher: String?, deleted: Bool?, sortField: Field?,
        ascending: Bool, after: [String]?, size: Int
    ) -> [String: Any] {
        let names = inField.map { [$0.name] } ?? fields.map(\.name)
        let order = ascending ? "asc" : "desc"
        let sorted = sortField ?? .lastHeight

        var sorts: [[String: String]] = [["field": sorted.name, "order": order]]
        if sorted != .id {
            sorts.append(["field": Field.id.name, "order": order])
        }

        var query: [String: Any] = ["match": ["fields": names, "value": text]]
        if let publisher, !publisher.isEmpty {
            query["equals"] = ["fields": [Field.publisher.name], "values": [publisher]]
        }
        if let deleted {
            let clause = ["fields": ["deleted"], "values": [deleted ? "true" : "false"]]
            query[query.keys.contains("equals") ? "terms" : "equals"] = clause
        }
        var dict: [String: Any] = [
            "entity": index,
            "query": query,
            "sort": sorts,
            "size": String(size)
        ]
        if let after, !after.isEmpty { dict["after"] = after }
        return dict
    }

    // MARK: - the two calls

    private func run<Row: Decodable & Sendable>(
        _ fcdsl: [String: Any], timeoutMs: Int, as rowType: Row.Type
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
        // 404 is the server's "nothing matched" — an empty page, and
        // for a FID that has never published, the normal reply.
        if let code = resp.code, code != 0 {
            if code == 404 {
                return Page(rows: [], last: nil, total: 0, bestHeight: resp.bestHeight)
            }
            throw Failure.fapiNonZeroCode(api: "base.search", code: code, message: resp.message)
        }
        guard let data = resp.data else {
            return Page(rows: [], last: resp.last, total: resp.total, bestHeight: resp.bestHeight)
        }
        do {
            let decoded = try JSONDecoder().decode([Row].self, from: data)
            return Page(
                rows: decoded.compactMap { Self.stampOnChain($0) },
                last: resp.last, total: resp.total, bestHeight: resp.bestHeight
            )
        } catch {
            throw Failure.underlying(error)
        }
    }

    private func byIds<Row: Decodable & Sendable>(
        index: String, ids: [String], timeoutMs: Int, as rowType: Row.Type
    ) async throws -> [String: Row] {
        guard !ids.isEmpty else { return [:] }
        var found: [String: Row] = [:]
        // The endpoint caps how many ids one call may name; page the
        // list rather than sending an unbounded one.
        for start in stride(from: 0, to: ids.count, by: 100) {
            let chunk = Array(ids[start..<min(start + 100, ids.count)])
            let body: Data
            do {
                body = try JSONSerialization.data(
                    withJSONObject: ["entity": index, "ids": chunk], options: [.sortedKeys]
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
            // By-ids answers with a *map* from id to record, not an
            // array — the shape mismatch that once made every SID
            // unresolvable. Ids absent from the reply have no record
            // yet, which for a just-broadcast carve is the expected
            // answer rather than an error.
            let page: [String: Row]
            do {
                page = try JSONDecoder().decode([String: Row].self, from: data)
            } catch {
                throw Failure.underlying(error)
            }
            for (key, row) in page {
                // The map key is authoritative: a record whose body
                // omits its own id still has one here.
                guard let stamped = Self.stampOnChain(row, fallbackId: key) else { continue }
                found[key] = stamped
            }
        }
        return found
    }

    /// Chain rows are on-chain by definition; the wire carries no such
    /// field, and the pane's whole layout keys off it. Rows with no
    /// usable id are dropped rather than shown as a blank.
    private static func stampOnChain<Row>(_ row: Row, fallbackId: String? = nil) -> Row? {
        if var text = row as? TextRecord {
            if text.id.isEmpty { text.id = fallbackId ?? "" }
            guard !text.id.isEmpty else { return nil }
            text.onChain = true
            return text as? Row
        }
        if var remark = row as? Remark {
            if remark.id.isEmpty { remark.id = fallbackId ?? "" }
            guard !remark.id.isEmpty else { return nil }
            remark.onChain = true
            return remark as? Row
        }
        if var statement = row as? Statement {
            if statement.id.isEmpty { statement.id = fallbackId ?? "" }
            guard !statement.id.isEmpty else { return nil }
            statement.onChain = true
            return statement as? Row
        }
        if var media = row as? MediaRecord {
            if media.id.isEmpty { media.id = fallbackId ?? "" }
            guard !media.id.isEmpty else { return nil }
            media.onChain = true
            return media as? Row
        }
        return row
    }
}

extension PublishService.Page where Row == MediaRecord {
    /// Stamp every row with the kind of the index it came from.
    ///
    /// No media index carries a `kind` field — the three are the same
    /// shape — so the only thing that knows is the query that was sent.
    /// Doing it here rather than in each caller means a row can never
    /// reach a pane claiming to be the wrong medium.
    func stamped(_ kind: MediaKind) -> Self {
        PublishService.Page(
            rows: rows.map { row in
                var copy = row
                copy.kind = kind
                return copy
            },
            last: last, total: total, bestHeight: bestHeight
        )
    }
}
