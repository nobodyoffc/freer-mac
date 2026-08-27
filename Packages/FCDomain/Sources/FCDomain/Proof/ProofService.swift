import Foundation
import FCCore
import FCTransport

/// On-chain proof reads — the port of Android's `ProofManager`'s API
/// half (`makeFcdsl` / `buildSearchFcdsl` / `fetchPageProofs`), over
/// `base.search` against the `proof` index.
///
/// The write half — issue, sign, transfer, destroy — lives on
/// ``ActiveSession`` next to the other carves, because it goes through
/// the wallet's send pipeline rather than this client.
///
/// **No key is needed to read.** Every field of a proof is public,
/// which makes this, like ``NewsService``, a path that works fully on a
/// watch-only identity: you can watch a proof you were invited to
/// countersign even from a FID you cannot sign with. What you cannot do
/// from there is countersign it.
public struct ProofService {

    /// The index this reads. Java's `IndicesNames.PROOF`.
    public static let index = "proof"

    public enum Failure: Error, CustomStringConvertible {
        case fapiNonZeroCode(api: String, code: Int, message: String?)
        case underlying(Error)

        public var description: String {
            switch self {
            case let .fapiNonZeroCode(api, code, message):
                return "ProofService: \(api) returned code=\(code) message=\(message ?? "<nil>")"
            case .underlying(let e):
                return "ProofService: \(e)"
            }
        }
    }

    /// A field the `proof` index can be searched or sorted on. The two
    /// sets differ — you can search the body text but not sort by it —
    /// so ``searchable`` and ``sortable`` name them separately, mirroring
    /// Java's `getSearchableFields` / `getSortableFields`.
    public enum Field: String, CaseIterable, Sendable, Identifiable {
        case title
        case content
        case issuer
        case owner
        case cosignersInvited
        case lastHeight
        case lastTime
        case id

        public var id: String { rawValue }

        /// The wire name — what goes in the fcdsl.
        public var name: String { rawValue }

        /// Display label. English only for now; Phase 11 localises.
        public var label: String {
            switch self {
            case .title:            return "Title"
            case .content:          return "Content"
            case .issuer:           return "Issuer"
            case .owner:            return "Owner"
            case .cosignersInvited: return "Cosigner"
            case .lastHeight:       return "Height"
            case .lastTime:         return "Time"
            case .id:               return "ID"
            }
        }

        public static let searchable: [Field] =
            [.title, .content, .issuer, .owner, .cosignersInvited, .id]
        public static let sortable: [Field] =
            [.lastHeight, .lastTime, .title, .issuer, .owner, .id]
    }

    /// One page of results plus what is needed to ask for the next.
    public struct Page: Sendable {
        public let proofs: [Proof]
        /// The server's own cursor for the page after this one. Feed it
        /// straight back as `after` — see ``search`` for why this rather
        /// than a locally rebuilt key pair.
        public let last: [String]?
        public let total: Int64?
        public let bestHeight: Int64?

        public init(
            proofs: [Proof], last: [String]?,
            total: Int64?, bestHeight: Int64?
        ) {
            self.proofs = proofs
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

    /// The proofs `fid` has a stake in — one page, newest first.
    ///
    /// **Three roles, one query.** The `equals` clause matches `fid`
    /// against `owner`, `issuer` *or* `cosignersInvited`, so the list
    /// holds proofs you hold, proofs you minted and gave away, and
    /// proofs somebody else minted and asked you to countersign. Those
    /// are three different relationships and the pane distinguishes
    /// them, but they are one fetch: they are exactly the set of proofs
    /// that can require something of you.
    ///
    /// `destroyed` nil fetches both live and retired records; false is
    /// the normal list, true is the retired-proofs view.
    public func fetchProofs(
        for fid: String,
        destroyed: Bool? = false,
        ascending: Bool = false,
        after: [String]? = nil,
        size: Int = 25,
        timeoutMs: Int = 15_000
    ) async throws -> Page {
        let order = ascending ? "asc" : "desc"
        var query: [String: Any] = [
            "equals": [
                "fields": [Field.owner.name, Field.issuer.name, Field.cosignersInvited.name],
                "values": [fid]
            ]
        ]
        // `terms` is what Java uses for this flag, and the values go as
        // strings — the index stores the boolean, the query spells it.
        if let destroyed {
            query["terms"] = ["fields": ["destroyed"], "values": [destroyed ? "true" : "false"]]
        }
        var dict: [String: Any] = [
            "entity": Self.index,
            "query": query,
            "sort": [
                ["field": Field.lastHeight.name, "order": order],
                ["field": Field.id.name,         "order": order]
            ],
            "size": String(size)
        ]
        if let after, !after.isEmpty { dict["after"] = after }
        return try await run(dict, timeoutMs: timeoutMs)
    }

    // MARK: - search

    /// Full-text search across `fid`'s proofs.
    ///
    /// Scoped to the same three-role `equals` clause as ``fetchProofs``:
    /// the chain index holds everyone's proofs, and a search box on a
    /// pane titled "your proofs" that quietly returned strangers'
    /// documents would be a different feature wearing this one's UI. A
    /// proof you were shown but are not party to is found by id through
    /// ``fetchProofsByIds(_:timeoutMs:)``.
    ///
    /// **Pages from the server's cursor.** Android rebuilds `after` as
    /// `[lastHeight, id]` for every search regardless of what it sorted
    /// by, and `search_after` compares positionally against the sort
    /// keys actually used — so its title-, issuer- and owner-sorted
    /// searches page wrong (the same defect as News, **Android issue
    /// C17**). Passing ``Page/last`` back is correct for every sort.
    public func search(
        for fid: String,
        query text: String,
        inField: Field? = nil,
        sortField: Field? = nil,
        ascending: Bool = false,
        destroyed: Bool? = false,
        after: [String]? = nil,
        size: Int = 25,
        timeoutMs: Int = 15_000
    ) async throws -> Page {
        let fields = inField.map { [$0.name] } ?? Field.searchable.map(\.name)
        let order = ascending ? "asc" : "desc"
        let sorted = sortField ?? .lastHeight

        var sorts: [[String: String]] = [["field": sorted.name, "order": order]]
        if sorted != .id {
            sorts.append(["field": Field.id.name, "order": order])
        }

        var query: [String: Any] = [
            "equals": [
                "fields": [Field.owner.name, Field.issuer.name, Field.cosignersInvited.name],
                "values": [fid]
            ],
            "match": ["fields": fields, "value": text]
        ]
        if let destroyed {
            query["terms"] = ["fields": ["destroyed"], "values": [destroyed ? "true" : "false"]]
        }
        var dict: [String: Any] = [
            "entity": Self.index,
            "query": query,
            "sort": sorts,
            "size": String(size)
        ]
        if let after, !after.isEmpty { dict["after"] = after }
        return try await run(dict, timeoutMs: timeoutMs)
    }

    // MARK: - by id

    /// Fetch specific proofs by record id, unscoped by owner —
    /// Android's `proofByIds`.
    ///
    /// This is the path for the two things the browse query cannot do:
    /// read back a proof you have only the id of (someone sent you one
    /// to verify), and confirm a carve you just broadcast — the record
    /// appears here once a block includes it, which is what flips a row
    /// from broadcast-unconfirmed to on-chain.
    ///
    /// **Not `base.search`.** By-ids is its own endpoint
    /// (``DirectoryService/getByIdsApi``) and its `data` is a *map* from
    /// id to record, not an array — the same shape mismatch that made
    /// every SID unresolvable when service lookups went to the wrong
    /// endpoint. Ids absent from the reply simply have no record yet,
    /// which for a just-broadcast carve is the expected answer.
    public func fetchProofsByIds(
        _ ids: [String],
        timeoutMs: Int = 15_000
    ) async throws -> [String: Proof] {
        guard !ids.isEmpty else { return [:] }
        var found: [String: Proof] = [:]
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
            let page: [String: Proof]
            do {
                page = try JSONDecoder().decode([String: Proof].self, from: data)
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
        // 404 is the server's "nothing matched" — an empty page, and
        // for a FID that has never touched a proof, the normal reply.
        if let code = resp.code, code != 0 {
            if code == 404 {
                return Page(proofs: [], last: nil, total: 0, bestHeight: resp.bestHeight)
            }
            throw Failure.fapiNonZeroCode(
                api: "base.search", code: code, message: resp.message
            )
        }
        guard let data = resp.data else {
            return Page(
                proofs: [], last: resp.last,
                total: resp.total, bestHeight: resp.bestHeight
            )
        }
        do {
            let decoded = try JSONDecoder().decode([Proof].self, from: data)
            // Chain rows are on-chain by definition; the wire may or may
            // not carry the flag, and the pane's whole layout keys off
            // it, so stamp it rather than trusting the field to be there.
            let proofs = decoded
                .filter { !$0.id.isEmpty }
                .map { row -> Proof in
                    var copy = row
                    copy.onChain = true
                    return copy
                }
            return Page(
                proofs: proofs,
                last: resp.last,
                total: resp.total,
                bestHeight: resp.bestHeight
            )
        } catch {
            throw Failure.underlying(error)
        }
    }
}
