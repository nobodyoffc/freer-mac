import Foundation
import FCTransport

/// Identity-directory FAPI calls: `base.freerByIds` for the on-chain
/// ``Freer`` block behind a FID, and `base.getByIds` for the
/// ``Service`` record behind a SID.
///
/// Lives next to ``WalletService`` rather than inside it because the
/// concerns are different: the wallet manages money state for a
/// specific live FID, the directory looks up arbitrary FIDs the user
/// is curious about (contact creation, contact refresh, future
/// CID→FID resolution).
///
/// Stateless w.r.t. caching — callers persist results into
/// ``ContactsStore`` and/or ``KeysStore`` themselves. That keeps the
/// service trivially constructable for tests and avoids a
/// who-owns-the-cache argument with `WalletService`.
public struct DirectoryService {

    public enum Failure: Error, CustomStringConvertible {
        case fapiNonZeroCode(api: String, code: Int, message: String?)
        case underlying(Error)

        public var description: String {
            switch self {
            case let .fapiNonZeroCode(api, code, message):
                return "DirectoryService: \(api) returned code=\(code) message=\(message ?? "<nil>")"
            case .underlying(let e):
                return "DirectoryService: \(e)"
            }
        }
    }

    public let fapi: any FapiCalling

    public init(fapi: any FapiCalling) {
        self.fapi = fapi
    }

    /// Look up the on-chain ``Freer`` records for `fids`. Mirrors the
    /// Java `FapiClient.freerByIds(...)`: FCDSL `{"ids": [...]}` against
    /// `base.freerByIds`, response `data` is `Map<String, Freer>` keyed
    /// by FID.
    ///
    /// FIDs that have no on-chain record are simply absent from the
    /// returned dictionary — not an error. An empty `fids` returns
    /// an empty dict without making a call.
    public func freerByIds(
        _ fids: [String],
        timeoutMs: Int = 5_000
    ) async throws -> [String: Freer] {
        guard !fids.isEmpty else { return [:] }
        let body = try JSONSerialization.data(
            withJSONObject: ["ids": fids],
            options: [.sortedKeys]
        )
        let reply = try await fapi.call(
            api: "base.freerByIds",
            params: nil, fcdsl: body, binary: nil,
            sid: nil, via: nil, maxCost: nil,
            timeoutMs: timeoutMs
        )
        let resp = reply.response
        // 404 / NOT_FOUND is what the server emits when none of the
        // requested FIDs exist on-chain. That's a normal "off-chain"
        // result, not a failure.
        if let code = resp.code, code != 0 {
            if code == 404 { return [:] }
            throw Failure.fapiNonZeroCode(
                api: "base.freerByIds",
                code: code,
                message: resp.message
            )
        }
        guard let data = resp.data else { return [:] }
        do {
            return try JSONDecoder().decode([String: Freer].self, from: data)
        } catch {
            throw Failure.underlying(error)
        }
    }

    /// Convenience wrapper: look up one FID. Returns nil when the
    /// server reports no on-chain record for it.
    public func freer(byId fid: String, timeoutMs: Int = 5_000) async throws -> Freer? {
        let map = try await freerByIds([fid], timeoutMs: timeoutMs)
        return map[fid]
    }

    /// The endpoint service records come from, and the index they live
    /// in — Java's `entityByIds(IndicesNames.SERVICE, …)`.
    ///
    /// **Not `base.serviceByIds`.** Freers have a dedicated endpoint;
    /// services do not, and go through the generic by-ids reader with
    /// the index named in the query. Calling the endpoint that reads
    /// like its sibling gets a 404, which this layer treats as "no such
    /// record" — so the mistake did not raise an error, it just made
    /// every SID unresolvable while leaving direct-URL homes working.
    public static let getByIdsApi = "base.getByIds"
    public static let serviceIndex = "service"

    /// Look up on-chain ``Service`` records by SID.
    ///
    /// This is how a `(sid)` in someone's `home` map becomes an address:
    /// see ``HomeServiceResolver``.
    public func serviceByIds(
        _ sids: [String],
        timeoutMs: Int = 5_000
    ) async throws -> [String: Service] {
        guard !sids.isEmpty else { return [:] }
        let body = try JSONSerialization.data(
            withJSONObject: ["entity": Self.serviceIndex, "ids": sids],
            options: [.sortedKeys]
        )
        let reply = try await fapi.call(
            api: Self.getByIdsApi,
            params: nil, fcdsl: body, binary: nil,
            sid: nil, via: nil, maxCost: nil,
            timeoutMs: timeoutMs
        )
        let resp = reply.response
        if let code = resp.code, code != 0 {
            if code == 404 { return [:] }
            throw Failure.fapiNonZeroCode(
                api: Self.getByIdsApi,
                code: code,
                message: resp.message
            )
        }
        guard let data = resp.data else { return [:] }
        do {
            return try JSONDecoder().decode([String: Service].self, from: data)
        } catch {
            throw Failure.underlying(error)
        }
    }

    /// One service by SID, or nil when the chain has no such record.
    public func serviceById(_ sid: String, timeoutMs: Int = 5_000) async throws -> Service? {
        try await serviceByIds([sid], timeoutMs: timeoutMs)[sid]
    }

    // MARK: - partial-match search

    /// One page of a ``searchFreers(matching:after:size:timeoutMs:)``
    /// result.
    public struct FreerSearchPage: Sendable {
        /// Matches, in server order.
        public let freers: [Freer]
        /// Cursor to pass as `after` for the next page. Nil/empty when
        /// the server didn't provide one.
        public let last: [String]?
        /// Total matches server-side, when reported — drives the
        /// "N left" hint next to a Load-more control.
        public let total: Int64?

        public init(freers: [Freer], last: [String]?, total: Int64?) {
            self.freers = freers
            self.last = last
            self.total = total
        }
    }

    /// Partial-match search for Freers whose FID or any current/past
    /// CID contains `term`. Mirrors the Android
    /// `CreateContactActivity.searchPartialCid`: FCDSL `part` query on
    /// `id` + `usedCids` against `base.search`, entity `freer`,
    /// cursor-paginated via `after`.
    ///
    /// No matches (server 404) is a normal empty page, not an error.
    public func searchFreers(
        matching term: String,
        after: [String]? = nil,
        size: Int = 10,
        timeoutMs: Int = 15_000
    ) async throws -> FreerSearchPage {
        var dict: [String: Any] = [
            "entity": "freer",
            "query": [
                "part": ["fields": ["id", "usedCids"], "value": term]
            ],
            "size": String(size)
        ]
        if let after, !after.isEmpty { dict["after"] = after }
        let body = try JSONSerialization.data(withJSONObject: dict, options: [.sortedKeys])

        let reply = try await fapi.call(
            api: "base.search",
            params: nil, fcdsl: body, binary: nil,
            sid: nil, via: nil, maxCost: nil,
            timeoutMs: timeoutMs
        )
        let resp = reply.response
        if let code = resp.code, code != 0 {
            if code == 404 { return FreerSearchPage(freers: [], last: nil, total: 0) }
            throw Failure.fapiNonZeroCode(
                api: "base.search", code: code, message: resp.message
            )
        }
        guard let data = resp.data else {
            return FreerSearchPage(freers: [], last: nil, total: resp.total)
        }
        do {
            let freers = try JSONDecoder().decode([Freer].self, from: data)
            return FreerSearchPage(freers: freers, last: resp.last, total: resp.total)
        } catch {
            throw Failure.underlying(error)
        }
    }

    // MARK: - on-chain contact sync

    /// Outcome of one ``syncOnChainContacts(owner:privkey:into:)`` run.
    public struct ContactSyncResult: Sendable {
        /// Contacts decrypted and written into the store.
        public let merged: Int
        /// Local rows removed because the chain reports their newest
        /// carve as deleted (`active == false`).
        public let removed: Int
        /// Local rows whose `onChain` flag was cleared because the
        /// chain has no carve for them at all (stale marking — e.g.
        /// rows saved by an old build that flipped `onChain` on a
        /// directory lookup).
        public let demoted: Int
        /// On-chain records whose cipher couldn't be decrypted (legacy
        /// algorithm, key mismatch, corrupt payload). Skipped, since
        /// without the plaintext we don't even know the contact's FID.
        public let undecryptable: Int
        /// Total records (active + deleted) the server returned for
        /// this owner.
        public let total: Int
        /// Reasons for the first few failures — surfaced so a
        /// systematic mismatch (wrong algorithm, wrong key) is
        /// diagnosable from the UI instead of an opaque count.
        public let failureReasons: [String]
    }

    /// Fetch every on-chain CONTACT record carved by `owner` — active
    /// AND deleted, like Android's `refreshEntitiesFromAPI` (which
    /// passes `active = null` so deletions can clean the local DB).
    /// Mirrors `ContactManager.makeFcdsl` otherwise: `base.search` on
    /// `entity: "contact"`, `query.equals owner == fid`, sorted
    /// `lastHeight desc, id desc`, cursor-paginated via `after`.
    public func fetchOnChainContactRecords(
        owner fid: String,
        pageSize: Int = 200,
        maxPages: Int = 200,
        timeoutMs: Int = 15_000
    ) async throws -> [OnChainContactRecord] {
        var all: [OnChainContactRecord] = []
        var after: [String]? = nil
        for _ in 0..<maxPages {
            let query: [String: Any] = [
                "equals": ["fields": ["owner"],  "values": [fid]]
            ]
            var dict: [String: Any] = [
                "entity": "contact",
                "query": query,
                "sort": [
                    ["field": "lastHeight", "order": "desc"],
                    ["field": "id",         "order": "desc"]
                ],
                "size": String(pageSize)
            ]
            if let after, !after.isEmpty { dict["after"] = after }
            let body = try JSONSerialization.data(withJSONObject: dict, options: [.sortedKeys])

            let reply = try await fapi.call(
                api: "base.search",
                params: nil, fcdsl: body, binary: nil,
                sid: nil, via: nil, maxCost: nil,
                timeoutMs: timeoutMs
            )
            let resp = reply.response
            // 404 / NOT_FOUND = no carved contacts. Normal for a fresh FID.
            if let code = resp.code, code != 0 {
                if code == 404 { break }
                throw Failure.fapiNonZeroCode(
                    api: "base.search", code: code, message: resp.message
                )
            }
            guard let data = resp.data else { break }
            let page: [OnChainContactRecord]
            do {
                page = try JSONDecoder().decode([OnChainContactRecord].self, from: data)
            } catch {
                throw Failure.underlying(error)
            }
            all.append(contentsOf: page)
            if page.count < pageSize { break }
            guard let next = resp.last, !next.isEmpty else { break }
            after = next
        }
        return all
    }

    /// Pull `owner`'s carved contacts from the chain, decrypt each
    /// record's cipher with `privkey`, enrich the decrypted FIDs via
    /// `base.freerByIds`, and upsert into `store`. Mirrors the Android
    /// `ContactActivity.loadInitialData` → `refreshContactsFromAPI` →
    /// `makeEntityDetails` path.
    ///
    /// Local-only contacts (never carved) are untouched. For a FID that
    /// exists both locally and on-chain, the on-chain detail block wins
    /// (it *is* the user's own saved data — newest copy from the chain)
    /// while Mac-local extras (`pinnedAt`, `addedAt`) are preserved.
    /// When the same FID was carved more than once, the highest
    /// `lastHeight` wins (the fetch is sorted newest-first).
    ///
    /// **Deletion cleanup.** The fetch includes deleted carves; when a
    /// FID's *newest* carve is `active == false`, its local row is
    /// removed — but only if that row came from the chain
    /// (`onChain == true`). A purely local contact that happens to
    /// share a FID with an old deleted carve stays put. Mirrors
    /// Android's `updateToDBForNewer` + `isEntityDeleted`.
    @discardableResult
    public func syncOnChainContacts(
        owner fid: String,
        privkey: Data,
        into store: ContactsStore,
        timeoutMs: Int = 15_000
    ) async throws -> ContactSyncResult {
        let records = try await fetchOnChainContactRecords(
            owner: fid, timeoutMs: timeoutMs
        )

        // Decrypt. Newest-first sort means the first decrypt of a FID
        // is the freshest carve — later duplicates are dropped.
        var detailByFid: [String: (record: OnChainContactRecord, detail: OnChainContactDetail)] = [:]
        var order: [String] = []
        var undecryptable = 0
        var failureReasons: [String] = []
        func noteFailure(_ record: OnChainContactRecord, _ reason: String) {
            undecryptable += 1
            if failureReasons.count < 3 {
                let rid = record.id.map { id in
                    id.count <= 16 ? id : "\(id.prefix(8))…\(id.suffix(8))"
                } ?? "?"
                failureReasons.append("[\(rid)] \(reason)")
            }
        }
        for record in records {
            guard let cipherString = record.cipher, !cipherString.isEmpty else {
                noteFailure(record, "record has no cipher field")
                continue
            }
            let plain: Data
            do {
                plain = try AsyOneWayCipher.decrypt(
                    cipherString: cipherString, privkey: privkey
                )
            } catch {
                noteFailure(record, String(describing: error))
                continue
            }
            guard let detail = try? JSONDecoder().decode(OnChainContactDetail.self, from: plain),
                  let contactFid = detail.fid, !contactFid.isEmpty else {
                noteFailure(record, String(describing:
                    AsyOneWayCipher.Failure.plaintextNotJson(alg: "?")))
                continue
            }
            if detailByFid[contactFid] == nil {
                detailByFid[contactFid] = (record, detail)
                order.append(contactFid)
            }
        }

        // Split into live upserts and deletions by the newest carve's
        // active flag before spending a freerByIds round-trip on FIDs
        // we're about to remove.
        let liveFids = order.filter { detailByFid[$0]?.record.active != false }

        // Enrich all live FIDs in one freerByIds round-trip.
        // Fail-soft: a directory hiccup shouldn't lose the decrypted
        // contacts themselves.
        let freers = (try? await freerByIds(liveFids, timeoutMs: timeoutMs)) ?? [:]

        var merged = 0
        var removed = 0
        for contactFid in order {
            guard let (record, detail) = detailByFid[contactFid] else { continue }

            if record.active == false {
                // Newest carve is a deletion. Drop the local row iff it
                // was chain-sourced; never touch local-only contacts.
                if let existing = try? store.get(fid: contactFid),
                   existing.onChain == true,
                   (try? store.remove(fid: contactFid)) == true {
                    removed += 1
                }
                continue
            }

            var contact = (try? store.get(fid: contactFid))
                ?? Contact(id: contactFid)
            contact.titles = detail.titles
            contact.memo = detail.memo
            contact.seeStatement = detail.seeStatement
            contact.seeWritings = detail.seeWritings
            contact.birthTime = record.birthTime
            if let h = record.lastHeight { contact.lastHeight = h }
            contact.active = record.active
            contact.onChain = true
            contact.carveId = record.id
            if let freer = freers[contactFid] {
                contact = contact.merging(freer)
            }
            do {
                try store.upsert(contact)
                merged += 1
            } catch {
                // A malformed FID inside a decrypted detail (store
                // validates Base58Check) — skip rather than abort the
                // whole sync.
                undecryptable += 1
                if failureReasons.count < 3 {
                    failureReasons.append(String(describing: error))
                }
            }
        }

        // The fetch above is exhaustive for this owner (active AND
        // deleted carves), so a local row still claiming `onChain`
        // whose FID appears in no carve at all is provably stale —
        // e.g. marked by an old build that flipped `onChain` on a
        // directory lookup. Clear the flag so the badge is honest.
        // Skipped when any record failed to decrypt: those records'
        // contact FIDs are unknown, and one of them might legitimately
        // back a row we'd otherwise demote.
        var demoted = 0
        if undecryptable == 0, let rows = try? store.all() {
            let carvedFids = Set(detailByFid.keys)
            for var row in rows
            where row.onChain == true && !carvedFids.contains(row.id) {
                row.onChain = false
                row.carveId = nil
                if (try? store.upsert(row)) != nil { demoted += 1 }
            }
        }

        return ContactSyncResult(
            merged: merged,
            removed: removed,
            demoted: demoted,
            undecryptable: undecryptable,
            total: records.count,
            failureReasons: failureReasons
        )
    }
}
