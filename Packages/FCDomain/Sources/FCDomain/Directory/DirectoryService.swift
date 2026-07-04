import Foundation
import FCTransport

/// Identity-directory FAPI calls. Today: `base.freerByIds` only —
/// fetch the on-chain ``Freer`` block for one or more FIDs.
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

    // MARK: - on-chain contact sync

    /// Outcome of one ``syncOnChainContacts(owner:privkey:into:)`` run.
    public struct ContactSyncResult: Sendable {
        /// Contacts decrypted and written into the store.
        public let merged: Int
        /// Local rows removed because the chain reports their newest
        /// carve as deleted (`active == false`).
        public let removed: Int
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

        return ContactSyncResult(
            merged: merged,
            removed: removed,
            undecryptable: undecryptable,
            total: records.count,
            failureReasons: failureReasons
        )
    }
}
