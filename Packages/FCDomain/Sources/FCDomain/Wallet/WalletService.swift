import Foundation
import FCCore
import FCTransport

/// Read path of the wallet. Wraps a ``FapiCalling`` (production:
/// ``FCTransport.FapiClient``) with FCH-aware methods. Stays
/// stateless w.r.t. network — the per-identity cache lives in
/// ``UtxosStore``, which the caller passes in. This keeps the service
/// trivially constructable for tests.
///
/// What's here: balance, UTXO listing, server-health smoke check.
/// What's next (Phase 5.5): coin selection + tx build + sign + broadcast.
public struct WalletService {

    public enum Failure: Error, CustomStringConvertible {
        case fapiNonZeroCode(api: String, code: Int, message: String?)
        case unexpectedDataShape(api: String)
        case unsupportedCashType(String)
        case underlying(Error)

        public var description: String {
            switch self {
            case let .fapiNonZeroCode(api, code, message):
                return "WalletService: \(api) returned code=\(code) message=\(message ?? "<nil>")"
            case .unexpectedDataShape(let api):
                return "WalletService: \(api) response data did not match the expected shape"
            case .unsupportedCashType(let t):
                return "WalletService: cash type '\(t)' isn't supported yet — Phase 8 adds CLTV / multisig signing"
            case .underlying(let e):
                return "WalletService: \(e)"
            }
        }
    }

    public let fapi: any FapiCalling
    public let cashes: CashesStore?
    public let recentActivity: RecentActivityStore?

    /// `cashes` is optional because the read path is meaningful even
    /// without a cache (the SwiftUI view-model can hold the latest
    /// snapshot in memory). Pass one in to enable durable caching.
    /// `recentActivity` is the Pattern C blob cache for the
    /// Transactions pane — same opt-in shape.
    public init(
        fapi: any FapiCalling,
        cashes: CashesStore? = nil,
        recentActivity: RecentActivityStore? = nil
    ) {
        self.fapi = fapi
        self.cashes = cashes
        self.recentActivity = recentActivity
    }

    // MARK: - health

    /// `base.health` — cheap server smoke test. Returns true when the
    /// server replies with code=0.
    public func health(timeoutMs: Int = 3_000) async throws -> Bool {
        let reply = try await fapi.call(
            api: "base.health",
            params: nil, fcdsl: nil, binary: nil,
            sid: nil, via: nil, maxCost: nil,
            timeoutMs: timeoutMs
        )
        return reply.response.isSuccess
    }

    // MARK: - balance

    /// `base.balanceByIds` — query for one FID. Returns satoshis.
    /// Uses the FCDSL `{ids: [...]}` shape that the Java reference
    /// builds with `Fcdsl.addIds(fids)`.
    public func balance(forFid fid: String, timeoutMs: Int = 5_000) async throws -> Balance {
        let map = try await balances(forFids: [fid], timeoutMs: timeoutMs)
        let sats = map.first?.satoshis ?? 0
        return Balance(
            fid: fid,
            satoshis: sats,
            bestHeight: map.first?.bestHeight,
            bestBlockId: map.first?.bestBlockId
        )
    }

    public func balances(forFids fids: [String], timeoutMs: Int = 5_000) async throws -> [Balance] {
        let fcdsl = try JSONSerialization.data(withJSONObject: ["ids": fids], options: [.sortedKeys])
        let reply = try await fapi.call(
            api: "base.balanceByIds",
            params: nil, fcdsl: fcdsl, binary: nil,
            sid: nil, via: nil, maxCost: nil,
            timeoutMs: timeoutMs
        )
        let resp = reply.response
        guard resp.isSuccess else {
            throw Failure.fapiNonZeroCode(api: "base.balanceByIds", code: resp.code ?? -1, message: resp.message)
        }
        guard let data = resp.data,
              let map = try JSONSerialization.jsonObject(with: data) as? [String: Any]
        else {
            throw Failure.unexpectedDataShape(api: "base.balanceByIds")
        }
        let now = Date()
        return fids.map { fid in
            let sats = (map[fid] as? NSNumber)?.int64Value ?? 0
            return Balance(
                fid: fid,
                satoshis: sats,
                bestHeight: resp.bestHeight,
                bestBlockId: resp.bestBlockId,
                fetchedAt: now
            )
        }
    }

    // MARK: - cashes

    /// Default page size for cash sync. The Java server caps responses
    /// per-page server-side; this just gives the upper bound for one
    /// network round-trip. Tunable so tests can shrink the page size
    /// without changing call sites.
    public static let defaultCashPageSize: Int = 200

    /// Filter cut for the Recent activity feed. Mirrors the three
    /// distinct cash searches the Android Freer client runs:
    ///
    /// - ``all``: everything affecting `liveFid`'s balance, sorted
    ///   by `lastHeight` desc — the unified view used since Phase 7.5.
    /// - ``incomes``: cashes paid TO `liveFid` by someone else
    ///   (`owner == liveFid AND issuer != liveFid`).
    /// - ``expenses``: cashes paid BY `liveFid` to someone else
    ///   (`issuer == liveFid AND owner ∉ {liveFid, OP_RETURN}`).
    public enum ActivityKind: String, Codable, Sendable, CaseIterable {
        case all
        case incomes
        case expenses
    }

    /// Reorg-protection window. Every incremental refresh re-fetches
    /// items whose `lastHeight > watermarkHeight - reorgWindowBlocks`
    /// so any reorg that rewrites the trailing window's state is
    /// reflected. Matches FCH's protocol-level reorg cap.
    public static let reorgWindowBlocks: Int64 = 30

    /// Public entry point. Tries incremental sync first when we have
    /// a watermark; falls back to a full bootstrap when there's no
    /// cache yet OR when the incremental round-trip fails (e.g. the
    /// live FAPI server's `base.search` contract isn't quite what we
    /// encode, or the call times out). Bootstrap is the always-safe
    /// reset.
    @discardableResult
    public func refreshCashes(
        forFid fid: String,
        pageSize: Int = WalletService.defaultCashPageSize,
        timeoutMs: Int = 5_000
    ) async throws -> CashSnapshot {
        if let cached = try? cashes?.snapshot(forAddress: fid),
           cached.watermarkHeight != nil {
            do {
                return try await refreshCashesIncremental(
                    forFid: fid, base: cached,
                    pageSize: pageSize, timeoutMs: timeoutMs
                )
            } catch {
                // Fall through to bootstrap on any incremental failure.
                // The user-facing wallet stays usable; the next attempt
                // can retry incremental from a fresh watermark.
            }
        }
        return try await bootstrapCashes(
            forFid: fid, pageSize: pageSize, timeoutMs: timeoutMs
        )
    }

    /// First-time sync: query `base.cashValid` mode 2 (params = `{fid}`)
    /// for every currently-spendable cash owned by `fid`. Single
    /// round-trip, no FCDSL — the server applies its own
    /// `valid=true` filter and routes by `fid`. Replaces any
    /// existing snapshot.
    ///
    /// **Pagination caveat:** mode 2 doesn't expose a cursor, so a
    /// FID with thousands of cashes may exceed the server's per-call
    /// cap. We can layer pagination on top later — either by
    /// iterating `sinceHeight` on mode 2 or by switching to a
    /// mode-1 FCDSL that combines `owner=fid` with `valid=true` (the
    /// FCDSL semantics for compound terms aren't yet pinned down in
    /// this client).
    public func bootstrapCashes(
        forFid fid: String,
        pageSize: Int = WalletService.defaultCashPageSize,
        timeoutMs: Int = 5_000
    ) async throws -> CashSnapshot {
        let params = try JSONSerialization.data(
            withJSONObject: ["fid": fid],
            options: [.sortedKeys]
        )
        let reply = try await fapi.call(
            api: "base.cashValid",
            params: params, fcdsl: nil, binary: nil,
            sid: nil, via: nil, maxCost: nil,
            timeoutMs: timeoutMs
        )
        let resp = reply.response
        // The server returns NOT_FOUND when an FID has zero cashes.
        // That's a normal "empty wallet" outcome — not a sync failure.
        if let code = resp.code, code != 0 {
            let snapshot = CashSnapshot(
                addr: fid, cashes: [],
                snapshotAt: Date(),
                bestHeight: resp.bestHeight,
                watermarkHeight: resp.bestHeight
            )
            if let store = self.cashes { try store.save(snapshot) }
            return snapshot
        }
        guard let data = resp.data else {
            throw Failure.unexpectedDataShape(api: "base.cashValid")
        }
        let cashList: [Cash]
        do {
            cashList = try Cash.parseFapiList(data)
        } catch {
            throw Failure.underlying(error)
        }

        let snapshot = CashSnapshot(
            addr: fid,
            cashes: cashList,
            snapshotAt: Date(),
            bestHeight: resp.bestHeight,
            watermarkHeight: resp.bestHeight
        )
        if let store = self.cashes {
            try store.save(snapshot)
        }
        return snapshot
    }

    /// Incremental sync: query `base.search` on the cash index for any
    /// cash whose `lastHeight > max(0, watermark − reorgWindow)` and
    /// `owner == fid`. Server returns BOTH active and spent cashes
    /// (the spent ones carry `valid = false`). We upsert active rows
    /// (replacing locally `.unknown` rows by id) and remove rows the
    /// server now reports as spent.
    public func refreshCashesIncremental(
        forFid fid: String,
        base: CashSnapshot,
        pageSize: Int = WalletService.defaultCashPageSize,
        timeoutMs: Int = 5_000
    ) async throws -> CashSnapshot {
        var working = base
        let watermark = base.watermarkHeight ?? 0
        let since = max(0, watermark - WalletService.reorgWindowBlocks)
        var bestHeight: Int64? = base.bestHeight

        try await pageCashes(
            api: "base.search",
            entity: "cash",
            ownerFid: fid,
            sinceLastHeightExclusive: since,
            pageSize: pageSize,
            timeoutMs: timeoutMs
        ) { cashes, pageBest in
            bestHeight = pageBest ?? bestHeight
            for cash in cashes {
                let isActive = cash.valid ?? true
                if isActive {
                    var stamped = cash
                    stamped.localState = .onchain
                    stamped.pendingSpend = false
                    working.upsert(stamped)
                } else {
                    working.remove(
                        id: cash.id,
                        birthTxId: cash.birthTxId,
                        birthIndex: cash.birthIndex
                    )
                }
            }
        }

        working.snapshotAt = Date()
        working.bestHeight = bestHeight
        working.watermarkHeight = bestHeight ?? watermark
        if let store = self.cashes {
            try store.save(working)
        }
        return working
    }

    /// Read the last cached snapshot for `addr`, or nil if we've
    /// never refreshed. No network round-trip; intended for "show
    /// last-known balance immediately on app open" UI flows.
    public func cachedSnapshot(forAddress addr: String) throws -> CashSnapshot? {
        try cashes?.snapshot(forAddress: addr)
    }

    /// Empty the cash cache for `fid` so the next ``refreshCashes`` call
    /// re-bootstraps. Recovery path for "the cash db looks wrong".
    public func purgeCashes(forFid fid: String) throws {
        _ = try cashes?.clear(addr: fid)
    }

    /// Fetch recent on-chain activity for `fid` from the cash index —
    /// the closest thing to a per-FID tx history. Each row is a
    /// ``Cash`` whose `lastHeight` marks the most recent state change
    /// (creation = income, spend = outgoing). Sorted newest first.
    ///
    /// Wire shape: `base.search` on `entity: "cash"`, filtering by
    /// owner == fid, sorting by `lastHeight desc, id desc`. The
    /// caller chooses the page size; pagination via the `after`
    /// cursor is a follow-up.
    /// Read whatever the last fetch of `kind` wrote to the recent-
    /// activity blob for `fid`. Returns nil if we've never fetched,
    /// or if no cache store was wired into this service. No network
    /// round-trip — intended for cache-first cold-start render.
    public func cachedRecentActivity(
        forFid fid: String,
        kind: ActivityKind = .all
    ) throws -> RecentActivitySnapshot? {
        try recentActivity?.snapshot(forFid: fid, kind: kind)
    }

    /// One page of `fetchRecentActivity` results plus the cursor the
    /// caller hands back for "Load more". `next == nil` means the
    /// server has no more rows past this page.
    public struct RecentActivityPage: Sendable {
        public let cashes: [Cash]
        public let next: [String]?
        public let bestHeight: Int64?

        public init(cashes: [Cash], next: [String]?, bestHeight: Int64? = nil) {
            self.cashes = cashes
            self.next = next
            self.bestHeight = bestHeight
        }
    }

    public func fetchRecentActivity(
        forFid fid: String,
        kind: ActivityKind = .all,
        after: [String]? = nil,
        limit: Int = 50,
        timeoutMs: Int = 15_000
    ) async throws -> RecentActivityPage {
        let body = try Self.activityFcdsl(
            kind: kind,
            ownerFid: fid,
            pageSize: limit,
            after: after
        )
        let reply: FapiClient.Reply
        do {
            reply = try await fapi.call(
                api: "base.search",
                params: nil, fcdsl: body, binary: nil,
                sid: nil, via: nil, maxCost: nil,
                timeoutMs: timeoutMs
            )
        } catch {
            // Surface the request body so a timeout or transport
            // failure points at the FCDSL we actually sent. Otherwise
            // the user just sees "FudpClient: timeout" with no clue
            // whether the wire shape was wrong.
            let bodyText = String(data: body, encoding: .utf8) ?? "<\(body.count) B non-utf8>"
            throw Failure.underlying(WireProbeError(
                api: "base.search",
                fcdsl: bodyText,
                inner: error
            ))
        }
        let resp = reply.response
        // Empty result is normal for a fresh FID — surface as [].
        // 404 / NOT_FOUND is what the server emits for "no rows".
        if let code = resp.code, code != 0, code != 404 {
            throw Failure.fapiNonZeroCode(api: "base.search", code: code, message: resp.message)
        }
        let cashList: [Cash]
        if let data = resp.data {
            do {
                cashList = try Cash.parseFapiList(data)
            } catch {
                throw Failure.underlying(error)
            }
        } else {
            cashList = []
        }
        // Persist the first page only — Pattern C cache exists for
        // cold-start UX, not for unbounded scroll-back history. Loaded-
        // more pages are in-memory; lost on restart, the user can
        // re-paginate. Each kind gets its own blob.
        if after == nil, let store = self.recentActivity {
            let snapshot = RecentActivitySnapshot(
                fid: fid,
                cashes: cashList,
                fetchedAt: Date(),
                bestHeight: resp.bestHeight
            )
            try? store.save(snapshot, kind: kind)
        }
        return RecentActivityPage(
            cashes: cashList,
            next: (resp.last?.isEmpty == false) ? resp.last : nil,
            bestHeight: resp.bestHeight
        )
    }

    /// Diagnostic wrapper: pretty-prints the API name + FCDSL JSON
    /// alongside the underlying transport error. Surfaced in the
    /// Transactions pane while we pin down the live `base.search`
    /// contract; once that's stable we can drop it.
    public struct WireProbeError: Error, CustomStringConvertible {
        public let api: String
        public let fcdsl: String
        public let inner: Error
        public var description: String {
            "WalletService: \(api) failed — \(inner)\nfcdsl: \(fcdsl)"
        }
    }

    /// Manually un-mark a `pendingSpend` row so the cash is selectable
    /// again. Use case: a Send was broadcast, the optimistic update
    /// flagged the input as `pendingSpend`, but the broadcast never
    /// confirmed (network drop, mempool eviction). This restores the
    /// row verbatim — the row still carries its full chain coords from
    /// before the would-be spend, since the optimistic path didn't
    /// touch them. Returns `true` if a row was changed.
    @discardableResult
    public func recoverPendingSpend(cashId: String, forFid fid: String) throws -> Bool {
        guard let store = self.cashes else { return false }
        guard var snap = try store.snapshot(forAddress: fid) else { return false }
        guard let idx = snap.cashes.firstIndex(where: { $0.id == cashId && $0.pendingSpend }) else {
            return false
        }
        var row = snap.cashes[idx]
        row.pendingSpend = false
        snap.cashes[idx] = row
        snap.snapshotAt = Date()
        try store.save(snap)
        return true
    }

    // MARK: - cash sync internals

    /// One-page-at-a-time loop over a paginated FCDSL cash query.
    /// Calls `apply` for each parsed page. Continues until the server
    /// returns fewer than `pageSize` items or stops emitting an
    /// `after` cursor — whichever comes first.
    private func pageCashes(
        api: String,
        entity: String?,
        ownerFid: String,
        sinceLastHeightExclusive: Int64?,
        pageSize: Int,
        timeoutMs: Int,
        apply: ([Cash], _ pageBestHeight: Int64?) throws -> Void
    ) async throws {
        var afterCursor: [String]? = nil
        while true {
            let body = try Self.cashFcdsl(
                entity: entity,
                ownerFid: ownerFid,
                sinceLastHeightExclusive: sinceLastHeightExclusive,
                pageSize: pageSize,
                after: afterCursor
            )
            let reply = try await fapi.call(
                api: api,
                params: nil, fcdsl: body, binary: nil,
                sid: nil, via: nil, maxCost: nil,
                timeoutMs: timeoutMs
            )
            let resp = reply.response
            guard resp.isSuccess else {
                throw Failure.fapiNonZeroCode(api: api, code: resp.code ?? -1, message: resp.message)
            }
            // Empty result: server returns NOT_FOUND on cashValid for
            // fid with zero cashes. Treat as "no more rows".
            if resp.code != nil, resp.code != 0 { return }
            guard let data = resp.data else { return }
            let page: [Cash]
            do {
                page = try Cash.parseFapiList(data)
            } catch {
                throw Failure.underlying(error)
            }
            try apply(page, resp.bestHeight)
            // Stop when the server signals the last page or returns less
            // than a full page. `resp.last` is the cursor to feed back
            // as `after`; absence means "no more".
            if page.count < pageSize { return }
            guard let next = resp.last, !next.isEmpty else { return }
            afterCursor = next
        }
    }

    /// Build the FCDSL for one of the three Recent activity tabs. The
    /// `query` and (optional) `except` clauses mirror the Android
    /// Freer client's per-tab cash searches; sort uses `birthHeight`
    /// for the filtered tabs because they only consider the cash's
    /// birth event, while `.all` keeps the unified `lastHeight` sort
    /// (a spent cash's last event is its spend height, not birth).
    private static func activityFcdsl(
        kind: ActivityKind,
        ownerFid: String,
        pageSize: Int,
        after: [String]?
    ) throws -> Data {
        // Every kind drops zero/null-value cashes via a server-side
        // range filter — those are typically OP_RETURN data outputs
        // and aren't real money movements. Cleaner than the prior
        // "exclude owner == OP_RETURN" hack: catches any zero-value
        // cash regardless of owner.
        var query: [String: Any] = [
            "range": ["fields": ["value"], "gt": "0"]
        ]
        var except: [String: Any]? = nil
        var sortField = "lastHeight"

        switch kind {
        case .all:
            query["terms"] = ["fields": ["owner"], "values": [ownerFid]]
        case .incomes:
            // owner == fid AND issuer != fid (drops self-change)
            query["terms"]  = ["fields": ["owner"],  "values": [ownerFid]]
            except = ["equals": ["fields": ["issuer"], "values": [ownerFid]]]
            sortField = "birthHeight"
        case .expenses:
            // issuer == fid AND owner != fid (drops self-change)
            query["terms"]  = ["fields": ["issuer"], "values": [ownerFid]]
            except = ["equals": ["fields": ["owner"], "values": [ownerFid]]]
            sortField = "birthHeight"
        }

        var dict: [String: Any] = [
            "entity": "cash",
            "query": query,
            "sort": [
                ["field": sortField, "order": "desc"],
                ["field": "id",      "order": "desc"]
            ],
            "size": String(pageSize)
        ]
        if let except { dict["except"] = except }
        if let after, !after.isEmpty { dict["after"] = after }
        return try JSONSerialization.data(withJSONObject: dict, options: [.sortedKeys])
    }

    /// Build the FCDSL JSON for cash pagination queries. Mirrors the
    /// shape `Freer/.../CashManager.java` builds and that the live
    /// `base.search` handler expects: conditions go in the `query`
    /// object, NOT the separate `filter` field. `filter` is what
    /// `base.cashValid` mode-1 reaches for, processed by a different
    /// server path; `query` is what `base.search` consumes via
    /// `queryExecutor.executeQuery`.
    private static func cashFcdsl(
        entity: String?,
        ownerFid: String,
        sinceLastHeightExclusive: Int64?,
        pageSize: Int,
        after: [String]?
    ) throws -> Data {
        var query: [String: Any] = [
            "terms": ["fields": ["owner"], "values": [ownerFid]]
        ]
        if let h = sinceLastHeightExclusive {
            query["range"] = ["fields": ["lastHeight"], "gt": String(h)]
        }
        var dict: [String: Any] = [
            "query": query,
            "sort": [
                ["field": "lastHeight", "order": "desc"],
                ["field": "id",         "order": "desc"]
            ],
            "size": String(pageSize)
        ]
        if let entity { dict["entity"] = entity }
        if let after, !after.isEmpty { dict["after"] = after }
        return try JSONSerialization.data(withJSONObject: dict, options: [.sortedKeys])
    }

    // MARK: - send (Phase 5.5)

    /// Result of a successful ``send`` call.
    public struct SendResult: Sendable {
        /// The fully-signed transaction. Inspect `.serialized` for the
        /// raw bytes or `.txidDisplay` for the explorer-friendly hex.
        public let transaction: Transaction
        /// Server-reported txid string. Should equal
        /// `transaction.txidDisplay` when the server agrees with us.
        /// Surfaced separately so callers can detect server-side
        /// rewriting if it ever happens.
        public let remoteTxid: String
        public let plan: CoinSelector.Plan

        public init(transaction: Transaction, remoteTxid: String, plan: CoinSelector.Plan) {
            self.transaction = transaction
            self.remoteTxid = remoteTxid
            self.plan = plan
        }
    }

    /// Send `amount` satoshis from `fromAddress` to `toFid`. Caller
    /// supplies the signing privkey for `fromAddress`. Refreshes UTXOs
    /// (or uses the cache when `useCache` is true and a snapshot
    /// exists), runs greedy coin selection, builds the tx, signs each
    /// P2PKH input, and broadcasts via `base.broadcastTx`.
    ///
    /// `feePerByte` defaults to 1 sat/byte — FCH's relay default.
    /// Pass a higher rate for faster confirmation when the mempool
    /// is congested. Fee estimation via `base.estimateFee` will be
    /// wired in when the server endpoint stabilizes.
    public func send(
        fromAddress: String,
        privkey: Data,
        to toFid: String,
        amount: Int64,
        feePerByte: Int64 = 1,
        useCache: Bool = false,
        timeoutMs: Int = 10_000
    ) async throws -> SendResult {

        // 1. Get cashes.
        let snapshot: CashSnapshot
        if useCache, let cached = try cachedSnapshot(forAddress: fromAddress) {
            snapshot = cached
        } else {
            snapshot = try await refreshCashes(forFid: fromAddress, timeoutMs: timeoutMs)
        }

        // 1a. Filter cashes by the wire-level `lockScript`, not the
        // `type` label. The server's `type` field is unreliable —
        // `Cash.fromUtxo` leaves it nil — so trusting it can let
        // multisig / CLTV outputs through and produce a tx the node
        // rejects (mandatory-script-verify-flag-failed). The
        // canonical P2PKH lockScript paying to *our* hash160 is the
        // strongest test: it both rules out non-standard scripts AND
        // proves we own the output.
        let ownerHash160: Data
        do {
            ownerHash160 = try FchAddress(fid: fromAddress).hash160
        } catch {
            throw Failure.underlying(error)
        }
        // Exclude rows that are locally-marked as spent
        // (`pendingSpend`) from selection. They stay in the cache so
        // manual recovery can restore them, but they are not spendable
        // until either the chain confirms the spend (we drop them) or
        // the user decides to recover (we unmark).
        let spendable = snapshot.cashes
            .filter { !$0.pendingSpend && $0.locksToP2PKH(hash160: ownerHash160) }
        if spendable.isEmpty, let sample = snapshot.cashes.first {
            // Surface a clearer error than "insufficient funds" when
            // the only thing the server returned is non-spendable.
            throw Failure.unsupportedCashType(sample.type ?? sample.lockScript ?? "<no lockScript>")
        }

        // 2. Coin select.
        let plan = try CoinSelector.select(
            cashes: spendable, amount: amount, feePerByte: feePerByte
        )

        // 3. Build unsigned tx.
        let unsigned = try TxBuilder.buildUnsigned(
            plan: plan, toFid: toFid, amount: amount, changeFid: fromAddress
        )

        // 4. Sign each input. signP2pkhInput rebuilds the tx with the
        // single input filled; we feed the result back in for the
        // next index so the running tx state is current.
        var signed = unsigned
        for (idx, cash) in plan.selected.enumerated() {
            signed = try TxHandler.signP2pkhInput(
                tx: signed,
                inputIndex: idx,
                privateKey: privkey,
                prevValueSats: UInt64(cash.value)
            )
        }

        // 5. Broadcast.
        let rawHex = signed.serialized.map { String(format: "%02x", $0) }.joined()
        let params = try JSONSerialization.data(
            withJSONObject: ["rawTx": rawHex],
            options: [.sortedKeys]
        )
        let reply = try await fapi.call(
            api: "base.broadcastTx",
            params: params, fcdsl: nil, binary: nil,
            sid: nil, via: nil, maxCost: nil,
            timeoutMs: timeoutMs
        )
        let resp = reply.response
        guard resp.isSuccess else {
            throw Failure.fapiNonZeroCode(api: "base.broadcastTx", code: resp.code ?? -1, message: resp.message)
        }
        // Java reference returns response.data.toString() for a
        // successful broadcast. JSON-encoded that's a quoted string,
        // so on our side we decode `data` and re-extract.
        guard let data = resp.data,
              let txidString = try JSONSerialization.jsonObject(with: data, options: [.fragmentsAllowed]) as? String
        else {
            throw Failure.unexpectedDataShape(api: "base.broadcastTx")
        }

        // 6. Optimistic post-broadcast update of the cash cache. We
        // know the chain hasn't confirmed yet, but the wallet UI
        // wants the new balance reflected immediately and a future
        // Send must not pick the same inputs. The next incremental
        // refresh either confirms (server emits the new change cashes
        // and a `valid:false` for the inputs, which we handle by
        // upsert/remove) or — if the tx never confirms — leaves these
        // rows untouched so the user can recover them manually.
        try? applyOptimisticPostSend(
            ownerFid: fromAddress,
            spent: plan.selected,
            transaction: signed,
            remoteTxid: txidString
        )

        return SendResult(transaction: signed, remoteTxid: txidString, plan: plan)
    }

    // MARK: - optimistic post-send

    /// Mark spent inputs `pendingSpend = true`, synthesize change cash
    /// rows with `localState = .unknown`, and persist. Skips silently
    /// when there's no ``cashes`` store wired (the in-test path runs
    /// without one).
    private func applyOptimisticPostSend(
        ownerFid: String,
        spent: [Cash],
        transaction: Transaction,
        remoteTxid: String
    ) throws {
        guard let store = self.cashes else { return }
        guard var snap = try store.snapshot(forAddress: ownerFid) else { return }

        // Mark each spent input. Keep the row's chain coordinates so
        // recovery can restore it verbatim.
        for inputCash in spent {
            if let idx = snap.cashes.firstIndex(where: { matches($0, inputCash) }) {
                var row = snap.cashes[idx]
                row.pendingSpend = true
                snap.cashes[idx] = row
            }
        }

        // Synthesize change cashes from the signed transaction's
        // outputs that pay back to `ownerFid`. Pre-compute the cash id
        // from `(txidDisplay, vout)` so the row merges by id with the
        // server's authoritative version on the next sync.
        let ownerHash160 = (try? FchAddress(fid: ownerFid))?.hash160
        let txidDisplay = remoteTxid.count == 64 ? remoteTxid : transaction.txidDisplay
        let canonicalLockScript = ownerHash160.map { Cash.canonicalP2PKHLockScript(hash160: $0) }

        for (i, out) in transaction.outputs.enumerated() {
            // Heuristic: any output that locks to our address is a
            // change cash. Recipient outputs lock to a different
            // hash160 and are filtered out here.
            guard let h160 = ownerHash160 else { continue }
            let outputScriptHex = out.scriptPubKey.bytes.map { String(format: "%02x", $0) }.joined().lowercased()
            guard outputScriptHex == Cash.canonicalP2PKHLockScript(hash160: h160) else { continue }

            let id = (try? Cash.makeId(birthTxId: txidDisplay, birthIndex: i)) ?? ""
            let change = Cash(
                id: id.isEmpty ? nil : id,
                owner: ownerFid,
                value: Int64(out.value),
                type: "P2PKH",
                birthTxId: txidDisplay,
                birthIndex: i,
                lockScript: canonicalLockScript,
                localState: .unknown,
                pendingSpend: false
            )
            snap.upsert(change)
        }

        snap.snapshotAt = Date()
        try store.save(snap)
    }

    /// Match an in-cache cash row to a freshly-spent input. Prefer id
    /// when both sides have one; fall back to `(birthTxId, birthIndex)`.
    private func matches(_ row: Cash, _ spent: Cash) -> Bool {
        if let lhs = row.id, let rhs = spent.id, !lhs.isEmpty, !rhs.isEmpty { return lhs == rhs }
        return row.birthTxId == spent.birthTxId && row.birthIndex == spent.birthIndex
    }
}
