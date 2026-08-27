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
        /// A caller-supplied input can't be spent by this identity —
        /// it doesn't lock to our hash160, or it's already committed
        /// to an unconfirmed spend.
        case unspendableInput(id: String, reason: String)
        /// Every otherwise-spendable cash is at the end of a
        /// ``Cash/maxUnconfirmedChain``-long line of unconfirmed
        /// spends. Nothing is wrong; the wallet has simply run ahead
        /// of the chain and has to wait for a block.
        case unconfirmedChainLimit(depth: Int)
        /// The approval gate said no. Not an error in the usual
        /// sense — the user read the transaction and declined it —
        /// but it has to unwind the send like one.
        case declinedByUser
        /// Another transaction claimed this cash between our coin
        /// selection and our attempt to reserve it. Recoverable —
        /// select again from what is left.
        case inputAlreadyClaimed(id: String)
        case underlying(Error)

        public var description: String {
            switch self {
            case let .fapiNonZeroCode(api, code, message):
                return "WalletService: \(api) returned code=\(code) message=\(message ?? "<nil>")"
            case .unexpectedDataShape(let api):
                return "WalletService: \(api) response data did not match the expected shape"
            case .unsupportedCashType(let t):
                return "WalletService: cash type '\(t)' isn't supported yet — Phase 8 adds CLTV / multisig signing"
            case let .unspendableInput(id, reason):
                return "WalletService: cash \(id) can't be spent — \(reason)"
            case .unconfirmedChainLimit(let depth):
                return "WalletService: every spendable cash is \(depth) unconfirmed spends deep — the network carries at most \(Cash.maxUnconfirmedChain). Wait for a block to confirm the ones already sent."
            case .declinedByUser:
                return "WalletService: the transaction was not approved, so nothing was signed or broadcast"
            case .inputAlreadyClaimed(let id):
                return "WalletService: cash \(id) was claimed by another transaction while this one was being prepared"
            case .underlying(let e):
                return "WalletService: \(e)"
            }
        }
    }

    public let fapi: any FapiCalling
    public let cashes: CashesStore?
    public let recentActivity: RecentActivityStore?

    /// Asked to approve every transaction this service is about to
    /// sign. Nil means sign without asking — which is what the tests
    /// and any headless caller want, and what the user gets when they
    /// turn the setting off.
    public let approve: TxApprover?

    /// `cashes` is optional because the read path is meaningful even
    /// without a cache (the SwiftUI view-model can hold the latest
    /// snapshot in memory). Pass one in to enable durable caching.
    /// `recentActivity` is the Pattern C blob cache for the
    /// Transactions pane — same opt-in shape.
    public init(
        fapi: any FapiCalling,
        cashes: CashesStore? = nil,
        recentActivity: RecentActivityStore? = nil,
        approve: TxApprover? = nil
    ) {
        self.fapi = fapi
        self.cashes = cashes
        self.recentActivity = recentActivity
        self.approve = approve
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
            var snapshot = CashSnapshot(
                addr: fid, cashes: [],
                snapshotAt: Date(),
                bestHeight: resp.bestHeight,
                watermarkHeight: resp.bestHeight
            )
            if let previous = try? cashes?.snapshot(forAddress: fid) {
                snapshot = mergeLocalAnnotations(into: snapshot, from: previous)
            }
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

        var snapshot = CashSnapshot(
            addr: fid,
            cashes: cashList,
            snapshotAt: Date(),
            bestHeight: resp.bestHeight,
            watermarkHeight: resp.bestHeight
        )
        if let previous = try? cashes?.snapshot(forAddress: fid) {
            snapshot = mergeLocalAnnotations(into: snapshot, from: previous)
        }
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
                    stamped.pendingSpend = carriedPendingSpend(for: cash, in: working)
                    // Depth clears only on evidence of a block. The
                    // index is built from confirmed blocks, so a row
                    // with a height in it has landed; a row without
                    // one keeps whatever ancestry we recorded.
                    let confirmed = (cash.birthHeight ?? 0) > 0 || (cash.lastHeight ?? 0) > 0
                    stamped.unconfirmedDepth = confirmed
                        ? 0
                        : (working.row(matching: cash)?.unconfirmedDepth ?? 0)
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

    /// Whether a server row that still looks spendable should stay
    /// flagged as pending-spend locally.
    ///
    /// **The index lags the mempool.** Seconds after we broadcast, the
    /// server still reports the cash we just spent as `valid: true` —
    /// it indexes confirmed blocks, and our transaction is not in one
    /// yet. Taking that at face value un-flags the input, the wallet
    /// offers it for spending again, and the next transaction is
    /// rejected as a mempool conflict (the `-26` the Android client
    /// documents at length). So a local `pendingSpend` survives every
    /// sync that still shows the cash as active; only the server
    /// reporting it *spent* (`valid: false`, handled by the remove
    /// branch) or the user explicitly recovering it clears the flag.
    private func carriedPendingSpend(for cash: Cash, in snapshot: CashSnapshot) -> Bool {
        snapshot.row(matching: cash)?.pendingSpend ?? false
    }

    /// Fold the local-only annotations of `previous` into a snapshot
    /// freshly built from a full server listing.
    ///
    /// A bootstrap replaces everything, which is right for the chain
    /// facts and wrong for the two things only this device knows: a
    /// cash we have already spent but whose spend hasn't confirmed,
    /// and a cash our own broadcast minted that the index hasn't seen.
    /// Dropping the first offers a spent input for re-spending;
    /// dropping the second makes the wallet's own change vanish until
    /// a block lands. Neither is acceptable as the *automatic*
    /// fallback that runs whenever incremental sync fails.
    ///
    /// Purge stays the clean slate: it deletes the stored row, so
    /// there is no `previous` to carry and the next bootstrap really
    /// does start from nothing.
    private func mergeLocalAnnotations(
        into fresh: CashSnapshot,
        from previous: CashSnapshot
    ) -> CashSnapshot {
        var merged = fresh
        for row in previous.cashes {
            if let server = merged.row(matching: row) {
                // The server knows this cash. Keep its facts, keep our
                // flag.
                if row.pendingSpend {
                    var updated = server
                    updated.pendingSpend = true
                    merged.upsert(updated)
                }
            } else if row.localState == .unknown {
                // We minted it ourselves and the index hasn't caught
                // up. Keep it — including its unconfirmed depth, which
                // is what stops a chain running past the limit.
                merged.upsert(row)
            }
        }
        return merged
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
        using chosenInputs: [Cash]? = nil,
        timeoutMs: Int = 10_000
    ) async throws -> SendResult {

        // 1-2. Which cashes fund this, and what does that cost? When
        // the caller named the inputs (the Cash pane's Send, where the
        // user ticked them), no snapshot is fetched and no selection
        // runs — the input set is the instruction, not a suggestion.
        //
        // Selecting and *reserving* are one step: from here on these
        // cashes are flagged, so a transaction being built in parallel
        // — a background carve, the chat outbox — picks different ones
        // rather than colliding with us in the mempool.
        let plan: CoinSelector.Plan
        if let chosenInputs {
            try requireSpendable(chosenInputs, fromAddress: fromAddress)
            plan = try planAndClaim(
                ownerFid: fromAddress,
                snapshot: CashSnapshot(addr: fromAddress, cashes: chosenInputs),
                // The user named these cashes; quietly substituting
                // others would be a different transaction.
                allowReselect: false,
                makePlan: { _ in
                    try CoinSelector.fixed(
                        cashes: chosenInputs, amount: amount, feePerByte: feePerByte
                    )
                },
                inputsOf: { $0.selected }
            )
        } else {
            let snapshot: CashSnapshot
            if useCache, let cached = try cachedSnapshot(forAddress: fromAddress) {
                snapshot = cached
            } else {
                snapshot = try await refreshCashes(forFid: fromAddress, timeoutMs: timeoutMs)
            }
            plan = try planAndClaim(
                ownerFid: fromAddress,
                snapshot: snapshot,
                makePlan: { snap in
                    // Filter to P2PKH cashes locking to our hash160
                    // (the server's `type` label is unreliable) that
                    // aren't locally marked `pendingSpend`. See
                    // `spendableCashes`.
                    let spendable = try spendableCashes(in: snap, fromAddress: fromAddress)
                    return try CoinSelector.select(
                        cashes: spendable, amount: amount, feePerByte: feePerByte
                    )
                },
                inputsOf: { $0.selected }
            )
        }

        // 3-5. Build, approve, sign, broadcast — releasing the claim
        // if any of it comes to nothing, so a refusal doesn't cost the
        // user the use of their cash.
        let signed: Transaction
        let txidString: String
        do {
            let unsigned = try TxBuilder.buildUnsigned(
                plan: plan, toFid: toFid, amount: amount, changeFid: fromAddress
            )
            try await requireApproval(
                kind: .payment, from: fromAddress, inputs: plan.selected,
                unsigned: unsigned, fee: plan.fee,
                estimatedSize: plan.estimatedSize, feePerByte: feePerByte
            )
            signed = try signAllInputs(unsigned: unsigned, inputs: plan.selected, privkey: privkey)
            txidString = try await broadcast(signed: signed, timeoutMs: timeoutMs)
        } catch {
            release(plan.selected, ownerFid: fromAddress)
            throw error
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

    // MARK: - unsigned send (watch-only / cold signing, Phase 7.8.3)

    /// Result of ``buildUnsignedSend`` — the exportable document plus
    /// the plan it was built from (for fee/change display).
    public struct UnsignedSendResult: Sendable {
        public let info: RawTxInfo
        public let plan: CoinSelector.Plan

        public init(info: RawTxInfo, plan: CoinSelector.Plan) {
            self.info = info
            self.plan = plan
        }
    }

    /// The watch-only counterpart of ``send``: same cash snapshot,
    /// spendability filter and coin selection — but instead of
    /// signing and broadcasting, returns a ``RawTxInfo`` document for
    /// export to a machine that holds the key (Android's
    /// `CreateTxActivity` imports it via paste or QR). Needs no
    /// privkey, and deliberately does **not** mark the selected
    /// inputs `pendingSpend` — nothing has been broadcast.
    public func buildUnsignedSend(
        fromAddress: String,
        to toFid: String,
        amount: Int64,
        feePerByte: Int64 = 1,
        useCache: Bool = false,
        using chosenInputs: [Cash]? = nil,
        timeoutMs: Int = 10_000
    ) async throws -> UnsignedSendResult {
        let plan: CoinSelector.Plan
        if let chosenInputs {
            try requireSpendable(chosenInputs, fromAddress: fromAddress)
            plan = try CoinSelector.fixed(
                cashes: chosenInputs, amount: amount, feePerByte: feePerByte
            )
        } else {
            let snapshot: CashSnapshot
            if useCache, let cached = try cachedSnapshot(forAddress: fromAddress) {
                snapshot = cached
            } else {
                snapshot = try await refreshCashes(forFid: fromAddress, timeoutMs: timeoutMs)
            }
            let spendable = try spendableCashes(in: snapshot, fromAddress: fromAddress)
            plan = try CoinSelector.select(
                cashes: spendable, amount: amount, feePerByte: feePerByte
            )
        }
        let info = RawTxInfo(
            sender: fromAddress,
            feeRate: RawTxInfo.feeRate(satsPerByte: feePerByte),
            inputs: plan.selected.map(RawTxInfo.Slot.input(from:)),
            outputs: [RawTxInfo.Slot.output(to: toFid, amount: amount)],
            changeTo: fromAddress
        )
        return UnsignedSendResult(info: info, plan: plan)
    }

    // MARK: - reorg (split / consolidate your own cashes)

    /// Result of a successful ``reorganize``.
    public struct ReorgResult: Sendable {
        public let transaction: Transaction
        public let remoteTxid: String
        public let plan: CashReorg.Plan

        public init(transaction: Transaction, remoteTxid: String, plan: CashReorg.Plan) {
            self.transaction = transaction
            self.remoteTxid = remoteTxid
            self.plan = plan
        }
    }

    /// The watch-only counterpart of ``reorganize``.
    public struct UnsignedReorgResult: Sendable {
        public let info: RawTxInfo
        public let plan: CashReorg.Plan

        public init(info: RawTxInfo, plan: CashReorg.Plan) {
            self.info = info
            self.plan = plan
        }
    }

    /// Spend `inputs` back to `fromAddress` in the denominations
    /// `shape` describes — Android's `ReorgCashActivity`. Nothing
    /// leaves the wallet but the fee.
    ///
    /// Unlike ``send``, this never fetches a snapshot or selects
    /// coins: the inputs are the user's explicit choice, and changing
    /// them would change the transaction they approved. It does still
    /// apply the optimistic post-broadcast update, so the new bills
    /// show up in the pane immediately and the spent ones stop being
    /// selectable.
    public func reorganize(
        fromAddress: String,
        privkey: Data,
        inputs: [Cash],
        shape: CashReorg.Shape,
        feePerByte: Int64 = 1,
        timeoutMs: Int = 10_000
    ) async throws -> ReorgResult {
        try requireSpendable(inputs, fromAddress: fromAddress)
        let plan = try planAndClaim(
            ownerFid: fromAddress,
            snapshot: CashSnapshot(addr: fromAddress, cashes: inputs),
            // The user ticked these rows; re-selecting would reshape a
            // different set of cash than the one they previewed.
            allowReselect: false,
            makePlan: { _ in
                do {
                    return try CashReorg.plan(
                        inputs: inputs, shape: shape, feePerByte: feePerByte
                    )
                } catch {
                    throw Failure.underlying(error)
                }
            },
            inputsOf: { $0.inputs }
        )

        let signed: Transaction
        let txidString: String
        do {
            let unsigned = try TxBuilder.buildUnsignedReorg(plan: plan, ownerFid: fromAddress)
            try await requireApproval(
                kind: .reorg, from: fromAddress, inputs: plan.inputs,
                unsigned: unsigned, fee: plan.fee,
                estimatedSize: plan.estimatedSize, feePerByte: feePerByte
            )
            signed = try signAllInputs(unsigned: unsigned, inputs: plan.inputs, privkey: privkey)
            txidString = try await broadcast(signed: signed, timeoutMs: timeoutMs)
        } catch {
            release(plan.inputs, ownerFid: fromAddress)
            throw error
        }

        try? applyOptimisticPostSend(
            ownerFid: fromAddress,
            spent: plan.inputs,
            transaction: signed,
            remoteTxid: txidString
        )
        return ReorgResult(transaction: signed, remoteTxid: txidString, plan: plan)
    }

    /// Build the same transaction ``reorganize`` would broadcast, but
    /// as an exportable ``RawTxInfo`` for a machine that holds the
    /// key. Marks nothing `pendingSpend` — nothing was broadcast.
    ///
    /// Every output is written out explicitly (rather than leaning on
    /// the signer to add a change output) because the whole point of
    /// a reorg is the exact set of bills: a signer that helpfully
    /// appended its own change would produce a different shape than
    /// the one previewed here.
    public func buildUnsignedReorg(
        fromAddress: String,
        inputs: [Cash],
        shape: CashReorg.Shape,
        feePerByte: Int64 = 1
    ) throws -> UnsignedReorgResult {
        try requireSpendable(inputs, fromAddress: fromAddress)
        let plan: CashReorg.Plan
        do {
            plan = try CashReorg.plan(
                inputs: inputs, shape: shape, feePerByte: feePerByte
            )
        } catch {
            throw Failure.underlying(error)
        }
        let info = RawTxInfo(
            sender: fromAddress,
            feeRate: RawTxInfo.feeRate(satsPerByte: feePerByte),
            inputs: plan.inputs.map(RawTxInfo.Slot.input(from:)),
            outputs: plan.outputs.map { RawTxInfo.Slot.output(to: fromAddress, amount: $0) },
            changeTo: fromAddress
        )
        return UnsignedReorgResult(info: info, plan: plan)
    }

    // MARK: - carve (OP_RETURN data tx)

    /// Write `opReturn` (typically a FEIP JSON document) onto the
    /// chain from `fromAddress`. With no recipient the tx spends the
    /// sender's own cashes into a change output plus a zero-value
    /// OP_RETURN carrying the data, and the cost is the miner fee.
    ///
    /// Pass `payTo`/`payAmount` to also pay someone in the same
    /// transaction — Android's `TxSender.carveFeipWithRecipient`. Mail
    /// is the caller that needs it: a mail is *addressed by paying its
    /// recipient*, so the payment is not a courtesy but the routing.
    ///
    /// Mirrors the Android `TxSender.carveSimpleFeip` → `sendTx`
    /// path, including the CoinDays rule: carves must destroy
    /// ``ContactFeip/cdRequired`` CD once the chain passes
    /// ``ContactFeip/cddCheckHeight`` (below it — and when the height
    /// is unknown after a fresh bootstrap that returned no height —
    /// Android only waives the requirement for a *known* low height,
    /// so we do the same).
    ///
    /// `minimumCd` is a floor a *particular op* puts under that rule,
    /// and it is never waived by the height: a square's `update` has to
    /// destroy more CoinDays than the square's own `cddToUpdate`, which
    /// is how a square resists being renamed on a whim. The generic FEIP
    /// requirement and this one are the same quantity, so the larger of
    /// the two wins rather than the two adding up.
    public func carve(
        fromAddress: String,
        privkey: Data,
        opReturn: String,
        payTo: String? = nil,
        payAmount: Int64 = 0,
        feePerByte: Int64 = 1,
        minimumCd: Int64 = 0,
        useCache: Bool = false,
        timeoutMs: Int = 10_000
    ) async throws -> SendResult {
        let snapshot: CashSnapshot
        if useCache, let cached = try cachedSnapshot(forAddress: fromAddress) {
            snapshot = cached
        } else {
            snapshot = try await refreshCashes(forFid: fromAddress, timeoutMs: timeoutMs)
        }
        let baselineCd: Int64
        if let height = snapshot.bestHeight, height < ContactFeip.cddCheckHeight {
            baselineCd = 0
        } else {
            baselineCd = ContactFeip.cdRequired
        }
        let requiredCd = max(baselineCd, minimumCd)

        // A payment needs a payee and vice versa; a half-specified one
        // would silently become a plain carve, i.e. a mail nobody
        // receives.
        let paying = payTo != nil && payAmount > 0
        if (payTo != nil) != (payAmount > 0) {
            throw Failure.underlying(CoinSelector.Failure.nonPositiveAmount(payAmount))
        }

        let opReturnData = Data(opReturn.utf8)
        // Carves are the app's *background* transactions — the chat
        // outbox, mail retries, contact syncs — so this is the path
        // where two builds racing for the same cash is likeliest.
        // Reserve as we select.
        let plan = try planAndClaim(
            ownerFid: fromAddress,
            snapshot: snapshot,
            makePlan: { snap in
                let spendable = try spendableCashes(in: snap, fromAddress: fromAddress)
                return try CoinSelector.selectForCarve(
                    cashes: spendable,
                    opReturnByteCount: opReturnData.count,
                    feePerByte: feePerByte,
                    requiredCd: requiredCd,
                    payAmount: paying ? payAmount : 0
                )
            },
            inputsOf: { $0.selected }
        )

        let signed: Transaction
        let txidString: String
        do {
            let unsigned = try TxBuilder.buildUnsignedCarve(
                plan: plan, changeFid: fromAddress, opReturn: opReturnData,
                toFid: paying ? payTo : nil, payAmount: paying ? payAmount : 0
            )
            try await requireApproval(
                kind: .carve, from: fromAddress, inputs: plan.selected,
                unsigned: unsigned, fee: plan.fee,
                estimatedSize: plan.estimatedSize, feePerByte: feePerByte,
                opReturn: opReturn
            )
            signed = try signAllInputs(unsigned: unsigned, inputs: plan.selected, privkey: privkey)
            txidString = try await broadcast(signed: signed, timeoutMs: timeoutMs)
        } catch {
            release(plan.selected, ownerFid: fromAddress)
            throw error
        }

        try? applyOptimisticPostSend(
            ownerFid: fromAddress,
            spent: plan.selected,
            transaction: signed,
            remoteTxid: txidString
        )
        return SendResult(transaction: signed, remoteTxid: txidString, plan: plan)
    }

    // MARK: - advanced (composed) transactions

    /// What a composed transaction costs, before anything is signed —
    /// the numbers the advanced pane shows live while the user edits.
    ///
    /// Held separate from ``sendAdvanced`` because the pane re-prices
    /// on every keystroke and must never touch the network, claim a
    /// cash, or ask for approval to do so.
    public struct AdvancedQuote: Sendable {
        public let info: RawTxInfo
        public let fee: Int64?
        /// What is left after outputs and fee. Negative means the
        /// inputs do not cover the transaction; exactly zero after the
        /// change-output credit means it balances with no change.
        public let rest: Int64
        public let willHaveChange: Bool
        public let estimatedSize: Int64
        public let opReturn: Data
        public let p2shOutputs: [P2sh]

        public var totalIn: Int64 { info.totalIn }
        public var totalOut: Int64 { info.totalOut }
        public var totalCd: Int64 { info.totalCd }
        /// True when the fee could not be worked out at all — an
        /// unparsable redeem script, or a multisig input with no group
        /// on file. Shown as "—" rather than as a zero fee.
        public var unpriced: Bool { fee == nil }
    }

    /// Price `info` without touching the network.
    ///
    /// `rest` is plainly `in − out − fee`, and a negative value means
    /// the inputs do not cover the transaction. Android additionally
    /// rounds a rest of exactly `−34` up to zero — a leftover from a
    /// fee calculator that always priced a change output whether or
    /// not one appeared. Against the current calculator that rule only
    /// fires on a genuine 34-satoshi shortfall, where it would report
    /// a balanced transaction that the builder then refuses to
    /// assemble. It is not reproduced: ``maxValueForOutput(in:adding:)``
    /// already lands "spend the rest" on exactly zero.
    public func quoteAdvanced(_ info: RawTxInfo) -> AdvancedQuote {
        let priced = TxFee.calc(info)
        var rest: Int64 = 0
        if let fee = priced.fee {
            rest = info.totalIn - info.totalOut - fee
        }
        return AdvancedQuote(
            info: info,
            fee: priced.fee,
            rest: rest,
            willHaveChange: priced.willHaveChange,
            estimatedSize: priced.estimatedSize,
            opReturn: priced.opReturn,
            p2shOutputs: priced.p2shOutputs
        )
    }

    /// Sign and broadcast a composed transaction.
    ///
    /// Unlike ``send``, nothing is selected: the inputs in `info` are
    /// the instruction. They are still claimed for the duration, so a
    /// background carve running at the same time cannot pick the same
    /// coins and collide in the mempool.
    ///
    /// `inputCashes` are the full ``Cash`` rows behind `info.inputs` —
    /// needed for the claim, the preview and the post-broadcast cache
    /// update, none of which the trimmed wire slots can serve.
    public func sendAdvanced(
        info: RawTxInfo,
        inputCashes: [Cash],
        privkey: Data,
        fromAddress: String,
        bestHeight: Int64 = 0,
        timeoutMs: Int = 10_000
    ) async throws -> SendResult {
        var info = info
        info.inputs = AdvancedTxBuilder.fillMissingRedeemScripts(info.inputs ?? [])
        try AdvancedTxBuilder.requireUnlocked(info.inputs ?? [], bestHeight: bestHeight)

        let slots = info.inputs ?? []
        try claim(inputCashes, ownerFid: fromAddress)

        let signed: Transaction
        let txidString: String
        let built: AdvancedTxBuilder.Built
        do {
            built = try AdvancedTxBuilder.build(info, inputCashes: inputCashes)
            try await requireApproval(
                kind: info.opReturn?.isEmpty == false || !built.opReturn.isEmpty
                    ? .carve : .payment,
                from: fromAddress,
                inputs: inputCashes,
                unsigned: built.transaction,
                fee: built.fee,
                estimatedSize: Int(built.estimatedSize),
                feePerByte: satsPerByte(of: info),
                opReturn: built.opReturn.isEmpty
                    ? nil : String(decoding: built.opReturn, as: UTF8.self)
            )
            signed = try AdvancedTxBuilder.signAll(
                built.transaction, slots: slots, privkey: privkey
            )
            txidString = try await broadcast(signed: signed, timeoutMs: timeoutMs)
        } catch {
            release(inputCashes, ownerFid: fromAddress)
            throw error
        }

        try? applyOptimisticPostSend(
            ownerFid: fromAddress,
            spent: inputCashes,
            transaction: signed,
            remoteTxid: txidString
        )

        return SendResult(
            transaction: signed,
            remoteTxid: txidString,
            plan: CoinSelector.Plan(
                selected: inputCashes,
                change: built.change,
                fee: built.fee,
                estimatedSize: Int(built.estimatedSize)
            )
        )
    }

    /// The watch-only counterpart of ``sendAdvanced``: validate and
    /// price the document, but return it for export instead of
    /// signing. Claims nothing, because nothing is broadcast.
    ///
    /// The returned document is trimmed for the wire — no
    /// `senderMultisig`, and any redeem script the inputs were missing
    /// filled in, so the signing machine has everything it needs.
    public func buildUnsignedAdvanced(
        info: RawTxInfo,
        bestHeight: Int64 = 0
    ) throws -> UnsignedSendResult {
        var info = info
        info.inputs = AdvancedTxBuilder.fillMissingRedeemScripts(info.inputs ?? [])
        try AdvancedTxBuilder.requireUnlocked(info.inputs ?? [], bestHeight: bestHeight)

        let built = try AdvancedTxBuilder.build(info, inputCashes: [])
        var exported = info
        exported.senderMultisig = nil
        if exported.changeTo == nil { exported.changeTo = built.changeTo ?? info.sender }
        return UnsignedSendResult(
            info: exported,
            plan: CoinSelector.Plan(
                selected: [],
                change: built.change,
                fee: built.fee,
                estimatedSize: Int(built.estimatedSize)
            )
        )
    }

    /// `base.multisigByIds` — the redeem-script details of one or more
    /// 3… addresses.
    ///
    /// Needed before a time-locked payment to a multisig group can be
    /// composed at all: the CLTV script wraps the group's `m`, `n` and
    /// public keys, none of which are recoverable from the address.
    /// Addresses with no on-chain record are simply absent from the
    /// result.
    public func multisigsByIds(
        _ ids: [String],
        timeoutMs: Int = 5_000
    ) async throws -> [String: Multisig] {
        guard !ids.isEmpty else { return [:] }
        let body = try JSONSerialization.data(
            withJSONObject: ["ids": ids], options: [.sortedKeys]
        )
        let reply = try await fapi.call(
            api: "base.multisigByIds",
            params: nil, fcdsl: body, binary: nil,
            sid: nil, via: nil, maxCost: nil,
            timeoutMs: timeoutMs
        )
        let resp = reply.response
        if let code = resp.code, code != 0 {
            if code == 404 { return [:] }
            throw Failure.fapiNonZeroCode(
                api: "base.multisigByIds", code: code, message: resp.message
            )
        }
        guard let data = resp.data else { return [:] }
        do {
            return try JSONDecoder().decode([String: Multisig].self, from: data)
        } catch {
            throw Failure.underlying(error)
        }
    }

    /// The largest value `candidate` could carry and still leave the
    /// transaction exactly funded — Android's "Rest…" tap, which fills
    /// the amount field with everything that is left.
    ///
    /// Computed by pricing the transaction *with* the candidate at a
    /// value big enough to rule out change, then subtracting: the
    /// answer is then `totalIn - totalOut - fee` by definition, and it
    /// is right for every output shape without a special case.
    /// Android instead measures the fee delta of adding the output and
    /// credits back a hardcoded change-output cost, which is the same
    /// number for a plain payee at the default rate and drifts from it
    /// for a P2SH one or a different fee rate.
    ///
    /// Nil when the transaction cannot be priced, or when nothing is
    /// left to spend.
    public func maxValueForOutput(
        in info: RawTxInfo,
        adding candidate: RawTxInfo.Slot
    ) -> Int64? {
        var probe = candidate
        // Any value that cannot leave change will do; the transaction's
        // own input total is the simplest such value, and the size of
        // an output does not depend on the number written in it.
        probe.value = max(info.totalIn, 1)
        var probed = info
        probed.outputs = (info.outputs ?? []) + [probe]
        guard let fee = TxFee.calc(probed).fee else { return nil }
        let value = info.totalIn - info.totalOut - fee
        return value > 0 ? value : nil
    }

    /// The document's fee rate expressed in sat/byte, for display.
    /// Rounds up, so a rate that shows as 1 is never actually less.
    private func satsPerByte(of info: RawTxInfo) -> Int64 {
        let rate = info.feeRate.map { $0 > 0 ? $0 : TxFee.defaultFeeRate } ?? TxFee.defaultFeeRate
        return max(1, Int64((rate / 1000 * Double(TxFee.coinToSatoshi)).rounded(.up)))
    }

    // MARK: - send/carve shared steps

    /// P2PKH-locking-to-us, not-pending-spend cashes — the only rows
    /// the tx builder can sign today. Throws `unsupportedCashType`
    /// when the server returned rows but none are spendable, so the
    /// user sees a clearer story than "insufficient funds".
    private func spendableCashes(
        in snapshot: CashSnapshot,
        fromAddress: String
    ) throws -> [Cash] {
        let ownerHash160: Data
        do {
            ownerHash160 = try FchAddress(fid: fromAddress).hash160
        } catch {
            throw Failure.underlying(error)
        }
        let ours = snapshot.cashes
            .filter { !$0.pendingSpend && $0.locksToP2PKH(hash160: ownerHash160) }
        // A cash at the end of a maximal unconfirmed chain is ours and
        // valid and still unspendable — the next node in the line is
        // one the mempool won't carry. Told apart from "nothing to
        // spend" because the fix is different: wait for a block.
        let spendable = ours.filter(\.withinUnconfirmedChainLimit)
        if spendable.isEmpty, !ours.isEmpty {
            throw Failure.unconfirmedChainLimit(
                depth: ours.map(\.unconfirmedDepth).min() ?? Cash.maxUnconfirmedChain
            )
        }
        if spendable.isEmpty, let sample = snapshot.cashes.first {
            throw Failure.unsupportedCashType(sample.type ?? sample.lockScript ?? "<no lockScript>")
        }
        return spendable
    }

    /// The caller-named-inputs counterpart of ``spendableCashes``.
    /// Filtering is wrong here: the user picked these rows, so a
    /// silently-dropped one would build a transaction they did not
    /// ask for — and if the dropped row was the one funding the
    /// payment, the failure would surface as a confusing
    /// "insufficient funds" instead of the truth.
    private func requireSpendable(_ inputs: [Cash], fromAddress: String) throws {
        guard !inputs.isEmpty else {
            throw Failure.underlying(CashReorg.Failure.noInputs)
        }
        let ownerHash160: Data
        do {
            ownerHash160 = try FchAddress(fid: fromAddress).hash160
        } catch {
            throw Failure.underlying(error)
        }
        for cash in inputs {
            let label = cash.id ?? "\(cash.birthTxId):\(cash.birthIndex)"
            if cash.pendingSpend {
                throw Failure.unspendableInput(
                    id: label,
                    reason: "it is already an input of a broadcast transaction that hasn't confirmed. Recover it first if that transaction is never coming back."
                )
            }
            guard cash.withinUnconfirmedChainLimit else {
                throw Failure.unspendableInput(
                    id: label,
                    reason: "it sits \(cash.unconfirmedDepth) unconfirmed spends deep and the network carries at most \(Cash.maxUnconfirmedChain). Wait for a block."
                )
            }
            guard cash.locksToP2PKH(hash160: ownerHash160) else {
                throw Failure.unspendableInput(
                    id: label,
                    reason: "its lockScript doesn't pay \(fromAddress) as plain P2PKH (type '\(cash.type ?? "unknown")')"
                )
            }
        }
    }

    // MARK: - input reservation

    /// Reserve `inputs` for this transaction: check none of them is
    /// already spoken for, then flag them all `pendingSpend` and
    /// persist — as one indivisible step.
    ///
    /// **Selection alone is not a claim.** Coin selection reads a
    /// snapshot and picks the largest cashes; two transactions being
    /// prepared at the same time read the same snapshot and pick the
    /// *same* cashes, and the second one to broadcast is rejected by
    /// the node as a mempool conflict. That is not a rare race in this
    /// app: the chat outbox, mail retries and DOCK fetches all carve
    /// in the background, so "another transaction is being built right
    /// now" is the normal state of affairs rather than an edge case.
    ///
    /// The critical section holds a plain lock and does no I/O beyond
    /// the store write — no network, no signing, no waiting on a
    /// human — so it is measured in microseconds.
    ///
    /// A claim outlives a crash: the flag is on disk. That is the
    /// conservative direction (the cash is at worst *believed* spent
    /// until Recover clears it, rather than spent twice), and the
    /// release path below covers every ordinary failure.
    private func claim(_ inputs: [Cash], ownerFid: String) throws {
        guard let store = self.cashes, !inputs.isEmpty else { return }
        try CashLedgerLock.withLock {
            guard var snap = try store.snapshot(forAddress: ownerFid) else { return }
            // Check everything before changing anything: a partial
            // claim would strand cashes nobody is spending.
            for input in inputs {
                guard let row = snap.row(matching: input) else { continue }
                if row.pendingSpend {
                    throw Failure.inputAlreadyClaimed(
                        id: row.id ?? "\(row.birthTxId):\(row.birthIndex)"
                    )
                }
            }
            for input in inputs {
                guard var row = snap.row(matching: input) else { continue }
                row.pendingSpend = true
                snap.upsert(row)
            }
            snap.snapshotAt = Date()
            try store.save(snap)
        }
    }

    /// Give back a claim that came to nothing — the user declined,
    /// signing failed, the broadcast was rejected. Without this a
    /// refused transaction would quietly cost the user the use of its
    /// inputs until they noticed and recovered them by hand.
    private func release(_ inputs: [Cash], ownerFid: String) {
        guard let store = self.cashes, !inputs.isEmpty else { return }
        try? CashLedgerLock.withLock {
            guard var snap = try store.snapshot(forAddress: ownerFid) else { return }
            for input in inputs {
                guard var row = snap.row(matching: input), row.pendingSpend else { continue }
                row.pendingSpend = false
                snap.upsert(row)
            }
            snap.snapshotAt = Date()
            try store.save(snap)
        }
    }

    /// Build a plan and reserve its inputs, retrying once against a
    /// freshly-read cache when someone else got there first.
    ///
    /// The retry is what makes concurrent spending *work* rather than
    /// merely fail safely: the second transaction re-selects from what
    /// is actually left and usually succeeds, instead of surfacing a
    /// conflict the user can do nothing about.
    private func planAndClaim<Plan>(
        ownerFid: String,
        snapshot: CashSnapshot,
        allowReselect: Bool = true,
        makePlan: (CashSnapshot) throws -> Plan,
        inputsOf: (Plan) -> [Cash]
    ) throws -> Plan {
        var working = snapshot
        var lastConflict: Error?
        for attempt in 0..<(allowReselect ? 2 : 1) {
            let plan = try makePlan(working)
            do {
                try claim(inputsOf(plan), ownerFid: ownerFid)
                return plan
            } catch let error as Failure {
                guard case .inputAlreadyClaimed = error else { throw error }
                lastConflict = error
                // Re-read the cache: the winner's claim is in it, so
                // the next selection avoids those cashes.
                guard attempt == 0,
                      let fresh = try? cachedSnapshot(forAddress: ownerFid) else { break }
                working = fresh
            }
        }
        throw lastConflict ?? Failure.unexpectedDataShape(api: "claim")
    }

    // MARK: - approval gate

    /// Ask ``approve`` — if anyone is listening — whether to sign
    /// `unsigned`, and throw ``Failure/declinedByUser`` if the answer
    /// is no.
    ///
    /// **The preview is read off the assembled transaction, not off
    /// the caller's intent.** Every output is decoded back out of its
    /// scriptPubKey, so what the dialog shows is what the bytes say:
    /// if a builder ever paid the wrong address or sized change
    /// wrongly, the preview shows *that*, which is the entire value of
    /// asking. A preview reconstructed from the same variables the
    /// builder used could only ever agree with it.
    private func requireApproval(
        kind: TxPreview.Kind,
        from: String,
        inputs: [Cash],
        unsigned: Transaction,
        fee: Int64,
        estimatedSize: Int,
        feePerByte: Int64,
        opReturn: String? = nil
    ) async throws {
        guard let approve else { return }
        let preview = TxPreview(
            kind: kind,
            from: from,
            inputs: inputs,
            outputs: unsigned.outputs.map { out in
                describeOutput(out, ownerFid: from)
            },
            fee: fee,
            estimatedSize: estimatedSize,
            feePerByte: feePerByte,
            opReturn: opReturn
        )
        if await approve(preview) { return }
        throw Failure.declinedByUser
    }

    /// Decode one built output back into something a person can read:
    /// the address it pays and whether that address is the sender's
    /// own.
    private func describeOutput(_ out: TxOutput, ownerFid: String) -> TxPreview.Output {
        let bytes = [UInt8](out.scriptPubKey.bytes)
        // OP_RETURN — pays nobody, carries the data.
        if bytes.first == 0x6a {
            return TxPreview.Output(fid: nil, amount: Int64(out.value), isSelf: false, isOpReturn: true)
        }
        // Canonical P2PKH: 76 a9 14 <20 bytes> 88 ac.
        if bytes.count == 25, bytes[0] == 0x76, bytes[1] == 0xa9, bytes[2] == 0x14,
           bytes[23] == 0x88, bytes[24] == 0xac {
            let hash160 = Data(bytes[3..<23])
            let fid = (try? FchAddress(hash160: hash160))?.fid
            return TxPreview.Output(
                fid: fid,
                amount: Int64(out.value),
                isSelf: fid == ownerFid
            )
        }
        // Canonical P2SH: a9 14 <20 bytes> 87. A time-locked or
        // multisig output lands here, and showing its 3… address is
        // the difference between a preview a person can check and a
        // wall of script hex they will click past.
        if bytes.count == 23, bytes[0] == 0xa9, bytes[1] == 0x14, bytes[22] == 0x87 {
            let scriptHash = Data(bytes[2..<22])
            let addr = try? FchAddress(
                versionByte: FchAddress.p2shVersionByte, hash160: scriptHash
            ).fid
            return TxPreview.Output(
                fid: addr, amount: Int64(out.value), isSelf: false
            )
        }
        // Anything else: show the script rather than pretend we know
        // who it pays.
        let hex = bytes.map { String(format: "%02x", $0) }.joined()
        return TxPreview.Output(fid: hex, amount: Int64(out.value), isSelf: false)
    }

    /// Sign each input in plan order. signP2pkhInput rebuilds the tx
    /// with the single input filled; we feed the result back in for
    /// the next index so the running tx state is current.
    private func signAllInputs(
        unsigned: Transaction,
        inputs: [Cash],
        privkey: Data
    ) throws -> Transaction {
        var signed = unsigned
        for (idx, cash) in inputs.enumerated() {
            signed = try TxHandler.signP2pkhInput(
                tx: signed,
                inputIndex: idx,
                privateKey: privkey,
                prevValueSats: UInt64(cash.value)
            )
        }
        return signed
    }

    /// `base.broadcastTx` with the serialized tx hex. Returns the
    /// server-reported txid. The Java reference returns
    /// `response.data.toString()` for a successful broadcast —
    /// JSON-encoded that's a quoted string, so we decode `data` as a
    /// fragment and re-extract.
    /// Broadcast an already-serialized transaction.
    ///
    /// The multisig path assembles its own bytes — the scriptSigs are
    /// built from signatures collected elsewhere, not by any signing
    /// call in this service — so it needs a way in that does not start
    /// from a ``Transaction`` this service signed itself.
    public func broadcastRaw(_ serialized: Data, timeoutMs: Int = 10_000) async throws -> String {
        try await broadcast(rawHex: Hex.encode(serialized), timeoutMs: timeoutMs)
    }

    private func broadcast(signed: Transaction, timeoutMs: Int) async throws -> String {
        try await broadcast(rawHex: Hex.encode(signed.serialized), timeoutMs: timeoutMs)
    }

    private func broadcast(rawHex: String, timeoutMs: Int) async throws -> String {
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
        guard let data = resp.data,
              let txidString = try JSONSerialization.jsonObject(with: data, options: [.fragmentsAllowed]) as? String
        else {
            throw Failure.unexpectedDataShape(api: "base.broadcastTx")
        }
        return txidString
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
        // A send with caller-named inputs never fetches a snapshot, so
        // there may not be one yet. Starting an empty one is better
        // than dropping the change on the floor — the next sync
        // reconciles it either way, but until then the wallet would
        // believe it had nothing.
        var snap = try store.snapshot(forAddress: ownerFid)
            ?? CashSnapshot(addr: ownerFid, cashes: [])

        // How far from a confirmed block the new cashes stand: one
        // step past the deepest input we are spending. Inputs the
        // chain has already confirmed are at depth 0, so a normal send
        // mints depth-1 cashes.
        let mintedDepth = 1 + (spent.map(\.unconfirmedDepth).max() ?? 0)

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
                pendingSpend: false,
                unconfirmedDepth: mintedDepth
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
