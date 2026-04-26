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

    /// `cashes` is optional because the read path is meaningful even
    /// without a cache (the SwiftUI view-model can hold the latest
    /// snapshot in memory). Pass one in to enable durable caching.
    public init(fapi: any FapiCalling, cashes: CashesStore? = nil) {
        self.fapi = fapi
        self.cashes = cashes
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

    /// Reorg-protection window. Every incremental refresh re-fetches
    /// items whose `lastHeight > watermarkHeight - reorgWindowBlocks`
    /// so any reorg that rewrites the trailing window's state is
    /// reflected. Matches FCH's protocol-level reorg cap.
    public static let reorgWindowBlocks: Int64 = 30

    /// Public entry point. Picks bootstrap or incremental based on
    /// whether we have a watermark for this fid. Caller doesn't need
    /// to care.
    @discardableResult
    public func refreshCashes(
        forFid fid: String,
        pageSize: Int = WalletService.defaultCashPageSize,
        timeoutMs: Int = 5_000
    ) async throws -> CashSnapshot {
        let cached = try? cashes?.snapshot(forAddress: fid)
        if let cached, let _ = cached.watermarkHeight {
            return try await refreshCashesIncremental(
                forFid: fid, base: cached,
                pageSize: pageSize, timeoutMs: timeoutMs
            )
        } else {
            return try await bootstrapCashes(
                forFid: fid, pageSize: pageSize, timeoutMs: timeoutMs
            )
        }
    }

    /// First-time sync: query `base.cashValid` for every spendable
    /// cash owned by `fid`, paging via the FCDSL `after` cursor until
    /// the server runs dry. Replaces any existing snapshot.
    ///
    /// Mode 1 (`params == null`, FCDSL filter) is the right path here
    /// because mode 2 ("smart selection") doesn't paginate.
    public func bootstrapCashes(
        forFid fid: String,
        pageSize: Int = WalletService.defaultCashPageSize,
        timeoutMs: Int = 5_000
    ) async throws -> CashSnapshot {
        var collected: [Cash] = []
        var bestHeight: Int64?

        try await pageCashes(
            api: "base.cashValid",
            entity: nil,                 // mode 1 of cashValid is bound to the cash index
            ownerFid: fid,
            sinceLastHeightExclusive: nil,
            pageSize: pageSize,
            timeoutMs: timeoutMs
        ) { cashes, pageBest in
            collected.append(contentsOf: cashes)
            bestHeight = bestHeight ?? pageBest
        }

        // Watermark = bestHeight at fetch time. The next incremental
        // refresh subtracts `reorgWindowBlocks` to re-fetch the
        // trailing reorg-prone window.
        let snapshot = CashSnapshot(
            addr: fid,
            cashes: collected,
            snapshotAt: Date(),
            bestHeight: bestHeight,
            watermarkHeight: bestHeight
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

    /// Build the FCDSL JSON for cash pagination queries. Uniform across
    /// `base.cashValid` mode-1 (no entity) and `base.search`
    /// (entity = "cash").
    private static func cashFcdsl(
        entity: String?,
        ownerFid: String,
        sinceLastHeightExclusive: Int64?,
        pageSize: Int,
        after: [String]?
    ) throws -> Data {
        var filter: [String: Any] = [
            "terms": ["fields": ["owner"], "values": [ownerFid]]
        ]
        if let h = sinceLastHeightExclusive {
            filter["range"] = ["fields": ["lastHeight"], "gt": String(h)]
        }
        var dict: [String: Any] = [
            "filter": filter,
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
