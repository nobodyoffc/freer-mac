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

    /// `base.cashValid` — fetch the spendable cash list for a FID. The
    /// server's mode-2 "smart selection" path takes `fid` (required)
    /// plus optional `amount` (BCH double — coarse filter) and `cd`
    /// (min coin-days). When ``cashes`` is non-nil the returned
    /// snapshot is persisted to the cache automatically.
    ///
    /// Why `cashValid` and not `getUtxo`: `Cash` carries the type +
    /// `redeemScript` + `lockTime` we need to spend P2SH-CLTV and
    /// multisig outputs (Phase 8). The lighter `Utxo` shape strips
    /// those fields and would force a second round-trip.
    public func refreshCashes(
        forFid fid: String,
        minAmountBch: Double? = nil,
        minCd: Int64? = nil,
        timeoutMs: Int = 5_000
    ) async throws -> CashSnapshot {
        var paramsDict: [String: Any] = ["fid": fid]
        if let amt = minAmountBch { paramsDict["amount"] = amt }
        if let cd  = minCd        { paramsDict["cd"] = cd }
        let params = try JSONSerialization.data(withJSONObject: paramsDict, options: [.sortedKeys])

        let reply = try await fapi.call(
            api: "base.cashValid",
            params: params, fcdsl: nil, binary: nil,
            sid: nil, via: nil, maxCost: nil,
            timeoutMs: timeoutMs
        )
        let resp = reply.response
        guard resp.isSuccess else {
            throw Failure.fapiNonZeroCode(api: "base.cashValid", code: resp.code ?? -1, message: resp.message)
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
            bestHeight: resp.bestHeight
        )
        if let store = self.cashes {
            try store.save(snapshot)
        }
        return snapshot
    }

    /// Read the last cached snapshot for `addr`, or nil if we've
    /// never refreshed. No network round-trip; intended for "show
    /// last-known balance immediately on app open" UI flows.
    public func cachedSnapshot(forAddress addr: String) throws -> CashSnapshot? {
        try cashes?.snapshot(forAddress: addr)
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

        // 1a. Reject any non-P2PKH cash up-front. CLTV / multisig
        // need dedicated signing paths (Phase 8); selecting one of
        // those here would build a tx we can't sign.
        let standard = snapshot.cashes.filter { $0.isStandardP2PKH }
        if standard.count != snapshot.cashes.count {
            // At least one cash had a non-standard type. Fall through
            // with the filtered list — but if the user has *only*
            // non-standard cashes, surface a clearer error than
            // CoinSelector's "insufficient funds".
            if standard.isEmpty, let first = snapshot.cashes.first {
                throw Failure.unsupportedCashType(first.type ?? "Unknown")
            }
        }

        // 2. Coin select.
        let plan = try CoinSelector.select(
            cashes: standard, amount: amount, feePerByte: feePerByte
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

        return SendResult(transaction: signed, remoteTxid: txidString, plan: plan)
    }
}
