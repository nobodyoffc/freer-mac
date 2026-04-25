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
        case underlying(Error)

        public var description: String {
            switch self {
            case let .fapiNonZeroCode(api, code, message):
                return "WalletService: \(api) returned code=\(code) message=\(message ?? "<nil>")"
            case .unexpectedDataShape(let api):
                return "WalletService: \(api) response data did not match the expected shape"
            case .underlying(let e):
                return "WalletService: \(e)"
            }
        }
    }

    public let fapi: any FapiCalling
    public let utxos: UtxosStore?

    /// `utxos` is optional because the read path is meaningful even
    /// without a cache (the SwiftUI view-model can hold the latest
    /// snapshot in memory). Pass one in to enable durable caching.
    public init(fapi: any FapiCalling, utxos: UtxosStore? = nil) {
        self.fapi = fapi
        self.utxos = utxos
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

    // MARK: - utxos

    /// `base.getUtxo` — fetch the spendable UTXO list for an address.
    /// `minAmountBch` is forwarded as `amount` (server may filter
    /// dust). When ``utxos`` is non-nil the returned snapshot is
    /// persisted to the cache automatically.
    public func refreshUtxos(
        forAddress addr: String,
        minAmountBch: Double? = nil,
        minCd: Int64? = nil,
        timeoutMs: Int = 5_000
    ) async throws -> UtxoSnapshot {
        var paramsDict: [String: Any] = ["addr": addr]
        if let amt = minAmountBch { paramsDict["amount"] = amt }
        if let cd  = minCd        { paramsDict["cd"] = cd }
        let params = try JSONSerialization.data(withJSONObject: paramsDict, options: [.sortedKeys])

        let reply = try await fapi.call(
            api: "base.getUtxo",
            params: params, fcdsl: nil, binary: nil,
            sid: nil, via: nil, maxCost: nil,
            timeoutMs: timeoutMs
        )
        let resp = reply.response
        guard resp.isSuccess else {
            throw Failure.fapiNonZeroCode(api: "base.getUtxo", code: resp.code ?? -1, message: resp.message)
        }
        guard let data = resp.data else {
            throw Failure.unexpectedDataShape(api: "base.getUtxo")
        }
        let utxos: [Utxo]
        do {
            utxos = try Utxo.parseFapiList(data)
        } catch {
            throw Failure.underlying(error)
        }

        let snapshot = UtxoSnapshot(
            addr: addr,
            utxos: utxos,
            snapshotAt: Date(),
            bestHeight: resp.bestHeight
        )
        if let store = self.utxos {
            try store.save(snapshot)
        }
        return snapshot
    }

    /// Read the last cached snapshot for `addr`, or nil if we've
    /// never refreshed. No network round-trip; intended for "show
    /// last-known balance immediately on app open" UI flows.
    public func cachedSnapshot(forAddress addr: String) throws -> UtxoSnapshot? {
        try utxos?.snapshot(forAddress: addr)
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

        // 1. Get UTXOs.
        let snapshot: UtxoSnapshot
        if useCache, let cached = try cachedSnapshot(forAddress: fromAddress) {
            snapshot = cached
        } else {
            snapshot = try await refreshUtxos(forAddress: fromAddress, timeoutMs: timeoutMs)
        }

        // 2. Coin select.
        let plan = try CoinSelector.select(
            utxos: snapshot.utxos, amount: amount, feePerByte: feePerByte
        )

        // 3. Build unsigned tx.
        let unsigned = try TxBuilder.buildUnsigned(
            plan: plan, toFid: toFid, amount: amount, changeFid: fromAddress
        )

        // 4. Sign each input. signP2pkhInput rebuilds the tx with the
        // single input filled; we feed the result back in for the
        // next index so the running tx state is current.
        var signed = unsigned
        for (idx, utxo) in plan.selected.enumerated() {
            signed = try TxHandler.signP2pkhInput(
                tx: signed,
                inputIndex: idx,
                privateKey: privkey,
                prevValueSats: UInt64(utxo.value)
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
