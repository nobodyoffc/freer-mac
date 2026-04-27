import Foundation

/// One on-chain transaction's net effect on the live FID's balance,
/// derived from a flat list of ``Cash`` rows. The Transactions pane
/// renders one row per group instead of one row per cash so a single
/// Send (which fans out into ≥1 spent input + 1 change output) lands
/// as one cohesive entry rather than two-or-more confusing slivers.
///
/// **Event txid**: a cash with `valid != false` belongs to the tx that
/// *created* it (`birthTxId`) — that's the income event. A cash with
/// `valid == false` belongs to the tx that *spent* it (`spendTxId`) —
/// that's the outgoing event. A single tx can produce both: when we
/// send to ourselves, our spent input AND our change output both
/// reference the same tx, so the group has both `incoming` and
/// `outgoing` cashes (a "mixed" role).
public struct TxGroup: Equatable, Sendable {
    public let txid: String
    public let height: Int64?
    public let time: Int64?
    public let incoming: [Cash]
    public let outgoing: [Cash]

    public enum Role: String, Sendable {
        case received
        case sent
        case mixed
    }

    /// `incoming.sum - outgoing.sum`. Positive means the live FID
    /// gained value in this tx; negative means it lost value.
    public var netSats: Int64 {
        let inc = incoming.reduce(Int64(0)) { $0 + $1.value }
        let out = outgoing.reduce(Int64(0)) { $0 + $1.value }
        return inc - out
    }

    public var role: Role {
        switch (incoming.isEmpty, outgoing.isEmpty) {
        case (false, true):  return .received
        case (true,  false): return .sent
        default:             return .mixed
        }
    }

    /// Cluster a flat cash list into per-tx groups, sorted by event
    /// height descending (newest first). Cashes are deduplicated by
    /// `(birthTxId, birthIndex)` so a server response that lists the
    /// same cash twice (e.g. with both `valid: true` and the prior
    /// `valid: false` somehow) doesn't double-count.
    public static func group(_ cashes: [Cash]) -> [TxGroup] {
        var byTxid: [String: (
            incoming: [Cash],
            outgoing: [Cash],
            height: Int64?,
            time: Int64?
        )] = [:]
        var seen = Set<String>()

        for cash in cashes {
            // Deduplicate by canonical cash id, preferring the
            // explicit one when present.
            let key = cash.id ?? "\(cash.birthTxId):\(cash.birthIndex)"
            guard seen.insert(key).inserted else { continue }

            let isSpent = (cash.valid ?? true) == false
            if isSpent, let txid = cash.spendTxId {
                var bucket = byTxid[txid] ?? ([], [], nil, nil)
                bucket.outgoing.append(cash)
                bucket.height = bucket.height ?? cash.spendHeight ?? cash.lastHeight
                bucket.time   = bucket.time   ?? cash.spendTime   ?? cash.lastTime
                byTxid[txid] = bucket
            } else {
                let txid = cash.birthTxId
                var bucket = byTxid[txid] ?? ([], [], nil, nil)
                bucket.incoming.append(cash)
                bucket.height = bucket.height ?? cash.birthHeight
                bucket.time   = bucket.time   ?? cash.birthTime
                byTxid[txid] = bucket
            }
        }

        return byTxid
            .map { (txid, b) in
                TxGroup(
                    txid: txid,
                    height: b.height,
                    time: b.time,
                    incoming: b.incoming,
                    outgoing: b.outgoing
                )
            }
            .sorted { lhs, rhs in
                // Newest first. Unconfirmed (height nil) sorts above
                // any confirmed tx — those are the user's most recent
                // pending sends and they want to see them at the top.
                switch (lhs.height, rhs.height) {
                case let (l?, r?): return l > r
                case (nil, _?):    return true
                case (_?, nil):    return false
                case (nil, nil):   return lhs.txid < rhs.txid
                }
            }
    }
}
