import Foundation

/// Greedy largest-first coin selection. Picks UTXOs in descending
/// value order until the running sum covers `amount + estimatedFee`.
/// Re-estimates the fee each iteration because adding an input grows
/// the tx by ~148 B.
///
/// Why largest-first (not smallest-first):
/// - Minimizes the number of inputs, which keeps fees down and the
///   signed tx small.
/// - Costs UTXO-set "consolidation" — small UTXOs accumulate. We can
///   add a periodic compaction sweep later if the set grows pathological.
///
/// Fee model: 1 sat/byte default, with the standard size formula
/// `10 + 148*nIn + 34*nOut` (P2PKH-only). Replace this with a live
/// `base.estimateFee` call when we wire it in.
public enum CoinSelector {

    /// P2PKH dust threshold. A change output worth less than this
    /// is dropped — the leftover dust becomes additional miner fee.
    /// 546 sat is the bitcoinj/Bitcoin Core relay default.
    public static let dustThresholdSats: Int64 = 546

    public static let txOverheadBytes = 10
    public static let p2pkhInputBytes = 148
    public static let p2pkhOutputBytes = 34

    public struct Plan: Equatable, Sendable {
        public var selected: [Utxo]
        public var change: Int64       // 0 if no change output
        public var fee: Int64
        public var estimatedSize: Int  // bytes

        public var totalIn: Int64 { selected.reduce(0) { $0 + $1.value } }

        public var hasChange: Bool { change > 0 }
    }

    public enum Failure: Error, CustomStringConvertible {
        case nonPositiveAmount(Int64)
        case nonPositiveFeeRate(Int64)
        case insufficientFunds(needed: Int64, have: Int64)

        public var description: String {
            switch self {
            case .nonPositiveAmount(let n):
                return "CoinSelector: amount must be > 0, got \(n)"
            case .nonPositiveFeeRate(let n):
                return "CoinSelector: feePerByte must be > 0, got \(n)"
            case let .insufficientFunds(needed, have):
                return "CoinSelector: need \(needed) sat, have \(have) sat"
            }
        }
    }

    /// Pick UTXOs to fund a payment of `amount` satoshis at
    /// `feePerByte` sat/byte. Returns a fully-priced ``Plan``.
    ///
    /// `amount` is paid to one recipient; the change (if any) goes to
    /// a second output. Both are P2PKH.
    public static func select(
        utxos: [Utxo],
        amount: Int64,
        feePerByte: Int64 = 1
    ) throws -> Plan {
        guard amount > 0 else { throw Failure.nonPositiveAmount(amount) }
        guard feePerByte > 0 else { throw Failure.nonPositiveFeeRate(feePerByte) }

        let candidates = utxos.sorted { $0.value > $1.value }
        var selected: [Utxo] = []
        var sum: Int64 = 0

        // Iterate: each added input bumps the fee, which may force
        // another input. The sum-feedback loop terminates because the
        // input-fee-cost (148 sat at 1 sat/byte) is well below any
        // reasonable per-utxo value.
        for utxo in candidates {
            selected.append(utxo)
            sum += utxo.value
            // Try to close the plan with TWO outputs (recipient + change).
            let twoOutSize = sizeFor(nIn: selected.count, nOut: 2)
            let twoOutFee = Int64(twoOutSize) * feePerByte
            let twoOutChange = sum - amount - twoOutFee
            if twoOutChange >= dustThresholdSats {
                return Plan(
                    selected: selected,
                    change: twoOutChange,
                    fee: twoOutFee,
                    estimatedSize: twoOutSize
                )
            }
            // Try to close with ONE output (no change; dust folded into fee).
            let oneOutSize = sizeFor(nIn: selected.count, nOut: 1)
            let oneOutFee = Int64(oneOutSize) * feePerByte
            if sum >= amount + oneOutFee {
                // Whatever is left over (sum - amount - feeWithoutChange)
                // becomes additional fee; the receiver still gets `amount`.
                let actualFee = sum - amount
                return Plan(
                    selected: selected,
                    change: 0,
                    fee: actualFee,
                    estimatedSize: oneOutSize
                )
            }
            // Still short — keep adding.
        }

        // Walked through every candidate; if we got here we couldn't
        // even afford the no-change branch.
        let neededAtMin = amount + Int64(sizeFor(nIn: selected.count, nOut: 1)) * feePerByte
        throw Failure.insufficientFunds(needed: neededAtMin, have: sum)
    }

    /// Estimated tx size in bytes for `nIn` P2PKH inputs and `nOut`
    /// P2PKH outputs. The 10-byte overhead is `version(4) +
    /// inCount(1) + outCount(1) + locktime(4)`. P2PKH input ≈ 148 B
    /// (32 prevTxHash + 4 outIndex + 1 scriptSig-len + 107 scriptSig +
    /// 4 sequence). P2PKH output ≈ 34 B.
    public static func sizeFor(nIn: Int, nOut: Int) -> Int {
        txOverheadBytes + p2pkhInputBytes * nIn + p2pkhOutputBytes * nOut
    }
}
