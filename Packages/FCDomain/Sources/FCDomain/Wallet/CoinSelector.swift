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
    /// BCH-Schnorr P2PKH input: txid(32) + outIndex(4) + scriptLen(1) +
    /// push65 sig+sighash(66) + push33 pubkey(34) + sequence(4) = 141 B.
    /// Matches Android freecashj's `141` constant. Pre-Schnorr ECDSA
    /// would have been ~148 B (DER sig is 70-72 B).
    public static let p2pkhInputBytes = 141
    public static let p2pkhOutputBytes = 34

    public struct Plan: Equatable, Sendable {
        public var selected: [Cash]
        public var change: Int64       // 0 if no change output
        public var fee: Int64
        public var estimatedSize: Int  // bytes

        public init(selected: [Cash], change: Int64, fee: Int64, estimatedSize: Int) {
            self.selected = selected
            self.change = change
            self.fee = fee
            self.estimatedSize = estimatedSize
        }

        public var totalIn: Int64 { selected.reduce(0) { $0 + $1.value } }

        public var hasChange: Bool { change > 0 }
    }

    public enum Failure: Error, CustomStringConvertible {
        case nonPositiveAmount(Int64)
        case nonPositiveFeeRate(Int64)
        case insufficientFunds(needed: Int64, have: Int64)
        case insufficientCoinDays(required: Int64, have: Int64)

        public var description: String {
            switch self {
            case .nonPositiveAmount(let n):
                return "CoinSelector: amount must be > 0, got \(n)"
            case .nonPositiveFeeRate(let n):
                return "CoinSelector: feePerByte must be > 0, got \(n)"
            case let .insufficientFunds(needed, have):
                return "CoinSelector: need \(needed) sat, have \(have) sat"
            case let .insufficientCoinDays(required, have):
                return "CoinSelector: carve requires destroying \(required) CoinDay(s), the spendable cashes only accumulate \(have) — wait for cashes to age or receive an older cash"
            }
        }
    }

    /// Pick cashes to fund a payment of `amount` satoshis at
    /// `feePerByte` sat/byte. Returns a fully-priced ``Plan``.
    ///
    /// `amount` is paid to one recipient; the change (if any) goes to
    /// a second output. Both are P2PKH — caller filters non-standard
    /// types before getting here.
    public static func select(
        cashes: [Cash],
        amount: Int64,
        feePerByte: Int64 = 1
    ) throws -> Plan {
        guard amount > 0 else { throw Failure.nonPositiveAmount(amount) }
        guard feePerByte > 0 else { throw Failure.nonPositiveFeeRate(feePerByte) }

        let candidates = cashes.sorted { $0.value > $1.value }
        var selected: [Cash] = []
        var sum: Int64 = 0

        // Iterate: each added input bumps the fee, which may force
        // another input. The sum-feedback loop terminates because the
        // input-fee-cost (148 sat at 1 sat/byte) is well below any
        // reasonable per-cash value.
        for cash in candidates {
            selected.append(cash)
            sum += cash.value
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

    // MARK: - carve (OP_RETURN) selection

    /// Serialized size of an OP_RETURN output carrying `byteCount`
    /// bytes of data: value(8) + scriptLen varint + script, where
    /// script = OP_RETURN(1) + pushdata prefix (1/2/3) + data.
    /// Mirrors the Java `TxHandler.calcOpReturnLen`.
    public static func opReturnOutputBytes(_ byteCount: Int) -> Int {
        let dataLen: Int
        if byteCount < 76 {
            dataLen = byteCount + 1        // direct push
        } else if byteCount < 256 {
            dataLen = byteCount + 2        // OP_PUSHDATA1
        } else {
            dataLen = byteCount + 3        // OP_PUSHDATA2
        }
        let scriptLen = dataLen + 1        // + OP_RETURN byte
        let scriptVarInt = scriptLen < 0xFD ? 1 : 3
        return 8 + scriptVarInt + scriptLen
    }

    /// Pick cashes to fund a data-carve tx: an OP_RETURN of
    /// `opReturnByteCount` bytes, an optional payment of `payAmount` to
    /// one recipient, and (usually) a change output back to the sender.
    ///
    /// `payAmount` is what separates a plain carve from a **mail**. A
    /// contact or secret carve pays nobody — the cost is just the miner
    /// fee — but a mail is addressed by *paying its recipient*, so the
    /// same transaction carries a real output alongside the data
    /// (Android's `TxSender.carveFeipWithRecipient`). Leave it at 0 for
    /// the paymentless carves.
    ///
    /// `requiredCd` is the CoinDays the inputs must jointly destroy —
    /// FEIP carves require 1 CD once the chain passes
    /// ``ContactFeip/cddCheckHeight``. Selection keeps adding inputs
    /// until the payment, the fee and the CD requirement are all
    /// covered; a value surplus can't substitute for missing CoinDays.
    ///
    /// Mirrors the Android path `getValidCashes(0, cd, 0, msgSize, …)`
    /// → `TxHandler.calcFee`: change > dust gets its own output,
    /// otherwise the remainder burns as extra fee.
    public static func selectForCarve(
        cashes: [Cash],
        opReturnByteCount: Int,
        feePerByte: Int64 = 1,
        requiredCd: Int64 = 0,
        payAmount: Int64 = 0
    ) throws -> Plan {
        guard feePerByte > 0 else { throw Failure.nonPositiveFeeRate(feePerByte) }
        guard payAmount >= 0 else { throw Failure.nonPositiveAmount(payAmount) }

        let opReturnLen = opReturnOutputBytes(opReturnByteCount)
        // The recipient output, when there is one, is present in both
        // the with-change and no-change shapes — it is the payment, not
        // the remainder.
        let payOutputs = payAmount > 0 ? 1 : 0
        let candidates = cashes.sorted { $0.value > $1.value }
        var selected: [Cash] = []
        var sum: Int64 = 0
        var cdSum: Int64 = 0

        for cash in candidates {
            selected.append(cash)
            sum += cash.value
            cdSum += cash.cd ?? 0
            guard cdSum >= requiredCd else { continue }

            // With change: overhead + inputs + pay? + change(34) + opReturn.
            let withChangeSize = sizeFor(nIn: selected.count, nOut: payOutputs + 1) + opReturnLen
            let withChangeFee = Int64(withChangeSize) * feePerByte
            let change = sum - payAmount - withChangeFee
            if change > dustThresholdSats {
                return Plan(
                    selected: selected,
                    change: change,
                    fee: withChangeFee,
                    estimatedSize: withChangeSize
                )
            }
            // Without change: the dust-or-less remainder burns as fee.
            // The recipient still receives exactly `payAmount`.
            let noChangeSize = sizeFor(nIn: selected.count, nOut: payOutputs) + opReturnLen
            let noChangeFee = Int64(noChangeSize) * feePerByte
            if sum >= payAmount + noChangeFee {
                return Plan(
                    selected: selected,
                    change: 0,
                    fee: sum - payAmount,
                    estimatedSize: noChangeSize
                )
            }
        }

        if cdSum < requiredCd {
            throw Failure.insufficientCoinDays(required: requiredCd, have: cdSum)
        }
        let neededAtMin = payAmount
            + Int64(sizeFor(nIn: max(selected.count, 1), nOut: payOutputs) + opReturnLen) * feePerByte
        throw Failure.insufficientFunds(needed: neededAtMin, have: sum)
    }
}
