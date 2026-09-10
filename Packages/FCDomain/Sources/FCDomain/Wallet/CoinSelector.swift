import Foundation

/// Coin selection that destroys as few CoinDays as it can.
///
/// Why not largest-first, which this used to be: it kept the input
/// count down, but the largest cash is usually also an old one, so a
/// small payment — or a carve that only has to destroy one CoinDay —
/// burned the whole age of the biggest bill. An extra input costs
/// 141 B; CoinDays can't be bought back. The rule is in
/// ``pick(_:payValue:requiredCd:feeFor:)`` and matches Android's
/// `CashSelector`, so both apps spend the same cashes.
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

        let feeFor: (Int) -> Int64 = { nIn in Int64(sizeFor(nIn: nIn, nOut: 1)) * feePerByte }
        let picked = pick(cashes, payValue: amount, requiredCd: 0, feeFor: feeFor)
        let pickedValue = picked.reduce(Int64(0)) { $0 + $1.value }
        if picked.isEmpty || pickedValue < amount + feeFor(picked.count) {
            let have = cashes.reduce(Int64(0)) { $0 + max($1.value, 0) }
            throw Failure.insufficientFunds(needed: amount + feeFor(max(picked.count, 1)), have: have)
        }
        // Priced exactly as if the user had ticked these cashes.
        return try fixed(cashes: picked, amount: amount, feePerByte: feePerByte)
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
        let feeFor: (Int) -> Int64 = { nIn in
            Int64(sizeFor(nIn: nIn, nOut: payOutputs) + opReturnLen) * feePerByte
        }
        let picked = pick(cashes, payValue: payAmount, requiredCd: requiredCd, feeFor: feeFor)
        if picked.reduce(Int64(0), { $0 + ($1.cd ?? 0) }) < requiredCd {
            let have = cashes.reduce(Int64(0)) { $0 + ($1.cd ?? 0) }
            throw Failure.insufficientCoinDays(required: requiredCd, have: have)
        }
        let pickedValue = picked.reduce(Int64(0)) { $0 + $1.value }
        if picked.isEmpty || pickedValue < payAmount + feeFor(picked.count) {
            let have = cashes.reduce(Int64(0)) { $0 + max($1.value, 0) }
            throw Failure.insufficientFunds(needed: payAmount + feeFor(max(picked.count, 1)), have: have)
        }
        return try fixedForCarve(
            cashes: picked, opReturnByteCount: opReturnByteCount, feePerByte: feePerByte,
            requiredCd: requiredCd, payAmount: payAmount
        )
    }

    // MARK: - fixed inputs (the Cash pane's "spend exactly these")

    /// Price a payment whose inputs are already decided — the Cash
    /// pane's Send, where the user ticked the cashes themselves.
    ///
    /// Every cash in `cashes` is spent, in the order given: nothing is
    /// selected and nothing is dropped, because the input set *is* the
    /// user's instruction. All that's left to compute is the fee and
    /// whether the remainder is worth a change output. A remainder at
    /// or below the dust threshold burns as extra fee, exactly as in
    /// ``select(cashes:amount:feePerByte:)`` — the recipient still
    /// receives `amount` either way.
    public static func fixed(
        cashes: [Cash],
        amount: Int64,
        feePerByte: Int64 = 1
    ) throws -> Plan {
        guard amount > 0 else { throw Failure.nonPositiveAmount(amount) }
        guard feePerByte > 0 else { throw Failure.nonPositiveFeeRate(feePerByte) }

        let sum = cashes.reduce(Int64(0)) { $0 + $1.value }
        let nIn = cashes.count

        let twoOutSize = sizeFor(nIn: nIn, nOut: 2)
        let twoOutFee = Int64(twoOutSize) * feePerByte
        let change = sum - amount - twoOutFee
        if change >= dustThresholdSats {
            return Plan(
                selected: cashes, change: change,
                fee: twoOutFee, estimatedSize: twoOutSize
            )
        }

        let oneOutSize = sizeFor(nIn: nIn, nOut: 1)
        let oneOutFee = Int64(oneOutSize) * feePerByte
        if sum >= amount + oneOutFee {
            return Plan(
                selected: cashes, change: 0,
                fee: sum - amount, estimatedSize: oneOutSize
            )
        }
        throw Failure.insufficientFunds(needed: amount + oneOutFee, have: sum)
    }

    /// The carve counterpart of ``fixed(cashes:amount:feePerByte:)``:
    /// price a data carve — optionally paying `payAmount` to one
    /// recipient — whose inputs are already decided, as when the user
    /// swaps them in the approval dialog. Every cash is spent, in the
    /// order given. The inputs must still destroy `requiredCd`: a carve
    /// short of its CoinDays is rejected by the parser no matter who
    /// picked the cash.
    public static func fixedForCarve(
        cashes: [Cash],
        opReturnByteCount: Int,
        feePerByte: Int64 = 1,
        requiredCd: Int64 = 0,
        payAmount: Int64 = 0
    ) throws -> Plan {
        guard feePerByte > 0 else { throw Failure.nonPositiveFeeRate(feePerByte) }
        guard payAmount >= 0 else { throw Failure.nonPositiveAmount(payAmount) }

        let cdSum = cashes.reduce(Int64(0)) { $0 + ($1.cd ?? 0) }
        if cdSum < requiredCd {
            throw Failure.insufficientCoinDays(required: requiredCd, have: cdSum)
        }

        let opReturnLen = opReturnOutputBytes(opReturnByteCount)
        let payOutputs = payAmount > 0 ? 1 : 0
        let sum = cashes.reduce(Int64(0)) { $0 + $1.value }
        let nIn = cashes.count

        // With change: overhead + inputs + pay? + change(34) + opReturn.
        let withChangeSize = sizeFor(nIn: nIn, nOut: payOutputs + 1) + opReturnLen
        let withChangeFee = Int64(withChangeSize) * feePerByte
        let change = sum - payAmount - withChangeFee
        if change > dustThresholdSats {
            return Plan(
                selected: cashes, change: change,
                fee: withChangeFee, estimatedSize: withChangeSize
            )
        }
        // Without change: the dust-or-less remainder burns as fee.
        // The recipient still receives exactly `payAmount`.
        let noChangeSize = sizeFor(nIn: nIn, nOut: payOutputs) + opReturnLen
        let noChangeFee = Int64(noChangeSize) * feePerByte
        if sum >= payAmount + noChangeFee {
            return Plan(
                selected: cashes, change: 0,
                fee: sum - payAmount, estimatedSize: noChangeSize
            )
        }
        throw Failure.insufficientFunds(needed: payAmount + noChangeFee, have: sum)
    }

    // MARK: - which cashes

    /// Choose the cashes to spend, before pricing: enough value for
    /// `payValue` plus `feeFor(inputCount)`, and at least `requiredCd`
    /// CoinDays, destroying as few CoinDays as it can.
    ///
    /// 1. **Required CoinDays first.** Take the smallest cash that
    ///    closes the gap on its own, or the largest when none does, and
    ///    look again — so the CoinDays destroyed overshoot the
    ///    requirement by little.
    /// 2. **Then the value, youngest first** — least CoinDays per
    ///    satoshi — and the larger cash first among equals. A cash worth
    ///    no more than the fee its own input adds is skipped.
    /// 3. **Then drop what the rest can do without**, most CoinDays
    ///    first: an early small pick is often made redundant by a later
    ///    one.
    ///
    /// Returns what it picked even when that falls short; the callers
    /// say which requirement wasn't met.
    static func pick(
        _ cashes: [Cash],
        payValue: Int64,
        requiredCd: Int64,
        feeFor: (Int) -> Int64
    ) -> [Cash] {
        func cd(_ i: Int) -> Int64 { cashes[i].cd ?? 0 }
        var remaining = cashes.indices.filter { cashes[$0].value > 0 }
        var picked: [Int] = []
        var value: Int64 = 0
        var cdSum: Int64 = 0

        if requiredCd > 0 {
            var withCd = remaining.filter { cd($0) > 0 }
                .sorted { cd($0) != cd($1) ? cd($0) < cd($1) : $0 < $1 }
            while cdSum < requiredCd, let largest = withCd.last {
                let gap = requiredCd - cdSum
                let choice = withCd.first { cd($0) >= gap } ?? largest
                withCd.removeAll { $0 == choice }
                remaining.removeAll { $0 == choice }
                picked.append(choice)
                value += cashes[choice].value
                cdSum += cd(choice)
            }
        }

        remaining.sort { a, b in
            let ageA = Double(cd(a)) / Double(cashes[a].value)
            let ageB = Double(cd(b)) / Double(cashes[b].value)
            if ageA != ageB { return ageA < ageB }
            if cashes[a].value != cashes[b].value { return cashes[a].value > cashes[b].value }
            return a < b
        }
        for i in remaining {
            if !picked.isEmpty, value >= payValue + feeFor(picked.count) { break }
            let addedFee = feeFor(picked.count + 1) - feeFor(picked.count)
            if cashes[i].value <= addedFee { continue }
            picked.append(i)
            value += cashes[i].value
            cdSum += cd(i)
        }

        let mostCdFirst = picked.sorted { cd($0) != cd($1) ? cd($0) > cd($1) : $0 < $1 }
        for i in mostCdFirst {
            guard picked.count > 1 else { break }
            let valueLeft = value - cashes[i].value
            let cdLeft = cdSum - cd(i)
            if valueLeft >= payValue + feeFor(picked.count - 1), cdLeft >= requiredCd {
                picked.removeAll { $0 == i }
                value = valueLeft
                cdSum = cdLeft
            }
        }
        return picked.map { cashes[$0] }
    }
}
