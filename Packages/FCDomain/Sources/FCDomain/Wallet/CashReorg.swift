import Foundation

/// Reorganize a chosen set of cashes into a chosen set of *bills* —
/// the Mac port of Android's `ReorgCashActivity`.
///
/// A reorg is a payment to yourself. Every input is a cash you already
/// own, every output is a cash you will own, and the only thing that
/// leaves is the miner fee. What it buys you is control over the
/// *shape* of your cash set, which ordinary sends never give you:
/// consolidating a hundred dust cashes into one so the next send fits
/// in a small tx, or splitting one large cash into equal bills so a
/// future payment doesn't have to reveal (and spend) the whole amount.
///
/// **Why this is not ``CoinSelector``.** Coin selection answers "which
/// cashes should fund this payment"; here the inputs are already
/// decided — the user ticked them — and the question is the inverse:
/// given these inputs, what outputs can they afford. Nothing is
/// selected and nothing may be dropped, so a planner that quietly
/// picked a subset would be building a different transaction from the
/// one the user asked for.
public enum CashReorg {

    /// Chain-side cap on the number of cashes one reorg may issue,
    /// change bill included. Mirrors Android's `MAX_NEW_CASH_COUNT`.
    public static let maxOutputs = 20

    /// Cap on inputs, mirroring Android's guard in `CashActivity`.
    /// A 200-input tx is already ~28 kB; past that the signing loop
    /// and the node's standardness rules both start to complain.
    public static let maxInputs = 200

    /// What the user asked for. The four cases are Android's four
    /// reorg strategies, and which one applies is decided by *which
    /// of the two fields they filled in* — count, denomination,
    /// both, or neither.
    public enum Shape: Equatable, Sendable {
        /// Neither field: everything collapses into one bill.
        case consolidate
        /// Count only: `n` bills of equal size (the last one carries
        /// the rounding remainder).
        case byCount(Int)
        /// Denomination only: as many `amount`-sized bills as the
        /// inputs afford, capped at ``maxOutputs`` − 1, plus change.
        case byAmount(Int64)
        /// Both: exactly `count` bills of `amount`, plus change.
        /// Fails rather than trimming — the user named a number.
        case exact(count: Int, amount: Int64)
    }

    /// A fully-priced reorg. ``outputs`` are satoshi values, all
    /// paying back to the owner, in the order the transaction will
    /// carry them; when ``hasChange`` the last one is the change
    /// bill. There is no separate `change` field because a reorg's
    /// change is not a leftover — it is one of the bills.
    public struct Plan: Equatable, Sendable {
        public var inputs: [Cash]
        public var outputs: [Int64]
        public var fee: Int64
        public var estimatedSize: Int
        /// True when the last output is a remainder rather than a
        /// bill the user asked for. Purely descriptive — the tx is
        /// identical either way.
        public var hasChange: Bool

        public init(
            inputs: [Cash],
            outputs: [Int64],
            fee: Int64,
            estimatedSize: Int,
            hasChange: Bool
        ) {
            self.inputs = inputs
            self.outputs = outputs
            self.fee = fee
            self.estimatedSize = estimatedSize
            self.hasChange = hasChange
        }

        public var totalIn: Int64 { inputs.reduce(0) { $0 + $1.value } }
        public var totalOut: Int64 { outputs.reduce(0, +) }
        public var totalCd: Int64 { inputs.reduce(0) { $0 + ($1.cd ?? 0) } }
    }

    public enum Failure: Error, CustomStringConvertible {
        case noInputs
        case tooManyInputs(Int)
        case tooManyOutputs(Int)
        case mixedOwners([String])
        case nonPositiveCount(Int)
        case nonPositiveAmount(Int64)
        case nonPositiveFeeRate(Int64)
        case insufficientFunds(needed: Int64, have: Int64)

        public var description: String {
            switch self {
            case .noInputs:
                return "CashReorg: no cashes selected"
            case .tooManyInputs(let n):
                return "CashReorg: \(n) inputs selected, at most \(CashReorg.maxInputs) can be spent in one transaction"
            case .tooManyOutputs(let n):
                return "CashReorg: \(n) new cashes requested, at most \(CashReorg.maxOutputs) (change included) can be issued in one transaction"
            case .mixedOwners(let owners):
                return "CashReorg: selected cashes have \(owners.count) different owners (\(owners.joined(separator: ", "))) — one transaction can only be signed by one key"
            case .nonPositiveCount(let n):
                return "CashReorg: count must be > 0, got \(n)"
            case .nonPositiveAmount(let n):
                return "CashReorg: amount must be > 0, got \(n) sat"
            case .nonPositiveFeeRate(let n):
                return "CashReorg: feePerByte must be > 0, got \(n)"
            case let .insufficientFunds(needed, have):
                return "CashReorg: the requested bills plus the fee come to \(needed) sat, the selected cashes only hold \(have) sat"
            }
        }
    }

    /// Price `shape` against `inputs`. Pure arithmetic — no network,
    /// no signing, no store writes — so the UI can call it on every
    /// keystroke to preview what a reorg would produce.
    public static func plan(
        inputs: [Cash],
        shape: Shape,
        feePerByte: Int64 = 1
    ) throws -> Plan {
        guard !inputs.isEmpty else { throw Failure.noInputs }
        guard inputs.count <= maxInputs else { throw Failure.tooManyInputs(inputs.count) }
        guard feePerByte > 0 else { throw Failure.nonPositiveFeeRate(feePerByte) }

        // One transaction is signed by one key. Two owners means two
        // keys, which is a different (multi-party) transaction and not
        // something this path can build.
        let owners = Set(inputs.map(\.owner))
        if owners.count > 1 { throw Failure.mixedOwners(owners.sorted()) }

        let total = inputs.reduce(Int64(0)) { $0 + $1.value }
        let nIn = inputs.count

        switch shape {
        case .consolidate:
            return try consolidate(inputs: inputs, total: total, nIn: nIn, feePerByte: feePerByte)

        case .byCount(let count):
            guard count > 0 else { throw Failure.nonPositiveCount(count) }
            guard count <= maxOutputs else { throw Failure.tooManyOutputs(count) }
            if count == 1 {
                return try consolidate(inputs: inputs, total: total, nIn: nIn, feePerByte: feePerByte)
            }
            // Equal bills, remainder folded into the last one. Fee is
            // sized for the full output count up front — output size
            // doesn't depend on the value, so this is exact rather
            // than an estimate.
            let size = CoinSelector.sizeFor(nIn: nIn, nOut: count)
            let fee = Int64(size) * feePerByte
            let available = total - fee
            let denomination = available / Int64(count)
            guard denomination > CoinSelector.dustThresholdSats else {
                throw Failure.insufficientFunds(
                    needed: (CoinSelector.dustThresholdSats + 1) * Int64(count) + fee,
                    have: total
                )
            }
            var outputs = Array(repeating: denomination, count: count - 1)
            outputs.append(available - denomination * Int64(count - 1))
            return Plan(
                inputs: inputs, outputs: outputs,
                fee: fee, estimatedSize: size, hasChange: true
            )

        case .byAmount(let amount):
            guard amount > 0 else { throw Failure.nonPositiveAmount(amount) }
            // As many bills as fit, but never so many that the change
            // bill would push the tx past the cap. Then shrink until
            // the fee fits too: each bill removed frees 34 bytes as
            // well as its own value, so the loop converges downward.
            var count = Int(min(total / amount, Int64(maxOutputs - 1)))
            while count > 0 {
                if let plan = close(
                    inputs: inputs, total: total, nIn: nIn,
                    bills: Array(repeating: amount, count: count),
                    feePerByte: feePerByte
                ) {
                    return plan
                }
                count -= 1
            }
            throw Failure.insufficientFunds(
                needed: amount + Int64(CoinSelector.sizeFor(nIn: nIn, nOut: 1)) * feePerByte,
                have: total
            )

        case let .exact(count, amount):
            guard count > 0 else { throw Failure.nonPositiveCount(count) }
            guard amount > 0 else { throw Failure.nonPositiveAmount(amount) }
            // +1 for the change bill: `exact` promises the user their
            // `count` bills, so the remainder needs a slot of its own.
            guard count + 1 <= maxOutputs else { throw Failure.tooManyOutputs(count + 1) }
            let bills = Array(repeating: amount, count: count)
            if let plan = close(
                inputs: inputs, total: total, nIn: nIn,
                bills: bills, feePerByte: feePerByte
            ) {
                return plan
            }
            let size = CoinSelector.sizeFor(nIn: nIn, nOut: count)
            throw Failure.insufficientFunds(
                needed: amount * Int64(count) + Int64(size) * feePerByte,
                have: total
            )
        }
    }

    // MARK: - internals

    /// One bill holding everything the inputs are worth, less the fee.
    private static func consolidate(
        inputs: [Cash],
        total: Int64,
        nIn: Int,
        feePerByte: Int64
    ) throws -> Plan {
        let size = CoinSelector.sizeFor(nIn: nIn, nOut: 1)
        let fee = Int64(size) * feePerByte
        let value = total - fee
        guard value > CoinSelector.dustThresholdSats else {
            throw Failure.insufficientFunds(
                needed: fee + CoinSelector.dustThresholdSats + 1, have: total
            )
        }
        return Plan(
            inputs: inputs, outputs: [value],
            fee: fee, estimatedSize: size, hasChange: false
        )
    }

    /// Try to close a plan around a fixed list of `bills`, adding a
    /// change bill when the remainder is worth its own output and
    /// burning it as extra fee when it is not. Returns nil when the
    /// inputs can't cover the bills plus the fee at all — the caller
    /// decides whether that means "try fewer bills" or "give up".
    private static func close(
        inputs: [Cash],
        total: Int64,
        nIn: Int,
        bills: [Int64],
        feePerByte: Int64
    ) -> Plan? {
        let billsTotal = bills.reduce(0, +)

        // With a change bill.
        let withChangeSize = CoinSelector.sizeFor(nIn: nIn, nOut: bills.count + 1)
        let withChangeFee = Int64(withChangeSize) * feePerByte
        let change = total - billsTotal - withChangeFee
        if change > CoinSelector.dustThresholdSats {
            return Plan(
                inputs: inputs, outputs: bills + [change],
                fee: withChangeFee, estimatedSize: withChangeSize, hasChange: true
            )
        }

        // Without: a dust remainder can't pay for the 34 bytes it
        // would need, so it goes to the miner instead. The user still
        // gets exactly the bills they asked for.
        let noChangeSize = CoinSelector.sizeFor(nIn: nIn, nOut: bills.count)
        let noChangeFee = Int64(noChangeSize) * feePerByte
        if total - billsTotal >= noChangeFee {
            return Plan(
                inputs: inputs, outputs: bills,
                fee: total - billsTotal, estimatedSize: noChangeSize, hasChange: false
            )
        }
        return nil
    }
}
