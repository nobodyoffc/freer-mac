import Foundation
import FCCore

/// Everything a person needs to decide whether to sign — assembled
/// after coin selection and transaction assembly, handed to the
/// approval gate, and thrown away either way.
///
/// **Why a model and not just a dialog.** The moment worth checking is
/// *after* the wallet has picked the coins and priced the fee, because
/// until then the numbers don't exist: a pane can promise "0.01 F to
/// Bob", but only the built transaction knows which four cashes are
/// being consumed, what the miner takes, and what comes back as
/// change. Every signing path in the app funnels through the same
/// preview so that what the user approves is the transaction that gets
/// signed, not a summary of the intent behind it.
///
/// This is also the only place a **carve** becomes legible. A contact
/// edit, a mail, a proof, a chat key rotation — all of them are
/// OP_RETURN payloads that the panes describe in their own words; the
/// preview shows the bytes that will actually land on chain, and names
/// the FEIP protocol behind them when it recognises one.
public struct TxPreview: Sendable, Equatable {

    /// Which of the three signing paths built this.
    public enum Kind: String, Sendable {
        /// A payment to someone else (``WalletService/send``).
        case payment
        /// An OP_RETURN data write, with or without a payment attached
        /// (``WalletService/carve``).
        case carve
        /// Paying yourself to change denominations
        /// (``WalletService/reorganize``).
        case reorg
    }

    /// One output as it will appear in the transaction.
    public struct Output: Sendable, Equatable {
        /// Recipient address. Nil for the OP_RETURN output, which pays
        /// nobody.
        public let fid: String?
        public let amount: Int64
        /// True when this output pays the sender — change, or a reorg
        /// bill. Worth marking because "0.5 F to F…xyz" reads as money
        /// leaving until you notice F…xyz is you.
        public let isSelf: Bool
        public let isOpReturn: Bool

        public init(fid: String?, amount: Int64, isSelf: Bool, isOpReturn: Bool = false) {
            self.fid = fid
            self.amount = amount
            self.isSelf = isSelf
            self.isOpReturn = isOpReturn
        }
    }

    public let kind: Kind
    public let from: String
    public let inputs: [Cash]
    public let outputs: [Output]
    public let fee: Int64
    public let estimatedSize: Int
    public let feePerByte: Int64
    /// The OP_RETURN payload, as text, when there is one.
    public let opReturn: String?

    public init(
        kind: Kind,
        from: String,
        inputs: [Cash],
        outputs: [Output],
        fee: Int64,
        estimatedSize: Int,
        feePerByte: Int64,
        opReturn: String? = nil
    ) {
        self.kind = kind
        self.from = from
        self.inputs = inputs
        self.outputs = outputs
        self.fee = fee
        self.estimatedSize = estimatedSize
        self.feePerByte = feePerByte
        self.opReturn = opReturn
    }

    public var totalIn: Int64 { inputs.reduce(0) { $0 + $1.value } }
    public var totalOut: Int64 { outputs.reduce(0) { $0 + $1.amount } }

    /// What actually leaves this identity: everything paid to someone
    /// else, plus the fee. The number a person means when they ask
    /// "how much is this costing me?" — change is not a cost, and a
    /// reorg's whole output set is change in that sense.
    public var leaving: Int64 {
        outputs.filter { !$0.isSelf && !$0.isOpReturn }.reduce(0) { $0 + $1.amount } + fee
    }

    /// Outputs paying someone else — the recipients.
    public var payments: [Output] { outputs.filter { !$0.isSelf && !$0.isOpReturn } }

    /// Coin-days this transaction destroys. FEIP carves have a floor
    /// on this, so it belongs in the preview: it is the one cost of a
    /// carve that isn't denominated in money.
    public var coinDaysDestroyed: Int64 { inputs.reduce(0) { $0 + ($1.cd ?? 0) } }

    /// Deepest unconfirmed ancestry among the inputs. Zero means every
    /// input is confirmed; anything else means this transaction is
    /// riding on one of ours that hasn't landed yet, and will vanish
    /// with it if that one is ever dropped.
    public var unconfirmedDepth: Int { inputs.map(\.unconfirmedDepth).max() ?? 0 }

    /// True when at least one input is still unconfirmed.
    public var spendsUnconfirmed: Bool { unconfirmedDepth > 0 }

    /// The redeem scripts a time-locked transaction publishes, when
    /// the payload is that manifest rather than a message.
    ///
    /// Worth recognising in the approval dialog because the raw form
    /// is a JSON array of script hex — true, verbatim, and no help at
    /// all to someone deciding whether to sign. What a person needs to
    /// know is that these are the scripts their payees will need in
    /// order to spend what they were just paid, and until which block
    /// they cannot.
    ///
    /// Empty unless *every* entry parses, so a message that merely
    /// happens to be a JSON array is never mistaken for a manifest.
    public var payloadRedeemScripts: [P2sh] {
        guard let opReturn,
              opReturn.trimmingCharacters(in: .whitespacesAndNewlines).hasPrefix("["),
              let data = opReturn.data(using: .utf8),
              let list = try? JSONSerialization.jsonObject(with: data) as? [String],
              !list.isEmpty
        else { return [] }
        let parsed = list.compactMap { try? P2sh(redeemScriptHex: $0) }
        return parsed.count == list.count ? parsed : []
    }

    /// Size of the payload **in bytes**, which is the number that
    /// matters: OP_RETURN is capped in bytes and charged in bytes, and
    /// a character count disagrees with both the moment the message
    /// stops being ASCII.
    public var opReturnByteCount: Int { opReturn?.utf8.count ?? 0 }

    /// The FEIP protocol this carve writes, when the payload announces
    /// one. Parses `{"type":"FEIP","sn":"1",…}` — the envelope every
    /// carve in this app produces — and resolves the serial number
    /// through ``FeipProtocol``. Nil for a payment, or for a payload
    /// that isn't a FEIP envelope.
    public var feipName: String? {
        guard let opReturn,
              let data = opReturn.data(using: .utf8),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else { return nil }
        let sn = (obj["sn"] as? String) ?? (obj["sn"] as? NSNumber)?.stringValue
        return FeipProtocol.displayName(forSn: sn)
    }
}

/// The approval gate. Returns `true` to sign, `false` to abort.
///
/// `async` because the only honest implementation asks a human, and
/// people are slow. Nothing is signed and nothing is broadcast until
/// this returns, so an implementation that never answers stalls the
/// send — which is the correct failure mode for a question about
/// spending money.
public typealias TxApprover = @Sendable (TxPreview) async -> Bool
