import Foundation
import FCCore

/// The cross-platform **unsigned transaction** document — the JSON a
/// watch-only wallet hands to a machine that holds the key. Mirrors
/// the Android `com.fc.fc_ajdk.core.fch.RawTxInfo` (ver "2"), which
/// `CreateTxActivity` imports (paste / QR) and signs, so a Mac export
/// must round-trip through `RawTxInfo.fromJson` unchanged.
///
/// Deliberately *not* built from ``Cash`` directly: `Cash` encodes
/// Mac-local bookkeeping (`localState`, `pendingSpend`) that must
/// never appear on the wire, and Android's `Cash.makeCashListForPay`
/// trims inputs to exactly the fields a signer needs. ``Slot`` is
/// that trimmed dialect for both inputs and outputs.
public struct RawTxInfo: Codable, Equatable, Sendable {

    public static let version2 = "2"

    /// One input or output in the Android `Cash` JSON dialect.
    /// Inputs carry `{birthTxId, birthIndex, value, cd, redeemScript,
    /// lockTime, owner}` (what `makeCashListForPay` keeps); outputs
    /// just `{owner, value}` plus an optional CLTV `lockTime`.
    public struct Slot: Codable, Equatable, Sendable {
        public var owner: String?
        public var value: Int64?
        public var birthTxId: String?
        public var birthIndex: Int?
        public var cd: Int64?
        public var redeemScript: String?
        public var lockTime: Int64?

        public init(
            owner: String? = nil,
            value: Int64? = nil,
            birthTxId: String? = nil,
            birthIndex: Int? = nil,
            cd: Int64? = nil,
            redeemScript: String? = nil,
            lockTime: Int64? = nil
        ) {
            self.owner = owner
            self.value = value
            self.birthTxId = birthTxId
            self.birthIndex = birthIndex
            self.cd = cd
            self.redeemScript = redeemScript
            self.lockTime = lockTime
        }

        /// Trim a spendable ``Cash`` down to the input fields —
        /// Android's `Cash.makeCashListForPay`.
        public static func input(from cash: Cash) -> Slot {
            Slot(
                owner: cash.owner,
                value: cash.value,
                birthTxId: cash.birthTxId,
                birthIndex: cash.birthIndex,
                cd: cash.cd,
                redeemScript: cash.redeemScript,
                lockTime: cash.lockTime
            )
        }

        public static func output(to fid: String, amount: Int64) -> Slot {
            Slot(owner: fid, value: amount)
        }

        /// A time-locked output. `owner` stays the address the user
        /// typed — the person being paid — while `redeemScript` carries
        /// the CLTV script the coins actually lock to. Android's
        /// `new Cash(fid, amount, lockTime)`.
        ///
        /// `multisig` is supplied when `fid` is a 3… multisig group, in
        /// which case the script is `<lockTime> CLTV DROP <m> …<n>
        /// CHECKMULTISIG` rather than a single-sig CLTV — the group
        /// still has to sign after the lock expires.
        public static func lockedOutput(
            to fid: String,
            amount: Int64,
            lockTime: Int64,
            multisig: Multisig? = nil
        ) throws -> Slot {
            let p2sh: P2sh
            if let multisig, let m = multisig.m, let n = multisig.n,
               let keys = multisig.pubkeys, !keys.isEmpty {
                p2sh = try P2sh(pubkeys: keys, m: m, n: n, lockTime: lockTime)
            } else {
                p2sh = try P2sh(fid: fid, lockTime: lockTime)
            }
            return Slot(
                owner: fid,
                value: amount,
                redeemScript: p2sh.redeemScriptHex,
                lockTime: lockTime
            )
        }

        /// The parsed P2SH shape of this slot, when it has one.
        public var p2sh: P2sh? {
            guard let redeemScript, !redeemScript.isEmpty else { return nil }
            return try? P2sh(redeemScriptHex: redeemScript)
        }
    }

    public var sender: String?
    /// Coins (F) per 1000 bytes — Android's unit. 1 sat/byte is
    /// 0.00001; see ``feeRate(satsPerByte:)``.
    public var feeRate: Double?
    public var inputs: [Slot]?
    public var outputs: [Slot]?
    public var opReturn: String?
    public var changeTo: String?
    public var lockTime: Int64?
    public var cd: Int64?
    public var cdd: Int64?
    public var ver: String?

    /// The multisig group that owns ``sender``, when the sender is a
    /// 3… address. Local only — Android keeps it inside `senderInfo`,
    /// which `toJson()` nulls out before export, so it never travels
    /// on the wire and is excluded from ``CodingKeys`` here for the
    /// same reason: a signer reconstructs it from its own records, and
    /// an exported document that carried it would leak the group's
    /// membership to anyone who saw the QR code.
    public var senderMultisig: Multisig? = nil

    /// Collected partial signatures: signer FID → one bare 64-byte
    /// Schnorr signature **per input**, hex, in input order.
    ///
    /// **This one does travel.** `senderMultisig` is stripped on export
    /// because it names the group; the signatures have to survive the
    /// trip or there is no point exporting at all, and Android's
    /// `RawTxInfo` likewise nulls `senderInfo` in `toJson()` while
    /// leaving `fidSigMap` a plain serialized field.
    ///
    /// Nothing is lost by dropping the group: every input carries its
    /// own `redeemScript`, and that script *is* the membership — the
    /// pubkeys, their order, and m-of-n all parse straight out of it.
    /// Recovering the group from the inputs is also safer than trusting
    /// a field beside them, because a document whose stated group
    /// disagrees with its inputs cannot arise.
    public var fidSigMap: [String: [String]]? = nil

    private enum CodingKeys: String, CodingKey {
        case sender, feeRate, inputs, outputs, opReturn, changeTo
        case lockTime, cd, cdd, ver, fidSigMap
    }

    public init(
        sender: String? = nil,
        feeRate: Double? = nil,
        inputs: [Slot]? = nil,
        outputs: [Slot]? = nil,
        opReturn: String? = nil,
        changeTo: String? = nil,
        lockTime: Int64? = nil,
        cd: Int64? = nil,
        cdd: Int64? = nil,
        ver: String? = RawTxInfo.version2,
        senderMultisig: Multisig? = nil,
        fidSigMap: [String: [String]]? = nil
    ) {
        self.sender = sender
        self.feeRate = feeRate
        self.inputs = inputs
        self.outputs = outputs
        self.opReturn = opReturn
        self.changeTo = changeTo
        self.lockTime = lockTime
        self.cd = cd
        self.cdd = cdd
        self.ver = ver
        self.senderMultisig = senderMultisig
        self.fidSigMap = fidSigMap
    }

    /// Sum of the input values, in satoshis.
    public var totalIn: Int64 { (inputs ?? []).reduce(0) { $0 + ($1.value ?? 0) } }

    /// Sum of the output values, in satoshis — excludes change, which
    /// does not exist until the transaction is assembled.
    public var totalOut: Int64 { (outputs ?? []).reduce(0) { $0 + ($1.value ?? 0) } }

    /// Coin-days the inputs carry.
    public var totalCd: Int64 { (inputs ?? []).reduce(0) { $0 + ($1.cd ?? 0) } }

    /// Convert the Mac-side sat/byte fee rate into Android's
    /// coins-per-1000-bytes: `TxHandler.calcFee` does
    /// `feeRateLong = feeRate / 1000 * COIN_TO_SATOSHI`, so the
    /// inverse is `satsPerByte * 1000 / 1e8`.
    public static func feeRate(satsPerByte: Int64) -> Double {
        Double(satsPerByte) * 1000.0 / 100_000_000.0
    }

    /// Pretty-printed JSON for export (Android's `toNiceJson`). Keys
    /// are sorted so repeated exports of the same tx are
    /// byte-identical — diffable and QR-stable.
    public func exportJson() throws -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        let data = try encoder.encode(self)
        return String(decoding: data, as: UTF8.self)
    }

    /// Decode an exported document (either platform's).
    public static func fromJson(_ json: String) throws -> RawTxInfo {
        try JSONDecoder().decode(RawTxInfo.self, from: Data(json.utf8))
    }
}

extension Cash {

    /// Rebuild a spendable ``Cash`` from a wire slot — for inputs that
    /// came from an imported document or were typed in by hand, where
    /// no cached row exists.
    ///
    /// The result is deliberately thin: it carries what the slot said
    /// and claims nothing else. `localState` is ``LocalState/unknown``
    /// because we have not seen this output confirmed ourselves, and
    /// treating an imported line as chain-verified is exactly the
    /// mistake that puts an already-spent input into a transaction.
    public init?(slot: RawTxInfo.Slot) {
        guard let birthTxId = slot.birthTxId, !birthTxId.isEmpty else { return nil }
        self.init(
            owner: slot.owner ?? "",
            value: slot.value ?? 0,
            birthTxId: birthTxId,
            birthIndex: slot.birthIndex ?? 0,
            redeemScript: slot.redeemScript,
            lockTime: slot.lockTime,
            cd: slot.cd,
            localState: .unknown
        )
    }
}
