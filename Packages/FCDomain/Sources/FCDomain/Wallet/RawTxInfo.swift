import Foundation

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
        ver: String? = RawTxInfo.version2
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
    }

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
