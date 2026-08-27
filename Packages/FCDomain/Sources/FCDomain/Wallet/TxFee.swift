import Foundation
import FCCore

/// Transaction sizing and fee pricing for the advanced builder — the
/// port of Android's `TxHandler.calcFee` and the constants around it.
///
/// **Why this exists next to ``CoinSelector``.** `CoinSelector` prices
/// a P2PKH-only payment while it is still choosing coins, and its
/// `10 + 141·nIn + 34·nOut` formula is exactly right for that job. The
/// advanced path prices a transaction the user has already composed —
/// arbitrary inputs, P2SH outputs, a CLTV redeem-script manifest in
/// OP_RETURN — where the size depends on script shapes that only exist
/// once the outputs are known. Two callers, two questions; sharing one
/// formula would mean the wrong answer for one of them.
///
/// Every number here is chosen to agree with the Android client
/// byte-for-byte. A fee that disagrees produces a different change
/// amount, and a different change amount produces a different
/// transaction — so "close enough" is not a thing.
public enum TxFee {

    /// Android's `TxHandler.DEFAULT_FEE_RATE`: coins per 1000 bytes.
    /// 0.00001 F/kB is 1 sat/byte.
    public static let defaultFeeRate: Double = 0.00001

    public static let coinToSatoshi: Int64 = 100_000_000

    /// A P2PKH change output costs 34 bytes (8 value + 1 script length
    /// + 25 script); P2SH costs 32 (the script is 23). Android names
    /// these `CHANGE_OUTPUT_FEE` / `CHANGE_P2SH_OUTPUT_FEE` and treats
    /// them as *fees* because at 1 sat/byte the two are the same
    /// number — a coincidence this port preserves rather than relies on.
    public static let changeOutputBytes: Int64 = 34
    public static let changeP2shOutputBytes: Int64 = 32

    /// Below this, a change output is not worth creating and the
    /// remainder is left to the miner. Android's
    /// `Constants.DustInSatoshi` — note it is 1000, not the 546 that
    /// ``CoinSelector/dustThresholdSats`` uses for the simple path.
    public static let dustSatoshi: Int64 = 1000

    /// BCH-Schnorr P2PKH input, the same 141 bytes ``CoinSelector`` uses.
    public static let p2pkhInputBytes: Int64 = 141

    /// Base overhead: version(4) + input count(1) + output count(1) +
    /// locktime(4).
    public static let baseBytes: Int64 = 10

    public static let p2pkhOutputBytes: Int64 = 34
    public static let p2shOutputBytes: Int64 = 32

    /// Amounts the output form accepts, in coins — Android's
    /// `Constants.MIN_AMOUNT` / `MAX_AMOUNT`.
    public static let minAmountCoins: Double = 0.000001
    public static let maxAmountCoins: Double = 99_999_999

    /// Lock times at or above this are Unix timestamps; below, block
    /// heights. Consensus rule, not a policy choice.
    public static let lockTimeThreshold: Int64 = 500_000_000

    /// What ``calc(_:)`` worked out. `fee` is nil when the transaction
    /// cannot be priced at all — a multisig input whose group is
    /// unknown, or a redeem script that will not parse — which is a
    /// different thing from a fee of zero and must not be shown as one.
    public struct Result: Sendable {
        public let fee: Int64?
        /// The OP_RETURN bytes that will actually be written. When the
        /// transaction has P2SH outputs this is the redeem-script
        /// manifest, which **replaces** any text the user typed —
        /// there is only one OP_RETURN output to go around.
        public let opReturn: Data
        public let p2shOutputs: [P2sh]
        public let willHaveChange: Bool
        public let estimatedSize: Int64

        public init(
            fee: Int64?, opReturn: Data, p2shOutputs: [P2sh],
            willHaveChange: Bool, estimatedSize: Int64
        ) {
            self.fee = fee
            self.opReturn = opReturn
            self.p2shOutputs = p2shOutputs
            self.willHaveChange = willHaveChange
            self.estimatedSize = estimatedSize
        }

        static let unpriceable = Result(
            fee: nil, opReturn: Data(), p2shOutputs: [],
            willHaveChange: false, estimatedSize: 0
        )
    }

    /// Size in bytes of a change output paying `fid`.
    public static func changeOutputBytes(payingTo fid: String?) -> Int64 {
        guard let fid, FchAddress.isP2sh(fid: fid) else { return changeOutputBytes }
        return changeP2shOutputBytes
    }

    /// Whether a lock time has passed. Values below
    /// ``lockTimeThreshold`` are block heights, above are Unix seconds.
    public static func isLockTimeUnlocked(
        _ lockTime: Int64, bestHeight: Int64, now: Date = Date()
    ) -> Bool {
        if lockTime == 0 { return true }
        if lockTime < lockTimeThreshold { return bestHeight >= lockTime }
        return Int64(now.timeIntervalSince1970) >= lockTime
    }

    // MARK: - the calculation

    /// Price `info` exactly the way Android's `TxHandler.calcFee` does.
    ///
    /// The change output is the subtle part, and the reason this can't
    /// be a one-line formula: whether it exists depends on the fee,
    /// and the fee depends on whether it exists. The resolution is
    /// Android's — price without change first, see whether the
    /// remainder clears dust, re-price with change if it does, and
    /// fall back to the no-change price if adding the output would
    /// push the remainder back under.
    public static func calc(_ info: RawTxInfo) -> Result {
        let feeRate = (info.feeRate.map { $0 > 0 ? $0 : defaultFeeRate }) ?? defaultFeeRate
        let feeRateLong = Int64(feeRate / 1000 * Double(coinToSatoshi))

        guard let inputs = info.inputs, !inputs.isEmpty else { return .unpriceable }

        // --- outputs, and the redeem scripts they imply ---
        var opReturnBytes = info.opReturn.flatMap { $0.isEmpty ? nil : Data($0.utf8) } ?? Data()
        var p2shOutputs: [P2sh] = []
        var totalOutputSize: Int64 = 0
        var totalOutputValue: Int64 = 0

        for output in info.outputs ?? [] {
            totalOutputValue += output.value ?? 0
            if let redeemScript = output.redeemScript, !redeemScript.isEmpty {
                totalOutputSize += p2shOutputBytes
                guard let p2sh = try? P2sh(redeemScriptHex: redeemScript) else {
                    return .unpriceable
                }
                p2shOutputs.append(p2sh)
            } else if let owner = output.owner, FchAddress.isP2sh(fid: owner) {
                totalOutputSize += p2shOutputBytes
            } else {
                totalOutputSize += p2pkhOutputBytes
            }
        }

        // The redeem-script manifest wins the OP_RETURN slot. It has
        // to: without it on chain, the recipient of a time-locked
        // output has no way to reconstruct the script that unlocks it.
        if !p2shOutputs.isEmpty {
            guard let manifest = try? P2sh.opReturnPayload(for: p2shOutputs) else {
                return .unpriceable
            }
            opReturnBytes = Data(manifest.utf8)
        }

        let opReturnSize: Int64 = opReturnBytes.isEmpty ? 0 : opReturnLen(opReturnBytes.count)

        // --- inputs ---
        var totalInputSize: Int64 = 0
        var totalInputValue: Int64 = 0

        for input in inputs {
            totalInputValue += input.value ?? 0
            let isSpecial = info.senderMultisig != nil || input.lockTime != nil
            guard isSpecial else {
                totalInputSize += p2pkhInputBytes
                continue
            }
            if let redeemScript = input.redeemScript, !redeemScript.isEmpty {
                guard let p2sh = try? P2sh(redeemScriptHex: redeemScript) else {
                    return .unpriceable
                }
                totalInputSize += p2shInputSize(p2sh)
            } else if let multisig = info.senderMultisig,
                      let m = multisig.m, let n = multisig.n {
                // No redeem script stored, but we know the group — so
                // we can build the script we would sign with and
                // measure it.
                var redeemScriptLen: Int64 = 0
                if let lockTime = input.lockTime, lockTime > 0 {
                    guard let keys = multisig.pubkeys,
                          let built = try? P2sh(pubkeys: keys, m: m, n: n, lockTime: lockTime)
                    else { return .unpriceable }
                    redeemScriptLen = Int64(built.redeemScript.count)
                } else if let hex = multisig.redeemScript, let bytes = Hex.decodeOrNil(hex) {
                    redeemScriptLen = Int64(bytes.count)
                }
                totalInputSize += multisigInputSize(n: n, m: m, redeemScriptLen: redeemScriptLen)
            } else {
                return .unpriceable
            }
        }

        // --- change, and the fee that decides whether it exists ---
        let changeAddress = info.changeTo
            ?? info.sender
            ?? inputs.first?.owner
        let changeSize = changeOutputBytes(payingTo: changeAddress)

        let sizeWithoutChange = baseBytes + totalInputSize + totalOutputSize + opReturnSize
        let feeWithoutChange = feeRateLong * sizeWithoutChange
        let potentialChange = totalInputValue - totalOutputValue - feeWithoutChange

        if potentialChange > dustSatoshi {
            let sizeWithChange = sizeWithoutChange + changeSize
            let feeWithChange = feeRateLong * sizeWithChange
            if totalInputValue - totalOutputValue - feeWithChange > dustSatoshi {
                return Result(
                    fee: feeWithChange, opReturn: opReturnBytes, p2shOutputs: p2shOutputs,
                    willHaveChange: true, estimatedSize: sizeWithChange
                )
            }
        }
        return Result(
            fee: feeWithoutChange, opReturn: opReturnBytes, p2shOutputs: p2shOutputs,
            willHaveChange: false, estimatedSize: sizeWithoutChange
        )
    }

    // MARK: - size helpers

    /// Bytes an OP_RETURN output adds: 8 for the (always zero) value,
    /// plus the script and its length prefix.
    static func opReturnLen(_ dataLen: Int) -> Int64 {
        let pushed: Int
        if dataLen < 76 { pushed = dataLen + 1 }
        else if dataLen < 256 { pushed = dataLen + 2 }
        else { pushed = dataLen + 3 }
        let scriptLen = (pushed + 1) + varIntSize(Int64(pushed + 1))
        return Int64(scriptLen) + 8
    }

    /// `OP_0 <sig…> <redeemScript>` — the m-of-n scriptSig.
    /// `redeemScriptLen == 0` means "plain multisig, work it out".
    static func multisigInputSize(n: Int, m: Int, redeemScriptLen: Int64) -> Int64 {
        var scriptLen = redeemScriptLen
        if scriptLen <= 0 {
            // <m> + n·(1 length byte + 33 pubkey) + <n> + OP_CHECKMULTISIG
            scriptLen = 1 + Int64(n) * 34 + 1 + 1
        }
        let pushLen: Int64 = scriptLen < 76 ? 1 : (scriptLen < 256 ? 2 : 3)
        // OP_0, then m × (length + 64-byte Schnorr sig + sighash flag).
        let sigsLen = Int64(m) * (1 + 64 + 1)
        let scriptSigLen = 1 + sigsLen + pushLen + scriptLen
        return 32 + 4 + Int64(varIntSize(scriptSigLen)) + scriptSigLen + 4
    }

    /// `<sig||flag> <pubkey> <redeemScript>` — the single-sig P2SH
    /// scriptSig that ``FCCore/TxHandler/signP2shInput`` produces.
    static func singleSigP2shInputSize(redeemScriptLen: Int64) -> Int64 {
        let scriptSigLen = (1 + 64 + 1) + (1 + 33)
            + Int64(varIntSize(redeemScriptLen)) + redeemScriptLen
        return 32 + 4 + Int64(varIntSize(scriptSigLen)) + scriptSigLen + 4
    }

    static func p2shInputSize(_ p2sh: P2sh) -> Int64 {
        let len = Int64(p2sh.redeemScript.count)
        switch p2sh.kind {
        case .cltv:
            return singleSigP2shInputSize(redeemScriptLen: len)
        case .multisig, .multisigCltv:
            guard let m = p2sh.m, let n = p2sh.n else {
                return singleSigP2shInputSize(redeemScriptLen: len)
            }
            return multisigInputSize(n: n, m: m, redeemScriptLen: len)
        }
    }

    static func varIntSize(_ value: Int64) -> Int {
        VarInt.encode(UInt64(max(0, value))).count
    }
}
