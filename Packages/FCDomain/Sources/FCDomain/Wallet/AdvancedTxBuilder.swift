import Foundation
import FCCore

/// Assemble an arbitrary composed transaction — the port of Android's
/// `TxHandler.createTx(RawTxInfo)`.
///
/// ``TxBuilder`` builds the three shapes the app generates on its own
/// (payment, carve, reorg) from a coin-selection plan. This one builds
/// whatever the user composed: inputs they picked, outputs that may be
/// P2PKH or P2SH, a time lock per output, an OP_RETURN. It takes a
/// ``RawTxInfo`` rather than a plan because that document *is* the
/// composition — the same one Android imports and exports.
///
/// Output order is fixed and matters, because both clients must
/// produce the same bytes from the same document: **payments, then
/// change, then OP_RETURN.**
public enum AdvancedTxBuilder {

    public enum Failure: Error, CustomStringConvertible {
        case noInputs
        case noChangeAddress
        case unpriceable
        case insufficientFunds(have: Int64, need: Int64)
        case invalidTxid(String)
        case invalidOutput(String)
        case senderMismatch(sender: String, multisig: String)
        case lockedInput(id: String, lockTime: Int64, bestHeight: Int64)

        public var description: String {
            switch self {
            case .noInputs:
                return "Transaction: no inputs — nothing to spend"
            case .noChangeAddress:
                return "Transaction: no change address, and no sender or input owner to fall back on"
            case .unpriceable:
                return "Transaction: the fee cannot be worked out — an input's redeem script is missing or unparsable"
            case let .insufficientFunds(have, need):
                return "Transaction: inputs total \(have) sat but outputs plus fee need \(need) sat"
            case .invalidTxid(let s):
                return "Transaction: invalid txid '\(s)'"
            case .invalidOutput(let why):
                return "Transaction: bad output — \(why)"
            case let .senderMismatch(sender, multisig):
                return "Transaction: sender \(sender) is not the multisig group \(multisig)"
            case let .lockedInput(id, lockTime, bestHeight):
                return "Transaction: input \(id) stays locked until block \(lockTime); the chain is at \(bestHeight)"
            }
        }
    }

    /// A built transaction and the numbers behind it, so the caller can
    /// show a preview without pricing it a second time.
    public struct Built: Sendable {
        public let transaction: Transaction
        public let fee: Int64
        public let change: Int64
        public let changeTo: String?
        public let estimatedSize: Int64
        /// The OP_RETURN as written — may be the redeem-script
        /// manifest rather than the user's text. See ``TxFee/Result``.
        public let opReturn: Data
        public let inputs: [Cash]

        public var hasChange: Bool { change > 0 }
    }

    /// Build the unsigned transaction `info` describes.
    ///
    /// `info` is taken by value and the resolved `changeTo` / `lockTime`
    /// are returned on ``Built`` rather than written back, so a caller
    /// can price a speculative variant without disturbing the document
    /// the user is editing.
    public static func build(_ info: RawTxInfo, inputCashes: [Cash]) throws -> Built {
        guard let slots = info.inputs, !slots.isEmpty else { throw Failure.noInputs }

        guard let changeTo = info.changeTo ?? info.sender ?? slots.first?.owner else {
            throw Failure.noChangeAddress
        }
        if let multisig = info.senderMultisig,
           let sender = info.sender,
           let groupFid = multisigAddress(multisig),
           sender != groupFid {
            throw Failure.senderMismatch(sender: sender, multisig: groupFid)
        }

        let priced = TxFee.calc(info)
        guard let fee = priced.fee else { throw Failure.unpriceable }

        // Spending a CLTV output requires the transaction's own
        // locktime to be at or past the lock, and the input's sequence
        // to be non-final so the locktime is consulted at all. Miss
        // either and the script fails; miss the second silently.
        let maxInputLockTime = slots.compactMap(\.lockTime).max() ?? 0

        var txInputs: [TxInput] = []
        var totalIn: Int64 = 0
        for slot in slots {
            guard let txid = slot.birthTxId else { throw Failure.invalidTxid("(missing)") }
            let prevTxHash: Data
            do { prevTxHash = try TxBuilder.decodeTxid(txid) }
            catch { throw Failure.invalidTxid(txid) }
            let outpoint = try OutPoint(
                prevTxHash: prevTxHash, outIndex: UInt32(slot.birthIndex ?? 0)
            )
            let sequence: UInt32 = (slot.lockTime ?? 0) > 0
                ? 0xFFFF_FFFE
                : TxBuilder.defaultSequence
            txInputs.append(TxInput(
                outpoint: outpoint, scriptSig: Script(Data()), sequence: sequence
            ))
            totalIn += slot.value ?? 0
        }

        var txOutputs: [TxOutput] = []
        var totalOut: Int64 = 0
        for slot in info.outputs ?? [] {
            let value = slot.value ?? 0
            totalOut += value
            if let redeemScript = slot.redeemScript, !redeemScript.isEmpty {
                guard let bytes = Hex.decodeOrNil(redeemScript) else {
                    throw Failure.invalidOutput("redeem script is not hex")
                }
                txOutputs.append(TxOutput(
                    value: UInt64(value),
                    scriptPubKey: try ScriptBuilder.p2shOutput(scriptHash: Hash.hash160(bytes))
                ))
            } else {
                guard let owner = slot.owner else {
                    throw Failure.invalidOutput("output has no address")
                }
                txOutputs.append(TxOutput(
                    value: UInt64(value),
                    scriptPubKey: try outputScript(for: owner)
                ))
            }
        }

        guard totalIn >= totalOut + fee else {
            throw Failure.insufficientFunds(have: totalIn, need: totalOut + fee)
        }

        // Change is always a plain payment back to `changeTo`, never
        // time-locked — even in a CLTV transaction. Locking your own
        // change would freeze the rest of the wallet along with the
        // gift.
        //
        // **Whether it exists is the pricer's decision, not a second
        // dust test here.** Android asks twice — `calcFee` decides,
        // then `createTx` re-checks `change > dust` — and the two
        // disagree in a window one change-output wide: a remainder
        // that clears dust before the output is priced but not after
        // gets priced as if there were no change and then given one
        // anyway. The transaction that comes out is 34 bytes larger
        // than the fee paid for, which at the default rate is below
        // the relay minimum and gets dropped. Deferring to
        // `willHaveChange` keeps fee and shape in agreement, at the
        // cost of differing from Android in exactly the window where
        // Android builds a transaction the network refuses.
        let change = priced.willHaveChange ? totalIn - totalOut - fee : 0
        if change > 0 {
            txOutputs.append(TxOutput(
                value: UInt64(change), scriptPubKey: try outputScript(for: changeTo)
            ))
        }

        if !priced.opReturn.isEmpty {
            txOutputs.append(TxOutput(
                value: 0, scriptPubKey: ScriptBuilder.opReturnOutput(data: priced.opReturn)
            ))
        }

        let tx = Transaction(
            version: TxBuilder.defaultVersion,
            inputs: txInputs,
            outputs: txOutputs,
            locktime: maxInputLockTime > 0 ? UInt32(truncatingIfNeeded: maxInputLockTime) : 0
        )

        return Built(
            transaction: tx,
            fee: fee,
            change: change,
            changeTo: change > 0 ? changeTo : nil,
            estimatedSize: priced.estimatedSize,
            opReturn: priced.opReturn,
            inputs: inputCashes
        )
    }

    /// Sign every input of a built transaction with one key, choosing
    /// the P2PKH or single-sig-P2SH path per input from whether the
    /// slot carries a redeem script.
    ///
    /// Multisig inputs are **not** signed here: they need one partial
    /// signature per member and a merge step, which is a different
    /// flow with a different UI. They are rejected rather than signed
    /// wrongly.
    public static func signAll(
        _ tx: Transaction,
        slots: [RawTxInfo.Slot],
        privkey: Data
    ) throws -> Transaction {
        var signed = tx
        for (i, slot) in slots.enumerated() {
            let value = UInt64(slot.value ?? 0)
            if let redeemScript = slot.redeemScript, !redeemScript.isEmpty {
                guard let bytes = Hex.decodeOrNil(redeemScript) else {
                    throw Failure.invalidOutput("input \(i): redeem script is not hex")
                }
                let kind = (try? P2sh(redeemScript: bytes))?.kind
                guard kind == .cltv else {
                    throw WalletService.Failure.unsupportedCashType(
                        "input \(i) is \(kind?.rawValue ?? "an unknown P2SH kind") — multisig inputs need every member's signature, which this path cannot collect"
                    )
                }
                signed = try TxHandler.signP2shInput(
                    tx: signed, inputIndex: i, privateKey: privkey,
                    prevValueSats: value, redeemScript: bytes
                )
            } else {
                signed = try TxHandler.signP2pkhInput(
                    tx: signed, inputIndex: i, privateKey: privkey, prevValueSats: value
                )
            }
        }
        return signed
    }

    /// Every input must be spendable *now*: a CLTV input included
    /// before its lock expires makes the whole transaction invalid,
    /// and the node's rejection message says nothing about which one.
    public static func requireUnlocked(_ slots: [RawTxInfo.Slot], bestHeight: Int64) throws {
        guard bestHeight > 0 else { return }
        for slot in slots {
            guard let lockTime = slot.lockTime, lockTime > 0 else { continue }
            guard TxFee.isLockTimeUnlocked(lockTime, bestHeight: bestHeight) else {
                throw Failure.lockedInput(
                    id: "\(slot.birthTxId ?? "?"):\(slot.birthIndex ?? 0)",
                    lockTime: lockTime,
                    bestHeight: bestHeight
                )
            }
        }
    }

    /// Fill in the redeem script a CLTV input needs in order to be
    /// signed. The chain stores it in the funding transaction's
    /// OP_RETURN, but an imported document may carry only the lock
    /// time — in which case it is reconstructible, because the script
    /// is a function of the owner and the lock. Android does the same
    /// repair in `goodTxInfo`.
    public static func fillMissingRedeemScripts(_ slots: [RawTxInfo.Slot]) -> [RawTxInfo.Slot] {
        slots.map { slot in
            guard slot.redeemScript == nil || slot.redeemScript?.isEmpty == true,
                  let lockTime = slot.lockTime, lockTime > 0,
                  let owner = slot.owner, !FchAddress.isP2sh(fid: owner),
                  let p2sh = try? P2sh(fid: owner, lockTime: lockTime)
            else { return slot }
            var repaired = slot
            repaired.redeemScript = p2sh.redeemScriptHex
            return repaired
        }
    }

    // MARK: - helpers

    static func outputScript(for fid: String) throws -> Script {
        let address = try FchAddress(fid: fid, expectedVersionByte: nil)
        return address.isP2sh
            ? try ScriptBuilder.p2shOutput(scriptHash: address.hash160)
            : try ScriptBuilder.p2pkhOutput(hash160: address.hash160)
    }

    static func multisigAddress(_ multisig: Multisig) -> String? {
        if let hex = multisig.redeemScript, let bytes = Hex.decodeOrNil(hex) {
            return try? FchAddress(
                versionByte: FchAddress.p2shVersionByte, hash160: Hash.hash160(bytes)
            ).fid
        }
        guard let keys = multisig.pubkeys, let m = multisig.m, let n = multisig.n,
              let p2sh = try? P2sh(pubkeys: keys, m: m, n: n, lockTime: nil)
        else { return nil }
        return p2sh.address
    }
}
