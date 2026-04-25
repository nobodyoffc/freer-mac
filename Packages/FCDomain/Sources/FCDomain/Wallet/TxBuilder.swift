import Foundation
import FCCore

/// Assemble an unsigned ``Transaction`` from a ``CoinSelector/Plan``.
/// The result has empty `scriptSig`s; ``WalletService`` runs each
/// input through ``FCCore.TxHandler/signP2pkhInput`` afterward.
///
/// **Byte-order trap:** ``Utxo/txid`` is the *display* hex of a
/// transaction — the byte-reversal of the natural order that lives
/// in `OutPoint.prevTxHash`. ``decodeTxid`` does the reverse for us;
/// callers should never construct an OutPoint by hex-decoding a txid
/// string directly.
public enum TxBuilder {

    public enum Failure: Error, CustomStringConvertible {
        case invalidTxid(String)
        case invalidFid(String, underlying: Error)

        public var description: String {
            switch self {
            case .invalidTxid(let s):
                return "TxBuilder: invalid txid hex '\(s)'"
            case let .invalidFid(s, e):
                return "TxBuilder: invalid FID '\(s)' — \(e)"
            }
        }
    }

    /// Default to BIP-68 final sequence — non-coinbase, non-RBF.
    /// freecashj uses 0xFFFFFFFF unconditionally.
    public static let defaultSequence: UInt32 = 0xFFFFFFFF

    /// Default to tx version 2 (post-BIP-68). Bitcoin Cash and
    /// freecashj have used version=2 since the 2017 fork.
    public static let defaultVersion: UInt32 = 2

    public static func buildUnsigned(
        plan: CoinSelector.Plan,
        toFid: String,
        amount: Int64,
        changeFid: String
    ) throws -> Transaction {
        let inputs: [TxInput] = try plan.selected.map { utxo in
            let prevTxHash = try decodeTxid(utxo.txid)
            let outpoint = try OutPoint(
                prevTxHash: prevTxHash,
                outIndex: UInt32(utxo.index)
            )
            return TxInput(
                outpoint: outpoint,
                scriptSig: Script(Data()),    // empty until signed
                sequence: defaultSequence
            )
        }

        var outputs: [TxOutput] = []
        let recipientHash160 = try hash160(forFid: toFid)
        outputs.append(TxOutput(
            value: UInt64(amount),
            scriptPubKey: try ScriptBuilder.p2pkhOutput(hash160: recipientHash160)
        ))
        if plan.hasChange {
            let changeHash160 = try hash160(forFid: changeFid)
            outputs.append(TxOutput(
                value: UInt64(plan.change),
                scriptPubKey: try ScriptBuilder.p2pkhOutput(hash160: changeHash160)
            ))
        }

        return Transaction(
            version: defaultVersion,
            inputs: inputs,
            outputs: outputs,
            locktime: 0
        )
    }

    /// Decode a display-order txid hex string to the 32-byte natural
    /// order required by ``OutPoint``. Same operation as
    /// `Utils.HEX.decode(txid).reversed()` in bitcoinj.
    public static func decodeTxid(_ hexDisplay: String) throws -> Data {
        guard hexDisplay.count == 64 else { throw Failure.invalidTxid(hexDisplay) }
        var raw = Data(capacity: 32)
        var idx = hexDisplay.startIndex
        while idx < hexDisplay.endIndex {
            let next = hexDisplay.index(idx, offsetBy: 2)
            guard let byte = UInt8(hexDisplay[idx..<next], radix: 16) else {
                throw Failure.invalidTxid(hexDisplay)
            }
            raw.append(byte)
            idx = next
        }
        return Data(raw.reversed())
    }

    private static func hash160(forFid fid: String) throws -> Data {
        do {
            return try FchAddress(fid: fid).hash160
        } catch {
            throw Failure.invalidFid(fid, underlying: error)
        }
    }
}
