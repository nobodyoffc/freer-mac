import Foundation

/// BCH sighash — BIP-143 preimage construction with `SIGHASH_FORKID` (bit
/// `0x40`) always set. This is the replay-protected variant BCH/FCH
/// adopted at the 2017 fork; legacy pre-fork sighash is not supported
/// because FCH never uses it.
///
/// Currently implements **`SIGHASH_ALL | SIGHASH_FORKID` (0x41)** only.
/// `NONE`, `SINGLE`, and `ANYONECANPAY` variants zero-out parts of the
/// preimage and need case-specific logic; we add them when a caller
/// actually needs them.
///
/// Preimage layout (per BIP-143 + FORKID):
/// ```
///   1. nVersion                               4 bytes LE
///   2. hashPrevouts                          32 bytes
///   3. hashSequence                          32 bytes
///   4. outpoint being signed                 36 bytes (32 hash + 4 LE index)
///   5. scriptCode                            varInt || bytes
///   6. value of the spent output              8 bytes LE
///   7. nSequence of the input being signed    4 bytes LE
///   8. hashOutputs                           32 bytes
///   9. nLocktime                              4 bytes LE
///  10. sighashType (with FORKID set)          4 bytes LE
/// ```
public enum BchSighash {

    public static let sighashAll: UInt32 = 0x01
    public static let sighashForkId: UInt32 = 0x40

    /// The standard BCH spending hashType: `SIGHASH_ALL | SIGHASH_FORKID`.
    public static let allForkId: UInt32 = sighashAll | sighashForkId  // 0x41

    public enum Failure: Error, CustomStringConvertible {
        case inputIndexOutOfRange(got: Int, have: Int)
        case unsupportedHashType(UInt32)

        public var description: String {
            switch self {
            case let .inputIndexOutOfRange(got, have):
                return "BchSighash: input index \(got) out of range (tx has \(have) inputs)"
            case .unsupportedHashType(let type):
                return String(format: "BchSighash: only ALL|FORKID (0x41) supported; got 0x%x", type)
            }
        }
    }

    /// Build the BIP-143 + FORKID sighash preimage.
    public static func preimage(
        tx: Transaction,
        inputIndex: Int,
        scriptCode: Data,
        prevValueSats: UInt64,
        hashType: UInt32 = allForkId
    ) throws -> Data {
        guard hashType == allForkId else {
            throw Failure.unsupportedHashType(hashType)
        }
        guard (0..<tx.inputs.count).contains(inputIndex) else {
            throw Failure.inputIndexOutOfRange(got: inputIndex, have: tx.inputs.count)
        }

        var out = Data()

        // 1. version
        out.append(TxBytes.le(tx.version))

        // 2. hashPrevouts = dsha256( concat(outpoint serializations) )
        var prevouts = Data()
        for input in tx.inputs {
            prevouts.append(input.outpoint.prevTxHash)
            prevouts.append(TxBytes.le(input.outpoint.outIndex))
        }
        out.append(Hash.doubleSha256(prevouts))

        // 3. hashSequence = dsha256( concat(sequence LE bytes) )
        var sequences = Data()
        for input in tx.inputs {
            sequences.append(TxBytes.le(input.sequence))
        }
        out.append(Hash.doubleSha256(sequences))

        // 4. outpoint of the input being signed
        let signing = tx.inputs[inputIndex]
        out.append(signing.outpoint.prevTxHash)
        out.append(TxBytes.le(signing.outpoint.outIndex))

        // 5. scriptCode (length-prefixed)
        out.append(VarInt.encode(UInt64(scriptCode.count)))
        out.append(scriptCode)

        // 6. value of the spent output
        out.append(TxBytes.le(prevValueSats))

        // 7. nSequence of the input being signed
        out.append(TxBytes.le(signing.sequence))

        // 8. hashOutputs = dsha256( concat(output serializations) )
        var outputs = Data()
        for output in tx.outputs {
            outputs.append(TxBytes.le(output.value))
            outputs.append(VarInt.encode(UInt64(output.scriptPubKey.bytes.count)))
            outputs.append(output.scriptPubKey.bytes)
        }
        out.append(Hash.doubleSha256(outputs))

        // 9. locktime
        out.append(TxBytes.le(tx.locktime))

        // 10. hashType (4 bytes LE)
        out.append(TxBytes.le(hashType))

        return out
    }

    /// Compute the 32-byte sighash = `double-sha256(preimage)`.
    public static func sighash(
        tx: Transaction,
        inputIndex: Int,
        scriptCode: Data,
        prevValueSats: UInt64,
        hashType: UInt32 = allForkId
    ) throws -> Data {
        let pre = try preimage(
            tx: tx,
            inputIndex: inputIndex,
            scriptCode: scriptCode,
            prevValueSats: prevValueSats,
            hashType: hashType
        )
        return Hash.doubleSha256(pre)
    }
}
