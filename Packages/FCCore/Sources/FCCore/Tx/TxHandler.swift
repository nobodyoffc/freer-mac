import Foundation

/// End-to-end transaction signing helpers, built on top of the Phase 2.1–2.3
/// primitives.
///
/// Current scope: P2PKH input signing. Multisig / P2SH signing comes as
/// separate helpers when a caller needs them.
///
/// Coin selection and fee estimation live higher in the stack; they depend
/// on a live wallet and UTXO set, so they'll land in a domain package
/// rather than here.
public enum TxHandler {

    public enum Failure: Error, CustomStringConvertible {
        case inputIndexOutOfRange(got: Int, have: Int)

        public var description: String {
            switch self {
            case let .inputIndexOutOfRange(got, have):
                return "TxHandler: input index \(got) out of range (tx has \(have) inputs)"
            }
        }
    }

    /// Sign a P2PKH input of `tx` and return a new `Transaction` with the
    /// scriptSig filled in. The other inputs are unchanged.
    ///
    /// - Parameters:
    ///   - tx: The transaction being signed. Inputs other than `inputIndex`
    ///     must already have their final scriptSig (even if empty) because
    ///     BIP-143 sighash only reads `hashPrevouts`/`hashSequence`, which
    ///     don't include scriptSigs — but when multiple inputs are signed,
    ///     each signature is computed against the tx state *at signing time*
    ///     and callers should commit each signed input before signing the
    ///     next one.
    ///   - inputIndex: The input to sign.
    ///   - privateKey: The 32-byte raw private key that owns the UTXO.
    ///   - prevValueSats: The value (satoshis) of the UTXO being spent.
    ///   - hashType: Defaults to `BchSighash.allForkId` (`0x41`).
    public static func signP2pkhInput(
        tx: Transaction,
        inputIndex: Int,
        privateKey: Data,
        prevValueSats: UInt64,
        hashType: UInt32 = BchSighash.allForkId
    ) throws -> Transaction {
        guard (0..<tx.inputs.count).contains(inputIndex) else {
            throw Failure.inputIndexOutOfRange(got: inputIndex, have: tx.inputs.count)
        }

        let pubkey = try Secp256k1.publicKey(fromPrivateKey: privateKey)
        let pubkeyHash = Hash.hash160(pubkey)
        let scriptCode = try ScriptBuilder.p2pkhOutput(hash160: pubkeyHash).bytes

        let sighash = try BchSighash.sighash(
            tx: tx,
            inputIndex: inputIndex,
            scriptCode: scriptCode,
            prevValueSats: prevValueSats,
            hashType: hashType
        )
        let derSig = try Secp256k1.signSighash(privateKey: privateKey, sighash: sighash)
        let scriptSig = try ScriptBuilder.p2pkhInput(
            signatureDER: derSig,
            sighashFlag: UInt8(hashType & 0xFF),
            pubkey: pubkey
        )

        var newInputs = tx.inputs
        let old = newInputs[inputIndex]
        newInputs[inputIndex] = TxInput(
            outpoint: old.outpoint,
            scriptSig: scriptSig,
            sequence: old.sequence
        )
        return Transaction(
            version: tx.version,
            inputs: newInputs,
            outputs: tx.outputs,
            locktime: tx.locktime
        )
    }
}
