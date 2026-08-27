import Foundation

/// End-to-end transaction signing helpers, built on top of the Phase 2.1–2.3
/// primitives.
///
/// Current scope: P2PKH input signing using **BCH 2019 Schnorr** (the
/// pre-BIP-340 variant). FCH mainnet rejects ECDSA-DER signatures on
/// P2PKH spends with a confusing `Signature cannot be 65 bytes in
/// CHECKMULTISIG` script-verify error — Schnorr is the only path the
/// chain accepts. The 64-byte signature plus 1-byte sighash flag (0x41)
/// is exactly 65 bytes, which matches Android freecashj's behaviour.
///
/// Single-sig P2SH signing is
/// ``signP2shInput(tx:inputIndex:privateKey:prevValueSats:redeemScript:hashType:)``;
/// m-of-n multisig is the three-step
/// ``signMultisigInput(tx:inputIndex:privateKey:prevValueSats:redeemScript:hashType:)``
/// → ``multisigInputScript(signatures:redeemScript:sighashFlag:)`` →
/// ``applyingScriptSig(_:to:at:)``, because the signatures come from
/// different people at different times.
///
/// Coin selection and fee estimation live higher in the stack; they depend
/// on a live wallet and UTXO set, so they'll land in a domain package
/// rather than here.
public enum TxHandler {

    public enum Failure: Error, CustomStringConvertible {
        case inputIndexOutOfRange(got: Int, have: Int)
        case tooManySignatures(got: Int)

        public var description: String {
            switch self {
            case let .inputIndexOutOfRange(got, have):
                return "TxHandler: input index \(got) out of range (tx has \(have) inputs)"
            case let .tooManySignatures(got):
                return "TxHandler: \(got) signatures will not fit a CHECKMULTISIG scriptSig (max 15)"
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
        let schnorrSig = try BchSchnorr.sign(message: sighash, privateKey: privateKey)
        let scriptSig = try ScriptBuilder.p2pkhInput(
            signature: schnorrSig,
            sighashFlag: UInt8(hashType & 0xFF),
            pubkey: pubkey
        )

        return TxHandler.replacingScriptSig(in: tx, at: inputIndex, with: scriptSig)
    }

    /// Sign a **single-sig P2SH** input — a CLTV output, or any other
    /// redeem script whose body ends in `OP_CHECKSIG` against one key.
    ///
    /// The scriptSig is `<sig||flag> <pubkey> <redeemScript>`, and the
    /// sighash is computed over the *redeem script*, not the output
    /// script: P2SH hides the real conditions behind a hash, so the
    /// script being committed to is the one being revealed.
    ///
    /// Two things the caller still owns, because they belong to the
    /// transaction rather than to one input:
    ///
    /// - `tx.locktime` must be ≥ the CLTV value, or `OP_CHECKLOCKTIMEVERIFY`
    ///   fails.
    /// - the input's `sequence` must be < `0xFFFFFFFF`, or the lock
    ///   time is not even consulted.
    ///
    /// ``TxHandler`` cannot enforce either without rewriting a
    /// transaction the caller already priced, so
    /// `AdvancedTxBuilder` sets both while assembling.
    public static func signP2shInput(
        tx: Transaction,
        inputIndex: Int,
        privateKey: Data,
        prevValueSats: UInt64,
        redeemScript: Data,
        hashType: UInt32 = BchSighash.allForkId
    ) throws -> Transaction {
        guard (0..<tx.inputs.count).contains(inputIndex) else {
            throw Failure.inputIndexOutOfRange(got: inputIndex, have: tx.inputs.count)
        }

        let pubkey = try Secp256k1.publicKey(fromPrivateKey: privateKey)
        let sighash = try BchSighash.sighash(
            tx: tx,
            inputIndex: inputIndex,
            scriptCode: redeemScript,
            prevValueSats: prevValueSats,
            hashType: hashType
        )
        let schnorrSig = try BchSchnorr.sign(message: sighash, privateKey: privateKey)

        var sigPlusFlag = Data(schnorrSig)
        sigPlusFlag.append(UInt8(hashType & 0xFF))

        var s = Data()
        s.append(ScriptBuilder.pushData(sigPlusFlag))
        s.append(ScriptBuilder.pushData(pubkey))
        s.append(ScriptBuilder.pushData(redeemScript))

        return TxHandler.replacingScriptSig(in: tx, at: inputIndex, with: Script(s))
    }

    // MARK: - multisig P2SH

    /// Sign one **multisig P2SH** input as a single member, returning
    /// the bare 64-byte Schnorr signature.
    ///
    /// **No sighash flag is appended.** The flag belongs to the
    /// assembled script, not to the stored signature —
    /// ``multisigInputScript(signatures:redeemScript:sighashFlag:)``
    /// adds it. Keeping it off here is what makes a partial signature
    /// safe to pass between signers as 64 bytes of hex, and it matches
    /// `TxHandler.signSchnorrMultiSignTx`, which stores raw sigs in its
    /// `fidSigMap` and merges the `0x41` only at build time.
    ///
    /// The sighash is taken over the **redeem script**, exactly as in
    /// ``signP2shInput(tx:inputIndex:privateKey:prevValueSats:redeemScript:hashType:)``:
    /// P2SH commits to the script being revealed, not to the output
    /// script that hides it. For a CLTV multisig the redeem script is
    /// the full time-locked one, prefix included — signing the bare
    /// multisig body instead produces a signature that verifies against
    /// nothing.
    ///
    /// Each member signs *every* input, so callers loop this over the
    /// inputs and keep the results in input order. A signature is
    /// bound to the transaction it was made against; changing a single
    /// output invalidates every signature already collected.
    public static func signMultisigInput(
        tx: Transaction,
        inputIndex: Int,
        privateKey: Data,
        prevValueSats: UInt64,
        redeemScript: Data,
        hashType: UInt32 = BchSighash.allForkId
    ) throws -> Data {
        guard (0..<tx.inputs.count).contains(inputIndex) else {
            throw Failure.inputIndexOutOfRange(got: inputIndex, have: tx.inputs.count)
        }
        let sighash = try BchSighash.sighash(
            tx: tx,
            inputIndex: inputIndex,
            scriptCode: redeemScript,
            prevValueSats: prevValueSats,
            hashType: hashType
        )
        return try BchSchnorr.sign(message: sighash, privateKey: privateKey)
    }

    /// Check one member's partial signature before trusting it — the
    /// port of `TxHandler.rawTxSigVerify`.
    ///
    /// Worth doing on every signature that arrives from somewhere else.
    /// A merge that accepts a bad signature produces a transaction the
    /// network rejects with a script error naming no member, and the
    /// group then has to guess which of them sent it.
    public static func verifyMultisigInput(
        tx: Transaction,
        inputIndex: Int,
        publicKey: Data,
        signature: Data,
        prevValueSats: UInt64,
        redeemScript: Data,
        hashType: UInt32 = BchSighash.allForkId
    ) throws -> Bool {
        guard (0..<tx.inputs.count).contains(inputIndex) else {
            throw Failure.inputIndexOutOfRange(got: inputIndex, have: tx.inputs.count)
        }
        let sighash = try BchSighash.sighash(
            tx: tx,
            inputIndex: inputIndex,
            scriptCode: redeemScript,
            prevValueSats: prevValueSats,
            hashType: hashType
        )
        return try BchSchnorr.verify(
            message: sighash, publicKey: publicKey, signature: signature
        )
    }

    /// Assemble a multisig scriptSig: `OP_0 <sig‖flag>… <redeemScript>`.
    ///
    /// **Two things here are FCH-specific and both look wrong if you
    /// come from Bitcoin or from modern BCH.**
    ///
    /// 1. *The leading `OP_0` is the classic `CHECKMULTISIG` off-by-one
    ///    dummy*, and it stays a null push. BCH replaced that dummy
    ///    with a "checkbits" bitfield when it allowed Schnorr into
    ///    `CHECKMULTISIG`, so on BCH a Schnorr multisig spend with a
    ///    null dummy is invalid. FCH did not follow: its nodes accept —
    ///    and `FC-AJDK` produces — Schnorr signatures under the legacy
    ///    null dummy. That combination is what this builds, because it
    ///    is what the chain takes.
    /// 2. *Signature order is pubkey order, not signer order.*
    ///    `OP_CHECKMULTISIG` walks signatures and pubkeys together in
    ///    one pass, so a signature that appears before the pubkey it
    ///    belongs to is never retried against a later key. Callers must
    ///    pass signatures ordered by their signer's position in the
    ///    redeem script, with absent members simply left out.
    ///
    /// `signatures` should hold exactly *m* entries; more than m makes
    /// the script fail, and fewer leaves it unsatisfied.
    public static func multisigInputScript(
        signatures: [Data],
        redeemScript: Data,
        sighashFlag: UInt8 = UInt8(BchSighash.allForkId & 0xFF)
    ) throws -> Script {
        guard signatures.count < 16 else {
            throw Failure.tooManySignatures(got: signatures.count)
        }
        var s = Data()
        s.append(0x00)  // OP_0 — the null dummy; see the note above.
        for signature in signatures {
            var withFlag = signature
            withFlag.append(sighashFlag)
            s.append(ScriptBuilder.pushData(withFlag))
        }
        s.append(ScriptBuilder.pushData(redeemScript))
        return Script(s)
    }

    /// Put a finished scriptSig on one input. Public because multisig
    /// assembly happens a step at a time — sign, collect, order,
    /// apply — rather than inside one signing call.
    public static func applyingScriptSig(
        _ scriptSig: Script, to tx: Transaction, at inputIndex: Int
    ) throws -> Transaction {
        guard (0..<tx.inputs.count).contains(inputIndex) else {
            throw Failure.inputIndexOutOfRange(got: inputIndex, have: tx.inputs.count)
        }
        return replacingScriptSig(in: tx, at: inputIndex, with: scriptSig)
    }

    private static func replacingScriptSig(
        in tx: Transaction, at inputIndex: Int, with scriptSig: Script
    ) -> Transaction {
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
