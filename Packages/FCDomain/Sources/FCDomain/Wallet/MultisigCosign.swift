import Foundation
import FCCore

/// Collecting m signatures from n people and turning them into one
/// broadcastable transaction — the port of `TxHandler`'s
/// `signSchnorrMultiSignTx` / `mergeMultisignTxData` /
/// `buildSchnorrMultiSignTx` trio.
///
/// **The document is the protocol.** A multisig spend is not one act
/// but a conversation: somebody proposes a transaction, each member
/// signs it wherever they are, and the partial results are merged.
/// What passes between them is a ``RawTxInfo`` — the same cold-sign
/// document the watch-only Send path already exports — carrying the
/// signatures gathered so far in ``RawTxInfo/fidSigMap``. Any transport
/// works: a file, a QR code, a chat message.
///
/// **Every signature commits to the whole transaction.** Change one
/// output, one input, or the fee, and every signature already collected
/// is void. So the document that goes out must be the document that
/// comes back; ``merge(_:)`` refuses to combine two that describe
/// different transactions rather than producing a script that fails at
/// the node with an error naming nobody.
///
/// **The group is read from the inputs, never from a field.** Each
/// input carries the redeem script it is spending, and that script is
/// the membership: pubkeys, their order, and m-of-n all parse out of
/// it. A stated group beside the inputs could disagree with them; a
/// derived one cannot.
public enum MultisigCosign {

    public enum Failure: Error, CustomStringConvertible {
        case noInputs
        case notMultisig(inputIndex: Int)
        case badRedeemScript(inputIndex: Int, underlying: String)
        case mixedGroups(first: String, other: String)
        case notAMember(fid: String, group: String)
        case signatureCountMismatch(fid: String, got: Int, want: Int)
        case badSignatureHex(fid: String, inputIndex: Int)
        case invalidSignature(fid: String, inputIndex: Int)
        case documentsDiffer(what: String)
        case notEnoughSignatures(have: Int, need: Int)

        public var description: String {
            switch self {
            case .noInputs:
                return "Multisig: the transaction has no inputs"
            case .notMultisig(let i):
                return "Multisig: input \(i) carries no multisig redeem script"
            case let .badRedeemScript(i, why):
                return "Multisig: input \(i)'s redeem script will not parse — \(why)"
            case let .mixedGroups(first, other):
                return "Multisig: inputs belong to two different groups (\(first) and \(other)) — one transaction cannot spend both"
            case let .notAMember(fid, group):
                return "Multisig: \(fid) is not a member of \(group)"
            case let .signatureCountMismatch(fid, got, want):
                return "Multisig: \(fid) signed \(got) input(s) but the transaction has \(want)"
            case let .badSignatureHex(fid, i):
                return "Multisig: \(fid)'s signature for input \(i) is not hex"
            case let .invalidSignature(fid, i):
                return "Multisig: \(fid)'s signature for input \(i) does not verify — it was made against a different transaction, or by a different key"
            case .documentsDiffer(let what):
                return "Multisig: these documents describe different transactions (\(what)) — signatures made against one are void for the other"
            case let .notEnoughSignatures(have, need):
                return "Multisig: \(have) of \(need) signatures collected"
            }
        }
    }

    // MARK: - the group

    /// Who can sign this transaction, in the order `OP_CHECKMULTISIG`
    /// will read them.
    public struct Group: Equatable, Sendable {
        /// The base multisig address — the 3… FID the group is known
        /// by. For a CLTV input this is still the *base* address, not
        /// the time-locked one the coins sit at; see ``P2sh/fid``.
        public let fid: String
        public let m: Int
        public let n: Int
        public let pubkeys: [String]
        /// Member FIDs, positionally matching ``pubkeys``.
        public let fids: [String]

        public func index(of fid: String) -> Int? { fids.firstIndex(of: fid) }
        public func contains(_ fid: String) -> Bool { fids.contains(fid) }
    }

    /// Recover the group from a document's inputs, checking that they
    /// all belong to the same one.
    public static func group(of info: RawTxInfo) throws -> Group {
        let slots = info.inputs ?? []
        guard !slots.isEmpty else { throw Failure.noInputs }

        var found: Group?
        for (i, slot) in slots.enumerated() {
            guard let hex = slot.redeemScript, !hex.isEmpty else {
                throw Failure.notMultisig(inputIndex: i)
            }
            let p2sh: P2sh
            do { p2sh = try P2sh(redeemScriptHex: hex) }
            catch { throw Failure.badRedeemScript(inputIndex: i, underlying: String(describing: error)) }

            guard p2sh.kind == .multisig || p2sh.kind == .multisigCltv,
                  let m = p2sh.m, let n = p2sh.n,
                  let pubkeys = p2sh.pubkeys, let fid = p2sh.fid
            else { throw Failure.notMultisig(inputIndex: i) }

            let fids = try pubkeys.map { hex -> String in
                guard let data = Hex.decodeOrNil(hex) else {
                    throw Failure.badRedeemScript(inputIndex: i, underlying: "pubkey is not hex")
                }
                return try FchAddress(publicKey: data).fid
            }
            let here = Group(fid: fid, m: m, n: n, pubkeys: pubkeys, fids: fids)
            if let found, found != here {
                throw Failure.mixedGroups(first: found.fid, other: here.fid)
            }
            found = here
        }
        // `found` is set: the loop ran at least once and every path
        // through it either assigns or throws.
        return found!
    }

    // MARK: - signing

    /// Sign every input as one member and return the document with our
    /// signatures added.
    ///
    /// Each input is signed against **its own** redeem script, which is
    /// what makes a mixed plain/CLTV spend work: the time-locked inputs
    /// commit to their prefixed script and the plain ones to the bare
    /// body, and signing them all against one script would silently
    /// produce signatures that verify against nothing.
    ///
    /// Signing twice is idempotent in effect — the second run replaces
    /// our own entry rather than adding a duplicate.
    public static func sign(
        _ info: RawTxInfo, inputCashes: [Cash] = [], privkey: Data
    ) throws -> RawTxInfo {
        let group = try group(of: info)
        let signerFid = try FchAddress(
            publicKey: try Secp256k1.publicKey(fromPrivateKey: privkey)
        ).fid
        guard group.contains(signerFid) else {
            throw Failure.notAMember(fid: signerFid, group: group.fid)
        }

        let built = try AdvancedTxBuilder.build(info, inputCashes: inputCashes)
        let slots = info.inputs ?? []
        var signatures: [String] = []
        for (i, slot) in slots.enumerated() {
            guard let hex = slot.redeemScript, let redeem = Hex.decodeOrNil(hex) else {
                throw Failure.notMultisig(inputIndex: i)
            }
            let sig = try TxHandler.signMultisigInput(
                tx: built.transaction,
                inputIndex: i,
                privateKey: privkey,
                prevValueSats: UInt64(slot.value ?? 0),
                redeemScript: redeem
            )
            signatures.append(Hex.encode(sig))
        }

        var out = info
        var map = out.fidSigMap ?? [:]
        map[signerFid] = signatures
        out.fidSigMap = map
        return out
    }

    // MARK: - merging

    /// Combine documents from different signers into one.
    ///
    /// Refuses documents that describe different transactions. That is
    /// the whole job: two members who each edited the fee before
    /// signing produce signatures that cannot coexist, and merging them
    /// anyway yields a transaction the node rejects for reasons that
    /// point at neither of them.
    public static func merge(_ documents: [RawTxInfo]) throws -> RawTxInfo {
        guard var out = documents.first else { throw Failure.noInputs }
        var map = out.fidSigMap ?? [:]

        for other in documents.dropFirst() {
            if let what = firstDifference(out, other) {
                throw Failure.documentsDiffer(what: what)
            }
            for (fid, sigs) in other.fidSigMap ?? [:] {
                map[fid] = sigs
            }
        }
        out.fidSigMap = map
        return out
    }

    /// What makes two documents describe different transactions, or nil
    /// when they are the same spend. Signatures are excluded — that is
    /// the field being merged.
    static func firstDifference(_ a: RawTxInfo, _ b: RawTxInfo) -> String? {
        if a.sender != b.sender { return "sender" }
        if a.opReturn != b.opReturn { return "op_return" }
        if a.changeTo != b.changeTo { return "change address" }
        if a.feeRate != b.feeRate { return "fee rate" }
        if a.lockTime != b.lockTime { return "lock time" }
        let ai = a.inputs ?? [], bi = b.inputs ?? []
        if ai.count != bi.count { return "input count" }
        for (x, y) in zip(ai, bi) {
            if x.birthTxId != y.birthTxId || x.birthIndex != y.birthIndex {
                return "inputs"
            }
            if x.value != y.value || x.redeemScript != y.redeemScript {
                return "inputs"
            }
        }
        let ao = a.outputs ?? [], bo = b.outputs ?? []
        if ao.count != bo.count { return "output count" }
        for (x, y) in zip(ao, bo) {
            if x.owner != y.owner || x.value != y.value { return "outputs" }
        }
        return nil
    }

    // MARK: - progress

    /// How far along a co-sign is — what the signing UI displays.
    public struct Status: Sendable {
        public let group: Group
        /// Members who have signed, in the group's own order.
        public let signed: [String]
        public let unsigned: [String]
        /// How many more signatures are needed. Zero means ready.
        public let remaining: Int
        public var isComplete: Bool { remaining == 0 }
    }

    public static func status(_ info: RawTxInfo) throws -> Status {
        let group = try group(of: info)
        let map = info.fidSigMap ?? [:]
        // Order by the group, not by the map: a dictionary has no
        // order, and the UI showing signers in a different sequence
        // each time it redraws looks broken.
        let signed = group.fids.filter { map[$0] != nil }
        let unsigned = group.fids.filter { map[$0] == nil }
        return Status(
            group: group,
            signed: signed,
            unsigned: unsigned,
            remaining: max(0, group.m - signed.count)
        )
    }

    // MARK: - assembling

    /// Turn a fully-signed document into a broadcastable transaction.
    ///
    /// Every signature is verified before it goes in. The cost is one
    /// ECDSA-class check per signature per input; the alternative is
    /// handing the node a script that fails with a message naming no
    /// member, leaving the group to guess who sent a bad one.
    public static func assemble(
        _ info: RawTxInfo, inputCashes: [Cash] = []
    ) throws -> Data {
        let group = try group(of: info)
        let map = info.fidSigMap ?? [:]
        let slots = info.inputs ?? []
        guard !slots.isEmpty else { throw Failure.noInputs }

        let built = try AdvancedTxBuilder.build(info, inputCashes: inputCashes)

        // Members who signed, in pubkey order. OP_CHECKMULTISIG walks
        // signatures and pubkeys together in a single pass, so a
        // signature ahead of its own pubkey is never reconsidered
        // against a later one — the order here is not cosmetic.
        let signers = group.fids.filter { map[$0] != nil }
        guard signers.count >= group.m else {
            throw Failure.notEnoughSignatures(have: signers.count, need: group.m)
        }
        // Exactly m, no more: a spare signature makes the script fail.
        // Dropping the *last* ones keeps the earliest members in pubkey
        // order, which is stable across runs — unlike Android's
        // `dropRedundantSigs`, which trims by walking a HashMap.
        let contributing = Array(signers.prefix(group.m))

        for (fid, sigs) in map {
            guard sigs.count == slots.count else {
                throw Failure.signatureCountMismatch(
                    fid: fid, got: sigs.count, want: slots.count
                )
            }
        }

        var tx = built.transaction
        for (i, slot) in slots.enumerated() {
            guard let hex = slot.redeemScript, let redeem = Hex.decodeOrNil(hex) else {
                throw Failure.notMultisig(inputIndex: i)
            }
            var ordered: [Data] = []
            for fid in contributing {
                guard let sigHex = map[fid]?[i], let sig = Hex.decodeOrNil(sigHex) else {
                    throw Failure.badSignatureHex(fid: fid, inputIndex: i)
                }
                guard let keyIndex = group.index(of: fid),
                      let pubkey = Hex.decodeOrNil(group.pubkeys[keyIndex])
                else { throw Failure.notAMember(fid: fid, group: group.fid) }

                let ok = try TxHandler.verifyMultisigInput(
                    tx: built.transaction,
                    inputIndex: i,
                    publicKey: pubkey,
                    signature: sig,
                    prevValueSats: UInt64(slot.value ?? 0),
                    redeemScript: redeem
                )
                guard ok else { throw Failure.invalidSignature(fid: fid, inputIndex: i) }
                ordered.append(sig)
            }
            let scriptSig = try TxHandler.multisigInputScript(
                signatures: ordered, redeemScript: redeem
            )
            tx = try TxHandler.applyingScriptSig(scriptSig, to: tx, at: i)
        }
        return tx.serialized
    }
}
