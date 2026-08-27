import Foundation

/// A P2SH redeem script and everything derivable from it — the port of
/// Android's `com.fc.fc_ajdk.data.fchData.P2SH`.
///
/// Three shapes exist on FCH, and they are the three ways a
/// transaction can lock coins to something other than a single key:
///
/// - ``Kind/cltv`` — `<lockTime> OP_CLTV OP_DROP` in front of a plain
///   P2PKH body. One key, but not before a block height.
/// - ``Kind/multisig`` — `<m> <pubkey…> <n> OP_CHECKMULTISIG`.
/// - ``Kind/multisigCltv`` — both, time lock first.
///
/// **Two addresses, and they are not the same one.** ``address`` is
/// where the coins actually go: `hash160` of *this* redeem script,
/// base58'd with the P2SH version byte. ``fid`` is who the script is
/// *about* — the F… key holder for a single-sig CLTV, or the base
/// multisig 3… address (the multisig script **without** the CLTV
/// prefix) for the multisig kinds. The Android UI shows `fid` and the
/// chain sees `address`; conflating them locks money somewhere nobody
/// meant.
public struct P2sh: Equatable, Sendable {

    public enum Kind: String, Sendable {
        case cltv = "P2SH_CLTV"
        case multisig = "P2SH_MULTISIG"
        case multisigCltv = "P2SH_MULTISIG_CLTV"
    }

    public enum Failure: Error, CustomStringConvertible {
        case emptyScript
        case notHex(String)
        case unparsable(String)
        case incompleteCltvPrefix
        case emptyBody
        case incompleteSingleSig
        case badPubkeyHash(got: Int)
        case badThreshold(m: Int?, n: Int?)
        case missingCheckMultisig
        case nonPositiveLockTime(Int64)

        public var description: String {
            switch self {
            case .emptyScript:
                return "P2SH: redeem script is empty"
            case .notHex(let s):
                return "P2SH: redeem script is not hex — '\(s.prefix(24))…'"
            case .unparsable(let why):
                return "P2SH: cannot parse redeem script — \(why)"
            case .incompleteCltvPrefix:
                return "P2SH: script starts with a push but no OP_CHECKLOCKTIMEVERIFY OP_DROP follows"
            case .emptyBody:
                return "P2SH: nothing after the CLTV prefix"
            case .incompleteSingleSig:
                return "P2SH: incomplete single-sig body (want DUP HASH160 <20> EQUALVERIFY CHECKSIG)"
            case .badPubkeyHash(let got):
                return "P2SH: pubkey hash must be 20 bytes, got \(got)"
            case let .badThreshold(m, n):
                return "P2SH: multisig must satisfy 1 ≤ m ≤ n ≤ 16; got \(m.map(String.init) ?? "?")-of-\(n.map(String.init) ?? "?")"
            case .missingCheckMultisig:
                return "P2SH: multisig body does not end in OP_CHECKMULTISIG"
            case .nonPositiveLockTime(let n):
                return "P2SH: lock time must be positive, got \(n)"
            }
        }
    }

    // Opcodes used by the three shapes.
    private static let opDrop: UInt8 = 0x75
    private static let opDup: UInt8 = 0x76
    private static let opEqualVerify: UInt8 = 0x88
    private static let opHash160: UInt8 = 0xA9
    private static let opCheckSig: UInt8 = 0xAC
    private static let opCheckMultisig: UInt8 = 0xAE
    private static let opCheckLockTimeVerify: UInt8 = 0xB1

    public let kind: Kind
    public let redeemScript: Data
    public let lockTime: Int64?
    public let pubkeyHash: Data?
    public let pubkeys: [String]?
    public let m: Int?
    public let n: Int?

    /// The party the script is about — see the type's note. F… for
    /// ``Kind/cltv``, 3… for the multisig kinds.
    public let fid: String?

    public var redeemScriptHex: String { Hex.encode(redeemScript) }

    /// `hash160(redeemScript)` — Android's `P2SH.id`.
    public var scriptHash: Data { Hash.hash160(redeemScript) }

    /// The 3… address the coins are actually paid to.
    public var address: String {
        // Force-try is safe: scriptHash is a hash160, always 20 bytes.
        try! FchAddress(versionByte: FchAddress.p2shVersionByte, hash160: scriptHash).fid
    }

    /// The output script that pays this redeem script.
    public var outputScript: Script {
        try! ScriptBuilder.p2shOutput(scriptHash: scriptHash)
    }

    // MARK: - build

    /// Single-sig CLTV: pay `fid`, but not before `lockTime`.
    public init(fid: String, lockTime: Int64) throws {
        guard lockTime > 0 else { throw Failure.nonPositiveLockTime(lockTime) }
        let hash160 = try FchAddress(fid: fid).hash160
        self.kind = .cltv
        self.lockTime = lockTime
        self.pubkeyHash = hash160
        self.pubkeys = nil
        self.m = nil
        self.n = nil
        self.fid = fid
        self.redeemScript = P2sh.cltvRedeemScript(lockUntil: lockTime, pubkeyHash: hash160)
    }

    /// Multisig, with an optional CLTV prefix. A nil or non-positive
    /// `lockTime` produces a plain ``Kind/multisig``.
    public init(pubkeys: [String], m: Int, n: Int, lockTime: Int64?) throws {
        guard (1...16).contains(m), (m...16).contains(n), !pubkeys.isEmpty else {
            throw Failure.badThreshold(m: m, n: n)
        }
        let keyData = try pubkeys.map { hex -> Data in
            guard let d = Hex.decodeOrNil(hex) else { throw Failure.notHex(hex) }
            return d
        }
        let base = try ScriptBuilder.multisigOutput(required: m, pubkeys: keyData).bytes

        self.pubkeys = pubkeys
        self.m = m
        self.n = n
        self.pubkeyHash = nil
        // Both kinds name the *base* multisig address, so a
        // MULTISIG_CLTV script still says who the signers are rather
        // than repeating its own P2SH address.
        self.fid = try! FchAddress(
            versionByte: FchAddress.p2shVersionByte, hash160: Hash.hash160(base)
        ).fid

        if let lockTime, lockTime > 0 {
            self.kind = .multisigCltv
            self.lockTime = lockTime
            self.redeemScript = P2sh.cltvPrefix(lockUntil: lockTime) + base
        } else {
            self.kind = .multisig
            self.lockTime = nil
            self.redeemScript = base
        }
    }

    /// `<lockTime> OP_CHECKLOCKTIMEVERIFY OP_DROP OP_DUP OP_HASH160
    /// <pubkeyHash> OP_EQUALVERIFY OP_CHECKSIG`.
    public static func cltvRedeemScript(lockUntil: Int64, pubkeyHash: Data) -> Data {
        var s = cltvPrefix(lockUntil: lockUntil)
        s.append(opDup)
        s.append(opHash160)
        s.append(ScriptBuilder.pushData(pubkeyHash))
        s.append(opEqualVerify)
        s.append(opCheckSig)
        return s
    }

    /// `<lockTime> OP_CHECKLOCKTIMEVERIFY OP_DROP` — bitcoinj's
    /// `ScriptBuilder.number` for the value, so heights above 16 push
    /// as a minimally-encoded script number.
    public static func cltvPrefix(lockUntil: Int64) -> Data {
        var s = ScriptBuilder.number(lockUntil)
        s.append(opCheckLockTimeVerify)
        s.append(opDrop)
        return s
    }

    // MARK: - parse

    /// Parse an existing redeem script, detecting its kind and
    /// recovering the parameters. Mirrors Android's `P2SH(String)`.
    public init(redeemScriptHex: String) throws {
        guard !redeemScriptHex.isEmpty else { throw Failure.emptyScript }
        guard let bytes = Hex.decodeOrNil(redeemScriptHex) else {
            throw Failure.notHex(redeemScriptHex)
        }
        try self.init(redeemScript: bytes)
    }

    public init(redeemScript bytes: Data) throws {
        guard !bytes.isEmpty else { throw Failure.emptyScript }
        let chunks: [ScriptChunk]
        do {
            chunks = try ScriptParser.chunks(bytes)
        } catch {
            throw Failure.unparsable(String(describing: error))
        }
        guard !chunks.isEmpty else { throw Failure.emptyScript }

        self.redeemScript = bytes

        // A leading push means a CLTV prefix — or a malformed script.
        var start = 0
        var parsedLockTime: Int64?
        if let first = chunks.first, first.isPush, !(first.data?.isEmpty ?? true) {
            guard chunks.count > 2,
                  chunks[1].opcode == P2sh.opCheckLockTimeVerify,
                  chunks[2].opcode == P2sh.opDrop
            else { throw Failure.incompleteCltvPrefix }
            parsedLockTime = first.pushedNumber
            start = 3
        }
        guard start < chunks.count else { throw Failure.emptyBody }

        let body = chunks[start]

        if body.opcode == P2sh.opDup {
            // DUP HASH160 <20> EQUALVERIFY CHECKSIG
            guard chunks.count >= start + 5 else { throw Failure.incompleteSingleSig }
            guard chunks[start + 1].opcode == P2sh.opHash160,
                  chunks[start + 3].opcode == P2sh.opEqualVerify,
                  chunks[start + 4].opcode == P2sh.opCheckSig
            else { throw Failure.incompleteSingleSig }
            guard let hash = chunks[start + 2].data, hash.count == 20 else {
                throw Failure.badPubkeyHash(got: chunks[start + 2].data?.count ?? 0)
            }
            self.kind = .cltv
            self.lockTime = parsedLockTime
            self.pubkeyHash = hash
            self.pubkeys = nil
            self.m = nil
            self.n = nil
            self.fid = try FchAddress(hash160: hash).fid
            return
        }

        // <m> <pubkey…> <n> OP_CHECKMULTISIG
        guard chunks.count >= start + 4,
              chunks[chunks.count - 1].opcode == P2sh.opCheckMultisig
        else { throw Failure.missingCheckMultisig }

        let mValue = body.smallNumber
        let nValue = chunks[chunks.count - 2].smallNumber
        guard let mValue, let nValue, (1...16).contains(mValue), (mValue...16).contains(nValue)
        else { throw Failure.badThreshold(m: mValue, n: nValue) }

        var keys: [String] = []
        for i in (start + 1)..<(chunks.count - 2) {
            if let d = chunks[i].data { keys.append(Hex.encode(d)) }
        }

        self.m = mValue
        self.n = nValue
        self.pubkeys = keys
        self.pubkeyHash = nil
        self.lockTime = parsedLockTime

        if parsedLockTime != nil {
            self.kind = .multisigCltv
            // Name the base multisig address, not this script's own.
            let keyData = keys.compactMap { Hex.decodeOrNil($0) }
            let base = (try? ScriptBuilder.multisigOutput(required: mValue, pubkeys: keyData).bytes)
                ?? Data()
            self.fid = base.isEmpty
                ? nil
                : try? FchAddress(
                    versionByte: FchAddress.p2shVersionByte, hash160: Hash.hash160(base)
                ).fid
        } else {
            self.kind = .multisig
            self.fid = try? FchAddress(
                versionByte: FchAddress.p2shVersionByte, hash160: Hash.hash160(bytes)
            ).fid
        }
    }

    /// Strict syntax check — the port of Android's
    /// `validateRedeemScriptSyntax`. A script that fails this would
    /// lock coins nobody can ever spend, so the carve path refuses to
    /// publish one rather than trusting the parser's tolerance.
    public static func isValidRedeemScript(_ hex: String) -> Bool {
        guard let p2sh = try? P2sh(redeemScriptHex: hex) else { return false }
        if let lockTime = p2sh.lockTime, lockTime <= 0 { return false }
        switch p2sh.kind {
        case .cltv:
            return p2sh.pubkeyHash?.count == 20
        case .multisig, .multisigCltv:
            guard let m = p2sh.m, let n = p2sh.n, let keys = p2sh.pubkeys else { return false }
            return keys.count == n && (1...16).contains(m) && m <= n
        }
    }

    /// The OP_RETURN payload that publishes a transaction's P2SH redeem
    /// scripts: a JSON array of hex strings, de-duplicated, in first-use
    /// order. Android's `makeRedeemScriptListJsonForOpReturn`.
    ///
    /// Publishing them is what makes a time-locked payment usable by the
    /// recipient at all: without the redeem script on chain, only the
    /// sender can reconstruct how to spend the output.
    public static func opReturnPayload(for scripts: [P2sh]) throws -> String {
        var seen = Set<String>()
        var ordered: [String] = []
        for p2sh in scripts {
            let hex = p2sh.redeemScriptHex
            guard !hex.isEmpty else { continue }
            guard isValidRedeemScript(hex) else {
                throw Failure.unparsable("would be unspendable: \(hex.prefix(40))…")
            }
            if seen.insert(hex).inserted { ordered.append(hex) }
        }
        let data = try JSONSerialization.data(withJSONObject: ordered, options: [])
        return String(decoding: data, as: UTF8.self)
    }

    /// Read the redeem scripts back out of an OP_RETURN payload,
    /// keyed by script hash. Nil when the payload is not the JSON
    /// array this format uses.
    public static func redeemScripts(fromOpReturn text: String) -> [String: String]? {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed.hasPrefix("["),
              let data = trimmed.data(using: .utf8),
              let list = try? JSONSerialization.jsonObject(with: data) as? [String],
              !list.isEmpty
        else { return nil }
        var map: [String: String] = [:]
        for hex in list {
            guard let bytes = Hex.decodeOrNil(hex) else { continue }
            map[Hex.encode(Hash.hash160(bytes))] = hex
        }
        return map
    }
}
