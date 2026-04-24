import Foundation

/// Bitcoin script bytes. A thin `Data` wrapper so APIs are self-documenting
/// ("expects a `Script`" vs "expects raw bytes").
public struct Script: Equatable, Hashable, Sendable {
    public let bytes: Data

    public init(_ bytes: Data) {
        self.bytes = Data(bytes)
    }
}

/// Standard-form script constructors. Output byte-exact parity with
/// freecashj's `org.bitcoinj.script.ScriptBuilder` is required and
/// asserted by the golden vectors in `tools/vector-gen/`.
public enum ScriptBuilder {

    public enum Failure: Error, CustomStringConvertible {
        case invalidHashLength(got: Int, expected: Int)
        case invalidMultisigThreshold(required: Int, total: Int)
        case invalidPubkeyLength(got: Int)

        public var description: String {
            switch self {
            case let .invalidHashLength(got, expected):
                return "Script: hash must be \(expected) bytes, got \(got)"
            case let .invalidMultisigThreshold(required, total):
                return "Script: multisig must satisfy 1 ≤ required ≤ total ≤ 16; got \(required)-of-\(total)"
            case let .invalidPubkeyLength(got):
                return "Script: pubkey must be 33 (compressed) or 65 (uncompressed) bytes, got \(got)"
            }
        }
    }

    /// P2PKH output: `OP_DUP OP_HASH160 <push20> <hash160> OP_EQUALVERIFY OP_CHECKSIG`.
    public static func p2pkhOutput(hash160: Data) throws -> Script {
        guard hash160.count == 20 else {
            throw Failure.invalidHashLength(got: hash160.count, expected: 20)
        }
        var s = Data()
        s.append(0x76)  // OP_DUP
        s.append(0xA9)  // OP_HASH160
        s.append(pushData(hash160))
        s.append(0x88)  // OP_EQUALVERIFY
        s.append(0xAC)  // OP_CHECKSIG
        return Script(s)
    }

    /// P2SH output: `OP_HASH160 <push20> <scriptHash> OP_EQUAL`.
    public static func p2shOutput(scriptHash: Data) throws -> Script {
        guard scriptHash.count == 20 else {
            throw Failure.invalidHashLength(got: scriptHash.count, expected: 20)
        }
        var s = Data()
        s.append(0xA9)  // OP_HASH160
        s.append(pushData(scriptHash))
        s.append(0x87)  // OP_EQUAL
        return Script(s)
    }

    /// n-of-m raw multisig output:
    /// `OP_n <push> <pub1> … <push> <pubm> OP_m OP_CHECKMULTISIG`.
    ///
    /// `required` and `pubkeys.count` must both be in `1...16`.
    public static func multisigOutput(required: Int, pubkeys: [Data]) throws -> Script {
        guard (1...16).contains(required),
              (required...16).contains(pubkeys.count) else {
            throw Failure.invalidMultisigThreshold(required: required, total: pubkeys.count)
        }
        for (i, key) in pubkeys.enumerated() {
            guard key.count == 33 || key.count == 65 else {
                throw Failure.invalidPubkeyLength(got: key.count)
            }
            _ = i
        }
        var s = Data()
        s.append(smallNumberOp(required))
        for key in pubkeys {
            s.append(pushData(key))
        }
        s.append(smallNumberOp(pubkeys.count))
        s.append(0xAE)  // OP_CHECKMULTISIG
        return Script(s)
    }

    /// P2PKH scriptSig: `<push> <sig || hashType> <push> <pubkey>`.
    ///
    /// `sighashFlag` is appended to the DER signature as a single byte.
    /// For BCH the expected flag is `0x41` (`SIGHASH_ALL | SIGHASH_FORKID`);
    /// other values are accepted so callers doing message-signing with
    /// non-standard flags can use this helper too.
    public static func p2pkhInput(
        signatureDER: Data,
        sighashFlag: UInt8,
        pubkey: Data
    ) throws -> Script {
        guard pubkey.count == 33 || pubkey.count == 65 else {
            throw Failure.invalidPubkeyLength(got: pubkey.count)
        }
        var sigPlusFlag = Data(signatureDER)
        sigPlusFlag.append(sighashFlag)
        var s = Data()
        s.append(pushData(sigPlusFlag))
        s.append(pushData(pubkey))
        return Script(s)
    }

    // MARK: - internal

    /// Canonical data-push: direct length prefix for 1–75 bytes, then
    /// `OP_PUSHDATA1`/`2`/`4` above. Empty data uses `OP_0`.
    static func pushData(_ data: Data) -> Data {
        var out = Data()
        let len = data.count
        switch len {
        case 0:
            out.append(0x00)  // OP_0 — pushes empty bytes
        case 1...0x4B:
            out.append(UInt8(len))
            out.append(data)
        case 0x4C...0xFF:
            out.append(0x4C)  // OP_PUSHDATA1
            out.append(UInt8(len))
            out.append(data)
        case 0x100...0xFFFF:
            out.append(0x4D)  // OP_PUSHDATA2
            var le = UInt16(len).littleEndian
            out.append(Data(bytes: &le, count: 2))
            out.append(data)
        default:
            out.append(0x4E)  // OP_PUSHDATA4
            var le = UInt32(len).littleEndian
            out.append(Data(bytes: &le, count: 4))
            out.append(data)
        }
        return out
    }

    /// `OP_0 = 0x00`, `OP_1 = 0x51`, `OP_2 = 0x52`, … `OP_16 = 0x60`.
    static func smallNumberOp(_ n: Int) -> UInt8 {
        if n == 0 { return 0x00 }
        return UInt8(0x50 + n)
    }
}
