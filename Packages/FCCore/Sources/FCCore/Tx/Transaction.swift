import Foundation

/// A reference to an output of a previous transaction.
///
/// `prevTxHash` is stored in *natural byte order* — the order produced by
/// `double-sha256(serialized_tx)`. That's the same order used inside a
/// serialized transaction. The hex you typically see in block explorers
/// or a JSON-RPC response is the byte-reversal of this value.
public struct OutPoint: Equatable, Hashable, Sendable {
    public static let hashLength = 32

    public let prevTxHash: Data
    public let outIndex: UInt32

    public init(prevTxHash: Data, outIndex: UInt32) throws {
        guard prevTxHash.count == OutPoint.hashLength else {
            throw TxError.invalidHashLength(got: prevTxHash.count, expected: OutPoint.hashLength)
        }
        self.prevTxHash = Data(prevTxHash)
        self.outIndex = outIndex
    }
}

public struct TxInput: Equatable, Hashable, Sendable {
    public static let finalSequence: UInt32 = 0xFFFFFFFF

    public let outpoint: OutPoint
    public let scriptSig: Script
    public let sequence: UInt32

    public init(outpoint: OutPoint, scriptSig: Script = Script(Data()), sequence: UInt32 = finalSequence) {
        self.outpoint = outpoint
        self.scriptSig = scriptSig
        self.sequence = sequence
    }
}

public struct TxOutput: Equatable, Hashable, Sendable {
    /// Value in the smallest unit (satoshis).
    public let value: UInt64
    public let scriptPubKey: Script

    public init(value: UInt64, scriptPubKey: Script) {
        self.value = value
        self.scriptPubKey = scriptPubKey
    }
}

/// FCH / Bitcoin-family transaction.
///
/// Serialization is the classic (pre-SegWit) format:
/// `version(4) || varInt(inputCount) || inputs || varInt(outputCount) || outputs || locktime(4)`,
/// which is what FCH uses — there is no SegWit variant.
public struct Transaction: Equatable, Hashable, Sendable {

    public var version: UInt32
    public var inputs: [TxInput]
    public var outputs: [TxOutput]
    public var locktime: UInt32

    public init(
        version: UInt32 = 2,
        inputs: [TxInput] = [],
        outputs: [TxOutput] = [],
        locktime: UInt32 = 0
    ) {
        self.version = version
        self.inputs = inputs
        self.outputs = outputs
        self.locktime = locktime
    }

    /// Serialized transaction in Bitcoin wire format.
    public var serialized: Data {
        var out = Data()
        out.append(TxBytes.le(version))
        out.append(VarInt.encode(UInt64(inputs.count)))
        for input in inputs {
            out.append(input.outpoint.prevTxHash)
            out.append(TxBytes.le(input.outpoint.outIndex))
            out.append(VarInt.encode(UInt64(input.scriptSig.bytes.count)))
            out.append(input.scriptSig.bytes)
            out.append(TxBytes.le(input.sequence))
        }
        out.append(VarInt.encode(UInt64(outputs.count)))
        for output in outputs {
            out.append(TxBytes.le(output.value))
            out.append(VarInt.encode(UInt64(output.scriptPubKey.bytes.count)))
            out.append(output.scriptPubKey.bytes)
        }
        out.append(TxBytes.le(locktime))
        return out
    }

    /// Transaction ID in *natural byte order* — `double-sha256(serialized)`.
    public var txid: Data {
        Hash.doubleSha256(serialized)
    }

    /// Transaction ID in *display byte order* (the 32-byte txid reversed,
    /// hex-encoded). This is what block explorers and JSON-RPC return.
    public var txidDisplay: String {
        txid.reversed().map { String(format: "%02x", $0) }.joined()
    }
}

public enum TxError: Error, CustomStringConvertible {
    case invalidHashLength(got: Int, expected: Int)

    public var description: String {
        switch self {
        case let .invalidHashLength(got, expected):
            return "Tx: hash must be \(expected) bytes, got \(got)"
        }
    }
}

// MARK: - little-endian helpers

enum TxBytes {
    static func le(_ value: UInt32) -> Data {
        var v = value.littleEndian
        return Data(bytes: &v, count: 4)
    }
    static func le(_ value: UInt64) -> Data {
        var v = value.littleEndian
        return Data(bytes: &v, count: 8)
    }
}
