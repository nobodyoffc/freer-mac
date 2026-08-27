import Foundation

/// One parsed element of a script: either an opcode on its own, or a
/// push whose bytes travel with it. The bitcoinj `ScriptChunk` shape,
/// because that is what the Android `P2SH` parser walks — and walking
/// chunks is the only honest way to tell `<lockTime> OP_CLTV OP_DROP …`
/// apart from a multisig script that happens to start with a push.
///
/// ``ScriptAsm/disassemble(_:)`` throws away exactly this distinction
/// (it renders both as text), which is why redeem-script parsing
/// cannot be built on top of it.
public struct ScriptChunk: Equatable, Sendable {

    /// The opcode byte. For a push this is the push opcode itself —
    /// the direct length for 1…75 bytes, or `OP_PUSHDATA1`/`2`/`4`.
    public let opcode: UInt8

    /// Pushed bytes, or nil when this chunk is a bare opcode.
    /// An empty push (`OP_0`) carries `Data()`, not nil, so callers
    /// can tell "pushed nothing" from "pushed at all".
    public let data: Data?

    public init(opcode: UInt8, data: Data? = nil) {
        self.opcode = opcode
        self.data = data
    }

    public var isPush: Bool { data != nil }

    /// Decode `OP_0`…`OP_16` (and a 1-byte push standing in for a small
    /// number) the way Android's `P2SH.decodeSmallNum` does. Returns
    /// nil when the chunk is neither.
    public var smallNumber: Int? {
        if opcode >= 0x51 && opcode <= 0x60 { return Int(opcode) - 0x50 }
        if opcode == 0x00 && (data?.isEmpty ?? true) { return 0 }
        if let data, data.count == 1 { return Int(data[0]) }
        return nil
    }

    /// A pushed script number, read as little-endian unsigned — the
    /// port of Android's `P2SH.bytesToLong`. Lock times are always
    /// positive, so the sign bit is not consulted.
    public var pushedNumber: Int64? {
        guard let data, !data.isEmpty else { return nil }
        var result: Int64 = 0
        for (i, byte) in data.prefix(8).enumerated() {
            result |= Int64(byte) << (8 * i)
        }
        return result
    }
}

/// Split raw script bytes into ``ScriptChunk``s.
public enum ScriptParser {

    public enum Failure: Error, CustomStringConvertible {
        case truncatedPush(opcode: UInt8, wanted: Int, available: Int)

        public var description: String {
            switch self {
            case let .truncatedPush(opcode, wanted, available):
                let name = ScriptAsm.name(for: opcode) ?? String(format: "0x%02x", opcode)
                return "Script: \(name) wants \(wanted) bytes but only \(available) remain"
            }
        }
    }

    public static func chunks(_ script: Data) throws -> [ScriptChunk] {
        var out: [ScriptChunk] = []
        let bytes = [UInt8](script)
        var i = 0

        while i < bytes.count {
            let opcode = bytes[i]
            i += 1

            if opcode >= 0x01 && opcode <= 0x4B {
                out.append(ScriptChunk(
                    opcode: opcode,
                    data: try take(bytes, at: &i, count: Int(opcode), opcode: opcode)
                ))
                continue
            }

            if let width = lengthWidth(opcode) {
                guard i + width <= bytes.count else {
                    throw Failure.truncatedPush(
                        opcode: opcode, wanted: width, available: bytes.count - i
                    )
                }
                var length = 0
                for shift in 0..<width { length |= Int(bytes[i + shift]) << (8 * shift) }
                i += width
                out.append(ScriptChunk(
                    opcode: opcode,
                    data: try take(bytes, at: &i, count: length, opcode: opcode)
                ))
                continue
            }

            // OP_0 pushes an empty array; bitcoinj models it as a push
            // with zero-length data, and the small-number decoders here
            // rely on that.
            if opcode == 0x00 {
                out.append(ScriptChunk(opcode: opcode, data: Data()))
                continue
            }

            out.append(ScriptChunk(opcode: opcode))
        }
        return out
    }

    private static func take(
        _ bytes: [UInt8], at i: inout Int, count: Int, opcode: UInt8
    ) throws -> Data {
        guard count >= 0, i + count <= bytes.count else {
            throw Failure.truncatedPush(opcode: opcode, wanted: count, available: bytes.count - i)
        }
        let slice = Data(bytes[i..<(i + count)])
        i += count
        return slice
    }

    private static func lengthWidth(_ opcode: UInt8) -> Int? {
        switch opcode {
        case 0x4C: return 1
        case 0x4D: return 2
        case 0x4E: return 4
        default:   return nil
        }
    }
}
