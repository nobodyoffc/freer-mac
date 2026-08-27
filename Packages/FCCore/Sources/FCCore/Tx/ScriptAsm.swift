import Foundation

/// Script ⇄ ASM, the port of Android's `P2SH.scriptHexToAsm` /
/// `scriptAsmToHex`.
///
/// Android delegates both directions to bitcoinj, so its ASM dialect is
/// bitcoinj's `Script.toString()`: pushes print as `PUSHDATA(20)[hex]`
/// and opcodes often lose their `OP_` prefix. We *emit* the
/// conventional Bitcoin ASM instead — `OP_DUP OP_HASH160 <hex>
/// OP_EQUALVERIFY OP_CHECKSIG` — because that is what block explorers
/// and every other tool print, and it is what a user comparing this
/// pane against an explorer will be holding. We *accept* both dialects,
/// so ASM copied out of the Android app still assembles here.
public enum ScriptAsm {

    public enum Failure: Error, CustomStringConvertible {
        case truncatedPush(opcode: UInt8, wanted: Int, available: Int)
        case unknownToken(String)
        case emptyInput

        public var description: String {
            switch self {
            case let .truncatedPush(opcode, wanted, available):
                let name = ScriptAsm.name(for: opcode) ?? String(format: "0x%02x", opcode)
                return "Script: \(name) wants \(wanted) bytes but only \(available) remain"
            case let .unknownToken(token):
                return "Script: '\(token)' is neither an opcode, a number, nor hex data"
            case .emptyInput:
                return "Script: nothing to convert"
            }
        }
    }

    // MARK: - Disassemble

    /// Bytes → ASM. Data pushes render as bare lowercase hex; a push
    /// whose declared length runs past the end of the script throws
    /// rather than printing a truncated blob, because a script that
    /// doesn't parse is exactly what the user needs to be told about.
    public static func disassemble(_ script: Data) throws -> String {
        guard !script.isEmpty else { throw Failure.emptyInput }
        var tokens: [String] = []
        let bytes = [UInt8](script)
        var i = 0

        while i < bytes.count {
            let opcode = bytes[i]
            i += 1

            // Direct push: the opcode *is* the length.
            if opcode >= 0x01 && opcode <= 0x4B {
                tokens.append(try take(bytes, at: &i, count: Int(opcode), opcode: opcode))
                continue
            }

            // OP_PUSHDATA1/2/4: a little-endian length follows.
            if let widthBytes = pushdataLengthWidth(opcode) {
                guard i + widthBytes <= bytes.count else {
                    throw Failure.truncatedPush(
                        opcode: opcode, wanted: widthBytes, available: bytes.count - i
                    )
                }
                var length = 0
                for shift in 0..<widthBytes {
                    length |= Int(bytes[i + shift]) << (8 * shift)
                }
                i += widthBytes
                tokens.append(try take(bytes, at: &i, count: length, opcode: opcode))
                continue
            }

            tokens.append(name(for: opcode) ?? String(format: "OP_UNKNOWN(0x%02x)", opcode))
        }
        return tokens.joined(separator: " ")
    }

    private static func take(
        _ bytes: [UInt8], at i: inout Int, count: Int, opcode: UInt8
    ) throws -> String {
        guard count >= 0, i + count <= bytes.count else {
            throw Failure.truncatedPush(opcode: opcode, wanted: count, available: bytes.count - i)
        }
        let slice = Data(bytes[i..<(i + count)])
        i += count
        return Hex.encode(slice)
    }

    private static func pushdataLengthWidth(_ opcode: UInt8) -> Int? {
        switch opcode {
        case 0x4C: return 1
        case 0x4D: return 2
        case 0x4E: return 4
        default:   return nil
        }
    }

    // MARK: - Assemble

    /// ASM → bytes. Tokens are resolved in this order, which is the
    /// order that makes ambiguity harmless:
    ///
    /// 1. `PUSHDATA(n)[hex]` and `[hex]` — bitcoinj's forms.
    /// 2. A known opcode name, with or without the `OP_` prefix.
    /// 3. A decimal integer — small values become `OP_0`…`OP_16`.
    /// 4. Hex, pushed as data.
    ///
    /// Opcodes are checked before hex on purpose. Without that,
    /// something like `DUP` is unambiguous but a bare `AB` is not: it
    /// reads as hex *and* as nothing else, while a name like `NOP` must
    /// never be mistaken for the byte pair it isn't.
    public static func assemble(_ asm: String) throws -> Data {
        let tokens = asm.split(whereSeparator: \.isWhitespace).map(String.init)
        guard !tokens.isEmpty else { throw Failure.emptyInput }

        var out = Data()
        for token in tokens {
            if let hex = bracketedHex(token) {
                out.append(ScriptBuilder.pushData(try Hex.decode(hex)))
                continue
            }
            let bare = token.hasPrefix("OP_") ? token : "OP_" + token
            if let opcode = opcode(named: bare.uppercased()) {
                out.append(opcode)
                continue
            }
            if let number = Int(token) {
                if (0...16).contains(number) {
                    out.append(ScriptBuilder.smallNumberOp(number))
                } else {
                    out.append(ScriptBuilder.pushData(scriptNumber(number)))
                }
                continue
            }
            guard Hex.isHex(token), let data = Hex.decodeOrNil(token) else {
                throw Failure.unknownToken(token)
            }
            out.append(ScriptBuilder.pushData(data))
        }
        return out
    }

    /// Extract the hex from `PUSHDATA(n)[hex]` or `[hex]`; nil when the
    /// token is neither.
    private static func bracketedHex(_ token: String) -> String? {
        guard token.hasSuffix("]"),
              let open = token.firstIndex(of: "["),
              token.hasPrefix("[") || token.hasPrefix("PUSHDATA(")
        else { return nil }
        let start = token.index(after: open)
        let end = token.index(before: token.endIndex)
        guard start <= end else { return nil }
        return String(token[start..<end])
    }

    /// Bitcoin's minimally-encoded signed little-endian number, for
    /// values outside the `OP_0`…`OP_16` range.
    static func scriptNumber(_ value: Int) -> Data {
        if value == 0 { return Data() }
        let negative = value < 0
        var magnitude = UInt64(abs(value))
        var out = Data()
        while magnitude > 0 {
            out.append(UInt8(magnitude & 0xFF))
            magnitude >>= 8
        }
        // The high bit of the last byte is the sign, so a value that
        // already fills it needs an extra byte to carry the sign.
        if out[out.count - 1] & 0x80 != 0 {
            out.append(negative ? 0x80 : 0x00)
        } else if negative {
            out[out.count - 1] |= 0x80
        }
        return out
    }

    // MARK: - Opcode table

    public static func name(for opcode: UInt8) -> String? {
        opcodeNames[opcode]
    }

    static func opcode(named name: String) -> UInt8? {
        opcodesByName[name]
    }

    private static let opcodesByName: [String: UInt8] = {
        var map = [String: UInt8]()
        for (code, name) in opcodeNames { map[name] = code }
        // Aliases bitcoinj and older tooling print.
        map["OP_FALSE"] = 0x00
        map["OP_TRUE"] = 0x51
        map["OP_NOP2"] = 0xB1  // renamed to OP_CHECKLOCKTIMEVERIFY
        map["OP_NOP3"] = 0xB2  // renamed to OP_CHECKSEQUENCEVERIFY
        return map
    }()

    private static let opcodeNames: [UInt8: String] = {
        var map: [UInt8: String] = [
            0x00: "OP_0",
            0x4C: "OP_PUSHDATA1", 0x4D: "OP_PUSHDATA2", 0x4E: "OP_PUSHDATA4",
            0x4F: "OP_1NEGATE", 0x50: "OP_RESERVED",
            0x61: "OP_NOP", 0x62: "OP_VER",
            0x63: "OP_IF", 0x64: "OP_NOTIF", 0x65: "OP_VERIF", 0x66: "OP_VERNOTIF",
            0x67: "OP_ELSE", 0x68: "OP_ENDIF", 0x69: "OP_VERIFY", 0x6A: "OP_RETURN",
            0x6B: "OP_TOALTSTACK", 0x6C: "OP_FROMALTSTACK",
            0x6D: "OP_2DROP", 0x6E: "OP_2DUP", 0x6F: "OP_3DUP",
            0x70: "OP_2OVER", 0x71: "OP_2ROT", 0x72: "OP_2SWAP",
            0x73: "OP_IFDUP", 0x74: "OP_DEPTH", 0x75: "OP_DROP", 0x76: "OP_DUP",
            0x77: "OP_NIP", 0x78: "OP_OVER", 0x79: "OP_PICK", 0x7A: "OP_ROLL",
            0x7B: "OP_ROT", 0x7C: "OP_SWAP", 0x7D: "OP_TUCK",
            0x7E: "OP_CAT", 0x7F: "OP_SPLIT", 0x80: "OP_NUM2BIN", 0x81: "OP_BIN2NUM",
            0x82: "OP_SIZE",
            0x83: "OP_INVERT", 0x84: "OP_AND", 0x85: "OP_OR", 0x86: "OP_XOR",
            0x87: "OP_EQUAL", 0x88: "OP_EQUALVERIFY",
            0x89: "OP_RESERVED1", 0x8A: "OP_RESERVED2",
            0x8B: "OP_1ADD", 0x8C: "OP_1SUB", 0x8D: "OP_2MUL", 0x8E: "OP_2DIV",
            0x8F: "OP_NEGATE", 0x90: "OP_ABS", 0x91: "OP_NOT", 0x92: "OP_0NOTEQUAL",
            0x93: "OP_ADD", 0x94: "OP_SUB", 0x95: "OP_MUL", 0x96: "OP_DIV",
            0x97: "OP_MOD", 0x98: "OP_LSHIFT", 0x99: "OP_RSHIFT",
            0x9A: "OP_BOOLAND", 0x9B: "OP_BOOLOR",
            0x9C: "OP_NUMEQUAL", 0x9D: "OP_NUMEQUALVERIFY", 0x9E: "OP_NUMNOTEQUAL",
            0x9F: "OP_LESSTHAN", 0xA0: "OP_GREATERTHAN",
            0xA1: "OP_LESSTHANOREQUAL", 0xA2: "OP_GREATERTHANOREQUAL",
            0xA3: "OP_MIN", 0xA4: "OP_MAX", 0xA5: "OP_WITHIN",
            0xA6: "OP_RIPEMD160", 0xA7: "OP_SHA1", 0xA8: "OP_SHA256",
            0xA9: "OP_HASH160", 0xAA: "OP_HASH256",
            0xAB: "OP_CODESEPARATOR",
            0xAC: "OP_CHECKSIG", 0xAD: "OP_CHECKSIGVERIFY",
            0xAE: "OP_CHECKMULTISIG", 0xAF: "OP_CHECKMULTISIGVERIFY",
            0xB0: "OP_NOP1",
            0xB1: "OP_CHECKLOCKTIMEVERIFY", 0xB2: "OP_CHECKSEQUENCEVERIFY",
            0xB3: "OP_NOP4", 0xB4: "OP_NOP5", 0xB5: "OP_NOP6",
            0xB6: "OP_NOP7", 0xB7: "OP_NOP8", 0xB8: "OP_NOP9", 0xB9: "OP_NOP10",
            0xBA: "OP_CHECKDATASIG", 0xBB: "OP_CHECKDATASIGVERIFY",
            0xBC: "OP_REVERSEBYTES",
        ]
        // OP_1 … OP_16 are contiguous.
        for n in 1...16 { map[UInt8(0x50 + n)] = "OP_\(n)" }
        return map
    }()
}
