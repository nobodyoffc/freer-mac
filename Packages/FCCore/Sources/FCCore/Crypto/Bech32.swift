import Foundation

/// The two base-32 address encodings the Address converter needs, which
/// share an alphabet and a bit-packing but *not* a checksum.
///
/// - ``Bech32`` is BIP-173, used for Bitcoin `bc1…` segwit addresses:
///   a 30-bit polymod over a `hrp`-expanded prefix, separator `1`, 6
///   checksum characters.
/// - ``CashAddr`` is the Bitcoin Cash variant: a 40-bit polymod with
///   its own generators, separator `:`, 8 checksum characters, and a
///   version byte folded into the payload rather than a witness
///   version.
///
/// Mixing the two silently produces a well-formed string that no wallet
/// on either chain will accept, so they are deliberately separate types
/// with no shared checksum code.
public enum Bech32 {

    static let charset = Array("qpzry9x8gf2tvdw0s3jn54khce6mua7l")

    public enum Failure: Error, CustomStringConvertible {
        case programLength(got: Int)
        case tooLong(got: Int)

        public var description: String {
            switch self {
            case let .programLength(got):
                return "Bech32: witness program must be 20 or 32 bytes, got \(got)"
            case let .tooLong(got):
                return "Bech32: address would be \(got) characters, over the 90 limit"
            }
        }
    }

    private static let generator: [UInt32] = [
        0x3b6a_57b2, 0x2650_8e6d, 0x1ea1_19fa, 0x3d42_33dd, 0x2a14_62b3,
    ]

    /// BIP-141 native segwit address: `hrp || "1" || witver || program`.
    /// Witness version 0 with a 20-byte program is P2WPKH — the `bc1q…`
    /// address a hash160 maps to.
    public static func segwitAddress(
        hash160: Data, hrp: String = "bc", witnessVersion: UInt8 = 0
    ) throws -> String {
        guard hash160.count == 20 || hash160.count == 32 else {
            throw Failure.programLength(got: hash160.count)
        }
        var words: [UInt8] = [witnessVersion]
        words += BitPacking.convert(Array(hash160), from: 8, to: 5, pad: true)
        return try encode(hrp: hrp, words: words)
    }

    /// Raw BIP-173 encode over 5-bit words.
    public static func encode(hrp: String, words: [UInt8]) throws -> String {
        let total = hrp.count + 1 + words.count + 6
        guard total <= 90 else { throw Failure.tooLong(got: total) }
        var combined = hrpExpand(hrp)
        combined += words
        combined += [0, 0, 0, 0, 0, 0]
        let mod = polymod(combined) ^ 1
        let checksum = (0..<6).map { UInt8((mod >> (5 * (5 - UInt32($0)))) & 31) }
        let body = (words + checksum).map { charset[Int($0)] }
        return hrp + "1" + String(body)
    }

    private static func hrpExpand(_ hrp: String) -> [UInt8] {
        let scalars = Array(hrp.unicodeScalars).map { UInt8($0.value & 0xFF) }
        return scalars.map { $0 >> 5 } + [0] + scalars.map { $0 & 31 }
    }

    private static func polymod(_ values: [UInt8]) -> UInt32 {
        var chk: UInt32 = 1
        for value in values {
            let b = chk >> 25
            chk = ((chk & 0x01FF_FFFF) << 5) ^ UInt32(value)
            for i in 0..<5 where (b >> UInt32(i)) & 1 == 1 {
                chk ^= generator[i]
            }
        }
        return chk
    }
}

/// Bitcoin Cash CashAddr (spec: bitcoincashorg/bitcoincash.org).
public enum CashAddr {

    public enum Failure: Error, CustomStringConvertible {
        case unsupportedHashLength(got: Int)

        public var description: String {
            switch self {
            case let .unsupportedHashLength(got):
                return "CashAddr: hash length \(got) is not one of 20, 24, 28, 32, 40, 48, 56, 64 bytes"
            }
        }
    }

    /// Address type nibble in the version byte.
    public enum Kind: UInt8 {
        case p2pkh = 0
        case p2sh = 1
    }

    private static let generator: [UInt64] = [
        0x98f2_bc8e_61, 0x79b7_6d99_e2, 0xf33e_5fb3_c4, 0xae2e_abe2_a8, 0x1e4f_43e4_70,
    ]

    /// Encode a hash as a CashAddr payload.
    ///
    /// Returned **without** the `bitcoincash:` prefix, matching Android's
    /// `BchCashAddr.hash160ToCashAddr`, which strips everything up to the
    /// colon before handing the string to the UI.
    public static func encode(
        hash: Data, kind: Kind = .p2pkh, prefix: String = "bitcoincash"
    ) throws -> String {
        guard let sizeBits = sizeBits(forByteCount: hash.count) else {
            throw Failure.unsupportedHashLength(got: hash.count)
        }
        var payload = Data([kind.rawValue << 3 | sizeBits])
        payload.append(hash)
        let words = BitPacking.convert(Array(payload), from: 8, to: 5, pad: true)

        var chk = prefixChk(prefix)
        for word in words {
            chk = polymod(chk) ^ UInt64(word)
        }
        for _ in 0..<8 { chk = polymod(chk) }
        chk ^= 1

        let checksum = (0..<8).map { UInt8((chk >> (5 * (7 - UInt64($0)))) & 0x1F) }
        return String((words + checksum).map { Bech32.charset[Int($0)] })
    }

    /// The full `prefix:payload` form, for when the caller wants the
    /// unambiguous address rather than the bare one.
    public static func encodeWithPrefix(
        hash: Data, kind: Kind = .p2pkh, prefix: String = "bitcoincash"
    ) throws -> String {
        prefix + ":" + (try encode(hash: hash, kind: kind, prefix: prefix))
    }

    /// Spec table: 160-bit hash → 0, then +32 bits per step up to 512.
    private static func sizeBits(forByteCount count: Int) -> UInt8? {
        switch count * 8 {
        case 160: return 0
        case 192: return 1
        case 224: return 2
        case 256: return 3
        case 320: return 4
        case 384: return 5
        case 448: return 6
        case 512: return 7
        default:  return nil
        }
    }

    private static func prefixChk(_ prefix: String) -> UInt64 {
        var chk: UInt64 = 1
        for scalar in prefix.lowercased().unicodeScalars {
            chk = polymod(chk) ^ UInt64(scalar.value & 0x1F)
        }
        return polymod(chk)
    }

    private static func polymod(_ pre: UInt64) -> UInt64 {
        let b = pre >> 35
        var v = (pre & 0x07_FFFF_FFFF) << 5
        for i in 0..<5 where (b >> UInt64(i)) & 1 == 1 {
            v ^= generator[i]
        }
        return v
    }
}

/// 8-bit ⇄ 5-bit regrouping shared by both encodings.
enum BitPacking {

    /// Regroup `data` from `inBits`-wide to `outBits`-wide units. With
    /// `pad`, a trailing partial group is zero-filled (what encoding
    /// needs); without it, leftover bits are dropped (what decoding
    /// needs).
    static func convert(_ data: [UInt8], from inBits: Int, to outBits: Int, pad: Bool) -> [UInt8] {
        var acc = 0
        var bits = 0
        var out: [UInt8] = []
        let maxValue = (1 << outBits) - 1
        for byte in data {
            acc = (acc << inBits) | Int(byte)
            bits += inBits
            while bits >= outBits {
                bits -= outBits
                out.append(UInt8((acc >> bits) & maxValue))
            }
        }
        if pad, bits > 0 {
            out.append(UInt8((acc << (outBits - bits)) & maxValue))
        }
        return out
    }
}
