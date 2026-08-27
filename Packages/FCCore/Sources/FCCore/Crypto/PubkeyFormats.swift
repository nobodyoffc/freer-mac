import Foundation
import BigInt

/// The half-dozen shapes a secp256k1 public key gets written in, and the
/// conversions between them — the port of Android's `KeyTools` pubkey
/// block (`getPubkey33`, `recoverPK33ToPK65`, `compressPk65To33`,
/// `getPubkeyWif*`).
///
/// Two of these forms are Base58Check with *no version byte* and one is
/// Base58Check with version `0x00`, which is why they can't share
/// ``FchAddress``' encoder: same alphabet, different payload rules.
public enum PubkeyFormats {

    public enum Failure: Error, CustomStringConvertible {
        case unrecognizedForm(length: Int)
        case badPrefix(String)
        case notOnCurve

        public var description: String {
            switch self {
            case let .unrecognizedForm(length):
                return "Pubkey: \(length) characters is not a recognized public key form"
            case let .badPrefix(prefix):
                return "Pubkey: prefix '\(prefix)' is not 02, 03 or 04"
            case .notOnCurve:
                return "Pubkey: the x coordinate has no matching y on secp256k1"
            }
        }
    }

    /// Field prime of secp256k1. Local rather than reaching into
    /// ``BchSchnorr`` so the two can't drift apart by accident.
    private static let p = BigInt(
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", radix: 16
    )!

    /// True when `string` is a bare hex public key — 33-byte compressed
    /// with an `02`/`03` prefix, or 65-byte uncompressed with `04`.
    /// Android's `KeyTools.isPubkey`, used by the Address converter to
    /// decide whether it was handed a key or an address.
    public static func isPubkey(_ string: String) -> Bool {
        guard Hex.isHex(string) else { return false }
        switch string.count {
        case 66:  return string.hasPrefix("02") || string.hasPrefix("03")
        case 130: return string.hasPrefix("04")
        default:  return false
        }
    }

    /// Normalize any accepted public-key form to 33-byte compressed hex.
    ///
    /// Accepts compressed hex (66), uncompressed hex (130), Base58Check
    /// without a version byte (50), and Base58Check with version `0x00`
    /// (51) — the three encodings ``wifForms(ofPubkey33:)`` emits, so a
    /// result pasted back in round-trips.
    public static func pubkey33(from input: String) throws -> String {
        let key = input.trimmingCharacters(in: .whitespacesAndNewlines)
        switch key.count {
        case 66:
            guard key.hasPrefix("02") || key.hasPrefix("03"), Hex.isHex(key) else {
                throw Failure.badPrefix(String(key.prefix(2)))
            }
            return key.lowercased()
        case 130:
            guard key.hasPrefix("04"), Hex.isHex(key) else {
                throw Failure.badPrefix(String(key.prefix(2)))
            }
            return try compress(pubkey65: key)
        case 50:
            return Hex.encode(try Base58Check.decode(key))
        case 51:
            // Version-prefixed: drop the leading 0x00 byte.
            return Hex.encode(try Base58Check.decode(key).dropFirst())
        default:
            throw Failure.unrecognizedForm(length: key.count)
        }
    }

    /// Compressed (33-byte) hex → uncompressed (65-byte) hex, by solving
    /// `y² = x³ + 7` over the field and picking the root whose parity
    /// matches the `02`/`03` prefix.
    public static func decompress(pubkey33: String) throws -> String {
        let key = pubkey33.lowercased()
        let prefix = String(key.prefix(2))
        guard prefix == "02" || prefix == "03" else { throw Failure.badPrefix(prefix) }
        guard let x = BigInt(String(key.dropFirst(2)), radix: 16) else {
            throw Failure.badPrefix(prefix)
        }

        let ySquared = (x.power(3, modulus: p) + 7).modulus(p)
        // p ≡ 3 (mod 4), so the square root is a single exponentiation.
        var y = ySquared.power((p + 1) / 4, modulus: p)
        guard y.power(2, modulus: p) == ySquared else { throw Failure.notOnCurve }

        let wantOdd = (prefix == "03")
        if y.isMultiple(of: 2) == wantOdd { y = p - y }

        return "04" + String(key.dropFirst(2)) + Hex.encode(leftPadded(y, to: 32))
    }

    /// Uncompressed (65-byte, `04…`) or bare 64-byte hex → compressed
    /// hex. The prefix follows the parity of the final y byte.
    public static func compress(pubkey65: String) throws -> String {
        let key = pubkey65.lowercased()
        let body: String
        switch key.count {
        case 130 where key.hasPrefix("04"): body = String(key.dropFirst(2))
        case 128:                           body = key
        default: throw Failure.unrecognizedForm(length: key.count)
        }
        let x = String(body.prefix(64))
        let y = String(body.suffix(64))
        guard let lastNibble = y.last.flatMap({ $0.hexDigitValue }) else {
            throw Failure.unrecognizedForm(length: key.count)
        }
        return (lastNibble % 2 == 0 ? "02" : "03") + x
    }

    /// The three Base58 renderings Android's Pubkey converter shows,
    /// keyed exactly as it labels them.
    public static func wifForms(ofPubkey33 pubkey33: String) throws -> (
        uncompressed: String, compressedWithVersion0: String, compressedWithoutVersion: String
    ) {
        let compressed = try Hex.decode(pubkey33)
        let uncompressed = try Hex.decode(decompress(pubkey33: pubkey33))
        return (
            uncompressed: Base58Check.encode(Data([0x00]) + uncompressed),
            compressedWithVersion0: Base58Check.encode(Data([0x00]) + compressed),
            compressedWithoutVersion: Base58Check.encode(compressed)
        )
    }

    /// Big-endian bytes of a non-negative `value`, zero-padded on the
    /// left to `length`. BigInt's own serialization drops leading zero
    /// bytes, which would produce a 64-character key with a short y.
    private static func leftPadded(_ value: BigInt, to length: Int) -> Data {
        let bytes = value.magnitude.serialize()
        if bytes.count >= length { return Data(bytes.suffix(length)) }
        return Data(repeating: 0, count: length - bytes.count) + bytes
    }
}
