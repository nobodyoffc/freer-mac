import Foundation

/// Wallet Import Format (WIF) decoder for FCH/Bitcoin mainnet
/// privkeys. The wire format is the same as Bitcoin's:
///
/// ```
/// base58check( 0x80 ‖ privkey(32) [‖ 0x01 if compressed] )
/// ```
///
/// `L`-prefixed strings are mainnet *compressed* (the trailing `0x01`
/// is present, total payload 34 B). `K`-prefixed are also compressed.
/// `5`-prefixed are mainnet *uncompressed* (no trailing flag, 33 B).
///
/// We accept all three but always strip the compressed flag — the
/// stored privkey is the same 32-byte scalar regardless. The caller
/// can derive a compressed pubkey deterministically afterwards.
public enum WifPrivkey {

    public static let mainnetVersionByte: UInt8 = 0x80
    public static let compressedFlagByte: UInt8 = 0x01

    public enum Failure: Error, CustomStringConvertible {
        case base58(Base58.Failure)
        case wrongVersionByte(UInt8)
        case wrongPayloadLength(Int)
        case missingCompressedFlag

        public var description: String {
            switch self {
            case .base58(let inner):           return "WIF: base58 — \(inner)"
            case .wrongVersionByte(let b):     return String(format: "WIF: expected version byte 0x80, got 0x%02x", b)
            case .wrongPayloadLength(let n):   return "WIF: payload must be 33 or 34 bytes, got \(n)"
            case .missingCompressedFlag:       return "WIF: 34-byte payload but trailing flag is not 0x01"
            }
        }
    }

    /// Decode a WIF string and return `(privkey, compressed)`.
    /// `compressed=true` matches the `L`/`K` prefixes; `false` is `5`.
    public static func decode(_ wif: String) throws -> (privkey: Data, compressed: Bool) {
        let payload: Data
        do {
            payload = try Base58Check.decode(wif)
        } catch let e as Base58.Failure {
            throw Failure.base58(e)
        }
        guard !payload.isEmpty, payload[payload.startIndex] == mainnetVersionByte else {
            throw Failure.wrongVersionByte(payload.first ?? 0)
        }
        switch payload.count {
        case 33:
            // uncompressed: 1 + 32
            let privkey = Data(payload.dropFirst())
            return (privkey, false)
        case 34:
            // compressed: 1 + 32 + 1
            let privkey = Data(payload.dropFirst().prefix(32))
            let flag = payload[payload.index(payload.startIndex, offsetBy: 33)]
            guard flag == compressedFlagByte else {
                throw Failure.missingCompressedFlag
            }
            return (privkey, true)
        default:
            throw Failure.wrongPayloadLength(payload.count)
        }
    }

    /// Encode a 32-byte privkey to WIF. `compressed` decides which
    /// flag byte and Base58 prefix the result will have.
    public static func encode(privkey: Data, compressed: Bool = true) -> String {
        var payload = Data(capacity: compressed ? 34 : 33)
        payload.append(mainnetVersionByte)
        payload.append(privkey)
        if compressed { payload.append(compressedFlagByte) }
        return Base58Check.encode(payload)
    }
}
