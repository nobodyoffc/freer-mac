import Foundation

/// One secp256k1 key, seven chains' worth of addresses — the port of
/// Android's `KeyTools.pubkeyToAddresses` / `hash160ToAddresses`.
///
/// The two entry points answer genuinely different questions, and the
/// difference is not cosmetic:
///
/// - ``fromPubkey(_:)`` starts from a key, so it can reach the chains
///   whose address is a hash of the *uncompressed* key rather than of
///   hash160 — ETH and TRX. Its Bitcoin entry is the legacy `1…` form.
/// - ``fromHash160(_:)`` starts from an already-hashed address, so ETH
///   and TRX are unreachable (their hash is over different bytes and
///   cannot be recovered from a hash160) and are reported as `nil`
///   rather than as a wrong-but-plausible string. Its Bitcoin entry is
///   the segwit `bc1…` form.
///
/// Preserving that asymmetry matters: a hash160 lifted from an FCH
/// address and re-rendered as an "ETH address" would be an address
/// nobody holds the key to, and funds sent there are gone.
public enum ChainAddresses {

    /// Chains in the order the converter lists them.
    public enum Chain: String, CaseIterable, Sendable {
        case fch = "FCH"
        case btc = "BTC"
        case bch = "BCH"
        case ltc = "LTC"
        case doge = "DOGE"
        case eth = "ETH"
        case trx = "TRX"
    }

    // Base58Check version bytes.
    static let btcVersionByte: UInt8 = 0x00
    static let ltcVersionByte: UInt8 = 0x30
    static let dogeVersionByte: UInt8 = 0x1E
    static let trxVersionByte: UInt8 = 0x41

    /// Every address derivable from a public key, compressed or not.
    /// Values are ordered by ``Chain/allCases``; a chain that fails to
    /// derive is omitted rather than shown blank.
    public static func fromPubkey(_ input: String) throws -> [(Chain, String)] {
        let pubkey33 = try PubkeyFormats.pubkey33(from: input)
        let hash160 = Hash.hash160(try Hex.decode(pubkey33))

        var out: [(Chain, String)] = []
        out.append((.fch, try FchAddress(hash160: hash160).fid))
        out.append((.btc, base58Address(hash160: hash160, version: btcVersionByte)))
        if let bch = try? CashAddr.encode(hash: hash160) { out.append((.bch, bch)) }
        out.append((.ltc, base58Address(hash160: hash160, version: ltcVersionByte)))
        out.append((.doge, base58Address(hash160: hash160, version: dogeVersionByte)))
        if let eth = try? ethAddress(pubkey33: pubkey33) { out.append((.eth, eth)) }
        if let trx = try? trxAddress(pubkey33: pubkey33) { out.append((.trx, trx)) }
        return out
    }

    /// Every address derivable from a 20-byte pubkey hash. ETH and TRX
    /// are absent by construction — see the type's note.
    public static func fromHash160(_ hash160: Data) throws -> [(Chain, String)] {
        guard hash160.count == 20 else {
            throw FchAddress.Failure.invalidHashLength(got: hash160.count)
        }
        var out: [(Chain, String)] = []
        out.append((.fch, try FchAddress(hash160: hash160).fid))
        out.append((.btc, try Bech32.segwitAddress(hash160: hash160)))
        if let bch = try? CashAddr.encode(hash: hash160) { out.append((.bch, bch)) }
        out.append((.ltc, base58Address(hash160: hash160, version: ltcVersionByte)))
        out.append((.doge, base58Address(hash160: hash160, version: dogeVersionByte)))
        return out
    }

    /// The 20-byte hash160 inside any Base58Check P2PKH address,
    /// whatever chain's version byte it carries. Android's
    /// `KeyTools.addrToHash160` blindly slices bytes 1…21 off a plain
    /// Base58 decode; going through Base58Check instead means a
    /// mistyped address is rejected on its checksum rather than
    /// converted into somebody else's addresses.
    public static func hash160(fromAddress address: String) throws -> Data {
        let payload = try Base58Check.decode(address.trimmingCharacters(in: .whitespacesAndNewlines))
        guard payload.count == 21 else {
            throw FchAddress.Failure.invalidPayloadLength(got: payload.count)
        }
        return Data(payload.dropFirst())
    }

    /// `version || hash160` under Base58Check — the shape BTC, LTC and
    /// DOGE all share, differing only in that first byte.
    static func base58Address(hash160: Data, version: UInt8) -> String {
        Base58Check.encode(Data([version]) + hash160)
    }

    /// `0x` + the low 20 bytes of `keccak256(x || y)`.
    static func ethAddress(pubkey33: String) throws -> String {
        let pubkey65 = try PubkeyFormats.decompress(pubkey33: pubkey33)
        let xy = try Hex.decode(String(pubkey65.dropFirst(2)))
        return "0x" + Hex.encode(Hash.keccak256(xy).suffix(20))
    }

    /// TRON: same keccak digest as ETH, but the low 20 bytes get a
    /// `0x41` version byte and are Base58Check-encoded into a `T…`.
    static func trxAddress(pubkey33: String) throws -> String {
        let pubkey65 = try PubkeyFormats.decompress(pubkey33: pubkey33)
        let xy = try Hex.decode(String(pubkey65.dropFirst(2)))
        let digest = Data(Hash.keccak256(xy).suffix(20))
        return Base58Check.encode(Data([trxVersionByte]) + digest)
    }
}
