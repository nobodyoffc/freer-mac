import Foundation

/// FCH (FreeCash) legacy address — Base58Check(`version || hash160`).
///
/// Mainnet P2PKH version byte is `0x23`, which produces "F…" addresses
/// (FIDs). This is the only address format Freer uses; there is no
/// CashAddr or Bech32 variant.
public struct FchAddress: Equatable, Hashable, Sendable {

    public static let mainnetVersionByte: UInt8 = 0x23
    public static let hash160Length = 20

    public let versionByte: UInt8

    /// The 20-byte pubkey hash (`Hash.hash160(pubkey)`).
    public let hash160: Data

    public enum Failure: Error, CustomStringConvertible {
        case invalidHashLength(got: Int)
        case invalidPayloadLength(got: Int)
        case unexpectedVersionByte(got: UInt8, expected: UInt8)
        case base58(Base58.Failure)

        public var description: String {
            switch self {
            case let .invalidHashLength(got):
                return "FchAddress: hash must be 20 bytes, got \(got)"
            case let .invalidPayloadLength(got):
                return "FchAddress: payload must be 21 bytes (version+hash160), got \(got)"
            case let .unexpectedVersionByte(got, expected):
                let fmt: (UInt8) -> String = { String(format: "0x%02x", $0) }
                return "FchAddress: version byte \(fmt(got)) != expected \(fmt(expected))"
            case .base58(let e):
                return "FchAddress: \(e)"
            }
        }
    }

    public init(versionByte: UInt8 = mainnetVersionByte, hash160: Data) throws {
        guard hash160.count == FchAddress.hash160Length else {
            throw Failure.invalidHashLength(got: hash160.count)
        }
        self.versionByte = versionByte
        self.hash160 = Data(hash160)
    }

    /// Construct from a 33-byte compressed public key.
    public init(publicKey: Data, versionByte: UInt8 = mainnetVersionByte) throws {
        try self.init(versionByte: versionByte, hash160: Hash.hash160(publicKey))
    }

    /// Parse a Base58Check-encoded FID. Defaults to requiring the FCH
    /// mainnet version byte; pass `expectedVersionByte: nil` to accept
    /// any version.
    public init(fid: String, expectedVersionByte: UInt8? = FchAddress.mainnetVersionByte) throws {
        let payload: Data
        do {
            payload = try Base58Check.decode(fid)
        } catch let error as Base58.Failure {
            throw Failure.base58(error)
        }
        guard payload.count == FchAddress.hash160Length + 1 else {
            throw Failure.invalidPayloadLength(got: payload.count)
        }
        let normalized = Data(payload)
        let version = normalized[0]
        if let expected = expectedVersionByte, version != expected {
            throw Failure.unexpectedVersionByte(got: version, expected: expected)
        }
        self.versionByte = version
        self.hash160 = Data(normalized.dropFirst())
    }

    /// Encoded Base58Check FID (e.g. `FEk41Kqjar45fLDriztUDTUkdki7mmcjWK`).
    public var fid: String {
        var payload = Data([versionByte])
        payload.append(hash160)
        return Base58Check.encode(payload)
    }
}
