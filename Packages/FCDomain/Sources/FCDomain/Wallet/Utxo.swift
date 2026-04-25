import Foundation

/// One unspent FCH cash output. The Mac side stores `value` in
/// satoshis (Int64), even though the FAPI wire format encodes
/// `amount` as a JSON `double` of BCH (× 1e8). Doing the conversion
/// at decode time keeps coin selection and fee math integer-pure
/// — floating-point arithmetic in the wallet path is a recipe for
/// off-by-one-satoshi bugs.
public struct Utxo: Codable, Equatable, Hashable, Sendable {

    public static let satoshisPerBch: Int64 = 100_000_000

    public var addr: String
    public var txid: String
    public var index: Int
    public var value: Int64           // satoshis
    public var issuer: String?
    public var birthTime: Int64?      // block time (seconds since epoch)

    public init(
        addr: String,
        txid: String,
        index: Int,
        value: Int64,
        issuer: String? = nil,
        birthTime: Int64? = nil
    ) {
        self.addr = addr
        self.txid = txid
        self.index = index
        self.value = value
        self.issuer = issuer
        self.birthTime = birthTime
    }

    /// Parse the `data` array from a `base.getUtxo` FAPI response.
    /// The wire shape uses `amount` (double BCH) and `txId` (camel-Z),
    /// so this codec is wire-specific and intentionally separate from
    /// the standard `Codable` synthesis used for local caching.
    public static func parseFapiList(_ rawJson: Data) throws -> [Utxo] {
        let parsed = try JSONSerialization.jsonObject(with: rawJson, options: [])
        guard let array = parsed as? [[String: Any]] else {
            throw Failure.unexpectedResponseShape
        }
        return try array.map { dict in
            guard
                let addr = dict["addr"] as? String,
                let txid = dict["txId"] as? String,
                let index = (dict["index"] as? NSNumber)?.intValue
            else {
                throw Failure.missingRequiredField
            }
            let amountBch = (dict["amount"] as? NSNumber)?.doubleValue ?? 0
            // Round to nearest satoshi: Java emits 1e8-scaled doubles,
            // which round-trip exactly for any reasonable balance, but
            // floor() instead of round() would silently lose 1 sat in
            // edge cases.
            let satoshis = Int64((amountBch * Double(satoshisPerBch)).rounded())
            return Utxo(
                addr: addr,
                txid: txid,
                index: index,
                value: satoshis,
                issuer: dict["issuer"] as? String,
                birthTime: (dict["birthTime"] as? NSNumber)?.int64Value
            )
        }
    }

    public enum Failure: Error, CustomStringConvertible {
        case unexpectedResponseShape
        case missingRequiredField

        public var description: String {
            switch self {
            case .unexpectedResponseShape: return "Utxo: FAPI response data was not a JSON array of objects"
            case .missingRequiredField:    return "Utxo: required field (addr/txId/index) missing or wrong type"
            }
        }
    }
}

/// Aggregate balance for a single FID, returned by ``WalletService``.
/// `bestHeight` and `bestBlockId` come from the surrounding
/// ``FapiResponse`` envelope when present.
public struct Balance: Codable, Equatable, Sendable {
    public var fid: String
    public var satoshis: Int64
    public var bestHeight: Int64?
    public var bestBlockId: String?
    public var fetchedAt: Date

    public init(
        fid: String,
        satoshis: Int64,
        bestHeight: Int64? = nil,
        bestBlockId: String? = nil,
        fetchedAt: Date = Date()
    ) {
        self.fid = fid
        self.satoshis = satoshis
        self.bestHeight = bestHeight
        self.bestBlockId = bestBlockId
        self.fetchedAt = fetchedAt
    }

    public var bch: Double {
        Double(satoshis) / Double(Utxo.satoshisPerBch)
    }
}
