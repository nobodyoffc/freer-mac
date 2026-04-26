import Foundation

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
        Double(satoshis) / Double(Cash.satoshisPerBch)
    }
}
