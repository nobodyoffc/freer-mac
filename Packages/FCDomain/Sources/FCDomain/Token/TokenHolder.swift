import Foundation
import FCCore

/// One FID's balance of one token — the Swift mirror of the Java
/// `feipData.TokenHolder`, and the record type of the `token_holder`
/// index.
///
/// **The id is derived, not assigned.** It is `sha256(fid + tokenId)`
/// in hex, which is what makes a holder row addressable without the
/// chain having to mint an identifier for every (holder, token) pair —
/// and what lets this client compute the id of a row it has never seen.
/// See ``id(fid:tokenId:)``.
public struct TokenHolder: Codable, Equatable, Sendable, Identifiable {

    // MARK: - wire fields, in Java declaration order

    public var fid: String?
    public var tokenId: String?
    /// The balance, as the indexer holds it.
    ///
    /// **A double, matching the indexer.** Every other numeric field on
    /// this path is a string precisely so that what the deployer signed
    /// survives round-tripping — but this one is not signed by anybody.
    /// It is the indexer's running sum, it arrives as a JSON number, and
    /// re-typing it here would only disguise the precision the chain
    /// already committed to. What this client *carves* keeps the user's
    /// exact digits; see ``TokenTransfer``.
    public var balance: Double?
    public var firstHeight: Int64?
    public var lastHeight: Int64?

    public var id: String

    // MARK: - local bookkeeping

    public var addedAt: Date
    public var updatedAt: Date

    private enum CodingKeys: String, CodingKey {
        case fid, tokenId, balance, firstHeight, lastHeight, id
        case addedAt, updatedAt
    }

    public init(
        id: String? = nil,
        fid: String? = nil,
        tokenId: String? = nil,
        balance: Double? = nil,
        firstHeight: Int64? = nil,
        lastHeight: Int64? = nil,
        addedAt: Date = Date(),
        updatedAt: Date = Date()
    ) {
        self.fid = fid
        self.tokenId = tokenId
        self.balance = balance
        self.firstHeight = firstHeight
        self.lastHeight = lastHeight
        self.addedAt = addedAt
        self.updatedAt = updatedAt
        if let id, !id.isEmpty {
            self.id = id
        } else if let fid, let tokenId {
            self.id = Self.id(fid: fid, tokenId: tokenId)
        } else {
            self.id = ""
        }
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        fid = try c.decodeIfPresent(String.self, forKey: .fid)
        tokenId = try c.decodeIfPresent(String.self, forKey: .tokenId)
        balance = try c.decodeIfPresent(Double.self, forKey: .balance)
        firstHeight = try c.decodeIfPresent(Int64.self, forKey: .firstHeight)
        lastHeight = try c.decodeIfPresent(Int64.self, forKey: .lastHeight)
        addedAt = (try c.decodeIfPresent(Date.self, forKey: .addedAt)) ?? Date()
        updatedAt = (try c.decodeIfPresent(Date.self, forKey: .updatedAt)) ?? Date()
        // Java's `getId()` derives the id lazily when the field is
        // absent; this does the same at the decode boundary so no
        // caller downstream has to wonder whether the id is filled in.
        let wire = try c.decodeIfPresent(String.self, forKey: .id)
        if let wire, !wire.isEmpty {
            id = wire
        } else if let fid, let tokenId {
            id = Self.id(fid: fid, tokenId: tokenId)
        } else {
            id = ""
        }
    }

    /// The record id of `fid`'s holding of `tokenId` — hex of
    /// `sha256(fid + tokenId)`, matching Java's
    /// `TokenHolder.getTokenHolderId`.
    ///
    /// Single sha256, **not** the double-sha256 that ids transactions.
    /// Getting that wrong produces a well-formed id that addresses
    /// nothing, which the by-ids endpoint reports as an empty result
    /// rather than an error.
    public static func id(fid: String, tokenId: String) -> String {
        Hex.encode(Hash.sha256(Data((fid + tokenId).utf8)))
    }

    /// A locally constructed row for a balance this device knows about
    /// but the indexer has not confirmed — used to show a just-carved
    /// issue against your own FID before the block lands.
    public static func local(fid: String, tokenId: String, balance: Double? = nil) -> TokenHolder {
        TokenHolder(
            id: Self.id(fid: fid, tokenId: tokenId),
            fid: fid, tokenId: tokenId, balance: balance
        )
    }

    /// Whether there is anything here to spend. A holder row can
    /// legitimately sit at zero — the chain keeps it once it has
    /// existed — and a Send button on such a row leads nowhere.
    public var hasBalance: Bool { (balance ?? 0) > 0 }

    /// Case-insensitive substring match across the fields the
    /// `token_holder` index exposes to search (`tokenId`, `id`), plus
    /// `fid`, so the local filter is never narrower than the chain's.
    public func matches(query: String) -> Bool {
        let needle = query.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !needle.isEmpty else { return false }
        func hit(_ s: String?) -> Bool {
            guard let s else { return false }
            return s.lowercased().contains(needle)
        }
        return hit(tokenId) || hit(fid) || hit(id)
    }
}
