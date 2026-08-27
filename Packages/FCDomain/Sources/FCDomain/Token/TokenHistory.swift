import Foundation

/// One token operation as the chain recorded it — the Swift mirror of
/// the Java `feipData.TokenHistory`, and the record type of the
/// `token_history` index.
///
/// This is the audit trail behind ``Token`` and ``TokenHolder``: those
/// two are *state*, derived by the indexer from the stream of ops; this
/// is the stream. Every field the `deploy` carve set appears here as
/// carved, which is why a history row is the only place to see what a
/// token's rules were at the moment they were fixed.
///
/// **The flags are strings here and booleans on ``Token``, and that is
/// not an oversight.** Java declares them `String` on this type
/// because a history row echoes the carve's own JSON text, and a carve
/// that wrote `"transferable":"true"` should read back as it was
/// written rather than as what a parser made of it. ``Token`` holds the
/// indexer's interpretation; this holds the record.
public struct TokenHistory: Codable, Equatable, Sendable, Identifiable {

    /// A payout line in an `issue` or `transfer` op — the Swift mirror
    /// of Java's nested `TokenHistory.FidAmount`.
    ///
    /// The amount is a double because that is how it arrives from the
    /// indexer; see ``TokenHolder/balance``. Nothing this client
    /// *carves* goes through this type — see ``TokenTransfer``.
    public struct FidAmount: Codable, Equatable, Sendable {
        public var fid: String?
        public var amount: Double?

        public init(fid: String? = nil, amount: Double? = nil) {
            self.fid = fid
            self.amount = amount
        }
    }

    // MARK: - wire fields, in Java declaration order

    /// The ids a `destroy` or `close` op named. The op-specific
    /// companion to ``tokenId``, which the single-token ops carry.
    public var tokenIds: [String]?
    public var height: Int64?
    /// Position of this op within its block.
    public var index: Int?
    /// Seconds since the epoch.
    public var time: Int64?
    /// Who signed the carve. For `issue` this is the issuer, for
    /// `transfer` the sender, for `deploy` the deployer.
    public var signer: String?
    /// The counterparty the indexer attributed the op to, when there is
    /// exactly one. Multi-recipient ops put everyone in ``transferTo`` /
    /// ``issueTo`` instead, so this can be nil on a perfectly ordinary
    /// row.
    public var recipient: String?
    /// Coin-days destroyed by the carve — what `minCddPerIssue` is
    /// measured against.
    public var cdd: Int64?

    public var tokenId: String?
    /// The op, lowercase: `deploy` / `issue` / `transfer` / `destroy` /
    /// `close`. See ``operation`` for the parsed form.
    public var op: String?
    public var name: String?
    public var desc: String?
    public var consensusId: String?
    public var capacity: String?
    public var decimal: String?
    public var transferable: String?
    public var closable: String?
    public var openIssue: String?
    public var maxAmtPerIssue: String?
    public var minCddPerIssue: String?
    public var maxIssuesPerAddr: String?
    public var issueTo: [FidAmount]?
    public var transferTo: [FidAmount]?

    /// The carve's txid.
    public var id: String

    private enum CodingKeys: String, CodingKey {
        case tokenIds, height, index, time, signer, recipient, cdd
        case tokenId, op, name, desc, consensusId, capacity, decimal
        case transferable, closable, openIssue
        case maxAmtPerIssue, minCddPerIssue, maxIssuesPerAddr
        case issueTo, transferTo, id
    }

    public init(
        id: String,
        tokenIds: [String]? = nil,
        height: Int64? = nil,
        index: Int? = nil,
        time: Int64? = nil,
        signer: String? = nil,
        recipient: String? = nil,
        cdd: Int64? = nil,
        tokenId: String? = nil,
        op: String? = nil,
        name: String? = nil,
        desc: String? = nil,
        consensusId: String? = nil,
        capacity: String? = nil,
        decimal: String? = nil,
        transferable: String? = nil,
        closable: String? = nil,
        openIssue: String? = nil,
        maxAmtPerIssue: String? = nil,
        minCddPerIssue: String? = nil,
        maxIssuesPerAddr: String? = nil,
        issueTo: [FidAmount]? = nil,
        transferTo: [FidAmount]? = nil
    ) {
        self.id = id
        self.tokenIds = tokenIds
        self.height = height
        self.index = index
        self.time = time
        self.signer = signer
        self.recipient = recipient
        self.cdd = cdd
        self.tokenId = tokenId
        self.op = op
        self.name = name
        self.desc = desc
        self.consensusId = consensusId
        self.capacity = capacity
        self.decimal = decimal
        self.transferable = transferable
        self.closable = closable
        self.openIssue = openIssue
        self.maxAmtPerIssue = maxAmtPerIssue
        self.minCddPerIssue = minCddPerIssue
        self.maxIssuesPerAddr = maxIssuesPerAddr
        self.issueTo = issueTo
        self.transferTo = transferTo
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = (try c.decodeIfPresent(String.self, forKey: .id)) ?? ""
        tokenIds = try c.decodeIfPresent([String].self, forKey: .tokenIds)
        height = try c.decodeIfPresent(Int64.self, forKey: .height)
        index = try c.decodeIfPresent(Int.self, forKey: .index)
        time = try c.decodeIfPresent(Int64.self, forKey: .time)
        signer = try c.decodeIfPresent(String.self, forKey: .signer)
        recipient = try c.decodeIfPresent(String.self, forKey: .recipient)
        cdd = try c.decodeIfPresent(Int64.self, forKey: .cdd)
        tokenId = try c.decodeIfPresent(String.self, forKey: .tokenId)
        op = try c.decodeIfPresent(String.self, forKey: .op)
        name = try c.decodeIfPresent(String.self, forKey: .name)
        desc = try c.decodeIfPresent(String.self, forKey: .desc)
        consensusId = try c.decodeIfPresent(String.self, forKey: .consensusId)
        capacity = try Self.text(c, .capacity)
        decimal = try Self.text(c, .decimal)
        transferable = try Self.text(c, .transferable)
        closable = try Self.text(c, .closable)
        openIssue = try Self.text(c, .openIssue)
        maxAmtPerIssue = try Self.text(c, .maxAmtPerIssue)
        minCddPerIssue = try Self.text(c, .minCddPerIssue)
        maxIssuesPerAddr = try Self.text(c, .maxIssuesPerAddr)
        issueTo = try c.decodeIfPresent([FidAmount].self, forKey: .issueTo)
        transferTo = try c.decodeIfPresent([FidAmount].self, forKey: .transferTo)
    }

    /// Read a field back as text no matter which JSON type it arrived
    /// as. A history row echoes a third party's carve, so its `capacity`
    /// may be a string or a number and its `transferable` a string or a
    /// bool — depending entirely on which client wrote it. Both are
    /// records of the same thing, and neither should cost the page it
    /// arrived on.
    private static func text(
        _ c: KeyedDecodingContainer<CodingKeys>, _ key: CodingKeys
    ) throws -> String? {
        if let s = try? c.decodeIfPresent(String.self, forKey: key) { return s }
        if let b = try? c.decodeIfPresent(Bool.self, forKey: key) { return b ? "true" : "false" }
        if let i = try? c.decodeIfPresent(Int64.self, forKey: key) { return String(i) }
        if let d = try? c.decodeIfPresent(Double.self, forKey: key) {
            if d == d.rounded(), abs(d) < 1e15 { return String(Int64(d)) }
            return String(d)
        }
        return nil
    }

    // MARK: - derived state

    /// The op as a case, or nil for one this build does not know. An
    /// unknown op is displayable — the row still has a signer, a time
    /// and a token — so this is nil rather than a decode failure.
    public var operation: TokenFeip.Op? {
        guard let op else { return nil }
        return TokenFeip.Op(rawValue: op.lowercased())
    }

    /// Every token this row touched, whichever field carried them.
    /// `deploy`/`issue`/`transfer` name one in ``tokenId``;
    /// `destroy`/`close` take a list in ``tokenIds``.
    public var affectedTokenIds: [String] {
        if let tokenId, !tokenId.isEmpty { return [tokenId] }
        return tokenIds ?? []
    }

    /// The payout lines of whichever op this is, so a caller does not
    /// have to know that `issue` and `transfer` spell the same idea
    /// with two different keys.
    public var allocations: [FidAmount] {
        issueTo ?? transferTo ?? []
    }

    /// What this op moved in total, when it moved anything. Nil for the
    /// ops that move no balance (`deploy`, `close`) rather than zero,
    /// so a caller can tell "nothing moved" from "not that kind of op".
    public var totalAmount: Double? {
        let lines = allocations
        guard !lines.isEmpty else { return nil }
        return lines.reduce(0) { $0 + ($1.amount ?? 0) }
    }

    /// Whether `fid` is a party to this op — either they signed it or
    /// it paid them. The condition behind the scoped history query in
    /// ``TokenService/fetchHistory(tokenId:fid:ascending:after:size:timeoutMs:)``.
    public func involves(_ fid: String) -> Bool {
        if signer == fid || recipient == fid { return true }
        return allocations.contains { $0.fid == fid }
    }

    public func matches(query: String) -> Bool {
        let needle = query.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !needle.isEmpty else { return false }
        func hit(_ s: String?) -> Bool {
            guard let s else { return false }
            return s.lowercased().contains(needle)
        }
        if hit(op) || hit(name) || hit(signer) || hit(recipient) || hit(id) { return true }
        if affectedTokenIds.contains(where: { hit($0) }) { return true }
        return allocations.contains { hit($0.fid) }
    }
}
