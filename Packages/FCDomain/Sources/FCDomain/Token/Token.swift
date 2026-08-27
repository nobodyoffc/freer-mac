import Foundation

/// An on-chain token — the Swift mirror of the Java `feipData.Token`,
/// and the record type of the `token` index that `base.search` reads.
///
/// A token is a ledger the chain keeps on someone's behalf: a name, a
/// supply cap, and a set of rules fixed at deploy time about who may
/// mint more of it and whether it can move. Everything here is public;
/// like ``Proof`` and unlike ``Secret``, there is no cipher anywhere on
/// this path.
///
/// **The rules are immutable.** ``transferable``, ``closable``,
/// ``openIssue`` and the three issue limits are set by the `deploy`
/// carve and there is no op to change them afterwards — a token whose
/// supply cap could be raised later would not be a supply cap. The one
/// state that moves is ``closed``, and only in one direction.
///
/// **Numbers arrive as strings, deliberately.** ``capacity``,
/// ``decimal`` and the three issue limits are strings on the wire
/// because the protocol carves them as strings; a capacity of
/// `21000000` and one of `21000000.00000000` are the same cap but not
/// the same carve, and re-encoding through a number type would silently
/// rewrite what the deployer signed. ``circulating`` is the exception:
/// it is the *indexer's* running total, not anything the deployer said,
/// and it arrives as a JSON number.
public struct Token: Codable, Equatable, Sendable, Identifiable {

    // MARK: - wire fields, in Java declaration order

    public var name: String?
    public var desc: String?
    /// The FID whose opinion settles disputes about this token, if the
    /// deployer named one. Purely declarative — the chain does not
    /// enforce anything about it.
    public var consensusId: String?
    /// The supply cap, as carved. Empty or nil means uncapped.
    public var capacity: String?
    /// How many decimal places an amount of this token may carry, as
    /// carved. See ``decimalPlaces`` for the parsed form.
    public var decimal: String?
    /// Whether holders may move their balance. Fixed at deploy.
    public var transferable: Bool?
    /// Whether the deployer may close the token. Fixed at deploy — a
    /// token deployed `closable: false` can never be closed, which is
    /// the guarantee a holder is buying.
    public var closable: Bool?
    /// Whether anyone may issue, or only the deployer. When true the
    /// three `…PerIssue` / `…PerAddr` limits are what stands between
    /// the token and infinite supply, which is why the parser only
    /// applies them in this case.
    public var openIssue: Bool?
    public var maxAmtPerIssue: String?
    public var minCddPerIssue: String?
    public var maxIssuesPerAddr: String?
    /// Closed for good. The one field of the rule set that moves, and
    /// only from false to true.
    public var closed: Bool?

    public var deployer: String?
    /// Total issued minus destroyed, per the indexer.
    public var circulating: Double?
    public var birthTime: Int64?
    public var birthHeight: Int64?
    public var lastTxId: String?
    /// Seconds since the epoch, like ``Proof/lastTime`` and unlike the
    /// millisecond fields on the IM path.
    public var lastTime: Int64?
    public var lastHeight: Int64?

    /// The txid of the `deploy` carve. A token has no local-only form —
    /// see ``TokenFeip`` — so this is always a real txid.
    public var id: String

    // MARK: - local bookkeeping

    /// When this row first entered the local cache. Not on the wire.
    public var addedAt: Date
    public var updatedAt: Date

    private enum CodingKeys: String, CodingKey {
        case name, desc, consensusId, capacity, decimal
        case transferable, closable, openIssue
        case maxAmtPerIssue, minCddPerIssue, maxIssuesPerAddr, closed
        case deployer, circulating
        case birthTime, birthHeight, lastTxId, lastTime, lastHeight
        case id
        case addedAt, updatedAt
    }

    public init(
        id: String,
        name: String? = nil,
        desc: String? = nil,
        consensusId: String? = nil,
        capacity: String? = nil,
        decimal: String? = nil,
        transferable: Bool? = nil,
        closable: Bool? = nil,
        openIssue: Bool? = nil,
        maxAmtPerIssue: String? = nil,
        minCddPerIssue: String? = nil,
        maxIssuesPerAddr: String? = nil,
        closed: Bool? = nil,
        deployer: String? = nil,
        circulating: Double? = nil,
        birthTime: Int64? = nil,
        birthHeight: Int64? = nil,
        lastTxId: String? = nil,
        lastTime: Int64? = nil,
        lastHeight: Int64? = nil,
        addedAt: Date = Date(),
        updatedAt: Date = Date()
    ) {
        self.id = id
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
        self.closed = closed
        self.deployer = deployer
        self.circulating = circulating
        self.birthTime = birthTime
        self.birthHeight = birthHeight
        self.lastTxId = lastTxId
        self.lastTime = lastTime
        self.lastHeight = lastHeight
        self.addedAt = addedAt
        self.updatedAt = updatedAt
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        // A row without an id is unusable, but throwing would fail the
        // whole page; the service drops those rows instead.
        id = (try c.decodeIfPresent(String.self, forKey: .id)) ?? ""
        name = try c.decodeIfPresent(String.self, forKey: .name)
        desc = try c.decodeIfPresent(String.self, forKey: .desc)
        consensusId = try c.decodeIfPresent(String.self, forKey: .consensusId)
        capacity = try Self.looseString(c, .capacity)
        decimal = try Self.looseString(c, .decimal)
        transferable = try Self.looseBool(c, .transferable)
        closable = try Self.looseBool(c, .closable)
        openIssue = try Self.looseBool(c, .openIssue)
        maxAmtPerIssue = try Self.looseString(c, .maxAmtPerIssue)
        minCddPerIssue = try Self.looseString(c, .minCddPerIssue)
        maxIssuesPerAddr = try Self.looseString(c, .maxIssuesPerAddr)
        closed = try Self.looseBool(c, .closed)
        deployer = try c.decodeIfPresent(String.self, forKey: .deployer)
        circulating = try c.decodeIfPresent(Double.self, forKey: .circulating)
        birthTime = try c.decodeIfPresent(Int64.self, forKey: .birthTime)
        birthHeight = try c.decodeIfPresent(Int64.self, forKey: .birthHeight)
        lastTxId = try c.decodeIfPresent(String.self, forKey: .lastTxId)
        lastTime = try c.decodeIfPresent(Int64.self, forKey: .lastTime)
        lastHeight = try c.decodeIfPresent(Int64.self, forKey: .lastHeight)
        addedAt = (try c.decodeIfPresent(Date.self, forKey: .addedAt)) ?? Date()
        updatedAt = (try c.decodeIfPresent(Date.self, forKey: .updatedAt)) ?? Date()
    }

    /// A wire field the protocol carves as a string but that reaches
    /// the index as whatever the deployer actually typed into the JSON.
    ///
    /// `capacity` is the field this exists for: every client is
    /// *supposed* to carve `"capacity":"21000000"`, and one that carves
    /// `21000000` unquoted produces a record that a strict
    /// `decodeIfPresent(String.self)` refuses — and then one malformed
    /// token on the page throws away the other twenty-four. Accepting
    /// the number and rendering it back to digits loses nothing: the
    /// value is only ever displayed and compared as text here.
    private static func looseString(
        _ c: KeyedDecodingContainer<CodingKeys>, _ key: CodingKeys
    ) throws -> String? {
        if let s = try? c.decodeIfPresent(String.self, forKey: key) { return s }
        if let i = try? c.decodeIfPresent(Int64.self, forKey: key) { return String(i) }
        if let d = try? c.decodeIfPresent(Double.self, forKey: key) {
            // Integral doubles print without the ".0" tail so a
            // capacity of 21000000 does not read as 21000000.0.
            if d == d.rounded(), abs(d) < 1e15 { return String(Int64(d)) }
            return String(d)
        }
        return nil
    }

    /// Same tolerance for the flags, which some carves spell as the
    /// strings `"true"`/`"false"` — Java's `TokenHistory` declares its
    /// copies of these very fields as `String` for exactly that reason.
    private static func looseBool(
        _ c: KeyedDecodingContainer<CodingKeys>, _ key: CodingKeys
    ) throws -> Bool? {
        if let b = try? c.decodeIfPresent(Bool.self, forKey: key) { return b }
        if let s = try? c.decodeIfPresent(String.self, forKey: key) {
            switch s.lowercased() {
            case "true", "1", "yes":  return true
            case "false", "0", "no":  return false
            default:                  return nil
            }
        }
        if let i = try? c.decodeIfPresent(Int.self, forKey: key) { return i != 0 }
        return nil
    }

    // MARK: - derived state

    /// List label: the name, else the elided id. A token with no name
    /// is legal on the wire and should still be identifiable.
    public var displayName: String {
        if let name, !name.isEmpty { return name }
        return id
    }

    /// Closed for good. **A missing flag means open** — the same trap
    /// ``Proof/isDestroyed`` documents: `closed != true` and
    /// `closed == false` disagree exactly on the rows the indexer
    /// omitted the flag from.
    public var isClosed: Bool { closed == true }

    /// How many decimal places an amount may carry, parsed from
    /// ``decimal``. Absent, unparsable or negative means zero — an
    /// integer token, which is what a deploy that names no decimal is.
    ///
    /// Capped at 18: beyond that the digits stop meaning anything a
    /// double-precision indexer can hold, and an uncapped value here
    /// would let one malformed record drive an amount formatter into
    /// producing hundreds of digits.
    public var decimalPlaces: Int {
        guard let decimal, let n = Int(decimal.trimmingCharacters(in: .whitespaces)) else {
            return 0
        }
        return min(max(n, 0), 18)
    }

    /// `fid` may issue more of this token.
    ///
    /// Two doors: the token is open-issue, or `fid` deployed it. Either
    /// way a closed token issues nothing — that is what closing means.
    public func canIssue(as fid: String) -> Bool {
        guard !isClosed else { return false }
        return openIssue == true || deployer == fid
    }

    /// `fid` may close this token: they deployed it, it was deployed
    /// closable, and it is not closed already.
    public func canClose(as fid: String) -> Bool {
        deployer == fid && closable == true && !isClosed
    }

    /// Whether a balance of this token can move at all. A token
    /// deployed non-transferable is a badge, not a currency; a closed
    /// one has stopped being either.
    public var canTransfer: Bool {
        transferable == true && !isClosed
    }

    /// Case-insensitive substring match across the fields the chain
    /// index exposes to search (`name`, `desc`, `consensusId`,
    /// `deployer`, `id`), so filtering the loaded rows and searching the
    /// chain agree about what a query means.
    public func matches(query: String) -> Bool {
        let needle = query.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !needle.isEmpty else { return false }
        func hit(_ s: String?) -> Bool {
            guard let s else { return false }
            return s.lowercased().contains(needle)
        }
        return hit(name) || hit(desc) || hit(consensusId) || hit(deployer) || hit(id)
    }
}
