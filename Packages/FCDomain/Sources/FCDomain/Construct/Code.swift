import Foundation
import FCCore

/// A code record published on chain — the Swift mirror of the Java
/// `feipData.Code`, and the record type of the `code` index that
/// `base.search` reads.
///
/// **The second of the four Construct records.** ``ProtocolSpec``
/// registers a specification — the rules two programs agree to speak.
/// A *code* record registers an **implementation** of one or more of
/// those specifications: this program, this version, written in these
/// languages, speaking these protocols, fetchable from here. A
/// ``Service`` registers a running instance of an implementation and an
/// App registers something a person can install. The four share one
/// lifecycle (`publish` → `update` → `stop` ⇄ `recover` → `close`),
/// one owner-and-waiters shape and one `rate` op; what differs is what
/// they register and which index holds them.
///
/// **What it does not carry is the code.** ``did`` is the digest of the
/// artefact, ``home`` says where to fetch it. The chain holds the claim
/// that this implementation exists and who stands behind it — not the
/// bytes, which would not fit in an OP_RETURN and would not be worth
/// putting there if they did.
///
/// **Where it differs from ``ProtocolSpec``, field for field.** Code has
/// no `type`, no `sn` and no `prePid` — an implementation is not
/// numbered by FEIP and does not supersede in place, it just bumps
/// ``ver``. It has ``langs`` (a list) where a protocol has one `lang`,
/// because a specification is *written* in a language while an
/// implementation is *written in* programming languages, plural. And it
/// has ``protocols``, which the protocol record has no analogue of: the
/// list of specifications this implementation claims to speak. That one
/// field is the whole edge between the first two Construct records.
///
/// **``onChain`` is three-valued, and deliberately so.** `true` means a
/// block confirms it, `false` means this row has never left the device,
/// and **`nil` means a carve was broadcast and no block has confirmed
/// it yet** — the state Android writes right after a successful
/// broadcast (`carvedCode.setOnChain(null)`). Collapsing nil into false
/// would tell the user to carve again something they already paid for.
public struct Code: Codable, Equatable, Sendable, Identifiable {

    // MARK: - wire fields, in Java declaration order

    public var name: String?
    /// The implementation's own version string. Free text: `"1.4.2"`,
    /// `"2026-08"`, whatever the publisher versions by.
    public var ver: String?
    /// Digest of the artefact itself, so what a reader fetches can be
    /// checked against what was registered. Points into the data layer
    /// (a HAT, a file) rather than carrying the code.
    public var did: String?
    public var desc: String?
    /// The programming languages it is written in. A list, unlike
    /// ``ProtocolSpec/lang``, and for a different reason: a spec is
    /// written in one natural language, an implementation is often
    /// written in several programming ones.
    public var langs: [String]?
    /// Where to get it, label → URL. The publish form takes `label`/`url`
    /// pairs.
    public var home: [String: String]?
    /// Record ids of the protocols this implementation claims to speak
    /// — ids in the `protocol` index, which is why the publish form can
    /// pick them from the registry rather than only accepting typed
    /// hex. **A claim, not a proof:** nothing on chain verifies that the
    /// code does what those specifications say.
    public var protocols: [String]?
    /// FIDs that serve this implementation — who to talk to about it. A
    /// waiter is not a co-owner: the list is informational, and only
    /// ``owner`` can carve.
    public var waiters: [String]?

    /// The FID that published it, and the only one that can `update`,
    /// `stop`, `recover` or `close` it.
    public var owner: String?
    /// Seconds since the epoch, like ``ProtocolSpec/birthTime`` and
    /// unlike the millisecond fields on the IM path.
    public var birthTime: Int64?
    public var birthHeight: Int64?
    public var lastTxId: String?
    public var lastTime: Int64?
    public var lastHeight: Int64?

    /// Total coin-days destroyed rating this code. The chain's measure
    /// of how much stake has been burned to speak well of it; see the
    /// `rate` op.
    public var tCdd: Int64?
    /// CDD-weighted average score, 1–5.
    public var tRate: Float?

    /// In force. `stop` sets it false, `recover` sets it true again.
    /// Nil on a record the indexer has said nothing about.
    public var active: Bool?
    /// Retired for good. Unlike ``active`` there is no op that undoes
    /// it — see ``CodeFeip/Op/close``.
    public var closed: Bool?
    /// Why it was closed, if the closer said. Carried on the `close` op.
    public var closeStatement: String?

    /// Confirmed / broadcast-unconfirmed / local-only — see the type's
    /// note.
    public var onChain: Bool?

    /// The publish carve's txid once carved; a locally derived digest
    /// before that. See ``localId(name:ver:did:desc:langs:home:protocols:waiters:)``.
    ///
    /// **There is no `birthTxId` here and the Java model has none
    /// either**, unlike `feipData.Protocol`. It would be redundant: a
    /// code record's id *is* its publish txid, so a second copy of it
    /// could only ever agree or be wrong.
    public var id: String

    // MARK: - local bookkeeping
    //
    // Not on the wire — see the CodingKeys note.

    public var addedAt: Date
    public var updatedAt: Date

    /// The wire fields only. `addedAt`/`updatedAt` are ours: a server
    /// reply never carries them, and decoding a record must not fail
    /// for their absence, which is why they are defaulted in
    /// ``init(from:)`` rather than made optional.
    private enum CodingKeys: String, CodingKey {
        case name, ver, did, desc, langs, home, protocols, waiters
        case owner, birthTime, birthHeight
        case lastTxId, lastTime, lastHeight
        case tCdd, tRate, active, closed, closeStatement
        case onChain, id
        case addedAt, updatedAt
    }

    public init(
        id: String,
        name: String? = nil,
        ver: String? = nil,
        did: String? = nil,
        desc: String? = nil,
        langs: [String]? = nil,
        home: [String: String]? = nil,
        protocols: [String]? = nil,
        waiters: [String]? = nil,
        owner: String? = nil,
        birthTime: Int64? = nil,
        birthHeight: Int64? = nil,
        lastTxId: String? = nil,
        lastTime: Int64? = nil,
        lastHeight: Int64? = nil,
        tCdd: Int64? = nil,
        tRate: Float? = nil,
        active: Bool? = nil,
        closed: Bool? = nil,
        closeStatement: String? = nil,
        onChain: Bool? = nil,
        addedAt: Date = Date(),
        updatedAt: Date = Date()
    ) {
        self.id = id
        self.name = name
        self.ver = ver
        self.did = did
        self.desc = desc
        self.langs = langs
        self.home = home
        self.protocols = protocols
        self.waiters = waiters
        self.owner = owner
        self.birthTime = birthTime
        self.birthHeight = birthHeight
        self.lastTxId = lastTxId
        self.lastTime = lastTime
        self.lastHeight = lastHeight
        self.tCdd = tCdd
        self.tRate = tRate
        self.active = active
        self.closed = closed
        self.closeStatement = closeStatement
        self.onChain = onChain
        self.addedAt = addedAt
        self.updatedAt = updatedAt
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        // A server row without an id is unusable, but throwing would
        // fail the whole page; the service drops those rows instead, so
        // decode tolerates it and leaves the id empty.
        id = (try c.decodeIfPresent(String.self, forKey: .id)) ?? ""
        name = try c.decodeIfPresent(String.self, forKey: .name)
        // `ver` is a string on the wire, but a publisher versioning
        // `1` or `2.0` may well have carved it as a JSON number. Both
        // decode to the same string here rather than failing the whole
        // page over a missing pair of quotes.
        ver = try Self.looseString(c, .ver)
        did = try c.decodeIfPresent(String.self, forKey: .did)
        desc = try c.decodeIfPresent(String.self, forKey: .desc)
        langs = try Self.looseStringList(c, .langs)
        home = try c.decodeIfPresent([String: String].self, forKey: .home)
        protocols = try Self.looseStringList(c, .protocols)
        waiters = try Self.looseStringList(c, .waiters)
        owner = try c.decodeIfPresent(String.self, forKey: .owner)
        birthTime = try c.decodeIfPresent(Int64.self, forKey: .birthTime)
        birthHeight = try c.decodeIfPresent(Int64.self, forKey: .birthHeight)
        lastTxId = try c.decodeIfPresent(String.self, forKey: .lastTxId)
        lastTime = try c.decodeIfPresent(Int64.self, forKey: .lastTime)
        lastHeight = try c.decodeIfPresent(Int64.self, forKey: .lastHeight)
        tCdd = try c.decodeIfPresent(Int64.self, forKey: .tCdd)
        tRate = try c.decodeIfPresent(Float.self, forKey: .tRate)
        active = try c.decodeIfPresent(Bool.self, forKey: .active)
        closed = try c.decodeIfPresent(Bool.self, forKey: .closed)
        closeStatement = try c.decodeIfPresent(String.self, forKey: .closeStatement)
        onChain = try c.decodeIfPresent(Bool.self, forKey: .onChain)
        addedAt = (try c.decodeIfPresent(Date.self, forKey: .addedAt)) ?? Date()
        updatedAt = (try c.decodeIfPresent(Date.self, forKey: .updatedAt)) ?? Date()
    }

    /// A string field that may have arrived unquoted.
    private static func looseString(
        _ c: KeyedDecodingContainer<CodingKeys>, _ key: CodingKeys
    ) throws -> String? {
        if let s = try? c.decodeIfPresent(String.self, forKey: key) { return s }
        if let i = try? c.decodeIfPresent(Int64.self, forKey: key) { return String(i) }
        if let d = try? c.decodeIfPresent(Double.self, forKey: key) { return String(d) }
        return nil
    }

    /// A list field that may have arrived as a bare string.
    ///
    /// `langs`, `protocols` and `waiters` are lists in the protocol, but
    /// a single-element list is exactly the thing an indexer or a
    /// hand-rolled publisher flattens to a scalar. One row spelled
    /// `"langs":"swift"` must not cost the page it arrived in.
    private static func looseStringList(
        _ c: KeyedDecodingContainer<CodingKeys>, _ key: CodingKeys
    ) throws -> [String]? {
        if let list = try? c.decodeIfPresent([String].self, forKey: key) { return list }
        if let one = try? c.decodeIfPresent(String.self, forKey: key) {
            return one.isEmpty ? nil : [one]
        }
        return nil
    }

    // MARK: - derived state

    /// List label: the name, else the id. A record with neither is legal
    /// on the wire and should still be identifiable.
    public var displayName: String {
        if let name, !name.isEmpty { return name }
        return id
    }

    /// Where a code record sits in its lifecycle. One value rather than
    /// three booleans read in the right order, because `closed` outranks
    /// `active` and a list that checks them the other way round shows a
    /// closed record as live.
    public enum State: String, Sendable {
        /// Composed here, never carved.
        case draft
        /// Carve broadcast, no block yet.
        case broadcast
        case live
        /// `stop`ped — recoverable.
        case stopped
        /// `close`d — permanent.
        case closed
    }

    public var state: State {
        if closed == true { return .closed }
        if onChain == false { return .draft }
        if onChain == nil { return .broadcast }
        if active == false { return .stopped }
        return .live
    }

    /// Retired for good. **A missing flag means not closed**, which is
    /// worth spelling out: `closed` is absent from plenty of rows, and
    /// `closed != true` and `closed == false` disagree exactly there.
    public var isClosed: Bool { closed == true }

    /// Stopped but not closed — the state `recover` undoes.
    public var isStopped: Bool { closed != true && active == false }

    /// Only the owner carves against a code record, and never against a
    /// closed one. The chain enforces both, but only after the miner
    /// fee is spent.
    public func canUpdate(as fid: String) -> Bool {
        owner == fid && !isClosed
    }

    /// Stoppable: owned, on chain, in force.
    public func canStop(as fid: String) -> Bool {
        owner == fid && onChain != false && !isClosed && active != false
    }

    /// Recoverable: owned, on chain, stopped rather than closed. A
    /// closed record is past recovering — that is the whole difference
    /// between the two ops.
    public func canRecover(as fid: String) -> Bool {
        owner == fid && onChain != false && isStopped
    }

    /// Closable: owned, on chain, not already closed.
    public func canClose(as fid: String) -> Bool {
        owner == fid && onChain != false && !isClosed
    }

    /// Case-insensitive substring match across the fields Android's
    /// `searchFromList` looks at — name, desc, owner, langs, protocols
    /// — plus waiters and the id, so pasting either finds its row.
    public func matches(query: String) -> Bool {
        let needle = query.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !needle.isEmpty else { return false }
        func hit(_ s: String?) -> Bool {
            guard let s else { return false }
            return s.lowercased().contains(needle)
        }
        if hit(name) || hit(desc) || hit(owner) || hit(ver) || hit(id) { return true }
        for list in [langs, protocols, waiters] {
            if (list ?? []).contains(where: { hit($0) }) { return true }
        }
        return false
    }

    // MARK: - local id

    /// The id a draft carries before it has a txid — `sha256x2` of the
    /// publish op it will carve, hex.
    ///
    /// Android uses `"local_" + System.currentTimeMillis()`, which
    /// changes every time the same draft is saved: edit a draft twice
    /// and you have three rows. Hashing the payload means an unchanged
    /// draft keeps its key across a save/reload — the property the id
    /// exists for — and a changed one moves, which the editor handles
    /// explicitly. It is 32 bytes of hex, so it can never collide with a
    /// txid of a different preimage, and it never leaves the device:
    /// once carved, the txid replaces it.
    public static func localId(
        name: String?,
        ver: String?,
        did: String?,
        desc: String?,
        langs: [String]?,
        home: [String: String]?,
        protocols: [String]?,
        waiters: [String]?
    ) -> String {
        let detail = (try? CodeFeip.publishOp(
            name: name, ver: ver, did: did, desc: desc,
            langs: langs, home: home, protocols: protocols, waiters: waiters
        )) ?? "\(name ?? "")\u{1F}\(ver ?? "")\u{1F}\(did ?? "")"
        return Hex.encode(Hash.doubleSha256(Data(detail.utf8)))
    }

    /// A brand-new local-only draft, owned by `owner` and not yet
    /// carved.
    ///
    /// ``active`` stays nil rather than true. Android writes
    /// `setActive(true)` here, which claims a record no chain has seen
    /// is already in force; `active` is the *indexer's* verdict, and a
    /// draft has no indexer behind it. ``state`` reads `.draft` off
    /// ``onChain`` instead, so nothing needs the lie.
    public static func createLocal(
        name: String,
        ver: String? = nil,
        did: String? = nil,
        desc: String? = nil,
        langs: [String]? = nil,
        home: [String: String]? = nil,
        protocols: [String]? = nil,
        waiters: [String]? = nil,
        owner: String
    ) -> Code {
        // Trimmed as well as emptied, because ``CodeFeip`` trims when
        // it carves: a draft holding `["  "]` would show one language
        // and publish none.
        func prune(_ list: [String]?) -> [String]? {
            let clean = (list ?? [])
                .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
                .filter { !$0.isEmpty }
            return clean.isEmpty ? nil : clean
        }
        let cleanLangs = prune(langs)
        let cleanProtocols = prune(protocols)
        let cleanWaiters = prune(waiters)
        let cleanHome = (home?.isEmpty == false) ? home : nil
        return Code(
            id: localId(
                name: name, ver: ver, did: did, desc: desc,
                langs: cleanLangs, home: cleanHome,
                protocols: cleanProtocols, waiters: cleanWaiters
            ),
            name: name,
            ver: ver,
            did: did,
            desc: desc,
            langs: cleanLangs,
            home: cleanHome,
            protocols: cleanProtocols,
            waiters: cleanWaiters,
            owner: owner,
            closed: false,
            onChain: false
        )
    }
}
