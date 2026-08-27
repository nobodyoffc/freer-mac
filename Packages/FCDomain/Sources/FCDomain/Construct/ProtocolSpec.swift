import Foundation
import FCCore

/// A protocol published on chain — the Swift mirror of the Java
/// `feipData.Protocol`, and the record type of the `protocol` index
/// that `base.search` reads.
///
/// **This is the first of the four Construct records.** Protocol,
/// ``Service``, Code and App are one family: the same lifecycle
/// (`publish` → `update` → `stop` ⇄ `recover` → `close`), the same
/// owner-and-waiters shape, the same rate op, four different serial
/// numbers. What distinguishes them is what they register. A *protocol*
/// registers a specification — the rules two programs agree to speak,
/// FEIP itself among them. Code registers an implementation of one, a
/// Service registers a running instance, an App registers something a
/// person can install. Together they are the Construct: the agreement,
/// the implementation, the instance, the thing you can hold. The chain
/// holds the agreement; the other three hold what keeps it.
///
/// **Why not `Protocol`.** `Protocol` is a class in `ObjectiveC`, which
/// Foundation re-exports, so a type by that name would be ambiguous in
/// every file that imports both — and `FeipProtocol` is already taken by
/// the sn→name registry this record's `sn` field is *not* (see
/// ``sn``). `ProtocolSpec` says what the record is: the registration of
/// a specification.
///
/// **``onChain`` is three-valued, and deliberately so.** `true` means a
/// block confirms it, `false` means this row has never left the device,
/// and **`nil` means a carve was broadcast and no block has confirmed
/// it yet** — the state Android writes right after a successful
/// broadcast. Collapsing nil into false would tell the user to carve
/// again something they already paid for.
public struct ProtocolSpec: Codable, Equatable, Sendable, Identifiable {

    // MARK: - wire fields, in Java declaration order

    /// Free text — what kind of protocol this is (`"FEIP"`,
    /// `"transport"`, whatever the publisher wants). Not the FEIP
    /// envelope's `type`, which is always the string `FEIP`.
    public var type: String?
    /// The publisher's own serial number for the protocol they are
    /// registering. **Not this record's FEIP sn**, which is always 1 —
    /// a protocol record describing FEIP-12 carries `sn` 12 while
    /// riding in an envelope whose `sn` is 1. The two are different
    /// numbers with the same name and they will be confused at least
    /// once by every reader of this file.
    public var sn: String?
    public var ver: String?
    /// Digest of the specification document itself, so the text a reader
    /// fetches can be checked against what was registered. Points into
    /// the data layer (a HAT, a file) rather than carrying the spec.
    public var did: String?
    public var name: String?
    public var lang: String?
    public var desc: String?
    /// The record this one supersedes. Chains versions together: a
    /// `ver` bump publishes a *new* record whose `prePid` is the old
    /// one's id, because a published spec is not editable in place.
    ///
    /// **Spelled `preDid` on the wire going out** and `prePid` coming
    /// back — see ``ProtocolFeip/publishOp(sn:name:type:ver:did:desc:lang:home:preDid:waiters:)``.
    public var prePid: String?
    /// Where the specification lives, label → URL. The publish form
    /// takes `label:url` pairs.
    public var home: [String: String]?
    public var title: String?
    /// The FID that published it, and the only one that can `update`,
    /// `stop`, `recover` or `close` it.
    public var owner: String?
    /// FIDs that serve this protocol — who to talk to about it. A
    /// waiter is not a co-owner: the list is informational, and only
    /// ``owner`` can carve.
    public var waiters: [String]?

    public var birthTxId: String?
    public var birthTime: Int64?
    public var birthHeight: Int64?
    public var lastTxId: String?
    /// Seconds since the epoch, like ``News/time`` and unlike the
    /// millisecond fields on the IM path.
    public var lastTime: Int64?
    public var lastHeight: Int64?

    /// Total coin-days destroyed rating this protocol. The chain's
    /// measure of how much stake has been burned to speak well of it;
    /// see the `rate` op.
    public var tCdd: Int64?
    /// CDD-weighted average score, 1–5.
    public var tRate: Float?

    /// In force. `stop` sets it false, `recover` sets it true again.
    /// Nil on a record the indexer has said nothing about.
    public var active: Bool?
    /// Retired for good. Unlike ``active`` there is no op that undoes
    /// it — see ``ProtocolFeip/Op/close``.
    public var closed: Bool?
    /// Why it was closed, if the closer said. Carried on the `close` op.
    public var closeStatement: String?

    /// Confirmed / broadcast-unconfirmed / local-only — see the type's
    /// note.
    public var onChain: Bool?

    /// The publish carve's txid once carved; a locally derived digest
    /// before that. See ``localId(name:type:sn:ver:did:desc:lang:home:preDid:waiters:)``.
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
        case type, sn, ver, did, name, lang, desc, prePid, home, title
        case owner, waiters
        case birthTxId, birthTime, birthHeight
        case lastTxId, lastTime, lastHeight
        case tCdd, tRate, active, closed, closeStatement
        case onChain, id
        case addedAt, updatedAt
    }

    public init(
        id: String,
        type: String? = nil,
        sn: String? = nil,
        ver: String? = nil,
        did: String? = nil,
        name: String? = nil,
        lang: String? = nil,
        desc: String? = nil,
        prePid: String? = nil,
        home: [String: String]? = nil,
        title: String? = nil,
        owner: String? = nil,
        waiters: [String]? = nil,
        birthTxId: String? = nil,
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
        self.type = type
        self.sn = sn
        self.ver = ver
        self.did = did
        self.name = name
        self.lang = lang
        self.desc = desc
        self.prePid = prePid
        self.home = home
        self.title = title
        self.owner = owner
        self.waiters = waiters
        self.birthTxId = birthTxId
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
        type = try c.decodeIfPresent(String.self, forKey: .type)
        // The chain carries `sn` and `ver` as strings, but a publisher
        // numbering their own protocol may well have carved them as
        // JSON numbers. Both decode to the same string here rather than
        // failing the whole page over a missing pair of quotes.
        sn = try Self.looseString(c, .sn)
        ver = try Self.looseString(c, .ver)
        did = try c.decodeIfPresent(String.self, forKey: .did)
        name = try c.decodeIfPresent(String.self, forKey: .name)
        lang = try c.decodeIfPresent(String.self, forKey: .lang)
        desc = try c.decodeIfPresent(String.self, forKey: .desc)
        prePid = try c.decodeIfPresent(String.self, forKey: .prePid)
        home = try c.decodeIfPresent([String: String].self, forKey: .home)
        title = try c.decodeIfPresent(String.self, forKey: .title)
        owner = try c.decodeIfPresent(String.self, forKey: .owner)
        waiters = try c.decodeIfPresent([String].self, forKey: .waiters)
        birthTxId = try c.decodeIfPresent(String.self, forKey: .birthTxId)
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

    // MARK: - derived state

    /// List label: the name, else the title, else the id. A record with
    /// neither is legal on the wire and should still be identifiable.
    public var displayName: String {
        if let name, !name.isEmpty { return name }
        if let title, !title.isEmpty { return title }
        return id
    }

    /// Where a protocol sits in its lifecycle. One value rather than
    /// three booleans read in the right order, because `closed` outranks
    /// `active` and a list that checks them the other way round shows a
    /// closed protocol as live.
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

    /// Only the owner carves against a protocol, and never against a
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
    /// closed protocol is past recovering — that is the whole
    /// difference between the two ops.
    public func canRecover(as fid: String) -> Bool {
        owner == fid && onChain != false && isStopped
    }

    /// Closable: owned, on chain, not already closed.
    public func canClose(as fid: String) -> Bool {
        owner == fid && onChain != false && !isClosed
    }

    /// Case-insensitive substring match across the fields Android's
    /// `searchFromList` looks at — name, desc, owner, type, sn — plus
    /// the id, so pasting one finds its row.
    public func matches(query: String) -> Bool {
        let needle = query.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !needle.isEmpty else { return false }
        func hit(_ s: String?) -> Bool {
            guard let s else { return false }
            return s.lowercased().contains(needle)
        }
        if hit(name) || hit(desc) || hit(owner) || hit(type) || hit(sn) || hit(id) {
            return true
        }
        return (waiters ?? []).contains { hit($0) }
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
        type: String?,
        sn: String?,
        ver: String?,
        did: String?,
        desc: String?,
        lang: String?,
        home: [String: String]?,
        preDid: String?,
        waiters: [String]?
    ) -> String {
        let detail = (try? ProtocolFeip.publishOp(
            sn: sn, name: name, type: type, ver: ver, did: did,
            desc: desc, lang: lang, home: home, preDid: preDid, waiters: waiters
        )) ?? "\(name ?? "")\u{1F}\(ver ?? "")\u{1F}\(did ?? "")"
        return Hex.encode(Hash.doubleSha256(Data(detail.utf8)))
    }

    /// A brand-new local-only draft, owned by `owner` and not yet
    /// carved.
    ///
    /// ``active`` stays nil rather than true. Android writes true here,
    /// which claims a protocol no chain has seen is already in force;
    /// `active` is the *indexer's* verdict, and a draft has no indexer
    /// behind it. ``state`` reads `.draft` off ``onChain`` instead, so
    /// nothing needs the lie.
    public static func createLocal(
        name: String,
        type: String? = nil,
        sn: String? = nil,
        ver: String? = nil,
        did: String? = nil,
        desc: String? = nil,
        lang: String? = nil,
        home: [String: String]? = nil,
        preDid: String? = nil,
        waiters: [String]? = nil,
        owner: String
    ) -> ProtocolSpec {
        let cleanWaiters = (waiters?.isEmpty == false) ? waiters : nil
        let cleanHome = (home?.isEmpty == false) ? home : nil
        return ProtocolSpec(
            id: localId(
                name: name, type: type, sn: sn, ver: ver, did: did,
                desc: desc, lang: lang, home: cleanHome,
                preDid: preDid, waiters: cleanWaiters
            ),
            type: type,
            sn: sn,
            ver: ver,
            did: did,
            name: name,
            lang: lang,
            desc: desc,
            prePid: preDid,
            home: cleanHome,
            owner: owner,
            waiters: cleanWaiters,
            closed: false,
            onChain: false
        )
    }
}
