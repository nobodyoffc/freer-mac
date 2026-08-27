import Foundation
import FCCore

/// A service record published on chain — the Swift mirror of the Java
/// `feipData.Service`, and the record type of the `service` index.
///
/// **The third of the four Construct records, and the only one that was
/// already here.** ``ProtocolSpec`` registers a specification, ``Code``
/// registers an implementation of one, and a *service* registers a
/// **running instance** you can actually talk to: this program, run by
/// this operator, reachable at this URL, at these prices. An App
/// registers something a person installs. The four share one lifecycle
/// (`publish` → `update` → `stop` ⇄ `recover` → `close`), one
/// owner-and-waiters shape and one `rate` op.
///
/// **This file predates the Construct phase and kept its home.** Before
/// 8.7.2 it modelled only the fields SID→URL discovery needed — that
/// path is load-bearing (``HomeServiceResolver`` resolves every `(sid)`
/// in a `home` map through it, which is how messages find a DOCK), and
/// it is read by ``DirectoryService`` on the IM hot path. So the
/// lifecycle half was *grown onto* the model rather than shipped as a
/// second `ServiceRecord` next to it: two types over one index would
/// have meant two decoders disagreeing about what a service is.
///
/// **Naming is where a service differs from its three siblings.** The
/// other three have a plain `name`; a service has ``stdName`` — a
/// canonical `COMPONENT@OWNER` string such as `DOCK@No1_NrC7` — plus
/// ``localNames``, a language→name map for display. Code that reaches
/// for `.name` on a service finds nothing at all.
///
/// **``onChain`` is three-valued**, as on ``Code``: `true` means a block
/// confirms it, `false` means the row never left this device, and `nil`
/// means broadcast-but-unconfirmed. Note the interaction with
/// ``isActive``, which predates it and answers a different question —
/// see that property.
public struct Service: Codable, Equatable, Sendable, Identifiable {

    // MARK: - identity and naming

    /// The service's canonical name, e.g. `DOCK@No1_NrC7`.
    public var stdName: String?
    /// Display names by language tag. Not searched by ``apiUrl`` or any
    /// resolution path — this is what to *call* it, not how to reach it.
    public var localNames: [String: String]?
    public var desc: String?
    /// What kind of service this is, e.g. `FAPI@No1_NrC7`.
    ///
    /// **Free text, and modelled as free text on purpose.** Java wraps
    /// this in a four-value `ServiceType` enum (`NASA_RPC`,
    /// `FAPI_No1_NrC7`, `NODE`, `OTHER`) that everything else falls back
    /// to `OTHER` through — see ``ServiceRegistry`` for what that costs
    /// Android on an update. A string round-trips whatever the chain
    /// actually holds.
    public var type: String?
    /// Which well-known services this one actually offers, e.g.
    /// `["DOCK@No1_NrC7", "DISK@No1_NrC7"]`. One FAPI server usually
    /// runs several, so **the component list — not ``type`` — is what a
    /// "find me a DOCK" search filters on**.
    public var components: [String]?
    public var ver: String?
    /// The FID that runs it. Set by the resolver from the record's
    /// surroundings, not carved by the publish op.
    public var dealer: String?
    public var dealerPubkey: String?
    /// Where to reach it. The `API` key is the endpoint; see
    /// ``apiUrl``.
    public var home: [String: String]?
    /// FIDs that serve this service — who to talk to about it. A waiter
    /// is not a co-owner: only ``owner`` can carve.
    public var waiters: [String]?
    /// Record ids in the `protocol` index that this service speaks.
    public var protocols: [String]?
    /// Record ids in the `code` index — which implementation is running
    /// here. **This is the field that makes the Construct a graph
    /// rather than four lists**: a service points at the code it runs,
    /// and that code points at the protocols it implements.
    public var codes: [String]?
    /// SIDs of other services this one depends on or federates with.
    public var services: [String]?

    // MARK: - pricing
    //
    // Thirteen flat strings, exactly as the chain carries them: every
    // numeric field on a service record is a decimal *string*, and
    // parsing them into numbers here would mean re-serialising a
    // publisher's `"0.001"` as `0.001` and carving something they did
    // not write. Java keeps them flat too — they were moved out of the
    // free-form `params` object at some point and never moved back.

    public var pricePerKB: String?
    /// Per KB of request data.
    public var pricePerKBIn: String?
    /// Per KB of response data.
    public var pricePerKBOut: String?
    /// Per KB per day, for anything stored.
    public var pricePerKBDay: String?
    public var minPayment: String?
    public var pricePerRequest: String?
    public var sessionDays: String?
    public var consumeViaShare: String?
    public var orderViaShare: String?
    public var currency: String?
    /// The floor balance a client must hold to be served.
    ///
    /// Android declares this on both the model and the op data and then
    /// never collects it: no field in `CreateServiceActivity` or
    /// `UpdateServiceActivity` writes it, so it is unreachable there.
    /// The publish sheet here has one.
    public var minCredit: String?
    /// The largest single item this service accepts, in bytes, written as
    /// a decimal **string**.
    ///
    /// For a DOCK this is the per-item ceiling FAPI13 enforces on
    /// `dock.put`. It is the operator's to set, and it varies: the server
    /// defaults to 64 KB when the record does not say. See
    /// ``itemSizeLimit`` for the parsed form.
    public var maxDataSize: String?
    public var dataExpiresInDays: String?

    // MARK: - ownership and chain state

    /// The FID that published it, and the only one that can `update`,
    /// `stop`, `recover` or `close` it.
    public var owner: String?

    public var birthTime: Int64?
    public var birthHeight: Int64?
    public var lastTxId: String?
    public var lastTime: Int64?
    public var lastHeight: Int64?

    /// Total coin-days destroyed rating this service.
    public var tCdd: Int64?
    /// CDD-weighted average score, 1–5.
    public var tRate: Float?

    /// In force. `stop` sets it false, `recover` sets it true again.
    public var active: Bool?
    /// Retired for good; nothing undoes it.
    public var closed: Bool?
    /// Why it was closed, if the closer said.
    public var closeStatement: String?
    /// Confirmed / broadcast-unconfirmed / local-only — see the type's
    /// note.
    public var onChain: Bool?

    /// The SID — 64 hex characters, and the id a `(sid)` home value
    /// points at.
    ///
    /// **Optional, unlike ``Code/id``.** By-ids replies key the record
    /// by its id and may omit it from the body, and this model has
    /// resolved SIDs since long before it grew a lifecycle. ``sid``
    /// is the non-optional form the pane and the store use.
    public var id: String?

    // MARK: - local bookkeeping
    //
    // Not on the wire; defaulted when decoding, like ``Code``'s pair.

    public var addedAt: Date
    public var updatedAt: Date

    private enum CodingKeys: String, CodingKey {
        case stdName, localNames, desc, type, components, ver
        case dealer, dealerPubkey, home
        case waiters, protocols, codes, services
        case pricePerKB, pricePerKBIn, pricePerKBOut, pricePerKBDay
        case minPayment, pricePerRequest, sessionDays
        case consumeViaShare, orderViaShare, currency, minCredit
        case maxDataSize, dataExpiresInDays
        case owner, birthTime, birthHeight
        case lastTxId, lastTime, lastHeight
        case tCdd, tRate, active, closed, closeStatement
        case onChain, id
        case addedAt, updatedAt
    }

    public init(
        stdName: String? = nil,
        localNames: [String: String]? = nil,
        desc: String? = nil,
        type: String? = nil,
        components: [String]? = nil,
        ver: String? = nil,
        dealer: String? = nil,
        dealerPubkey: String? = nil,
        home: [String: String]? = nil,
        waiters: [String]? = nil,
        protocols: [String]? = nil,
        codes: [String]? = nil,
        services: [String]? = nil,
        pricePerKB: String? = nil,
        pricePerKBIn: String? = nil,
        pricePerKBOut: String? = nil,
        pricePerKBDay: String? = nil,
        minPayment: String? = nil,
        pricePerRequest: String? = nil,
        sessionDays: String? = nil,
        consumeViaShare: String? = nil,
        orderViaShare: String? = nil,
        currency: String? = nil,
        minCredit: String? = nil,
        maxDataSize: String? = nil,
        dataExpiresInDays: String? = nil,
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
        id: String? = nil,
        addedAt: Date = Date(),
        updatedAt: Date = Date()
    ) {
        self.stdName = stdName
        self.localNames = localNames
        self.desc = desc
        self.type = type
        self.components = components
        self.ver = ver
        self.dealer = dealer
        self.dealerPubkey = dealerPubkey
        self.home = home
        self.waiters = waiters
        self.protocols = protocols
        self.codes = codes
        self.services = services
        self.pricePerKB = pricePerKB
        self.pricePerKBIn = pricePerKBIn
        self.pricePerKBOut = pricePerKBOut
        self.pricePerKBDay = pricePerKBDay
        self.minPayment = minPayment
        self.pricePerRequest = pricePerRequest
        self.sessionDays = sessionDays
        self.consumeViaShare = consumeViaShare
        self.orderViaShare = orderViaShare
        self.currency = currency
        self.minCredit = minCredit
        self.maxDataSize = maxDataSize
        self.dataExpiresInDays = dataExpiresInDays
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
        self.id = id
        self.addedAt = addedAt
        self.updatedAt = updatedAt
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        stdName = try c.decodeIfPresent(String.self, forKey: .stdName)
        localNames = try c.decodeIfPresent([String: String].self, forKey: .localNames)
        desc = try c.decodeIfPresent(String.self, forKey: .desc)
        type = try c.decodeIfPresent(String.self, forKey: .type)
        components = try Self.looseStringList(c, .components)
        ver = try Self.looseString(c, .ver)
        dealer = try c.decodeIfPresent(String.self, forKey: .dealer)
        dealerPubkey = try c.decodeIfPresent(String.self, forKey: .dealerPubkey)
        home = try c.decodeIfPresent([String: String].self, forKey: .home)
        waiters = try Self.looseStringList(c, .waiters)
        protocols = try Self.looseStringList(c, .protocols)
        codes = try Self.looseStringList(c, .codes)
        services = try Self.looseStringList(c, .services)
        // Every price is a decimal string on the wire, but a publisher
        // carving `"pricePerKB":0.001` has produced a number, and one
        // unquoted price must not cost the whole page.
        pricePerKB = try Self.looseString(c, .pricePerKB)
        pricePerKBIn = try Self.looseString(c, .pricePerKBIn)
        pricePerKBOut = try Self.looseString(c, .pricePerKBOut)
        pricePerKBDay = try Self.looseString(c, .pricePerKBDay)
        minPayment = try Self.looseString(c, .minPayment)
        pricePerRequest = try Self.looseString(c, .pricePerRequest)
        sessionDays = try Self.looseString(c, .sessionDays)
        consumeViaShare = try Self.looseString(c, .consumeViaShare)
        orderViaShare = try Self.looseString(c, .orderViaShare)
        currency = try c.decodeIfPresent(String.self, forKey: .currency)
        minCredit = try Self.looseString(c, .minCredit)
        maxDataSize = try Self.looseString(c, .maxDataSize)
        dataExpiresInDays = try Self.looseString(c, .dataExpiresInDays)
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
        id = try c.decodeIfPresent(String.self, forKey: .id)
        addedAt = (try c.decodeIfPresent(Date.self, forKey: .addedAt)) ?? Date()
        updatedAt = (try c.decodeIfPresent(Date.self, forKey: .updatedAt)) ?? Date()
    }

    /// A string field that may have arrived unquoted — see the price
    /// note in ``init(from:)``.
    private static func looseString(
        _ c: KeyedDecodingContainer<CodingKeys>, _ key: CodingKeys
    ) throws -> String? {
        if let s = try? c.decodeIfPresent(String.self, forKey: key) { return s }
        if let i = try? c.decodeIfPresent(Int64.self, forKey: key) { return String(i) }
        if let d = try? c.decodeIfPresent(Double.self, forKey: key) { return String(d) }
        return nil
    }

    /// A list field that may have arrived as a bare string — the shape
    /// an indexer flattens a one-element list to.
    private static func looseStringList(
        _ c: KeyedDecodingContainer<CodingKeys>, _ key: CodingKeys
    ) throws -> [String]? {
        if let list = try? c.decodeIfPresent([String].self, forKey: key) { return list }
        if let one = try? c.decodeIfPresent(String.self, forKey: key) {
            return one.isEmpty ? nil : [one]
        }
        return nil
    }

    // MARK: - discovery (the half that predates the lifecycle)

    /// The SID, non-optional. Empty for a record that has none, which
    /// ``ServiceRegistry`` drops rather than shows.
    public var sid: String { id ?? "" }

    /// The endpoint clients should call.
    ///
    /// **Case-insensitive on the key.** Services register the URL under
    /// `API` or `api` depending on who published them, and a resolver
    /// that only looked for one spelling would silently fail to reach
    /// half the network. Java tolerates both and so does this.
    public var apiUrl: String? {
        guard let home, !home.isEmpty else { return nil }
        if let exact = home["API"] { return exact }
        for (key, value) in home where key.lowercased() == "api" {
            return value
        }
        return nil
    }

    /// A service is live unless the chain says otherwise — a missing
    /// flag is not a retirement.
    ///
    /// **This is the discovery question, not the lifecycle one.** It
    /// asks "may I route traffic here", so an absent flag means yes and
    /// a closed record still reads true. The pane asks ``state``
    /// instead, which ranks `closed` above `active` and distinguishes a
    /// draft from a live record. Both are correct for their caller and
    /// they disagree on purpose.
    public var isActive: Bool { active ?? true }

    /// Whether this service offers `component`, e.g.
    /// ``ServiceName/dock``. Case-insensitive, because the component
    /// list is operator-written text.
    public func offers(_ component: String) -> Bool {
        components?.contains { $0.caseInsensitiveCompare(component) == .orderedSame } ?? false
    }

    /// What to call it on screen: its standard name, else its SID.
    public var displayName: String {
        if let stdName, !stdName.isEmpty { return stdName }
        return id ?? ""
    }

    /// ``maxDataSize`` as a byte count, when the record carries a usable
    /// one.
    ///
    /// `nil` means "the record does not say", which is different from
    /// zero and different from unlimited: the server then applies its own
    /// default, so a caller should assume
    /// ``ImMessage/assumedDockItemLimit`` rather than send freely. A
    /// value that will not parse, or is not positive, is treated as
    /// absent — the server does the same thing with it.
    public var itemSizeLimit: Int? {
        guard let maxDataSize,
              let bytes = Int(maxDataSize.trimmingCharacters(in: .whitespaces)),
              bytes > 0
        else { return nil }
        return bytes
    }

    // MARK: - lifecycle

    /// Where a service sits in its lifecycle. One value rather than
    /// three booleans read in the right order, because `closed`
    /// outranks `active`.
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

    /// Retired for good. **A missing flag means not closed** — `closed`
    /// is absent from plenty of rows, and `closed != true` and
    /// `closed == false` disagree exactly there.
    public var isClosed: Bool { closed == true }

    /// Stopped but not closed — the state `recover` undoes.
    public var isStopped: Bool { closed != true && active == false }

    /// Only the owner carves against a service, and never against a
    /// closed one. The chain enforces both, but only after the miner
    /// fee is spent.
    public func canUpdate(as fid: String) -> Bool {
        owner == fid && !isClosed
    }

    public func canStop(as fid: String) -> Bool {
        owner == fid && onChain != false && !isClosed && active != false
    }

    /// Recoverable: owned, on chain, stopped rather than closed.
    public func canRecover(as fid: String) -> Bool {
        owner == fid && onChain != false && isStopped
    }

    public func canClose(as fid: String) -> Bool {
        owner == fid && onChain != false && !isClosed
    }

    /// Case-insensitive substring match across the fields Java's
    /// `getSearchableFields` names — plus the SID, so pasting one finds
    /// its row, and the local names, which are what a reader sees.
    public func matches(query: String) -> Bool {
        let needle = query.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !needle.isEmpty else { return false }
        func hit(_ s: String?) -> Bool {
            guard let s else { return false }
            return s.lowercased().contains(needle)
        }
        if hit(stdName) || hit(desc) || hit(type) || hit(owner)
            || hit(ver) || hit(id) || hit(dealer) { return true }
        for list in [components, waiters, protocols, codes, services] {
            if (list ?? []).contains(where: { hit($0) }) { return true }
        }
        for value in (localNames ?? [:]).values where hit(value) { return true }
        for (key, value) in (home ?? [:]) where hit(key) || hit(value) { return true }
        return false
    }

    /// Every pricing field as one bag, for the sheets and the carve.
    /// The wire keeps them flat; this is a Swift grouping only.
    public var pricing: ServiceFeip.Pricing {
        ServiceFeip.Pricing(
            pricePerKB: pricePerKB,
            pricePerKBIn: pricePerKBIn,
            pricePerKBOut: pricePerKBOut,
            pricePerKBDay: pricePerKBDay,
            minPayment: minPayment,
            pricePerRequest: pricePerRequest,
            sessionDays: sessionDays,
            consumeViaShare: consumeViaShare,
            orderViaShare: orderViaShare,
            currency: currency,
            minCredit: minCredit,
            maxDataSize: maxDataSize,
            dataExpiresInDays: dataExpiresInDays
        )
    }

    /// Overwrite the thirteen pricing fields from a bag.
    public mutating func applyPricing(_ p: ServiceFeip.Pricing) {
        pricePerKB = p.pricePerKB
        pricePerKBIn = p.pricePerKBIn
        pricePerKBOut = p.pricePerKBOut
        pricePerKBDay = p.pricePerKBDay
        minPayment = p.minPayment
        pricePerRequest = p.pricePerRequest
        sessionDays = p.sessionDays
        consumeViaShare = p.consumeViaShare
        orderViaShare = p.orderViaShare
        currency = p.currency
        minCredit = p.minCredit
        maxDataSize = p.maxDataSize
        dataExpiresInDays = p.dataExpiresInDays
    }

    // MARK: - local id

    /// The id a draft carries before it has a txid — `sha256x2` of the
    /// publish op it will carve, hex. Same rationale as
    /// ``Code/localId(name:ver:did:desc:langs:home:protocols:waiters:)``:
    /// Android's `"local_" + currentTimeMillis()` gives the same draft a
    /// new key on every save.
    public static func localId(
        stdName: String?,
        localNames: [String: String]? = nil,
        desc: String? = nil,
        type: String? = nil,
        components: [String]? = nil,
        ver: String? = nil,
        home: [String: String]? = nil,
        waiters: [String]? = nil,
        protocols: [String]? = nil,
        codes: [String]? = nil,
        services: [String]? = nil,
        pricing: ServiceFeip.Pricing = .init()
    ) -> String {
        let detail = (try? ServiceFeip.publishOp(
            stdName: stdName, localNames: localNames, desc: desc, type: type,
            components: components, ver: ver, home: home, waiters: waiters,
            protocols: protocols, codes: codes, services: services, pricing: pricing
        )) ?? "\(stdName ?? "")\u{1F}\(type ?? "")\u{1F}\(ver ?? "")"
        return Hex.encode(Hash.doubleSha256(Data(detail.utf8)))
    }

    /// A brand-new local-only draft, owned by `owner` and not yet
    /// carved. ``active`` stays nil — a draft has no indexer behind it
    /// to call it live.
    public static func createLocal(
        stdName: String,
        localNames: [String: String]? = nil,
        desc: String? = nil,
        type: String? = nil,
        components: [String]? = nil,
        ver: String? = nil,
        home: [String: String]? = nil,
        waiters: [String]? = nil,
        protocols: [String]? = nil,
        codes: [String]? = nil,
        services: [String]? = nil,
        pricing: ServiceFeip.Pricing = .init(),
        owner: String
    ) -> Service {
        // Trimmed as well as emptied, because ``ServiceFeip`` trims when
        // it carves: a draft holding `["  "]` would show one component
        // and publish none.
        func prune(_ list: [String]?) -> [String]? {
            let clean = (list ?? [])
                .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
                .filter { !$0.isEmpty }
            return clean.isEmpty ? nil : clean
        }
        let cleanComponents = prune(components)
        let cleanWaiters = prune(waiters)
        let cleanProtocols = prune(protocols)
        let cleanCodes = prune(codes)
        let cleanServices = prune(services)
        let cleanHome = (home?.isEmpty == false) ? home : nil
        let cleanLocalNames = (localNames?.isEmpty == false) ? localNames : nil
        let clean = pricing.pruned
        var draft = Service(
            stdName: stdName,
            localNames: cleanLocalNames,
            desc: desc,
            type: type,
            components: cleanComponents,
            ver: ver,
            home: cleanHome,
            waiters: cleanWaiters,
            protocols: cleanProtocols,
            codes: cleanCodes,
            services: cleanServices,
            owner: owner,
            closed: false,
            onChain: false,
            id: localId(
                stdName: stdName, localNames: cleanLocalNames, desc: desc,
                type: type, components: cleanComponents, ver: ver,
                home: cleanHome, waiters: cleanWaiters, protocols: cleanProtocols,
                codes: cleanCodes, services: cleanServices, pricing: clean
            )
        )
        draft.applyPricing(clean)
        return draft
    }
}

/// Well-known service names, as they appear as keys in an entity's
/// `home` map.
public enum ServiceName {
    /// Store-and-forward for messages whose recipient is offline.
    public static let dock = "DOCK@No1_NrC7"
    /// Live relay for messages whose recipient is online but
    /// unreachable directly.
    public static let road = "ROAD@No1_NrC7"
    /// Content-addressed file storage (Phase 8.4).
    public static let disk = "DISK@No1_NrC7"
    /// The chain-index API.
    public static let fapi = "FAPI@No1_NrC7"
}
