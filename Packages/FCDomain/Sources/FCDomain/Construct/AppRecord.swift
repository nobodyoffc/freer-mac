import Foundation
import FCCore

/// An app record published on chain — the Swift mirror of the Java
/// `feipData.App`, and the record type of the `app` index.
///
/// **The fourth and last of the Construct records.** ``ProtocolSpec``
/// registers a specification, ``Code`` registers an implementation of
/// one, ``Service`` registers an implementation somebody is running at
/// an address, and an *app* registers **something a person can
/// install**. The four share one lifecycle (`publish` → `update` →
/// `stop` ⇄ `recover` → `close`), one owner-and-waiters shape and one
/// `rate` op; what differs is what they register and which index holds
/// them.
///
/// **`AppRecord`, not `App`.** SwiftUI's `App` protocol is in scope in
/// every view file in this project, so the type would be ambiguous
/// wherever both are imported — the same collision that made
/// ``ProtocolSpec`` not `Protocol`. The wire is unaffected: the carve
/// still says `"name":"APP"`.
///
/// **The field with no analogue in the other three is ``downloads``** —
/// a list of `{os, link, did}` objects, so one record can offer a build
/// per platform and a digest to check each one against. It is also the
/// only *nested object* list anywhere in the Construct family; the rest
/// are flat strings.
///
/// **Android never implemented it.** `CreateAppActivity` and
/// `UpdateAppActivity` both pass `null` where downloads go, with the
/// comment "not implemented in this UI", and `AppActivity` does not
/// display them. So an app record published from Android cannot say
/// where to get the app — and because an update resends the whole
/// mutable half, **updating from Android erases any downloads another
/// client carved** (**Android issue C23**).
///
/// **``onChain`` is three-valued**, as on the other three: `true` means
/// a block confirms it, `false` means the row never left this device,
/// and `nil` means broadcast-but-unconfirmed.
public struct AppRecord: Codable, Equatable, Sendable, Identifiable {

    /// Where to get one build of the app.
    ///
    /// **The `did` is the point.** A link alone asks the reader to trust
    /// whatever the host serves today; the digest is what turns the
    /// chain record into a check on the download. Nothing enforces it —
    /// the reader has to do the hashing — but the claim is signed and
    /// permanent, so a substituted binary is provably not the one that
    /// was registered.
    public struct Download: Codable, Equatable, Sendable, Identifiable {
        /// Which platform this build is for. Free text: `macos`,
        /// `android`, `linux-arm64`, whatever the publisher uses.
        public var os: String?
        /// Where to fetch it.
        public var link: String?
        /// Digest of the artefact at ``link``.
        public var did: String?

        /// Identity for a list editor. Derived rather than stored: the
        /// wire has no id here, and adding one would carve a field the
        /// protocol does not define.
        public var id: String { "\(os ?? "")\u{1F}\(link ?? "")\u{1F}\(did ?? "")" }

        public init(os: String? = nil, link: String? = nil, did: String? = nil) {
            self.os = os
            self.link = link
            self.did = did
        }

        /// Trimmed, with blanks dropped — nil when nothing is left
        /// worth carving. A row with only an OS names a platform and
        /// offers nothing, which is worse than no row.
        public var pruned: Download? {
            func clean(_ s: String?) -> String? {
                guard let t = s?.trimmingCharacters(in: .whitespacesAndNewlines), !t.isEmpty
                else { return nil }
                return t
            }
            let link = clean(link)
            let did = clean(did)
            guard link != nil || did != nil else { return nil }
            return Download(os: clean(os), link: link, did: did)
        }

        /// The JSON object this becomes inside a carve, keys sorted so
        /// the payload is byte-stable.
        public var wireObject: [String: String] {
            var out: [String: String] = [:]
            if let os, !os.isEmpty { out["os"] = os }
            if let link, !link.isEmpty { out["link"] = link }
            if let did, !did.isEmpty { out["did"] = did }
            return out
        }
    }

    // MARK: - wire fields, in Java declaration order

    /// The app's canonical name. Like ``Service`` and unlike
    /// ``Code``/``ProtocolSpec``, an app is named `stdName` plus a
    /// ``localNames`` map rather than a plain `name`.
    public var stdName: String?
    /// Display names by language tag.
    public var localNames: [String: String]?
    /// What kind of app it is — a *list*, unlike ``Service/type``,
    /// because one app is often several things at once (`wallet`,
    /// `im`, `browser`).
    public var types: [String]?
    public var desc: String?
    public var ver: String?
    /// Where to read about it, label → URL. Not where to download it —
    /// that is ``downloads``.
    public var home: [String: String]?
    /// One entry per platform build. See the type note.
    public var downloads: [Download]?
    /// FIDs that serve this app — who to talk to about it. A waiter is
    /// not a co-owner: only ``owner`` can carve.
    public var waiters: [String]?
    /// Record ids in the `protocol` index that this app speaks.
    public var protocols: [String]?
    /// Record ids in the `code` index — which implementation it is
    /// built from.
    public var codes: [String]?
    /// SIDs in the `service` index that it talks to.
    public var services: [String]?

    /// The FID that published it, and the only one that can `update`,
    /// `stop`, `recover` or `close` it.
    public var owner: String?
    /// Seconds since the epoch.
    public var birthTime: Int64?
    public var birthHeight: Int64?
    public var lastTxId: String?
    public var lastTime: Int64?
    public var lastHeight: Int64?

    /// Total coin-days destroyed rating this app.
    public var tCdd: Int64?
    /// CDD-weighted average score, 1–5.
    public var tRate: Float?

    /// In force. `stop` sets it false, `recover` sets it true again.
    public var active: Bool?
    /// Retired for good; nothing undoes it.
    public var closed: Bool?
    /// Why it was closed, if the closer said.
    public var closeStatement: String?
    /// Confirmed / broadcast-unconfirmed / local-only.
    public var onChain: Bool?

    /// The AID — the publish carve's txid once carved, a locally
    /// derived digest before that.
    public var id: String

    // MARK: - local bookkeeping
    //
    // Not on the wire — see the CodingKeys note.

    public var addedAt: Date
    public var updatedAt: Date

    /// The wire fields only. `addedAt`/`updatedAt` are ours: a server
    /// reply never carries them, and decoding must not fail for their
    /// absence.
    private enum CodingKeys: String, CodingKey {
        case stdName, localNames, types, desc, ver, home, downloads
        case waiters, protocols, codes, services
        case owner, birthTime, birthHeight
        case lastTxId, lastTime, lastHeight
        case tCdd, tRate, active, closed, closeStatement
        case onChain, id
        case addedAt, updatedAt
    }

    public init(
        id: String,
        stdName: String? = nil,
        localNames: [String: String]? = nil,
        types: [String]? = nil,
        desc: String? = nil,
        ver: String? = nil,
        home: [String: String]? = nil,
        downloads: [Download]? = nil,
        waiters: [String]? = nil,
        protocols: [String]? = nil,
        codes: [String]? = nil,
        services: [String]? = nil,
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
        self.stdName = stdName
        self.localNames = localNames
        self.types = types
        self.desc = desc
        self.ver = ver
        self.home = home
        self.downloads = downloads
        self.waiters = waiters
        self.protocols = protocols
        self.codes = codes
        self.services = services
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
        stdName = try c.decodeIfPresent(String.self, forKey: .stdName)
        localNames = try c.decodeIfPresent([String: String].self, forKey: .localNames)
        types = try Self.looseStringList(c, .types)
        desc = try c.decodeIfPresent(String.self, forKey: .desc)
        // A publisher versioning `1` or `2.0` may well have carved it as
        // a JSON number; both decode to the same string rather than
        // failing the whole page over a missing pair of quotes.
        ver = try Self.looseString(c, .ver)
        home = try c.decodeIfPresent([String: String].self, forKey: .home)
        // A malformed downloads list must not cost the row it arrived
        // in: an app whose other fields are fine is still worth showing,
        // and the list is the field most likely to be hand-rolled.
        downloads = try? c.decodeIfPresent([Download].self, forKey: .downloads)
        waiters = try Self.looseStringList(c, .waiters)
        protocols = try Self.looseStringList(c, .protocols)
        codes = try Self.looseStringList(c, .codes)
        services = try Self.looseStringList(c, .services)
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

    // MARK: - derived state

    /// List label: the standard name, else the AID.
    public var displayName: String {
        if let stdName, !stdName.isEmpty { return stdName }
        return id
    }

    /// Where an app record sits in its lifecycle. One value rather than
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

    /// Only the owner carves against an app record, and never against a
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

    /// The download for one platform, if the record offers one.
    /// Case-insensitive, because the OS string is publisher-written
    /// text.
    public func download(forOS os: String) -> Download? {
        downloads?.first { $0.os?.caseInsensitiveCompare(os) == .orderedSame }
    }

    /// Case-insensitive substring match across the fields Java's
    /// `getSearchableFields` names — plus the AID, the local names and
    /// the downloads, which a reader can see and Java's list cannot
    /// reach.
    public func matches(query: String) -> Bool {
        let needle = query.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !needle.isEmpty else { return false }
        func hit(_ s: String?) -> Bool {
            guard let s else { return false }
            return s.lowercased().contains(needle)
        }
        if hit(stdName) || hit(desc) || hit(owner) || hit(ver) || hit(id) { return true }
        for list in [types, waiters, protocols, codes, services] {
            if (list ?? []).contains(where: { hit($0) }) { return true }
        }
        for value in (localNames ?? [:]).values where hit(value) { return true }
        for (key, value) in (home ?? [:]) where hit(key) || hit(value) { return true }
        for d in (downloads ?? []) where hit(d.os) || hit(d.link) || hit(d.did) { return true }
        return false
    }

    // MARK: - local id

    /// The id a draft carries before it has a txid — `sha256x2` of the
    /// publish op it will carve, hex.
    ///
    /// Same rationale as ``Code/localId(name:ver:did:desc:langs:home:protocols:waiters:)``:
    /// Android's `"local_" + System.currentTimeMillis()` gives the same
    /// draft a new key on every save, so editing one twice leaves three
    /// rows.
    public static func localId(
        stdName: String?,
        localNames: [String: String]? = nil,
        types: [String]? = nil,
        desc: String? = nil,
        ver: String? = nil,
        home: [String: String]? = nil,
        downloads: [Download]? = nil,
        waiters: [String]? = nil,
        protocols: [String]? = nil,
        codes: [String]? = nil,
        services: [String]? = nil
    ) -> String {
        let detail = (try? AppFeip.publishOp(
            stdName: stdName, localNames: localNames, types: types, desc: desc,
            ver: ver, home: home, downloads: downloads, waiters: waiters,
            protocols: protocols, codes: codes, services: services
        )) ?? "\(stdName ?? "")\u{1F}\(ver ?? "")"
        return Hex.encode(Hash.doubleSha256(Data(detail.utf8)))
    }

    /// A brand-new local-only draft, owned by `owner` and not yet
    /// carved.
    ///
    /// ``active`` stays nil rather than true. Android writes
    /// `setActive(true)` here, which claims a record no chain has seen
    /// is already in force; `active` is the *indexer's* verdict, and a
    /// draft has no indexer behind it.
    public static func createLocal(
        stdName: String,
        localNames: [String: String]? = nil,
        types: [String]? = nil,
        desc: String? = nil,
        ver: String? = nil,
        home: [String: String]? = nil,
        downloads: [Download]? = nil,
        waiters: [String]? = nil,
        protocols: [String]? = nil,
        codes: [String]? = nil,
        services: [String]? = nil,
        owner: String
    ) -> AppRecord {
        // Trimmed as well as emptied, because ``AppFeip`` trims when it
        // carves: a draft holding `["  "]` would show one type and
        // publish none.
        func prune(_ list: [String]?) -> [String]? {
            let clean = (list ?? [])
                .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
                .filter { !$0.isEmpty }
            return clean.isEmpty ? nil : clean
        }
        let cleanTypes = prune(types)
        let cleanWaiters = prune(waiters)
        let cleanProtocols = prune(protocols)
        let cleanCodes = prune(codes)
        let cleanServices = prune(services)
        let cleanHome = (home?.isEmpty == false) ? home : nil
        let cleanLocalNames = (localNames?.isEmpty == false) ? localNames : nil
        let cleanDownloads: [Download]? = {
            let kept = (downloads ?? []).compactMap(\.pruned)
            return kept.isEmpty ? nil : kept
        }()
        return AppRecord(
            id: localId(
                stdName: stdName, localNames: cleanLocalNames, types: cleanTypes,
                desc: desc, ver: ver, home: cleanHome, downloads: cleanDownloads,
                waiters: cleanWaiters, protocols: cleanProtocols,
                codes: cleanCodes, services: cleanServices
            ),
            stdName: stdName,
            localNames: cleanLocalNames,
            types: cleanTypes,
            desc: desc,
            ver: ver,
            home: cleanHome,
            downloads: cleanDownloads,
            waiters: cleanWaiters,
            protocols: cleanProtocols,
            codes: cleanCodes,
            services: cleanServices,
            owner: owner,
            closed: false,
            onChain: false
        )
    }
}
