import Foundation
import FCStorage

/// One outstanding question: "please send me this entity's key".
///
/// **An ask is state, not a notice.** Three separate rules need to know
/// that this device asked for a key, and none of them can be answered by
/// a toast that has already faded:
///
/// - FIMP §4.2 admits a key from a non-owner **only** as the answer to a
///   request we made. Without a record of what we asked, every member's
///   answer is indistinguishable from an unsolicited push and has to be
///   discarded — which is what Android has always done, and why answers
///   from ordinary members used to vanish while the owner's got through.
/// - FIMP §7.4 rate-limits asking, and the limit has to survive a
///   restart or a relaunch re-asks everything.
/// - A person needs to see that recovery is stalled, and who they
///   already asked, because which member to ask next is a judgement
///   about people that nothing else can make.
///
/// See SYMKEY_IDENTITY_SPEC.md §4.
public struct KeyAsk: Codable, Equatable, Sendable, Identifiable {

    /// The room or team whose key is wanted.
    public var entityId: String
    /// The version wanted, or ``KeyAsksStore/currentVersion`` for
    /// "whatever you hold now" — a joiner who holds nothing, or a
    /// `ROOM_INFO` ask, which cannot know what it is about to be given.
    public var version: Int64
    /// What was sent: ``RequestType/symkey`` or ``RequestType/roomInfo``.
    public var kind: RequestType
    /// Who was asked, in the order they were asked.
    public var askedFids: [String]
    /// FID → when we last put this question to them, in milliseconds.
    /// The cooldown is per person, so this is per person.
    public var askedAt: [String: Int64]
    /// The id of every request message sent for this ask — one per
    /// person, and a new one each time somebody is asked again. An
    /// answer must carry one of these or it is not an answer.
    public var requestIds: [String]
    public var firstAskedAt: Int64
    /// How many request messages this ask has cost, all told. What the
    /// UI means by "asked 3 times".
    public var attempts: Int

    public var id: String { KeyAsksStore.storageKey(entityId: entityId, version: version) }

    /// The last time anybody was asked.
    public var lastAskedAt: Int64 { askedAt.values.max() ?? firstAskedAt }

    public init(
        entityId: String,
        version: Int64,
        kind: RequestType,
        askedFids: [String] = [],
        askedAt: [String: Int64] = [:],
        requestIds: [String] = [],
        firstAskedAt: Int64,
        attempts: Int = 0
    ) {
        self.entityId = entityId
        self.version = version
        self.kind = kind
        self.askedFids = askedFids
        self.askedAt = askedAt
        self.requestIds = requestIds
        self.firstAskedAt = firstAskedAt
        self.attempts = attempts
    }
}

/// The asks this device has outstanding — what it asked for, who it
/// asked, and when.
///
/// Shaped on ``HistorySharesStore``, which keeps the same kind of record
/// for a history request, because the two are the same problem: a
/// question whose answer arrives on a later receive, addressed to a
/// device that has to still know it asked.
public struct KeyAsksStore {

    public static let namespace = "im.keyasks.v1"

    /// The version that means "whatever you hold now". Not a version any
    /// key can have — ``SymkeyStore/minimumVersion`` is 1 — so it cannot
    /// be confused with one.
    public static let currentVersion: Int64 = 0

    /// One request per person per `(entity, version)` per two minutes —
    /// FIMP §7.4.
    ///
    /// **Per person, not per question.** The limit exists because a
    /// responder pays for answering (FIMP §9.8), so what has to be
    /// bounded is how often *one member* is made to answer the same
    /// thing. Counting per question instead would mean a user who asked
    /// one member and got nothing could not ask a second member for two
    /// minutes, which throttles the wrong thing: that is not a repeat,
    /// it is the next attempt at recovery, and it costs the first member
    /// nothing.
    public static let cooldown: TimeInterval = 120

    /// An ask nobody answered stops being shown after this, so a
    /// recovery that was abandoned does not nag forever.
    public static let expiry: TimeInterval = 30 * 24 * 60 * 60

    /// Request ids kept per ask, newest last. Enough to cover every
    /// member of a real group asked several times over; older ones fall
    /// off, and an answer to one of those is then treated as
    /// unsolicited, which after this many later requests it effectively
    /// is.
    public static let maxRequestIds = 64

    private let inner: TypedStore<KeyAsk>

    public init(kv: EncryptedKVStore) {
        self.inner = TypedStore(kv: kv, namespace: Self.namespace)
    }

    /// `<entityId>_<19-digit version>`, so the row order is the version
    /// order and an entity's asks read off the key list together.
    static func storageKey(entityId: String, version: Int64) -> String {
        entityId + "_" + String(format: "%019lld", version)
    }

    // MARK: - reading

    public func ask(entityId: String, version: Int64) throws -> KeyAsk? {
        try inner.get(Self.storageKey(entityId: entityId, version: version))
    }

    /// Every ask still outstanding, oldest question first.
    public func all() throws -> [KeyAsk] {
        try inner.all().map(\.value).sorted { $0.firstAskedAt < $1.firstAskedAt }
    }

    /// The asks outstanding for one entity.
    public func asks(for entityId: String) throws -> [KeyAsk] {
        try all().filter { $0.entityId == entityId }
    }

    // MARK: - asking

    /// Which of `fids` may be asked now, and when the rest become
    /// askable again.
    ///
    /// The caller builds request messages only for `allowed`, then
    /// reports what it sent with
    /// ``record(entityId:version:kind:sent:now:)``. Splitting it this way
    /// is what lets the UI say "asked 40s ago" instead of silently
    /// dropping a button press.
    public func askable(
        _ fids: [String],
        entityId: String,
        version: Int64,
        now: Date = Date()
    ) throws -> (allowed: [String], waiting: [(fid: String, until: Date)]) {
        let existing = try ask(entityId: entityId, version: version)
        var allowed: [String] = []
        var waiting: [(fid: String, until: Date)] = []
        var seen: Set<String> = []
        for fid in fids where !fid.isEmpty && seen.insert(fid).inserted {
            guard let last = existing?.askedAt[fid] else {
                allowed.append(fid)
                continue
            }
            let readyAt = Date(timeIntervalSince1970: Double(last) / 1000 + Self.cooldown)
            if readyAt <= now { allowed.append(fid) } else { waiting.append((fid, readyAt)) }
        }
        return (allowed, waiting)
    }

    /// Record the requests we just sent. `sent` pairs each person asked
    /// with the id of the message asking them.
    ///
    /// Merges into the ask already there rather than replacing it: the
    /// earlier request ids still have to be recognised, because the
    /// member who has not answered yet may still answer.
    @discardableResult
    public func record(
        entityId: String,
        version: Int64,
        kind: RequestType,
        sent: [(fid: String, requestId: String)],
        now: Date = Date()
    ) throws -> KeyAsk {
        let stamp = Int64(now.timeIntervalSince1970 * 1000)
        let storageKey = Self.storageKey(entityId: entityId, version: version)
        var ask = try inner.get(storageKey) ?? KeyAsk(
            entityId: entityId, version: version, kind: kind, firstAskedAt: stamp
        )
        for (fid, requestId) in sent {
            guard !fid.isEmpty else { continue }
            if !ask.askedFids.contains(fid) { ask.askedFids.append(fid) }
            ask.askedAt[fid] = stamp
            if !requestId.isEmpty, !ask.requestIds.contains(requestId) {
                ask.requestIds.append(requestId)
            }
            ask.attempts += 1
        }
        if ask.requestIds.count > Self.maxRequestIds {
            ask.requestIds.removeFirst(ask.requestIds.count - Self.maxRequestIds)
        }
        try inner.put(ask, key: storageKey)
        return ask
    }

    // MARK: - admitting an answer

    /// Whether a key arriving for `(entityId, version)` under
    /// `requestId` answers something we asked for.
    ///
    /// An ask for ``currentVersion`` is answered by **any** version: we
    /// asked for whatever the responder had, so we cannot then object to
    /// which one we were given. An ask naming a version is answered only
    /// by that version — a responder substituting its current key for the
    /// one asked for is the failure FIMP §5.1 forbids, and admitting it
    /// would store a key that opens nothing and block the one that does.
    public func isSolicited(
        entityId: String, version: Int64, requestId: String?
    ) throws -> Bool {
        guard let requestId, !requestId.isEmpty else { return false }
        for ask in try asks(for: entityId) where ask.requestIds.contains(requestId) {
            if ask.version == Self.currentVersion || ask.version == version { return true }
        }
        return false
    }

    // MARK: - finishing

    /// Clear what a key for `(entityId, version)` answers: the ask naming
    /// that version, and any ask for the entity's current key, which this
    /// also satisfies.
    @discardableResult
    public func resolve(entityId: String, version: Int64) throws -> Int {
        var cleared = 0
        for candidate in [version, Self.currentVersion] {
            let storageKey = Self.storageKey(entityId: entityId, version: candidate)
            if try inner.exists(storageKey) {
                try inner.delete(storageKey)
                cleared += 1
            }
        }
        return cleared
    }

    /// Clear every ask for `entityId` that the keys now held answer.
    ///
    /// For the deliveries that carry a key without naming which request
    /// they answer — a room's `ROOM_INFO`, whose key rides along with the
    /// membership — the only honest test is whether what we now hold
    /// covers what we asked for.
    @discardableResult
    public func resolve(entityId: String, heldVersions: Set<Int64>) throws -> Int {
        var cleared = 0
        for ask in try asks(for: entityId) {
            let answered = ask.version == Self.currentVersion
                ? !heldVersions.isEmpty
                : heldVersions.contains(ask.version)
            guard answered else { continue }
            if try remove(entityId: entityId, version: ask.version) { cleared += 1 }
        }
        return cleared
    }

    /// Give up on one ask — the user's "stop showing me this".
    @discardableResult
    public func remove(entityId: String, version: Int64) throws -> Bool {
        let storageKey = Self.storageKey(entityId: entityId, version: version)
        guard try inner.exists(storageKey) else { return false }
        try inner.delete(storageKey)
        return true
    }

    /// Drop asks nothing has answered in ``expiry``. Returns how many
    /// went.
    @discardableResult
    public func prune(now: Date = Date()) throws -> Int {
        let cutoff = Int64((now.timeIntervalSince1970 - Self.expiry) * 1000)
        var pruned = 0
        for (key, ask) in try inner.all() where ask.lastAskedAt < cutoff {
            try inner.delete(key)
            pruned += 1
        }
        return pruned
    }
}
