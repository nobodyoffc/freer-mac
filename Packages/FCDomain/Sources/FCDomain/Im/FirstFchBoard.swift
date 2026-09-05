import Foundation
import FCStorage
import FCTransport

/// A decision already taken about one asker: you funded them, or you
/// chose not to. Recorded so the same face does not come back tomorrow
/// asking the same thing.
///
/// **It expires.** A permanent list would be the wrong shape twice over:
/// it grows without bound on a board anyone can post to, and it is not
/// what the decision meant — skipping somebody today is not a promise
/// never to help them, and funding somebody is not a claim they can
/// never need coins again. Seven days is long enough that a helper
/// working through the board over a week never sees a row twice, and
/// short enough that a genuine second ask eventually gets through.
public struct BoardDismissal: Codable, Equatable, Sendable {

    public enum Reason: String, Codable, Sendable {
        /// We sent this FID coins.
        case funded
        /// We looked and chose not to.
        case skipped
    }

    public var reason: Reason
    /// Epoch millis after which this stops hiding anything.
    public var until: Int64

    public init(reason: Reason, until: Int64) {
        self.reason = reason
        self.until = until
    }

    public func isActive(at now: Int64) -> Bool { now < until }
}

/// What this identity has done with the first-FCH board.
///
/// Per FID, not per vault: one unlocked main can operate as several
/// identities, and "I already asked" is a fact about the FID that asked.
public struct FirstFchBoardState: Codable, Equatable, Sendable {

    /// The newest board `createTime` this identity has read past.
    ///
    /// **Only the viewer advances it.** A login check that moved the
    /// cursor would hide from the board the very requests it just
    /// prompted about.
    public var cursor: Int64

    /// When this FID posted its own request, if it has. A FID asks once:
    /// a second post says nothing new and only costs the helpers a
    /// duplicate row to read past.
    public var askedAt: Int64?

    /// Whether to look at the board on login. **Off by default** —
    /// helping newcomers is something a user opts into, not something the
    /// app decides for them.
    public var checkAtLogin: Bool

    /// Askers this identity has answered or skipped, and when each stops
    /// being hidden. Pruned and capped on every write — see
    /// ``FirstFchBoardStore/dismiss(_:reason:fid:now:)``.
    public var dismissed: [String: BoardDismissal]

    public init(
        cursor: Int64 = 0,
        askedAt: Int64? = nil,
        checkAtLogin: Bool = false,
        dismissed: [String: BoardDismissal] = [:]
    ) {
        self.cursor = cursor
        self.askedAt = askedAt
        self.checkAtLogin = checkAtLogin
        self.dismissed = dismissed
    }

    /// Decoded field by field so a row written by an older build — one
    /// with no `dismissed` key — still loads. Swift's synthesised
    /// `Decodable` does **not** fall back to a property's default value,
    /// so without this, adding a field silently turns every stored row
    /// into a decode failure and resets the identity's cursor and its
    /// asked-once flag.
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        cursor = try c.decodeIfPresent(Int64.self, forKey: .cursor) ?? 0
        askedAt = try c.decodeIfPresent(Int64.self, forKey: .askedAt)
        checkAtLogin = try c.decodeIfPresent(Bool.self, forKey: .checkAtLogin) ?? false
        dismissed = try c.decodeIfPresent(
            [String: BoardDismissal].self, forKey: .dismissed
        ) ?? [:]
    }

    public var hasAsked: Bool { askedAt != nil }

    /// The dismissals still in force, with the lapsed ones dropped.
    public func activeDismissals(now: Int64) -> [String: BoardDismissal] {
        dismissed.filter { $0.value.isActive(at: now) }
    }
}

/// Per-identity board state, keyed by FID. Human-scale.
public struct FirstFchBoardStore {

    public static let namespace = "im.firstfchboard.v1"

    /// How long a funded-or-skipped asker stays hidden.
    public static let dismissalWindow: TimeInterval = 7 * 24 * 60 * 60

    /// Ceiling on remembered dismissals per identity. A public board is
    /// an unbounded source of FIDs, so the row that remembers decisions
    /// about them needs a bound of its own — expiry alone does not give
    /// one, because a week of a busy board can still be more names than
    /// belong in a settings row. Over the cap the **soonest to expire**
    /// go first: they are the decisions closest to being forgotten
    /// anyway, so the most recent ones survive.
    public static let maxDismissals = 500

    private let inner: TypedStore<FirstFchBoardState>

    public init(kv: EncryptedKVStore) {
        self.inner = TypedStore(kv: kv, namespace: Self.namespace)
    }

    public func get(fid: String) -> FirstFchBoardState {
        ((try? inner.get(fid)) ?? nil) ?? FirstFchBoardState()
    }

    public func put(_ state: FirstFchBoardState, fid: String) throws {
        try inner.put(state, key: fid)
    }

    /// Read-modify-write one identity's row.
    ///
    /// **Every write prunes.** That is the whole storage policy: there is
    /// no sweeper task and no startup pass, because the only thing that
    /// grows this row is a write, so the only place it has to be trimmed
    /// is a write.
    @discardableResult
    public func mutate(
        fid: String, now: Date = Date(), _ change: (inout FirstFchBoardState) -> Void
    ) throws -> FirstFchBoardState {
        var state = get(fid: fid)
        change(&state)
        state.dismissed = Self.trimmed(state.dismissed, now: Self.millis(now))
        try put(state, fid: fid)
        return state
    }

    /// Hide these askers for ``dismissalWindow``.
    @discardableResult
    public func dismiss(
        _ fids: some Sequence<String>,
        reason: BoardDismissal.Reason,
        fid: String,
        now: Date = Date()
    ) throws -> FirstFchBoardState {
        let until = Self.millis(now.addingTimeInterval(Self.dismissalWindow))
        return try mutate(fid: fid, now: now) { state in
            for asker in fids {
                // A later decision wins outright rather than extending
                // the old one: funding somebody you had skipped should
                // record that you funded them.
                state.dismissed[asker] = BoardDismissal(reason: reason, until: until)
            }
        }
    }

    /// Un-hide these askers — the undo for a mis-click on Ignore, which
    /// would otherwise cost a week.
    @discardableResult
    public func restore(
        _ fids: some Sequence<String>, fid: String, now: Date = Date()
    ) throws -> FirstFchBoardState {
        try mutate(fid: fid, now: now) { state in
            for asker in fids { state.dismissed.removeValue(forKey: asker) }
        }
    }

    /// Drop what has lapsed, then drop the soonest-to-expire until the
    /// row fits.
    static func trimmed(
        _ dismissed: [String: BoardDismissal], now: Int64
    ) -> [String: BoardDismissal] {
        var live = dismissed.filter { $0.value.isActive(at: now) }
        guard live.count > maxDismissals else { return live }
        let doomed = live
            .sorted { $0.value.until < $1.value.until }
            .prefix(live.count - maxDismissals)
        for entry in doomed { live.removeValue(forKey: entry.key) }
        return live
    }

    public static func millis(_ date: Date) -> Int64 {
        Int64(date.timeIntervalSince1970 * 1000)
    }
}

/// Both sides of the first-FCH board: posting a request when you have
/// nothing, and reading what other people have posted when you do.
///
/// The two sides never share an identity. A newcomer posts **as
/// themselves** to the board's inbox; a helper reads that inbox while
/// staying signed in as themselves and answers with an ordinary on-chain
/// payment from their own FID. Nothing in this file ever signs, connects
/// or spends as the nobody — its key being public is precisely why it
/// must never be used as an identity.
///
/// **Reading is a DOCK fetch of somebody else's inbox**, which is unusual
/// enough that a server may refuse it: a DOCK that does not grant
/// public-board semantics answers a fetch for a recipient that is not the
/// session's own with an error. That refusal is carried in
/// ``FetchResult/error`` rather than swallowed, because a refusal and an
/// empty board are otherwise the same blank screen.
public struct FirstFchBoard {

    /// How much of the board one fetch pulls.
    public static let pageSize = 100

    private let directory: DirectoryService
    private let resolver: HomeServiceResolver
    private let registry: DockRegistry
    /// Whose decisions apply, and where they are kept. Held here rather
    /// than left to the caller so that **every** reader filters the same
    /// way — the pane and the login check both go through ``fetch``, and
    /// a nudge that counted askers the user had already funded would be
    /// worse than no nudge.
    private let state: FirstFchBoardStore
    private let liveFid: String

    public init(
        directory: DirectoryService,
        resolver: HomeServiceResolver,
        registry: DockRegistry,
        state: FirstFchBoardStore,
        liveFid: String
    ) {
        self.directory = directory
        self.resolver = resolver
        self.registry = registry
        self.state = state
        self.liveFid = liveFid
    }

    // MARK: - the board's server

    /// Connect to the DOCK named in the board freer's on-chain home,
    /// reusing ``DockRegistry`` so an existing connection is shared and a
    /// server that just refused is left in its cooldown.
    public func boardDock(timeoutMs: Int = 10_000) async -> (any FapiCalling)? {
        guard let freer = try? await directory.freer(
            byId: NobodyBoard.defaultNobodyFid, timeoutMs: timeoutMs
        ) else { return nil }
        guard let url = await resolver.dockUrl(home: freer.home, timeoutMs: timeoutMs)
        else { return nil }
        return await registry.client(for: url)
    }

    // MARK: - asking (the newcomer's side)

    /// Post one request to the board.
    ///
    /// Deliberately **not** a ``ChatService`` send: the board must never
    /// appear in the chat list, must not become a conversation, and has no
    /// owner to acknowledge delivery — so there is nothing for the outbox
    /// to retry against and nothing for the transcript to show. What comes
    /// back is the DOCK's receipt for the put, which is the only success
    /// this can honestly report.
    ///
    /// The body is sealed to the board's pubkey like any other P2P
    /// message. That is not privacy — the key that opens it is published
    /// two files up — it is the transport's rule applied without an
    /// exception, so that "sealed unless someone remembered otherwise"
    /// never becomes representable.
    @discardableResult
    public func post(
        note: String?,
        as liveFid: String,
        privkey: Data,
        timeoutMs: Int = 15_000
    ) async throws -> DockItem {
        guard let client = await boardDock(timeoutMs: timeoutMs) else {
            throw Failure.boardUnreachable
        }
        var message = ImMessage.text(
            type: .p2p,
            from: liveFid,
            to: NobodyBoard.defaultNobodyFid,
            NobodyBoard.buildRequest(from: liveFid, note: note)
        )
        message.setId(fudpId: ImMessage.newFudpId())
        try message.sealBody(privkey: privkey, recipientPubkey: NobodyBoard.pubkey)

        return try await DockService(fapi: client).put(
            try message.toWireBytes(),
            recipients: [NobodyBoard.defaultNobodyFid],
            // This connection *is* the board's DOCK — nothing to forward.
            targetDockUrl: nil,
            ownDockUrl: nil,
            timeoutMs: timeoutMs
        )
    }

    // MARK: - reading (the helper's side)

    /// One pass over the board.
    public struct FetchResult: Sendable {
        /// Open requests, newest first: one per asker, nobody who has
        /// since been funded, and nobody this identity has already dealt
        /// with. **This is the count a nudge may use.**
        public let requests: [NobodyBoard.Request]
        /// Open requests held back by a live ``BoardDismissal``, with the
        /// decision that hid each one. Returned rather than dropped so
        /// the pane can say how many are hidden and offer them back —
        /// a persisted hide with no way to undo it is a trap.
        public let dismissed: [(request: NobodyBoard.Request, dismissal: BoardDismissal)]
        /// The newest server `createTime` seen across **everything**
        /// retrieved — including posts that were filtered out, so the
        /// cursor moves past spam and answered asks too rather than
        /// re-reading them forever.
        public let maxCreateTime: Int64
        /// Why the board could not be read, when it could not be.
        public let error: String?

        public var isEmpty: Bool { requests.isEmpty }
    }

    /// Read the board, keeping only what a helper can still act on.
    ///
    /// Three filters, in this order:
    ///
    ///   - **The template.** Anything that is not a
    ///     ``NobodyBoard/Request`` is not shown. See the template's note.
    ///   - **Latest per asker.** Someone who posted three times is one
    ///     row, at their newest post.
    ///   - **Still broke.** A requester with an on-chain balance was
    ///     already helped — or is farming — and either way no longer needs
    ///     answering. One `base.freerByIds` covers the whole page, so this
    ///     costs a single call however many rows came back.
    ///
    /// `newerThan` is the caller's cursor. It keys off the **server's**
    /// `createTime` and never the sender's `timestamp`: the timestamp is
    /// written by whoever posted, so a scammer could set it years ahead
    /// and step over every reader's cursor at once.
    public func fetch(
        newerThan cursor: Int64 = 0,
        now: Date = Date(),
        timeoutMs: Int = 15_000
    ) async -> FetchResult {
        guard let client = await boardDock(timeoutMs: timeoutMs) else {
            return FetchResult(
                requests: [], dismissed: [], maxCreateTime: cursor,
                error: "The board's DOCK could not be reached. It publishes where it lives "
                    + "on chain, so this needs a working connection to the index as well."
            )
        }

        let items: [DockItem]
        do {
            items = try await DockService(fapi: client).fetchNewest(
                recipientIds: [NobodyBoard.defaultNobodyFid],
                newerThanCreateTime: cursor > 0 ? cursor : nil,
                size: Self.pageSize,
                timeoutMs: timeoutMs
            )
        } catch {
            return FetchResult(
                requests: [], dismissed: [], maxCreateTime: cursor,
                error: "The board's DOCK refused the read: \(error)"
            )
        }

        var maxCreateTime = cursor
        var latestByFid: [String: NobodyBoard.Request] = [:]
        for item in items {
            if let created = item.createTime, created > maxCreateTime {
                maxCreateTime = created
            }
            guard let data = item.data,
                  let message = NobodyBoard.openPost(wireBytes: data),
                  let request = NobodyBoard.parseRequest(
                      message.content,
                      // The server's time is the honest one; the message's
                      // own is only a fallback for a DOCK that omits it.
                      createTime: item.createTime ?? message.timestamp
                  )
            else { continue }
            if let seen = latestByFid[request.requesterFid], seen.createTime >= request.createTime {
                continue
            }
            latestByFid[request.requesterFid] = request
        }

        var open = latestByFid.values.sorted { $0.createTime > $1.createTime }
        if !open.isEmpty {
            let funded = await fundedFids(among: open.map(\.requesterFid), timeoutMs: timeoutMs)
            open.removeAll { funded.contains($0.requesterFid) }
        }

        // Last filter, and the only one that is about *us* rather than
        // about the asker: what this identity has already decided.
        let dismissals = state.get(fid: liveFid).activeDismissals(now: FirstFchBoardStore.millis(now))
        var shown: [NobodyBoard.Request] = []
        var hidden: [(request: NobodyBoard.Request, dismissal: BoardDismissal)] = []
        for request in open {
            if let dismissal = dismissals[request.requesterFid] {
                hidden.append((request, dismissal))
            } else {
                shown.append(request)
            }
        }
        return FetchResult(
            requests: shown, dismissed: hidden, maxCreateTime: maxCreateTime, error: nil
        )
    }

    /// Which of `fids` already hold coins. A lookup that fails answers
    /// "none of them": showing a request that turns out to be answered
    /// wastes a helper's glance, and hiding one that is still open wastes
    /// the newcomer's day.
    private func fundedFids(among fids: [String], timeoutMs: Int) async -> Set<String> {
        guard let freers = try? await directory.freerByIds(fids, timeoutMs: timeoutMs)
        else { return [] }
        return Set(freers.filter { ($0.value.balance ?? 0) > 0 }.keys)
    }

    public enum Failure: Error, CustomStringConvertible {
        case boardUnreachable

        public var description: String {
            switch self {
            case .boardUnreachable:
                return "The first-FCH board's DOCK could not be reached — check your connection and try again."
            }
        }
    }
}
