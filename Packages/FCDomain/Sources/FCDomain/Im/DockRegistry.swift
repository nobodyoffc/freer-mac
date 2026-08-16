import Foundation
import FCStorage
import FCTransport

/// Which DOCK server each conversation lives on, and a connected client
/// for every one of them — the port of Android's `DockServiceRegistry`.
///
/// **Why this has to exist.** Every party in a chat declares its own
/// DOCK in its `home` map: a FID's in `freer.home`, a group's in
/// `team.home` / `square.home` / `room.home`. Those are *not* our DOCK
/// and mostly not each other's. A client that owned a single FAPI
/// connection could therefore only ever talk to the one server it was
/// configured with, which shows up as two failures that look unrelated:
///
///   - **Sending** works only into groups that happen to sit on our own
///     server, because a put aimed anywhere else depends on our DOCK
///     agreeing to forward — and forwarding is a paid, optional feature
///     a server may simply not offer.
///   - **Receiving** finds nothing at all beyond P2P, because a group's
///     messages are addressed to the group and rest on *the group's*
///     DOCK. Polling our own server for them asks the wrong machine.
///
/// So the unit of connection is the DOCK URL, not the app. This holds
/// one client per distinct URL, hands them out by URL, and knows which
/// recipient ids to ask each server for.
///
/// **What is registered.** Our own DOCK under our FID (where P2P
/// messages to us come to rest, whoever sent them), and every group we
/// belong to under its own id. Partners are deliberately *not*
/// registered: a P2P message always ends up in the recipient's DOCK, by
/// direct put or by forward, so polling a partner's server would only
/// ever find messages we sent ourselves.
public actor DockRegistry {

    /// Opens a connected client to one DOCK URL. Supplied by the app
    /// shell, which is the only layer holding the private key a FUDP
    /// handshake needs. Called again on every recovery, so it must be
    /// safe to invoke repeatedly.
    public typealias Connect = @Sendable (String) async throws -> any FapiCalling

    /// How long a DOCK that refused to connect is left alone. A server
    /// that is down stays down for longer than a poll interval, and
    /// hammering it would stall every *other* DOCK's fetch behind it.
    public static let retryCooldown: TimeInterval = 60

    public enum EntityType: String, Sendable, Codable {
        /// Our own DOCK, holding P2P messages addressed to us.
        case ownFid
        case team, square, room
    }

    /// One entity and the DOCK its messages rest on.
    public struct Entry: Sendable, Equatable {
        public let entityId: String
        public let entityType: EntityType
        /// Normalised — see ``FudpUrl``.
        public let dockUrl: String
        /// What to ask this DOCK for: our FID for ``EntityType/ownFid``,
        /// the group's id otherwise.
        public let recipientId: String
    }

    /// One server, and everything to ask it for in a single fetch.
    public struct Target: Sendable, Equatable {
        public let dockUrl: String
        public let recipientIds: [String]
    }

    /// An entity whose `home` the registry should resolve.
    public struct GroupRef: Sendable, Equatable {
        public let id: String
        public let type: EntityType
        public let home: [String: String]?

        public init(id: String, type: EntityType, home: [String: String]?) {
            self.id = id
            self.type = type
            self.home = home
        }
    }

    public static let cursorNamespace = "im.dock.cursors.v1"

    private let resolver: HomeServiceResolver
    private let kv: EncryptedKVStore

    private var entries: [String: Entry] = [:]
    private var clients: [String: any FapiCalling] = [:]
    /// When each URL last refused to connect. Presence means "cooling
    /// down"; absence means "try it".
    private var failedAt: [String: Date] = [:]

    private var connect: Connect?
    private var ownClient: (any FapiCalling)?
    /// Normalised URL of the server ``ownClient`` is pointed at.
    public private(set) var ownDockUrl: String?

    private var liveFid: String?
    private var cursors: [String: [String]] = [:]
    private var cursorsLoadedFor: String?

    public init(resolver: HomeServiceResolver, kv: EncryptedKVStore) {
        self.resolver = resolver
        self.kv = kv
    }

    // MARK: - wiring

    /// Point the registry at our own DOCK and give it a way to open
    /// others. Called by the app shell whenever the FAPI settings
    /// change, so the previous per-DOCK clients — bound to a transport
    /// that may no longer be valid — are dropped.
    public func configure(
        ownDockUrl: String?,
        ownClient: (any FapiCalling)?,
        connect: Connect?
    ) {
        let normalized = FudpUrl.normalize(ownDockUrl)
        self.ownDockUrl = normalized
        self.ownClient = ownClient
        self.connect = connect
        clients.removeAll()
        failedAt.removeAll()
        if let normalized, let ownClient {
            clients[normalized] = ownClient
        }
    }

    /// Drop every cached client without forgetting who lives where. For
    /// wake-from-sleep and network changes, where the sockets are dead
    /// but the registrations are still true.
    public func invalidateAllClients() {
        clients.removeAll()
        failedAt.removeAll()
        if let ownDockUrl, let ownClient {
            clients[ownDockUrl] = ownClient
        }
    }

    // MARK: - registration

    /// Re-derive the whole map: our own DOCK, plus one entry per group.
    ///
    /// Rebuilt wholesale rather than patched, because a group that has
    /// *moved* its DOCK and a group we have *left* both have to
    /// disappear from the old server's recipient list, and a patch that
    /// only adds would keep polling it forever.
    public func refresh(liveFid: String, groups: [GroupRef]) async {
        loadCursorsIfNeeded(for: liveFid)
        self.liveFid = liveFid

        var rebuilt: [String: Entry] = [:]
        if let ownDockUrl {
            rebuilt["\(EntityType.ownFid.rawValue):\(liveFid)"] = Entry(
                entityId: liveFid,
                entityType: .ownFid,
                dockUrl: ownDockUrl,
                recipientId: liveFid
            )
        }
        for group in groups {
            guard let resolved = await resolver.dockUrl(home: group.home),
                  let url = FudpUrl.normalize(resolved)
            else {
                // A group missing from the registry is a conversation
                // that silently receives nothing, so it is worth saying
                // out loud even though it is not an error here.
                SystemLog.shared.warning(
                    SystemSource.dock,
                    "No usable DOCK for \(group.type.rawValue) \(group.id.middleElided())",
                    detail: group.home.map { "home: \($0)" }
                        ?? "This group publishes no home map, so its messages cannot be collected."
                )
                continue
            }
            rebuilt["\(group.type.rawValue):\(group.id)"] = Entry(
                entityId: group.id,
                entityType: group.type,
                dockUrl: url,
                recipientId: group.id
            )
        }
        entries = rebuilt
    }

    /// Every server to poll, with everything to ask each one for.
    ///
    /// Recipient ids are deduplicated per server: a group hosted on our
    /// own DOCK shares one fetch with our P2P inbox rather than opening
    /// a second round trip to the same machine.
    public func fetchTargets() -> [Target] {
        var byUrl: [String: [String]] = [:]
        for entry in entries.values {
            var ids = byUrl[entry.dockUrl] ?? []
            if !ids.contains(entry.recipientId) { ids.append(entry.recipientId) }
            byUrl[entry.dockUrl] = ids
        }
        return byUrl
            .map { Target(dockUrl: $0.key, recipientIds: $0.value.sorted()) }
            .sorted { $0.dockUrl < $1.dockUrl }
    }

    public func entry(type: EntityType, id: String) -> Entry? {
        entries["\(type.rawValue):\(id)"]
    }

    /// Where one conversation's incoming messages come to rest — what
    /// ``DockFetchScheduler`` puts on its fast lane while that
    /// conversation is open.
    ///
    /// A P2P thread answers with **our own** DOCK, not the partner's:
    /// their messages to us are put into our server, so theirs is where
    /// our *outgoing* mail lands and holds nothing for us to collect.
    public func dockUrl(forTarget targetId: String, type: ImType) -> String? {
        switch type {
        case .p2p: return ownDockUrl
        case .team: return entry(type: .team, id: targetId)?.dockUrl
        case .square: return entry(type: .square, id: targetId)?.dockUrl
        case .room: return entry(type: .room, id: targetId)?.dockUrl
        }
    }

    public var registrationCount: Int { entries.count }

    // MARK: - clients

    /// Whether a URL names the server our own client is already
    /// connected to.
    public func isOwnDock(_ dockUrl: String?) -> Bool {
        FudpUrl.sameEndpoint(dockUrl, ownDockUrl)
    }

    /// A connected client for `dockUrl`, opening one if we do not have
    /// it yet.
    ///
    /// Returns nil when the URL is unusable, when there is no way to
    /// open clients, or when this DOCK refused recently enough to still
    /// be cooling down — all three being "not now", not "never". The
    /// caller falls through to its next route, which is the same thing
    /// it does for a peer that is merely unreachable.
    public func client(for dockUrl: String, now: Date = Date()) async -> (any FapiCalling)? {
        guard let url = FudpUrl.normalize(dockUrl) else { return nil }
        if let existing = clients[url] { return existing }
        if let since = failedAt[url], now.timeIntervalSince(since) < Self.retryCooldown {
            return nil
        }
        guard let connect else { return nil }

        do {
            let client = try await connect(url)
            clients[url] = client
            failedAt[url] = nil
            SystemLog.shared.info(SystemSource.dock, "Connected to \(url)")
            return client
        } catch {
            failedAt[url] = now
            SystemLog.shared.error(
                SystemSource.dock,
                "Could not connect to \(url)",
                detail: "\(error)\nNot retried for \(Int(Self.retryCooldown))s."
            )
            return nil
        }
    }

    /// Drop a client whose connection has died, so the next attempt
    /// opens a fresh one. Does *not* start the cooldown: a socket that
    /// broke mid-call is not evidence the server is down.
    public func invalidate(_ dockUrl: String) {
        guard let url = FudpUrl.normalize(dockUrl) else { return }
        // The own-DOCK client heals itself — it is a
        // `ReconnectingFapiClient` — and dropping it here would leave
        // the registry unable to rebuild it, since `connect` opens
        // *additional* clients, not the configured one.
        guard url != ownDockUrl else { return }
        clients[url] = nil
    }

    /// Mark a DOCK as refusing, starting its cooldown.
    public func markFailed(_ dockUrl: String, now: Date = Date()) {
        guard let url = FudpUrl.normalize(dockUrl) else { return }
        failedAt[url] = now
        invalidate(url)
    }

    /// Forget every cooldown, so the next pass retries all of them. For
    /// the moment the app comes back to the foreground, where waiting
    /// out a timer the user did not start is just latency.
    public func clearCooldowns() {
        failedAt.removeAll()
    }

    // MARK: - cursors

    /// Where the last fetch from this DOCK got to: the `[createTime,
    /// id]` of the final item seen.
    ///
    /// Cursors are what make polling cheap *and* what make it safe not
    /// to delete. A group's items are addressed to the group and every
    /// member fetches the same copy, so deleting one after reading it
    /// would take it from everybody else; the cursor is how we avoid
    /// re-reading it instead. They are persisted for the same reason —
    /// a relaunch that reset them would re-file every message the
    /// server is still holding.
    public func cursor(for dockUrl: String) -> [String]? {
        guard let url = FudpUrl.normalize(dockUrl) else { return nil }
        return cursors[url]
    }

    public func setCursor(_ cursor: [String]?, for dockUrl: String) {
        guard let url = FudpUrl.normalize(dockUrl) else { return }
        if let cursor, !cursor.isEmpty {
            cursors[url] = cursor
        } else {
            cursors[url] = nil
        }
        saveCursors()
    }

    /// Forget where we got to, so the next fetch collects everything
    /// the servers still hold. Costs a re-file of messages we already
    /// have — which ``MessagesStore`` keys by id, so it overwrites
    /// rather than duplicates — and nothing else.
    public func resetCursors() {
        cursors.removeAll()
        saveCursors()
    }

    private func loadCursorsIfNeeded(for fid: String) {
        guard cursorsLoadedFor != fid else { return }
        cursorsLoadedFor = fid
        cursors = (try? kv.get(
            [String: [String]].self, namespace: Self.cursorNamespace, key: fid
        )) ?? [:]
    }

    private func saveCursors() {
        guard let liveFid else { return }
        try? kv.put(cursors, namespace: Self.cursorNamespace, key: liveFid)
    }
}
