import Foundation
import FCStorage

/// What we last observed about one peer — Android's `PeerInfo`.
///
/// All of it is **observation, not truth**: `online` means "the last
/// thing that happened with this peer said they were there", and it
/// decays into a guess the moment nothing else happens. Nothing here is
/// authoritative and nothing here should gate a send — it decides what
/// route to *try first*, which is why a stale `true` costs one failed
/// attempt rather than a lost message.
public struct PeerInfo: Codable, Equatable, Sendable, Identifiable {

    public var fid: String
    /// Milliseconds since the epoch, of the last sign of life.
    public var lastSeenAt: Int64?
    /// How we last reached them successfully. A `dockStored` here means
    /// they were *not* reachable live last time.
    public var lastDeliveryMethod: DeliveryMethod?
    /// Whether a FUDP endpoint for them is worth trying.
    public var fudpReachable: Bool?

    public var id: String { fid }

    public init(
        fid: String,
        lastSeenAt: Int64? = nil,
        lastDeliveryMethod: DeliveryMethod? = nil,
        fudpReachable: Bool? = nil
    ) {
        self.fid = fid
        self.lastSeenAt = lastSeenAt
        self.lastDeliveryMethod = lastDeliveryMethod
        self.fudpReachable = fudpReachable
    }

    /// Whether we should treat them as present, given how long ago we
    /// last heard anything. Presence is not a flag we can store, because
    /// nothing tells us when someone leaves — a peer that closes their
    /// laptop sends no goodbye — so it is always a question about age.
    public func isOnline(now: Date = Date(), within seconds: TimeInterval = PeerBook.presenceWindow) -> Bool {
        guard let lastSeenAt else { return false }
        let age = now.timeIntervalSince1970 * 1000 - Double(lastSeenAt)
        return age >= 0 && age <= seconds * 1000
    }
}

/// Presence and last-known routing for the peers we talk to.
///
/// Human-scale — one row per person we have exchanged anything with —
/// so it loads whole. It is a **cache with no authority**: losing it
/// costs a few failed first attempts and nothing else, which is why it
/// records observations eagerly and never blocks anything.
public struct PeerBook {

    public static let namespace = "im.peers.v1"

    /// How long a sighting counts as presence. Two minutes: long enough
    /// to survive a screen lock, short enough that a peer who has walked
    /// away stops being offered the direct route.
    public static let presenceWindow: TimeInterval = 120

    private let inner: TypedStore<PeerInfo>

    public init(kv: EncryptedKVStore) {
        self.inner = TypedStore(kv: kv, namespace: Self.namespace)
    }

    public func get(fid: String) throws -> PeerInfo? {
        try inner.get(fid)
    }

    /// Everyone we know something about, most recently seen first.
    public func all() throws -> [PeerInfo] {
        try inner.all().map(\.value).sorted { ($0.lastSeenAt ?? 0) > ($1.lastSeenAt ?? 0) }
    }

    /// Peers seen recently enough to count as present.
    public func online(now: Date = Date()) throws -> [PeerInfo] {
        try all().filter { $0.isOnline(now: now) }
    }

    public func upsert(_ peer: PeerInfo) throws {
        try inner.put(peer, key: peer.fid)
    }

    /// Note a sign of life — a message, a pong, a connection. Creates
    /// the row if this is the first thing we have heard from them.
    @discardableResult
    public func sighted(_ fid: String, now: Date = Date()) throws -> PeerInfo {
        var peer = try get(fid: fid) ?? PeerInfo(fid: fid)
        peer.lastSeenAt = Int64(now.timeIntervalSince1970 * 1000)
        try upsert(peer)
        return peer
    }

    /// Note how a message actually got to them.
    ///
    /// A live route (`fudpDirect`, `roadRelay`) is also a sighting — it
    /// could not have worked otherwise. A DOCK delivery is the opposite:
    /// it says nothing about presence, and it is evidence they were
    /// *not* reachable, so it must not refresh `lastSeenAt`.
    @discardableResult
    public func delivered(to fid: String, via method: DeliveryMethod, now: Date = Date()) throws -> PeerInfo {
        var peer = try get(fid: fid) ?? PeerInfo(fid: fid)
        peer.lastDeliveryMethod = method
        if method.isOnline {
            peer.lastSeenAt = Int64(now.timeIntervalSince1970 * 1000)
            peer.fudpReachable = method == .fudpDirect ? true : peer.fudpReachable
        }
        try upsert(peer)
        return peer
    }

    /// Record whether a FUDP endpoint for this peer is worth trying —
    /// what ``DeliveryPolicy/Capabilities/peerFudpReachable`` reads.
    @discardableResult
    public func setFudpReachable(_ reachable: Bool, for fid: String) throws -> PeerInfo {
        var peer = try get(fid: fid) ?? PeerInfo(fid: fid)
        peer.fudpReachable = reachable
        try upsert(peer)
        return peer
    }

    @discardableResult
    public func remove(fid: String) throws -> Bool {
        guard try inner.exists(fid) else { return false }
        try inner.delete(fid)
        return true
    }
}
