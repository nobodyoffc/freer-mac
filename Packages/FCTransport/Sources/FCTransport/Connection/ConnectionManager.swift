import Foundation
import Network

/// Tracks per-connection state across all peers. Three indexes:
///
/// - `connectionId → PeerConnection` — primary, O(1).
/// - `peerFid → [connectionId]` — list of all open connections from one
///   peer identity. Capped at `maxConnectionsPerFid` to prevent a
///   single FID from saturating the table; oldest idle connection is
///   evicted first when the cap is hit.
/// - `endpointKey → connectionId` — used by the receive loop to route
///   an incoming packet from a known address to its connection without
///   having to decrypt to learn the peer's identity.
///
/// Mirrors the shape of FC-JDK's `ConnectionManager` (3-level index,
/// per-FID cap, address-to-connId routing) but the local fields are
/// off-the-wire — no byte-parity requirement.
public final class ConnectionManager: @unchecked Sendable {

    public static let defaultMaxConnectionsPerFid = 5
    public static let defaultMaxTotalConnections = 4_096

    public enum Failure: Error, CustomStringConvertible {
        case nonPositive(field: String, got: Int)

        public var description: String {
            switch self {
            case let .nonPositive(field, got):
                return "ConnectionManager: \(field) must be > 0, got \(got)"
            }
        }
    }

    public let maxConnectionsPerFid: Int
    public let maxTotalConnections: Int

    private let lock = NSLock()

    private var byConnId: [Int64: PeerConnection] = [:]
    private var byPeerFid: [String: [Int64]] = [:]
    private var byAddressKey: [String: Int64] = [:]

    /// Counts (eviction reasons) — for monitoring/tests.
    private var _perFidEvictions: Int = 0
    private var _totalEvictions: Int = 0

    public init(
        maxConnectionsPerFid: Int = ConnectionManager.defaultMaxConnectionsPerFid,
        maxTotalConnections: Int = ConnectionManager.defaultMaxTotalConnections
    ) throws {
        guard maxConnectionsPerFid > 0 else {
            throw Failure.nonPositive(field: "maxConnectionsPerFid", got: maxConnectionsPerFid)
        }
        guard maxTotalConnections > 0 else {
            throw Failure.nonPositive(field: "maxTotalConnections", got: maxTotalConnections)
        }
        self.maxConnectionsPerFid = maxConnectionsPerFid
        self.maxTotalConnections = maxTotalConnections
    }

    // MARK: - lookup

    public func connection(for connectionId: Int64) -> PeerConnection? {
        lock.lock(); defer { lock.unlock() }
        return byConnId[connectionId]
    }

    public func connection(for address: NWEndpoint) -> PeerConnection? {
        lock.lock(); defer { lock.unlock() }
        guard let connId = byAddressKey[ConnectionManager.endpointKey(address)] else {
            return nil
        }
        return byConnId[connId]
    }

    public func connections(forFid fid: String) -> [PeerConnection] {
        lock.lock(); defer { lock.unlock() }
        guard let connIds = byPeerFid[fid] else { return [] }
        return connIds.compactMap { byConnId[$0] }
    }

    public var totalConnections: Int {
        lock.lock(); defer { lock.unlock() }
        return byConnId.count
    }

    public var perFidEvictions: Int {
        lock.lock(); defer { lock.unlock() }
        return _perFidEvictions
    }

    public var totalEvictions: Int {
        lock.lock(); defer { lock.unlock() }
        return _totalEvictions
    }

    // MARK: - mutation

    /// Insert a freshly-built `PeerConnection`. Enforces both the global
    /// total cap and the per-FID cap by evicting the oldest connection
    /// (by `lastActivityMs`) that's already closed or idle, then by
    /// `lastActivityMs` regardless of state. Returns the evicted
    /// connections (empty if none were evicted).
    @discardableResult
    public func insert(_ connection: PeerConnection) -> [PeerConnection] {
        lock.lock(); defer { lock.unlock() }
        var evicted: [PeerConnection] = []

        // Per-FID cap: only enforce if a peer FID is known.
        if let fid = connection.peerFid {
            var connIds = byPeerFid[fid] ?? []
            if connIds.count >= maxConnectionsPerFid {
                if let drop = oldestByActivity(connIds) {
                    removeLocked(connectionId: drop.connectionId)
                    evicted.append(drop)
                    _perFidEvictions += 1
                }
                connIds = byPeerFid[fid] ?? []
            }
            connIds.append(connection.connectionId)
            byPeerFid[fid] = connIds
        }

        // Global cap.
        while byConnId.count >= maxTotalConnections,
              let drop = oldestByActivity(Array(byConnId.keys)) {
            removeLocked(connectionId: drop.connectionId)
            evicted.append(drop)
            _totalEvictions += 1
        }

        byConnId[connection.connectionId] = connection
        byAddressKey[ConnectionManager.endpointKey(connection.peerAddress)] = connection.connectionId
        return evicted
    }

    /// Remove the connection with `connectionId` from all indexes.
    @discardableResult
    public func remove(connectionId: Int64) -> PeerConnection? {
        lock.lock(); defer { lock.unlock() }
        return removeLocked(connectionId: connectionId)
    }

    public func clear() {
        lock.lock(); defer { lock.unlock() }
        byConnId.removeAll()
        byPeerFid.removeAll()
        byAddressKey.removeAll()
    }

    // MARK: - private

    @discardableResult
    private func removeLocked(connectionId: Int64) -> PeerConnection? {
        guard let conn = byConnId.removeValue(forKey: connectionId) else { return nil }
        if let fid = conn.peerFid, var list = byPeerFid[fid] {
            list.removeAll { $0 == connectionId }
            if list.isEmpty {
                byPeerFid.removeValue(forKey: fid)
            } else {
                byPeerFid[fid] = list
            }
        }
        let addrKey = ConnectionManager.endpointKey(conn.peerAddress)
        // Only remove the address mapping if it still points at *this*
        // connection — another connection may have rebound the same
        // address since.
        if byAddressKey[addrKey] == connectionId {
            byAddressKey.removeValue(forKey: addrKey)
        }
        return conn
    }

    /// Pick the connection with the smallest `lastActivityMs`. Ties
    /// broken by `connectionId` for determinism in tests.
    private func oldestByActivity(_ candidates: [Int64]) -> PeerConnection? {
        var best: PeerConnection?
        for id in candidates {
            guard let cand = byConnId[id] else { continue }
            if let cur = best {
                let candTime = cand.lastActivityMs
                let curTime = cur.lastActivityMs
                if candTime < curTime || (candTime == curTime && cand.connectionId < cur.connectionId) {
                    best = cand
                }
            } else {
                best = cand
            }
        }
        return best
    }

    // MARK: -

    /// Stable string key for a Network.framework endpoint. Used as
    /// `byAddressKey` index. Format mirrors `NWEndpoint`'s default
    /// `description` (`hostname:port` for `hostPort` endpoints).
    public static func endpointKey(_ endpoint: NWEndpoint) -> String {
        "\(endpoint)"
    }
}
