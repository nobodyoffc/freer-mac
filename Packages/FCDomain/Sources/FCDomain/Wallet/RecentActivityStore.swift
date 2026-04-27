import Foundation
import FCStorage

/// One cached page of recent on-chain activity for an FID — Pattern C
/// from the sync design (cache-as-hint, never authoritative). Stored
/// in the per-identity ``EncryptedKVStore`` so the Transactions pane
/// has an instant first paint while a fresh `base.search` query runs
/// in the background.
///
/// Unlike ``CashSnapshot`` (Pattern A — UTXO mirror, server-of-truth
/// per-item), this blob is a **frozen-in-time** copy of whatever the
/// server returned on the last successful refresh. Every online open
/// replaces it wholesale; no merge, no incremental sync. The point is
/// solely "show *something* before the network round-trip completes."
public struct RecentActivitySnapshot: Codable, Equatable, Sendable {
    public var fid: String
    public var cashes: [Cash]
    public var fetchedAt: Date
    public var bestHeight: Int64?

    public init(
        fid: String,
        cashes: [Cash],
        fetchedAt: Date = Date(),
        bestHeight: Int64? = nil
    ) {
        self.fid = fid
        self.cashes = cashes
        self.fetchedAt = fetchedAt
        self.bestHeight = bestHeight
    }
}

/// Per-identity store for ``RecentActivitySnapshot``. Keyed by FID so
/// switching the live FID swaps caches automatically.
public struct RecentActivityStore {

    public static let namespace = "recentActivity"

    private let inner: TypedStore<RecentActivitySnapshot>

    public init(kv: EncryptedKVStore) {
        self.inner = TypedStore(kv: kv, namespace: Self.namespace)
    }

    public func snapshot(forFid fid: String) throws -> RecentActivitySnapshot? {
        try inner.get(fid)
    }

    public func save(_ snapshot: RecentActivitySnapshot) throws {
        try inner.put(snapshot, key: snapshot.fid)
    }

    @discardableResult
    public func clear(forFid fid: String) throws -> Bool {
        guard try inner.exists(fid) else { return false }
        try inner.delete(fid)
        return true
    }
}
