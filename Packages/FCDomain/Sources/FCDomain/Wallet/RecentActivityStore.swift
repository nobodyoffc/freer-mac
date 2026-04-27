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

/// Per-identity store for ``RecentActivitySnapshot``. Keyed by
/// `(fid, kind)` so each Recent activity tab gets its own cold-start
/// blob without overwriting the others. The `.all` kind uses a
/// bare-fid key for backward compatibility with snapshots written
/// before tabs existed.
public struct RecentActivityStore {

    public static let namespace = "recentActivity"

    private let inner: TypedStore<RecentActivitySnapshot>

    public init(kv: EncryptedKVStore) {
        self.inner = TypedStore(kv: kv, namespace: Self.namespace)
    }

    public func snapshot(
        forFid fid: String,
        kind: WalletService.ActivityKind = .all
    ) throws -> RecentActivitySnapshot? {
        try inner.get(Self.key(fid: fid, kind: kind))
    }

    public func save(
        _ snapshot: RecentActivitySnapshot,
        kind: WalletService.ActivityKind = .all
    ) throws {
        try inner.put(snapshot, key: Self.key(fid: snapshot.fid, kind: kind))
    }

    @discardableResult
    public func clear(
        forFid fid: String,
        kind: WalletService.ActivityKind = .all
    ) throws -> Bool {
        let k = Self.key(fid: fid, kind: kind)
        guard try inner.exists(k) else { return false }
        try inner.delete(k)
        return true
    }

    private static func key(fid: String, kind: WalletService.ActivityKind) -> String {
        // .all keeps the bare-fid key so blobs from before tabs
        // existed still load. .incomes / .expenses get a suffix.
        kind == .all ? fid : "\(fid):\(kind.rawValue)"
    }
}
