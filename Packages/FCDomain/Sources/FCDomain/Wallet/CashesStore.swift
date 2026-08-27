import Foundation
import FCStorage

/// One cached snapshot of the cash set for an address (== owner FID
/// for P2PKH; script-hash address for P2SH variants). Stored in the
/// per-identity ``EncryptedKVStore`` so the wallet can show
/// last-known balance instantly on app open while a refresh runs in
/// the background.
///
/// `watermarkHeight` is the chain height through which we last
/// successfully synced the cash index. The next incremental
/// `base.search` query filters `lastHeight > max(0, watermarkHeight − 30)`
/// to re-fetch the reorg-prone trailing window. `nil` means we haven't
/// bootstrapped yet — callers should call ``WalletService/bootstrapCashes``
/// instead of `refreshCashes`.
public struct CashSnapshot: Codable, Equatable, Sendable {
    public var addr: String
    public var cashes: [Cash]
    public var snapshotAt: Date
    public var bestHeight: Int64?
    public var watermarkHeight: Int64?

    public init(
        addr: String,
        cashes: [Cash],
        snapshotAt: Date = Date(),
        bestHeight: Int64? = nil,
        watermarkHeight: Int64? = nil
    ) {
        self.addr = addr
        self.cashes = cashes
        self.snapshotAt = snapshotAt
        self.bestHeight = bestHeight
        self.watermarkHeight = watermarkHeight
    }

    public var totalValue: Int64 { cashes.reduce(0) { $0 + $1.value } }

    private enum CodingKeys: String, CodingKey {
        case addr, cashes, snapshotAt, bestHeight, watermarkHeight
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.addr            = try c.decode         (String.self, forKey: .addr)
        self.cashes          = try c.decode         ([Cash].self, forKey: .cashes)
        self.snapshotAt      = try c.decode         (Date.self,   forKey: .snapshotAt)
        self.bestHeight      = try c.decodeIfPresent(Int64.self,  forKey: .bestHeight)
        self.watermarkHeight = try c.decodeIfPresent(Int64.self,  forKey: .watermarkHeight)
    }

    // MARK: - mutators

    /// Insert or replace `cash` by id. If the snapshot has no cash
    /// with that id, append; otherwise overwrite the matching row in
    /// place (preserving array order). Falls back to `(birthTxId,
    /// birthIndex)` matching when either side has a nil id, since
    /// optimistically-inserted rows always set id but server
    /// responses might in theory omit it.
    public mutating func upsert(_ cash: Cash) {
        if let idx = indexOf(cash) {
            cashes[idx] = cash
        } else {
            cashes.append(cash)
        }
    }

    /// Remove the cash with `id` (or matching `birthTxId+birthIndex`
    /// when id is nil). No-op if not present.
    @discardableResult
    public mutating func remove(id: String?, birthTxId: String? = nil, birthIndex: Int? = nil) -> Bool {
        let before = cashes.count
        cashes.removeAll { c in
            if let id, let cid = c.id, cid == id { return true }
            if let birthTxId, let birthIndex,
               c.birthTxId == birthTxId, c.birthIndex == birthIndex { return true }
            return false
        }
        return cashes.count < before
    }

    /// The row this snapshot already holds for `cash`, if any —
    /// matched the same way ``upsert(_:)`` matches. Callers merging a
    /// server response need it to carry local annotations across: the
    /// server's copy of a cash knows nothing about a spend we
    /// broadcast a second ago.
    public func row(matching cash: Cash) -> Cash? {
        indexOf(cash).map { cashes[$0] }
    }

    /// Locate the index of an existing row that should be replaced
    /// when upserting `cash`. Matches by id first, then by
    /// `(birthTxId, birthIndex)` as a fallback.
    private func indexOf(_ cash: Cash) -> Int? {
        if let cid = cash.id, !cid.isEmpty {
            if let idx = cashes.firstIndex(where: { $0.id == cid }) { return idx }
        }
        return cashes.firstIndex {
            $0.birthTxId == cash.birthTxId && $0.birthIndex == cash.birthIndex
        }
    }
}

/// Per-identity cash cache. Keyed by address.
public struct CashesStore {

    public static let namespace = "cashes"

    private let inner: TypedStore<CashSnapshot>

    public init(kv: EncryptedKVStore) {
        self.inner = TypedStore(kv: kv, namespace: Self.namespace)
    }

    public func snapshot(forAddress addr: String) throws -> CashSnapshot? {
        try inner.get(addr)
    }

    public func save(_ snapshot: CashSnapshot) throws {
        try inner.put(snapshot, key: snapshot.addr)
    }

    @discardableResult
    public func clear(addr: String) throws -> Bool {
        guard try inner.exists(addr) else { return false }
        try inner.delete(addr)
        return true
    }

    public func addresses() throws -> [String] {
        try inner.keys()
    }
}
