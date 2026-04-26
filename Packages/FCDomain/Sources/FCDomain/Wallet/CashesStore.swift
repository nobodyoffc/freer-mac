import Foundation
import FCStorage

/// One cached snapshot of the cash set for an address (== owner FID
/// for P2PKH; script-hash address for P2SH variants). Stored in the
/// per-identity ``EncryptedKVStore`` so the wallet can show
/// last-known balance instantly on app open while a refresh runs in
/// the background.
public struct CashSnapshot: Codable, Equatable, Sendable {
    public var addr: String
    public var cashes: [Cash]
    public var snapshotAt: Date
    public var bestHeight: Int64?

    public init(addr: String, cashes: [Cash], snapshotAt: Date = Date(), bestHeight: Int64? = nil) {
        self.addr = addr
        self.cashes = cashes
        self.snapshotAt = snapshotAt
        self.bestHeight = bestHeight
    }

    public var totalValue: Int64 { cashes.reduce(0) { $0 + $1.value } }
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
