import Foundation
import FCStorage

/// One snapshot of the UTXO set for an address, plus the timestamp it
/// was captured. Stored in the per-identity ``EncryptedKVStore`` so
/// the wallet can show the last-known balance instantly on app open
/// while it kicks off a refresh in the background.
public struct UtxoSnapshot: Codable, Equatable, Sendable {
    public var addr: String
    public var utxos: [Utxo]
    public var snapshotAt: Date
    public var bestHeight: Int64?

    public init(addr: String, utxos: [Utxo], snapshotAt: Date = Date(), bestHeight: Int64? = nil) {
        self.addr = addr
        self.utxos = utxos
        self.snapshotAt = snapshotAt
        self.bestHeight = bestHeight
    }

    public var totalValue: Int64 { utxos.reduce(0) { $0 + $1.value } }
}

/// Per-identity UTXO cache. Keyed by address (== owner FID for
/// P2PKH). The wallet refreshes via ``WalletService`` and reads
/// snapshots from here for offline display.
public struct UtxosStore {

    public static let namespace = "utxos"

    private let inner: TypedStore<UtxoSnapshot>

    public init(_ identity: Identity) throws {
        self.inner = TypedStore(kv: try identity.storage(), namespace: Self.namespace)
    }

    public func snapshot(forAddress addr: String) throws -> UtxoSnapshot? {
        try inner.get(addr)
    }

    public func save(_ snapshot: UtxoSnapshot) throws {
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
