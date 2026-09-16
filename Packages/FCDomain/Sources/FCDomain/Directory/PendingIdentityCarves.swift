import Foundation
import FCStorage

/// A CID, master or home carve this identity has broadcast and the chain does not
/// show yet — the identity-record counterpart of ``PendingGroup``.
///
/// **Why keep it.** Until the block confirms, the chain still says "no
/// CID" and "no DOCK", so every screen reading the chain offers the carve
/// again, and a second press pays a second fee. This is what lets Settings
/// and the getting-started checklist say "waiting for the chain" instead.
///
/// **Cleared by the chain, not by time.** ``isLanded(on:)`` compares the
/// record to what was carved, and ``PendingIdentityCarvesStore/reconcile(fid:info:)``
/// runs on every refresh of the FID's record. A carve still missing after
/// ``PendingGroupsStore/overdueMs`` is kept but reported overdue, so the
/// screens reopen the carve with a warning rather than waiting forever.
public struct PendingIdentityCarve: Codable, Equatable, Sendable {

    public enum Kind: String, Codable, Sendable {
        case cid
        case master
        case home
    }

    public var fid: String
    public var kind: Kind
    /// For ``Kind/cid``: the name carved, without the suffix the parser adds.
    public var name: String?
    /// For ``Kind/master``: the FID named.
    public var master: String?
    /// For ``Kind/home``: the whole map carved.
    public var home: [String: String]?
    public var txid: String
    /// Epoch ms.
    public var broadcastAt: Int64

    public init(
        fid: String, kind: Kind, name: String? = nil, master: String? = nil,
        home: [String: String]? = nil, txid: String, broadcastAt: Int64
    ) {
        self.fid = fid
        self.kind = kind
        self.name = name
        self.master = master
        self.home = home
        self.txid = txid
        self.broadcastAt = broadcastAt
    }

    public func isOverdue(now: Date) -> Bool {
        Int64(now.timeIntervalSince1970 * 1000) - broadcastAt >= PendingGroupsStore.overdueMs
    }

    /// Whether the chain's record shows this carve took effect.
    ///
    /// A CID is matched by shape, since the suffix is the parser's choice:
    /// the carved name, an underscore, then at least four characters that
    /// end the FID. A bare prefix test would take `Al_x_vkUV` as the
    /// result of carving `Al`.
    public func isLanded(on info: LiveFidInfo) -> Bool {
        switch kind {
        case .cid:
            guard let name, let cid = info.cid, cid.hasPrefix(name + "_") else { return false }
            let suffix = cid.dropFirst(name.count + 1)
            return suffix.count >= CidFeip.baseSuffixLength && fid.hasSuffix(suffix)
        case .master:
            // Any master counts: FEIP6 is write-once, so once the chain holds
            // one this carve can no longer change it, landed or not.
            return !(info.master ?? "").trimmingCharacters(in: .whitespaces).isEmpty
        case .home:
            guard let home else { return true }
            let stored = info.home ?? [:]
            return home.allSatisfy { stored[$0.key] == $0.value }
        }
    }
}

/// One pending carve per identity and kind: a newer carve of the same
/// record replaces the older, because only the newer one says what the
/// chain should end up holding.
public struct PendingIdentityCarvesStore {

    public static let namespace = "identity.pending.v1"

    private let inner: TypedStore<PendingIdentityCarve>

    public init(kv: EncryptedKVStore) {
        self.inner = TypedStore(kv: kv, namespace: Self.namespace)
    }

    static func key(fid: String, kind: PendingIdentityCarve.Kind) -> String {
        "\(fid)|\(kind.rawValue)"
    }

    public func record(_ pending: PendingIdentityCarve) throws {
        try inner.put(pending, key: Self.key(fid: pending.fid, kind: pending.kind))
    }

    public func get(fid: String, kind: PendingIdentityCarve.Kind) throws -> PendingIdentityCarve? {
        try inner.get(Self.key(fid: fid, kind: kind))
    }

    /// Drop what `info` shows landed. Returns how many were cleared.
    @discardableResult
    public func reconcile(fid: String, info: LiveFidInfo) throws -> Int {
        var cleared = 0
        for kind in [PendingIdentityCarve.Kind.cid, .master, .home] {
            guard let pending = try get(fid: fid, kind: kind), pending.isLanded(on: info) else { continue }
            try inner.delete(Self.key(fid: fid, kind: kind))
            cleared += 1
        }
        return cleared
    }
}
