import Foundation
import FCStorage

/// The on-chain numbers behind one FID — everything the FID bar shows
/// that ``KeyInfo`` does not already hold locally.
///
/// Android keeps these fields on its own `KeyInfo` and rewrites it on
/// every `refreshLiveFidCidInfoAsync`. The Mac deliberately does not:
/// `KeyInfo` lives inside the encrypted `Setting`, so re-encrypting and
/// re-writing the whole Setting every time a balance ticks would cost
/// real work to store values that are public, volatile, and re-fetchable
/// in one call. They live in the per-identity KV cache instead.
///
/// Every field is optional for the same reason ``Freer``'s are: the
/// server omits keys it has no value for, and a FID that has never
/// touched the chain has none of them.
public struct LiveFidInfo: Codable, Hashable, Sendable {

    public var fid: String

    /// The registered CID, when this FID has bought one. The bar shows
    /// this in place of the FID as the display name.
    public var cid: String?

    /// Set when the private key behind this FID is public knowledge.
    /// The avatar renders desaturated for these, matching Android's
    /// `NobodyBoard.applyNobodyMark`.
    public var isNobody: Bool?

    public var balance: Int64?      // satoshis
    public var cash: Int64?         // count of UTXOs
    public var cd: Int64?           // CoinDays

    public var reputation: Int64?
    public var hot: Int64?
    public var weight: Int64?

    public var fetchedAt: Date

    public init(fid: String, fetchedAt: Date = Date()) {
        self.fid = fid
        self.fetchedAt = fetchedAt
    }

    /// Overwrite the on-chain fields from a freshly fetched ``Freer``,
    /// leaving any field the server omitted at its previous value.
    ///
    /// Absent means "the server said nothing", not "zero" — a FID that
    /// has spent down to nothing comes back with an explicit `balance: 0`
    /// from the index, so keeping the old value on absence cannot pin a
    /// stale balance on screen.
    public func merging(_ freer: Freer, fetchedAt: Date = Date()) -> LiveFidInfo {
        var info = self
        if let v = freer.cid { info.cid = v }
        if let v = freer.isNobody { info.isNobody = v }
        if let v = freer.balance { info.balance = v }
        if let v = freer.cash { info.cash = v }
        if let v = freer.cd { info.cd = v }
        if let v = freer.reputation { info.reputation = v }
        if let v = freer.hot { info.hot = v }
        if let v = freer.weight { info.weight = v }
        info.fetchedAt = fetchedAt
        return info
    }

    /// What the bar shows as the name: the CID when there is one, the
    /// FID otherwise. Mirrors Android's `FidCardHelper` fallback.
    public var displayName: String {
        guard let cid, !cid.trimmingCharacters(in: .whitespaces).isEmpty else {
            return fid
        }
        return cid
    }

    /// Whether the name line is showing a CID — the bar renders the FID
    /// separately only when it isn't already the name.
    public var hasCid: Bool { displayName != fid }

    /// Android hides each metric individually when it is null or 0, and
    /// hides the whole row when none of the three survives.
    public var hasMetrics: Bool {
        [weight, reputation, hot].contains { ($0 ?? 0) != 0 }
    }
}

/// Per-identity cache of ``LiveFidInfo``, keyed by FID.
///
/// Keyed rather than single-valued because one unlocked main can operate
/// as several FIDs (watched, multisig, servant), and switching between
/// them should show that identity's numbers immediately rather than
/// blanking the bar until the network answers.
public struct LiveFidInfoStore {

    public static let namespace = "livefid.v1"

    private let inner: TypedStore<LiveFidInfo>

    public init(kv: EncryptedKVStore) {
        self.inner = TypedStore(kv: kv, namespace: Self.namespace)
    }

    public func get(fid: String) throws -> LiveFidInfo? {
        try inner.get(fid)
    }

    public func upsert(_ info: LiveFidInfo) throws {
        try inner.put(info, key: info.fid)
    }

    @discardableResult
    public func remove(fid: String) throws -> Bool {
        guard try inner.exists(fid) else { return false }
        try inner.delete(fid)
        return true
    }
}
