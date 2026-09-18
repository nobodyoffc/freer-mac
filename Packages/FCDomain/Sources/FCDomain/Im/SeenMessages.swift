import Foundation
import FCStorage

/// Every message this identity has taken in, by author and id — FIMP0V3
/// §3.5 step 4.
///
/// **Why a signed message still needs this.** A signature proves who wrote
/// a message, not that it is arriving for the first time. Anyone who has
/// seen a signed envelope can put the same bytes on a DOCK again, under a
/// new item id, and it will verify every time. A replayed chat line is a
/// duplicate row; a replayed key request, key share or room notice is an
/// action taken twice. So the pair `(senderId, id)` is remembered, and a
/// second arrival is dropped before anything acts on it.
///
/// The id alone is not enough: ids are unique per sender, and two people's
/// messages may share one. The DOCK item id is no use either, since a
/// replay gets a fresh one.
///
/// Entries are kept a little longer than a DOCK may hold an item (365 days),
/// which is as long as the same envelope can come back from one.
public struct SeenMessagesStore {

    public static let namespace = "im.seen.v1"
    public static let retentionMs: Int64 = 400 * 24 * 60 * 60 * 1000

    struct Seen: Codable {
        let at: Int64
    }

    private let inner: TypedStore<Seen>

    public init(kv: EncryptedKVStore) {
        self.inner = TypedStore(kv: kv, namespace: Self.namespace)
    }

    static func key(sender: String, id: String) -> String { "\(sender)|\(id)" }

    public func hasSeen(sender: String, id: String) throws -> Bool {
        try inner.exists(Self.key(sender: sender, id: id))
    }

    public func markSeen(sender: String, id: String, now: Date = Date()) throws {
        try inner.put(Seen(at: Int64(now.timeIntervalSince1970 * 1000)), key: Self.key(sender: sender, id: id))
    }

    /// Forget entries older than ``retentionMs``. Returns how many went.
    @discardableResult
    public func prune(now: Date = Date()) throws -> Int {
        let cutoff = Int64(now.timeIntervalSince1970 * 1000) - Self.retentionMs
        var removed = 0
        for (key, seen) in try inner.all() where seen.at < cutoff {
            try inner.delete(key)
            removed += 1
        }
        return removed
    }
}
