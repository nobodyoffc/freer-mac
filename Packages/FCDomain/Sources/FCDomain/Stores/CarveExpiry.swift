import Foundation

/// How long a broadcast carve may stay unconfirmed before the chain sync
/// stops waiting for it.
///
/// A row carved but not yet confirmed is *pending*: it cannot be edited,
/// and it is not carved again, because a second `add` would create a
/// second item. A carve that never confirms (dropped, or rolled back and
/// not mined again) would leave the row pending forever. Once this window
/// has passed and the chain still has no record of the carve, the sync
/// turns the row back into a local-only one, which can be saved or carved
/// afresh. The window is generous: FCH blocks come about once a minute,
/// and the apps' fee confirms in the next block when blocks are not full.
/// Android uses the same window (`CarvePlan.PENDING_EXPIRY_MS`).
public enum CarveExpiry {
    public static let window: TimeInterval = 2 * 60 * 60

    /// True when a carve broadcast at `carvedAt` should no longer be
    /// waited for. A pending row with no time (written before carves were
    /// timed) counts as expired.
    public static func isExpired(_ carvedAt: Date?, now: Date = Date()) -> Bool {
        guard let carvedAt else { return true }
        return now.timeIntervalSince(carvedAt) > window
    }
}
