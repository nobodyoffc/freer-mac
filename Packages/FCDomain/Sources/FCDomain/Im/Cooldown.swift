import Foundation

/// At most one go per `interval`, across threads.
///
/// For work a flood of inbound messages could each trigger — a chain
/// query, say — where the first trigger is worth acting on and the rest
/// within the window are not.
public final class Cooldown: @unchecked Sendable {

    public let interval: TimeInterval
    private let lock = NSLock()
    private var last: Date?

    public init(interval: TimeInterval) {
        self.interval = interval
    }

    /// True, and the window restarts, when the last go was at least
    /// `interval` ago (or there was none). False otherwise.
    public func claim(now: Date = Date()) -> Bool {
        lock.lock(); defer { lock.unlock() }
        if let last, now.timeIntervalSince(last) < interval { return false }
        last = now
        return true
    }
}
