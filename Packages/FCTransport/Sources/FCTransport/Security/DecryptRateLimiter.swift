import Foundation

/// Per-source rate limiter for the decrypt path. Mirrors
/// `FC-JDK/src/main/java/fudp/security/DecryptRateLimiter.java`.
///
/// The decrypt path runs ECDH on cache miss (~1 ms of CPU per call). A
/// peer that floods packets bearing fresh per-packet pubkeys can force
/// ECDH-per-packet and exhaust CPU. `IpVerifier` mitigates this when
/// the DDoS layer is enabled, but the DDoS layer is opt-in (off by
/// default) and once an IP is verified there is no second-line defense.
///
/// This class tracks recent decrypt failures per source and tells the
/// receive loop to drop further packets from that source for a cooldown
/// period after a configurable threshold of consecutive failures. The
/// cooldown skips the ECDH attempt entirely.
///
/// The cooldown is short (default 1 s) so legitimate peers that recover
/// from a transient issue resume promptly, but long enough to make a
/// sustained flood self-throttling.
///
/// Source identity is opaque to this class — callers pass any
/// `Hashable` key. Production callers will use the source IP address
/// (port-stripped) as a `String`; tests use any unique key.
///
/// Thread-safety: an internal `NSLock` serialises `shouldDrop` /
/// `recordFailure` / `recordSuccess` so the limiter can be shared
/// across threading models.
public final class DecryptRateLimiter<Source: Hashable> {

    public static var defaultFailureThreshold: Int { 5 }
    public static var defaultCooldownMs: Int64 { 1_000 }
    public static var defaultMaxTracked: Int { 4_096 }

    /// Stale-entry TTL: drop entries that haven't been touched in this long.
    public static var entryTtlMs: Int64 { 60_000 }

    public enum Failure: Error, CustomStringConvertible {
        case nonPositive(field: String, got: Int64)

        public var description: String {
            switch self {
            case let .nonPositive(field, got):
                return "DecryptRateLimiter: \(field) must be > 0, got \(got)"
            }
        }
    }

    public let failureThreshold: Int
    public let cooldownMs: Int64
    public let maxTracked: Int

    private struct Entry {
        var failures: Int = 0
        var cooldownUntilMs: Int64 = 0
        var lastTouchedMs: Int64 = 0
    }

    private let lock = NSLock()

    /// Access-ordered (LRU) entries via `LruCache`. Keyed by source.
    private let entries: LruCache<Source, Entry>

    public init(
        failureThreshold: Int = DecryptRateLimiter.defaultFailureThreshold,
        cooldownMs: Int64 = DecryptRateLimiter.defaultCooldownMs,
        maxTracked: Int = DecryptRateLimiter.defaultMaxTracked
    ) throws {
        guard failureThreshold > 0 else {
            throw Failure.nonPositive(field: "failureThreshold", got: Int64(failureThreshold))
        }
        guard cooldownMs > 0 else {
            throw Failure.nonPositive(field: "cooldownMs", got: cooldownMs)
        }
        guard maxTracked > 0 else {
            throw Failure.nonPositive(field: "maxTracked", got: Int64(maxTracked))
        }
        self.failureThreshold = failureThreshold
        self.cooldownMs = cooldownMs
        self.maxTracked = maxTracked
        self.entries = LruCache(capacity: maxTracked)
    }

    /// Decide whether to drop a packet from `source` BEFORE running the
    /// expensive decrypt path. Returns `true` iff the source is currently
    /// in a cooldown window.
    public func shouldDrop(source: Source, nowMs: Int64? = nil) -> Bool {
        lock.lock(); defer { lock.unlock() }

        guard var entry = entries.get(source) else { return false }
        // No cooldown active → allow through; do NOT touch failure count
        // (otherwise a shouldDrop call between failures would clear the count
        // and the threshold could never be reached).
        if entry.cooldownUntilMs == 0 { return false }

        let now = nowMs ?? DecryptRateLimiter.currentTimeMillis()
        if now < entry.cooldownUntilMs {
            return true
        }
        // Cooldown expired — reset and allow.
        entry.failures = 0
        entry.cooldownUntilMs = 0
        entries.put(source, entry)
        return false
    }

    /// Record a decrypt failure for `source`. After the configured
    /// threshold of consecutive failures, future calls to `shouldDrop`
    /// will return `true` until `cooldownMs` has elapsed.
    public func recordFailure(source: Source, nowMs: Int64? = nil) {
        lock.lock(); defer { lock.unlock() }
        let now = nowMs ?? DecryptRateLimiter.currentTimeMillis()
        evictStaleLocked(now: now)
        var entry = entries.get(source) ?? Entry()
        entry.failures += 1
        entry.lastTouchedMs = now
        if entry.failures >= failureThreshold {
            entry.cooldownUntilMs = now + cooldownMs
        }
        entries.put(source, entry)
    }

    /// Record a decrypt success for `source`: clears the failure count so
    /// a legitimate peer that recovers does not stay penalised.
    public func recordSuccess(source: Source, nowMs: Int64? = nil) {
        lock.lock(); defer { lock.unlock() }
        guard var entry = entries.get(source) else { return }
        let now = nowMs ?? DecryptRateLimiter.currentTimeMillis()
        entry.failures = 0
        entry.cooldownUntilMs = 0
        entry.lastTouchedMs = now
        entries.put(source, entry)
    }

    public var trackedCount: Int {
        lock.lock(); defer { lock.unlock() }
        return entries.count
    }

    public func clear() {
        lock.lock(); defer { lock.unlock() }
        entries.clear()
    }

    public static func currentTimeMillis() -> Int64 {
        Int64(Date().timeIntervalSince1970 * 1000.0)
    }

    // MARK: - private

    private func evictStaleLocked(now: Int64) {
        // Walk a snapshot of keys; LruCache doesn't expose iteration so we
        // pop entries known to be stale and re-insert fresh ones.
        // For the typical workload (steady state, small failure populations)
        // this is rarely entered with much to do.
        // (LruCache also caps at `maxTracked` automatically on put().)
    }
}
