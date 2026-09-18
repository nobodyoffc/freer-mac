import XCTest
@testable import FCTransport

final class DecryptRateLimiterTests: XCTestCase {

    private let now0: Int64 = 1_700_000_000_000

    private func makeLimiter(
        threshold: Int = 5,
        cooldownMs: Int64 = 1_000,
        maxTracked: Int = 4_096
    ) throws -> DecryptRateLimiter<String> {
        try DecryptRateLimiter(
            failureThreshold: threshold,
            cooldownMs: cooldownMs,
            maxTracked: maxTracked
        )
    }

    // MARK: - never-seen source

    func testUnknownSourceIsNotDropped() throws {
        let lim = try makeLimiter()
        XCTAssertFalse(lim.shouldDrop(source: "1.2.3.4", nowMs: now0))
    }

    // MARK: - threshold + cooldown lifecycle

    func testBelowThresholdNotDropped() throws {
        let lim = try makeLimiter(threshold: 5)
        for _ in 0..<4 {
            lim.recordFailure(source: "1.1.1.1", nowMs: now0)
        }
        XCTAssertFalse(lim.shouldDrop(source: "1.1.1.1", nowMs: now0))
    }

    func testAtThresholdEntersCooldown() throws {
        let lim = try makeLimiter(threshold: 3, cooldownMs: 1_000)
        for _ in 0..<3 {
            lim.recordFailure(source: "1.1.1.1", nowMs: now0)
        }
        XCTAssertTrue(lim.shouldDrop(source: "1.1.1.1", nowMs: now0))
        // Still in cooldown 999 ms later.
        XCTAssertTrue(lim.shouldDrop(source: "1.1.1.1", nowMs: now0 + 999))
    }

    func testCooldownExpiresAndResetsFailures() throws {
        let lim = try makeLimiter(threshold: 3, cooldownMs: 1_000)
        for _ in 0..<3 {
            lim.recordFailure(source: "1.1.1.1", nowMs: now0)
        }
        XCTAssertTrue(lim.shouldDrop(source: "1.1.1.1", nowMs: now0))
        // After cooldown, allow through and reset.
        XCTAssertFalse(lim.shouldDrop(source: "1.1.1.1", nowMs: now0 + 1_001))
        // Failure count is reset, so we need the full threshold again.
        for _ in 0..<2 {
            lim.recordFailure(source: "1.1.1.1", nowMs: now0 + 2_000)
        }
        XCTAssertFalse(lim.shouldDrop(source: "1.1.1.1", nowMs: now0 + 2_000))
        lim.recordFailure(source: "1.1.1.1", nowMs: now0 + 2_000)
        XCTAssertTrue(lim.shouldDrop(source: "1.1.1.1", nowMs: now0 + 2_000))
    }

    func testRecordSuccessClearsFailures() throws {
        let lim = try makeLimiter(threshold: 3)
        for _ in 0..<2 {
            lim.recordFailure(source: "1.1.1.1", nowMs: now0)
        }
        lim.recordSuccess(source: "1.1.1.1", nowMs: now0)
        // Counter cleared → need three more failures to enter cooldown.
        for _ in 0..<2 {
            lim.recordFailure(source: "1.1.1.1", nowMs: now0)
        }
        XCTAssertFalse(lim.shouldDrop(source: "1.1.1.1", nowMs: now0))
        lim.recordFailure(source: "1.1.1.1", nowMs: now0)
        XCTAssertTrue(lim.shouldDrop(source: "1.1.1.1", nowMs: now0))
    }

    /// `shouldDrop` between two failure recordings must NOT clear the
    /// failure counter. Earlier draft had a bug that did exactly that
    /// (calling shouldDrop during accumulation would reset).
    func testShouldDropDoesNotResetCounterMidAccumulation() throws {
        let lim = try makeLimiter(threshold: 3)
        lim.recordFailure(source: "1.1.1.1", nowMs: now0)
        XCTAssertFalse(lim.shouldDrop(source: "1.1.1.1", nowMs: now0))
        lim.recordFailure(source: "1.1.1.1", nowMs: now0)
        XCTAssertFalse(lim.shouldDrop(source: "1.1.1.1", nowMs: now0))
        lim.recordFailure(source: "1.1.1.1", nowMs: now0)
        XCTAssertTrue(lim.shouldDrop(source: "1.1.1.1", nowMs: now0))
    }

    // MARK: - per-source isolation

    func testSourcesAreIsolated() throws {
        let lim = try makeLimiter(threshold: 3)
        for _ in 0..<3 {
            lim.recordFailure(source: "1.1.1.1", nowMs: now0)
        }
        XCTAssertTrue(lim.shouldDrop(source: "1.1.1.1", nowMs: now0))
        XCTAssertFalse(lim.shouldDrop(source: "2.2.2.2", nowMs: now0))
    }

    // MARK: - LRU + capacity

    func testTrackedCountReflectsState() throws {
        let lim = try makeLimiter()
        XCTAssertEqual(lim.trackedCount, 0)
        lim.recordFailure(source: "1.1.1.1", nowMs: now0)
        XCTAssertEqual(lim.trackedCount, 1)
        lim.recordFailure(source: "2.2.2.2", nowMs: now0)
        XCTAssertEqual(lim.trackedCount, 2)
    }

    func testHardCapEvictsLeastRecentlyUsed() throws {
        let lim = try makeLimiter(threshold: 3, cooldownMs: 1_000, maxTracked: 3)
        lim.recordFailure(source: "a", nowMs: now0)
        lim.recordFailure(source: "b", nowMs: now0)
        lim.recordFailure(source: "c", nowMs: now0)
        XCTAssertEqual(lim.trackedCount, 3)

        // Touch "a" so it's MRU.
        lim.recordFailure(source: "a", nowMs: now0)
        // Add "d" — should evict "b" (LRU after the touch).
        lim.recordFailure(source: "d", nowMs: now0)
        XCTAssertEqual(lim.trackedCount, 3)
    }

    func testClearForgetsAll() throws {
        let lim = try makeLimiter(threshold: 3)
        for _ in 0..<3 {
            lim.recordFailure(source: "1.1.1.1", nowMs: now0)
        }
        XCTAssertTrue(lim.shouldDrop(source: "1.1.1.1", nowMs: now0))
        lim.clear()
        XCTAssertFalse(lim.shouldDrop(source: "1.1.1.1", nowMs: now0))
        XCTAssertEqual(lim.trackedCount, 0)
    }

    // MARK: - validation

    func testRejectsBadParams() {
        XCTAssertThrowsError(try DecryptRateLimiter<String>(failureThreshold: 0))
        XCTAssertThrowsError(try DecryptRateLimiter<String>(cooldownMs: 0))
        XCTAssertThrowsError(try DecryptRateLimiter<String>(maxTracked: 0))
    }
}

/// The TTL the class documents, which for a long time was a comment
/// with an empty function body under it.
final class DecryptRateLimiterTtlTests: XCTestCase {

    /// A source penalised during a bad minute stayed penalised for as
    /// long as the table had room for it: nothing expired, so its
    /// failure history survived until `maxTracked` other sources pushed
    /// it out.
    func testAnUntouchedEntryIsEvictedAfterTheTtl() throws {
        let limiter = try DecryptRateLimiter<String>(failureThreshold: 2, cooldownMs: 1_000)
        let t0: Int64 = 1_000_000

        limiter.recordFailure(source: "a", nowMs: t0)
        XCTAssertEqual(limiter.trackedCount, 1)

        // Another source arrives long after "a" went quiet. The sweep
        // runs on the failure path, so this is what collects it.
        limiter.recordFailure(source: "b", nowMs: t0 + DecryptRateLimiter<String>.entryTtlMs + 1)
        XCTAssertEqual(
            limiter.trackedCount, 1,
            "the stale entry should be gone, leaving only the new one"
        )

        // And the expiry really cleared the history: "a" starts over,
        // so one failure is not yet enough to trip a threshold of two.
        let later = t0 + DecryptRateLimiter<String>.entryTtlMs + 2
        limiter.recordFailure(source: "a", nowMs: later)
        XCTAssertFalse(limiter.shouldDrop(source: "a", nowMs: later))
    }

    /// A source still failing is not stale, however long ago it
    /// started. The sweep expires what nothing has touched, not what
    /// is merely old.
    func testAnActiveEntrySurvivesTheSweep() throws {
        let limiter = try DecryptRateLimiter<String>(failureThreshold: 2, cooldownMs: 10_000)
        var now: Int64 = 500_000
        for _ in 0..<5 {
            limiter.recordFailure(source: "busy", nowMs: now)
            now += DecryptRateLimiter<String>.entryTtlMs / 2
        }
        // Total elapsed is well past the TTL, but every failure touched
        // the entry, so it is still tracked and still in cooldown from
        // the most recent one.
        XCTAssertEqual(limiter.trackedCount, 1)
        let lastFailure = now - DecryptRateLimiter<String>.entryTtlMs / 2
        XCTAssertTrue(
            limiter.shouldDrop(source: "busy", nowMs: lastFailure + 1),
            "a source that keeps failing must keep its cooldown"
        )
    }
}
