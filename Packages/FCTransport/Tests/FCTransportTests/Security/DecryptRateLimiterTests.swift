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
