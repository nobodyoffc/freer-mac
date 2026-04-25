import XCTest
@testable import FCTransport

final class ReplayProtectionTests: XCTestCase {

    // Fixed clock value used across most tests so tolerance behaviour is
    // deterministic regardless of when the suite runs.
    private let fixedNow: Int64 = 1_700_000_000_000  // 2023-11-14 22:13:20 UTC

    private func makeRP(
        maxWindows: Int = 16,
        toleranceMs: Int64 = ReplayProtection.defaultTimestampToleranceMs
    ) throws -> ReplayProtection {
        try ReplayProtection(maxWindows: maxWindows, timestampToleranceMs: toleranceMs)
    }

    private func record(
        _ rp: ReplayProtection,
        connId: Int64 = 1,
        packetNumber: Int64,
        sessionEpoch: Int64 = 0xCAFE,
        timestamp: Int64? = nil
    ) -> ReplayProtection.CheckResult {
        rp.checkAndRecord(
            connectionId: connId,
            packetNumber: packetNumber,
            timestamp: timestamp ?? fixedNow,
            sessionEpoch: sessionEpoch,
            nowMs: fixedNow
        )
    }

    // MARK: - the three CheckResult outcomes on a single connection

    func testFirstPacketIsAccepted() throws {
        let rp = try makeRP()
        XCTAssertEqual(record(rp, packetNumber: 0), .ok)
    }

    func testSamePacketTwiceIsDuplicate() throws {
        let rp = try makeRP()
        XCTAssertEqual(record(rp, packetNumber: 5), .ok)
        XCTAssertEqual(record(rp, packetNumber: 5), .duplicate)
    }

    func testOutOfOrderInsideWindowIsAccepted() throws {
        let rp = try makeRP()
        XCTAssertEqual(record(rp, packetNumber: 100), .ok)
        XCTAssertEqual(record(rp, packetNumber: 90), .ok)
        XCTAssertEqual(record(rp, packetNumber: 90), .duplicate)
        XCTAssertEqual(record(rp, packetNumber: 99), .ok)
    }

    func testTooOldOutsideWindowIsDuplicate() throws {
        let rp = try makeRP()
        let high = Int64(ReplayProtection.windowSize) + 100
        XCTAssertEqual(record(rp, packetNumber: high), .ok)
        // packetNumber <= high - WINDOW_SIZE → outside window
        XCTAssertEqual(record(rp, packetNumber: 99), .duplicate)
        XCTAssertEqual(record(rp, packetNumber: 100), .duplicate)
        // 101 is just inside the window: high - WINDOW_SIZE = 100, so 101 > 100 ⇒ accepted
        XCTAssertEqual(record(rp, packetNumber: 101), .ok)
    }

    func testNewHighestSlidesWindow() throws {
        let rp = try makeRP()
        XCTAssertEqual(record(rp, packetNumber: 10), .ok)
        XCTAssertEqual(record(rp, packetNumber: 5), .ok)         // within window
        XCTAssertEqual(record(rp, packetNumber: 100), .ok)       // new highest, slides
        XCTAssertEqual(record(rp, packetNumber: 5), .duplicate)  // still remembered
        XCTAssertEqual(record(rp, packetNumber: 10), .duplicate) // still remembered
    }

    func testJumpBeyondWindowClearsBitmap() throws {
        let rp = try makeRP()
        XCTAssertEqual(record(rp, packetNumber: 10), .ok)
        // jump way ahead — old bits should be discarded
        XCTAssertEqual(record(rp, packetNumber: 10 + Int64(ReplayProtection.windowSize) + 5), .ok)
        // packet 10 is now outside the window → duplicate
        XCTAssertEqual(record(rp, packetNumber: 10), .duplicate)
    }

    // MARK: - timestamp tolerance

    func testInvalidTimestampInPast() throws {
        let rp = try makeRP(toleranceMs: 60_000)
        let result = rp.checkAndRecord(
            connectionId: 1,
            packetNumber: 0,
            timestamp: fixedNow - 60_001,  // just past the tolerance
            sessionEpoch: 1,
            nowMs: fixedNow
        )
        XCTAssertEqual(result, .invalidTimestamp)
    }

    func testInvalidTimestampInFuture() throws {
        let rp = try makeRP(toleranceMs: 60_000)
        let result = rp.checkAndRecord(
            connectionId: 1,
            packetNumber: 0,
            timestamp: fixedNow + 60_001,
            sessionEpoch: 1,
            nowMs: fixedNow
        )
        XCTAssertEqual(result, .invalidTimestamp)
    }

    func testTimestampAtToleranceBoundaryAccepted() throws {
        let rp = try makeRP(toleranceMs: 60_000)
        // |timestamp - now| == tolerance is allowed (Math.abs(...) > tolerance is the rejection condition).
        let result = rp.checkAndRecord(
            connectionId: 1,
            packetNumber: 0,
            timestamp: fixedNow - 60_000,
            sessionEpoch: 1,
            nowMs: fixedNow
        )
        XCTAssertEqual(result, .ok)
    }

    // MARK: - peer restart via session epoch

    func testEpochChangeReportsPeerRestartAndAcceptsPacket() throws {
        let rp = try makeRP()
        XCTAssertEqual(record(rp, packetNumber: 100, sessionEpoch: 0xAAAA), .ok)
        XCTAssertEqual(record(rp, packetNumber: 50, sessionEpoch: 0xBBBB), .peerRestart)
        // After restart the window was reset, so packet 50 is the new "first".
        // packet 50 should now be remembered:
        XCTAssertEqual(record(rp, packetNumber: 50, sessionEpoch: 0xBBBB), .duplicate)
        // And 100 (which used to be highest under the old epoch) is now in the future, accepted.
        XCTAssertEqual(record(rp, packetNumber: 100, sessionEpoch: 0xBBBB), .ok)
    }

    func testFirstPacketSetsEpochSilently() throws {
        let rp = try makeRP()
        // First-ever packet on a connection sets the epoch, no PEER_RESTART.
        XCTAssertEqual(record(rp, packetNumber: 0, sessionEpoch: 0x1234), .ok)
        XCTAssertEqual(record(rp, packetNumber: 1, sessionEpoch: 0x1234), .ok)
    }

    // MARK: - per-connection isolation

    func testConnectionsHaveSeparatePacketSequences() throws {
        let rp = try makeRP()
        XCTAssertEqual(record(rp, connId: 1, packetNumber: 0), .ok)
        XCTAssertEqual(record(rp, connId: 2, packetNumber: 0), .ok)  // different connection, fresh window
        XCTAssertEqual(record(rp, connId: 1, packetNumber: 0), .duplicate)
    }

    // MARK: - LRU eviction

    func testLruEvictsLeastRecentlyUsedConnection() throws {
        let rp = try makeRP(maxWindows: 3)
        // Fill the cache.
        XCTAssertEqual(record(rp, connId: 1, packetNumber: 0), .ok)
        XCTAssertEqual(record(rp, connId: 2, packetNumber: 0), .ok)
        XCTAssertEqual(record(rp, connId: 3, packetNumber: 0), .ok)
        XCTAssertEqual(rp.windowCount, 3)
        XCTAssertEqual(rp.evictionCount, 0)

        // Touch conn 1 so it's MRU.
        XCTAssertEqual(record(rp, connId: 1, packetNumber: 1), .ok)
        // Add a fourth — should evict conn 2 (LRU after the touch).
        XCTAssertEqual(record(rp, connId: 4, packetNumber: 0), .ok)
        XCTAssertEqual(rp.windowCount, 3)
        XCTAssertEqual(rp.evictionCount, 1)

        // Conn 2's window is gone, so its packet 0 looks fresh again.
        XCTAssertEqual(record(rp, connId: 2, packetNumber: 0), .ok)
        // Conn 1 wasn't evicted, so packet 1 is still a duplicate there.
        XCTAssertEqual(record(rp, connId: 1, packetNumber: 1), .duplicate)
    }

    func testRemoveConnectionForgetsState() throws {
        let rp = try makeRP()
        XCTAssertEqual(record(rp, connId: 7, packetNumber: 0), .ok)
        XCTAssertEqual(record(rp, connId: 7, packetNumber: 0), .duplicate)
        rp.removeConnection(7)
        XCTAssertEqual(record(rp, connId: 7, packetNumber: 0), .ok)  // fresh again
    }

    func testClearForgetsAllConnections() throws {
        let rp = try makeRP()
        XCTAssertEqual(record(rp, connId: 1, packetNumber: 0), .ok)
        XCTAssertEqual(record(rp, connId: 2, packetNumber: 0), .ok)
        rp.clear()
        XCTAssertEqual(rp.windowCount, 0)
        XCTAssertEqual(record(rp, connId: 1, packetNumber: 0), .ok)
        XCTAssertEqual(record(rp, connId: 2, packetNumber: 0), .ok)
    }

    // MARK: - configuration validation

    func testRejectsBadMaxWindows() {
        XCTAssertThrowsError(try ReplayProtection(maxWindows: 0)) { e in
            guard case ReplayProtection.Failure.invalidMaxWindows = e else {
                XCTFail("wrong error: \(e)"); return
            }
        }
        XCTAssertThrowsError(try ReplayProtection(maxWindows: -1))
    }

    func testRejectsBadTolerance() {
        XCTAssertThrowsError(try ReplayProtection(maxWindows: 16, timestampToleranceMs: 0)) { e in
            guard case ReplayProtection.Failure.invalidToleranceMs = e else {
                XCTFail("wrong error: \(e)"); return
            }
        }
        XCTAssertThrowsError(try ReplayProtection(maxWindows: 16, timestampToleranceMs: 7_200_000))
    }
}
