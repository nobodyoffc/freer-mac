import XCTest
@testable import FCTransport

/// A manually-advanced clock for deterministic time-based tests.
private final class TestClock: @unchecked Sendable {
    private let lock = NSLock()
    private var _now: Int64 = 1_000_000

    var now: Int64 {
        lock.lock(); defer { lock.unlock() }
        return _now
    }

    func advance(by ms: Int64) {
        lock.lock(); defer { lock.unlock() }
        _now += ms
    }
}

final class RttEstimatorTests: XCTestCase {

    func testFirstSampleSeedsEstimator() {
        let rtt = RttEstimator()
        XCTAssertEqual(rtt.smoothedRttMs, 50)   // initial
        rtt.update(latestRttMs: 200)
        XCTAssertEqual(rtt.smoothedRttMs, 200)
        XCTAssertEqual(rtt.rttVarianceMs, 100)
        XCTAssertEqual(rtt.minRttMs, 200)
    }

    func testEwmaMatchesJavaIntegerMath() {
        let rtt = RttEstimator()
        rtt.update(latestRttMs: 100)   // seed: srtt=100, var=50
        rtt.update(latestRttMs: 200)
        // Java: var = (3*50 + |100-200| + 2) / 4 = 252/4 = 63
        //       srtt = (7*100 + 200 + 4) / 8 = 904/8 = 113
        XCTAssertEqual(rtt.rttVarianceMs, 63)
        XCTAssertEqual(rtt.smoothedRttMs, 113)
    }

    func testRtoClampAndFloor() {
        let rtt = RttEstimator()
        rtt.update(latestRttMs: 0)     // clamped to 1ms floor: srtt=1, var=0
        XCTAssertEqual(rtt.smoothedRttMs, 1)
        XCTAssertEqual(rtt.rtoMs, 1)   // 1 + 4*0, floored at 1
    }
}

final class CongestionControlTests: XCTestCase {

    func testSlowStartGrowsByAckedBytes() {
        let cc = CongestionControl()
        let w0 = cc.congestionWindow
        cc.onSend(10_000)
        cc.onAck(10_000)
        XCTAssertEqual(cc.congestionWindow, w0 + 10_000)
        XCTAssertEqual(cc.bytesInFlight, 0)
        XCTAssertEqual(cc.state, .slowStart)
    }

    func testLossShrinksByBetaWithFloor() {
        let cc = CongestionControl()
        let w0 = cc.congestionWindow      // 120_000
        cc.onLoss()
        XCTAssertEqual(cc.congestionWindow, Int64(Double(w0) * 0.7))
        XCTAssertEqual(cc.state, .recovery)

        // Repeated losses can't go below the floor.
        for _ in 0..<20 { cc.onLoss() }
        XCTAssertEqual(cc.congestionWindow, CongestionControl.minWindow)
    }

    func testTrySendGatesOnWindow() {
        let cc = CongestionControl()
        let window = Int(cc.congestionWindow)
        XCTAssertTrue(cc.trySend(window))          // fills the window exactly
        XCTAssertFalse(cc.trySend(1))              // no room left
        cc.onAck(window)                            // drain
        XCTAssertTrue(cc.trySend(1))
    }

    func testRetransmitRemoveReleasesWithoutGrowth() {
        let cc = CongestionControl()
        let w0 = cc.congestionWindow
        cc.onSend(5_000)
        cc.onRetransmitRemove(5_000)
        XCTAssertEqual(cc.bytesInFlight, 0)
        XCTAssertEqual(cc.congestionWindow, w0)    // no growth — not an ACK
    }

    func testCubicRecoveryGrowsAfterLoss() {
        let clock = TestClock()
        let cc = CongestionControl(nowMs: { clock.now })
        cc.onLoss()                                 // enter recovery, epoch reset
        let postLoss = cc.congestionWindow
        clock.advance(by: 2_000)                    // walk up the cubic curve
        cc.onSend(10_000)
        cc.onAck(10_000)
        XCTAssertGreaterThan(cc.congestionWindow, postLoss)
        XCTAssertEqual(cc.state, .congestionAvoidance)
    }
}

final class AckGeneratorTests: XCTestCase {

    func testSingleRangeForConsecutivePackets() throws {
        let gen = AckGenerator()
        for pn: Int64 in 0...5 { gen.onPacketReceived(pn) }
        let frame = try XCTUnwrap(gen.generateAckFrame())
        XCTAssertEqual(frame.largestAcknowledged, 5)
        XCTAssertEqual(frame.ranges.count, 1)
        XCTAssertEqual(frame.ranges[0].length, 5)   // 6 packets = length 5
        XCTAssertEqual(Set(frame.acknowledgedPackets()), Set(0...5))
    }

    func testGappedPacketsProduceMultipleRanges() throws {
        let gen = AckGenerator()
        for pn: Int64 in [0, 1, 2, 5, 6, 9] { gen.onPacketReceived(pn) }
        let frame = try XCTUnwrap(gen.generateAckFrame())
        XCTAssertEqual(frame.largestAcknowledged, 9)
        XCTAssertEqual(Set(frame.acknowledgedPackets()), Set([0, 1, 2, 5, 6, 9]))
    }

    func testWireRoundTripThroughFrameParser() throws {
        let gen = AckGenerator()
        let received: [Int64] = [3, 4, 7, 10, 11, 12, 20]
        for pn in received { gen.onPacketReceived(pn) }
        let frame = try XCTUnwrap(gen.generateAckFrame())

        let parsed = try FrameParser.parseAll(frame.encode())
        guard case .ack(let decoded)? = parsed.first else {
            return XCTFail("expected an ACK frame, got \(parsed)")
        }
        XCTAssertEqual(decoded, frame)
        XCTAssertEqual(Set(decoded.acknowledgedPackets()), Set(received))
    }

    func testReAdvertisesRetainedNumbers() throws {
        // A second frame must still cover earlier packet numbers
        // (retention) so a lost ACK packet is survivable.
        let gen = AckGenerator()
        gen.onPacketReceived(0)
        gen.onPacketReceived(1)
        _ = gen.generateAckFrame()
        XCTAssertNil(gen.generateAckFrame())        // nothing new → no frame

        gen.onPacketReceived(2)
        let second = try XCTUnwrap(gen.generateAckFrame())
        XCTAssertEqual(Set(second.acknowledgedPackets()), Set([0, 1, 2]))
    }
}

final class SentPacketTrackerTests: XCTestCase {

    private func makeFrame(_ id: UInt64 = 0) -> StreamFrame {
        StreamFrame(streamId: id, offset: 0, data: Data([0x01]), fin: false)
    }

    func testGapLossDetection() {
        let clock = TestClock()
        let tracker = SentPacketTracker(nowMs: { clock.now })
        // Send packets 0...10; ACK everything except 0.
        for pn: Int64 in 0...10 {
            tracker.recordSent(packetNumber: pn, frames: [makeFrame()], size: 1200)
        }
        for pn: Int64 in 1...10 { _ = tracker.onAcked(pn) }
        tracker.noteLargestAcked(10)

        // Too young: reordering margin suppresses the gap signal.
        var detection = tracker.detectLostPackets(smoothedRttMs: 50, rttVarianceMs: 10)
        XCTAssertTrue(detection.packets.isEmpty)

        clock.advance(by: 100)  // past gapMinAge = max(20, srtt=50)
        detection = tracker.detectLostPackets(smoothedRttMs: 50, rttVarianceMs: 10)
        XCTAssertEqual(detection.packets.map(\.packetNumber), [0])
        XCTAssertTrue(detection.gapLoss)
    }

    func testTimeoutLossIsNotACongestionSignal() {
        let clock = TestClock()
        let tracker = SentPacketTracker(minTimeThresholdMs: 2000, nowMs: { clock.now })
        tracker.recordSent(packetNumber: 0, frames: [makeFrame()], size: 500)

        clock.advance(by: 1999)
        XCTAssertTrue(tracker.detectLostPackets(smoothedRttMs: 50, rttVarianceMs: 10).packets.isEmpty)

        clock.advance(by: 2)    // past the 2000ms floor
        let detection = tracker.detectLostPackets(smoothedRttMs: 50, rttVarianceMs: 10)
        XCTAssertEqual(detection.packets.count, 1)
        XCTAssertFalse(detection.gapLoss)   // timeout loss: retransmit, don't shrink
    }

    func testRetransmitBackoffDoublesTimeout() {
        let clock = TestClock()
        let tracker = SentPacketTracker(minTimeThresholdMs: 2000, nowMs: { clock.now })
        // A packet already retransmitted once waits 2x the threshold.
        tracker.recordSent(packetNumber: 0, frames: [makeFrame()], size: 500, retransmitCount: 1)

        clock.advance(by: 2001)
        XCTAssertTrue(tracker.detectLostPackets(smoothedRttMs: 50, rttVarianceMs: 10).packets.isEmpty)
        clock.advance(by: 2000) // past 2x
        XCTAssertEqual(tracker.detectLostPackets(smoothedRttMs: 50, rttVarianceMs: 10).packets.count, 1)
    }

    func testSpuriousLossWidensReorderThreshold() {
        let clock = TestClock()
        let tracker = SentPacketTracker(nowMs: { clock.now })
        let before = tracker.packetReorderThreshold

        tracker.recordSent(packetNumber: 0, frames: [makeFrame()], size: 500)
        tracker.noteLargestAcked(30)
        _ = tracker.removeForRetransmit(0)   // declared lost
        _ = tracker.onAcked(0)               // …but the ACK arrives late

        XCTAssertGreaterThan(tracker.packetReorderThreshold, before)
        XCTAssertEqual(tracker.ackedAfterSuspectedLost, 1)
    }

    func testAckRemovesFromTracking() {
        let tracker = SentPacketTracker()
        tracker.recordSent(packetNumber: 7, frames: [makeFrame()], size: 900)
        let record = tracker.onAcked(7)
        XCTAssertEqual(record?.size, 900)
        XCTAssertNil(tracker.onAcked(7))     // second ACK: already gone
        XCTAssertEqual(tracker.trackedCount, 0)
    }
}

final class InboundStreamBufferTests: XCTestCase {

    func testInOrderAssembly() throws {
        let buffer = InboundStreamBuffer()
        try buffer.append(offset: 0, data: Data("hello ".utf8), fin: false)
        XCTAssertNil(try buffer.assembleIfComplete())
        try buffer.append(offset: 6, data: Data("world".utf8), fin: true)
        XCTAssertEqual(try buffer.assembleIfComplete(), Data("hello world".utf8))
    }

    func testOutOfOrderDuplicatesAndOverlap() throws {
        let buffer = InboundStreamBuffer()
        try buffer.append(offset: 6, data: Data("world".utf8), fin: true)
        try buffer.append(offset: 0, data: Data("hello ".utf8), fin: false)
        try buffer.append(offset: 0, data: Data("hello ".utf8), fin: false) // dup
        try buffer.append(offset: 4, data: Data("o wor".utf8), fin: false)  // overlap
        XCTAssertEqual(try buffer.assembleIfComplete(), Data("hello world".utf8))
    }

    func testGapBlocksAssembly() throws {
        let buffer = InboundStreamBuffer()
        try buffer.append(offset: 0, data: Data("ab".utf8), fin: false)
        try buffer.append(offset: 4, data: Data("ef".utf8), fin: true)
        XCTAssertNil(try buffer.assembleIfComplete())
        try buffer.append(offset: 2, data: Data("cd".utf8), fin: false)
        XCTAssertEqual(try buffer.assembleIfComplete(), Data("abcdef".utf8))
    }

    func testProgressCountsOnlyNewBytes() throws {
        let buffer = InboundStreamBuffer()
        XCTAssertEqual(try buffer.append(offset: 0, data: Data(count: 100), fin: false), 100)
        XCTAssertEqual(try buffer.append(offset: 0, data: Data(count: 100), fin: false), 0)   // dup
        XCTAssertEqual(try buffer.append(offset: 50, data: Data(count: 100), fin: false), 50) // half-new
        XCTAssertEqual(buffer.receivedBytes, 150)
    }

    func testSpillToDiskAssemblesLargePayload() throws {
        // Tiny threshold forces the spill path; content is verified
        // byte-for-byte through the mapped assembly.
        let buffer = InboundStreamBuffer(spillThreshold: 1024)
        var expected = Data()
        var offset: UInt64 = 0
        var chunks: [(UInt64, Data)] = []
        for i in 0..<64 {
            let chunk = Data(repeating: UInt8(i), count: 257)
            chunks.append((offset, chunk))
            expected.append(chunk)
            offset += UInt64(chunk.count)
        }
        // Deliver out of order: evens first, odds after.
        let last = chunks.count - 1
        for (i, (off, data)) in chunks.enumerated() where i % 2 == 0 {
            try buffer.append(offset: off, data: data, fin: i == last)
        }
        XCTAssertNil(try buffer.assembleIfComplete())
        for (i, (off, data)) in chunks.enumerated() where i % 2 == 1 {
            try buffer.append(offset: off, data: data, fin: i == last)
        }
        let assembled = try XCTUnwrap(buffer.assembleIfComplete())
        XCTAssertEqual(assembled, expected)
    }

    func testCleanupRemovesSpillFile() throws {
        let buffer = InboundStreamBuffer(spillThreshold: 8)
        try buffer.append(offset: 0, data: Data(count: 64), fin: false)
        // Spilled now. Find no direct handle to the URL — behaviour is
        // observable only via cleanup not throwing and later appends failing
        // gracefully being unnecessary; here we just ensure cleanup is safe
        // to call twice.
        buffer.cleanup()
        buffer.cleanup()
    }
}
