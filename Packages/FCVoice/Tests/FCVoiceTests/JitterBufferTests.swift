import XCTest
@testable import FCVoice

/// JitterBuffer (VOICE_SPEC §9.3) against simulated arrivals, ported from
/// Android's JitterBufferTest: a sender making one frame every 20 ms, a
/// network that delays or drops them, and a playout clock pulling once per period.
final class JitterBufferTests: XCTestCase {

    static let frameMs: Int64 = 20

    /// A seeded generator, so a run is the same every time.
    struct Seeded {
        var state: UInt64
        mutating func next() -> Double {
            state = state &* 6364136223846793005 &+ 1442695040888963407
            return Double(state >> 11) / Double(1 << 53)
        }
    }

    final class Sim {
        let jb = JitterBuffer(frameMs: Int(frameMs))
        var pulls: [JitterBuffer.Kind] = []
        var arrivals: [(at: Int64, seq: Int64, flags: Int, level: Int)] = []

        func send(_ seq: Int64, _ delay: Int64, _ flags: Int, level: Int? = nil) {
            arrivals.append((seq * frameMs + delay, seq, flags, level ?? (flags & 1 != 0 ? 127 : 30)))
        }

        func run(_ until: Int64) {
            arrivals.sort { $0.at < $1.at }
            var next = 0
            for t in 0...until {
                while next < arrivals.count && arrivals[next].at <= t {
                    let a = arrivals[next]
                    next += 1
                    jb.put(seq: a.seq, timestamp: a.seq * 960, data: Data([UInt8(truncatingIfNeeded: a.seq)]),
                           silent: a.flags & 1 != 0, afterDtx: a.flags & 2 != 0, level: a.level, arrivalMs: a.at)
                }
                if t % frameMs == 5 { pulls.append(jb.pull(nowMs: t).kind) }
            }
        }
    }

    func steady(_ frames: Int64, _ delay: (Int64) -> Int64) -> Sim {
        let s = Sim()
        for i in 0..<frames {
            let d = delay(i)
            if d >= 0 { s.send(i, d, 0) }
        }
        return s
    }

    func testSteadyStreamPlaysEverythingAtMinimumDelay() {
        let s = steady(250) { _ in 30 }
        s.run(250 * Self.frameMs + 500)
        let st = s.jb.stats
        XCTAssertEqual(st.played, 250)
        XCTAssertEqual(st.fecRecovered + st.concealed + st.late, 0)
        XCTAssertEqual(st.targetMs, JitterBuffer.minTargetMs)
    }

    func testLostFrameIsRecoveredFromTheNextFramesFec() {
        let s = steady(100) { $0 == 50 ? -1 : 30 }
        s.run(100 * Self.frameMs + 500)
        let st = s.jb.stats
        XCTAssertEqual(st.played, 99)
        XCTAssertEqual(st.fecRecovered, 1)
        XCTAssertEqual(st.concealed, 0)
        XCTAssertTrue(s.pulls.contains(.fec))
    }

    func testTwoLostInARowConcealsTheFirstAndRecoversTheSecond() {
        let s = steady(100) { $0 == 50 || $0 == 51 ? -1 : 30 }
        s.run(100 * Self.frameMs + 500)
        let st = s.jb.stats
        XCTAssertEqual(st.concealed, 1)
        XCTAssertEqual(st.fecRecovered, 1)
        XCTAssertEqual(st.lossPercent, 2.0, accuracy: 0.01)
    }

    func testTargetFollowsJitterAndKeepsLateFramesRare() {
        var r = Seeded(state: 7)
        let s = steady(500) { _ in 30 + Int64(r.next() * 100) }
        s.run(500 * Self.frameMs + 1000)
        let st = s.jb.stats
        XCTAssertTrue((80...110).contains(st.targetMs), "target \(st.targetMs) should track ~95 ms of jitter")
        XCTAssertLessThanOrEqual(st.fecRecovered + st.concealed, 25)
        XCTAssertGreaterThan(st.stretched, 0, "it grew by waiting for late frames")
    }

    func testTargetStaysWithinBounds() {
        let s = steady(300) { 30 + ($0 % 2 == 0 ? 0 : 900) }
        s.run(300 * Self.frameMs + 2000)
        XCTAssertLessThanOrEqual(s.jb.stats.targetMs, JitterBuffer.maxTargetMs)
    }

    func testShortDtxGapIsSilenceNotLoss() {
        let s = Sim()
        for i in Int64(0)..<100 where !(40..<45).contains(i) { s.send(i, 30, i == 45 ? 2 : 0) }
        s.run(100 * Self.frameMs + 500)
        let st = s.jb.stats
        XCTAssertEqual(st.dtxGap, 5)
        XCTAssertEqual(st.fecRecovered + st.concealed, 0)
    }

    func testLongPauseRestartsPlayoutAtTheNextSpurt() {
        let s = Sim()
        for i in Int64(0)..<50 { s.send(i, 30, 0) }
        for i in Int64(100)..<150 { s.send(i, 30, i == 100 ? 2 : 0) }
        s.run(150 * Self.frameMs + 500)
        let st = s.jb.stats
        XCTAssertEqual(st.played, 100)
        XCTAssertEqual(st.fecRecovered + st.concealed + st.late, 0)
    }

    func testABurstAfterAStallIsCaughtUpNotPlayedLate() {
        let s = Sim()
        for i in Int64(0)..<300 {
            let d = i >= 100 && i < 150 ? 3000 - i * Self.frameMs : 30
            s.send(i, d, 1)
        }
        s.run(300 * Self.frameMs + 1000)
        let st = s.jb.stats
        XCTAssertGreaterThan(st.skipped, 0)
        XCTAssertLessThanOrEqual(st.depthMs, JitterBuffer.maxTargetMs)
    }

    func testFivePercentRandomLossIsReportedAsFivePercent() {
        var r = Seeded(state: 11)
        let s = steady(2000) { _ in r.next() < 0.05 ? -1 : 30 }
        s.run(2000 * Self.frameMs + 500)
        let st = s.jb.stats
        XCTAssertEqual(st.lossPercent, 5.0, accuracy: 1.0)
        XCTAssertGreaterThan(st.fecRecovered, st.concealed)
    }

    func testDuplicatesAndLateArrivalsAreCountedNotPlayed() {
        let s = steady(100) { _ in 30 }
        s.send(20, 30, 0)
        s.send(60, 1500, 0)
        s.run(100 * Self.frameMs + 2000)
        let st = s.jb.stats
        XCTAssertEqual(st.played, 100)
        XCTAssertEqual(st.duplicates, 1)
        XCTAssertEqual(st.late, 1)
    }

    func spikeInSpeech(_ level: (Int64) -> Int) -> Sim {
        let s = Sim()
        for i in Int64(0)..<700 {
            let d = i >= 100 && i < 107 ? 30 + (107 - i) * Self.frameMs : 30
            s.send(i, d, 0, level: level(i))
        }
        return s
    }

    func testContinuousSpeechDoesNotKeepTheExtraDelay() {
        let s = spikeInSpeech { _ in 30 }
        s.run(700 * Self.frameMs - 200)
        let st = s.jb.stats
        XCTAssertGreaterThan(st.stretched, 0)
        XCTAssertGreaterThan(st.forced, 0)
        XCTAssertLessThanOrEqual(st.depthMs, st.targetMs + 3 * Int(Self.frameMs))
    }

    func testQuietGapsBetweenSyllablesAreSkippedFirst() {
        let s = spikeInSpeech { $0 % 5 == 0 ? 60 : 30 }
        s.run(700 * Self.frameMs - 200)
        let st = s.jb.stats
        XCTAssertGreaterThan(st.skipped, 0)
        XCTAssertEqual(st.forced, 0)
        XCTAssertLessThanOrEqual(st.depthMs, st.targetMs + 3 * Int(Self.frameMs))
    }
}
