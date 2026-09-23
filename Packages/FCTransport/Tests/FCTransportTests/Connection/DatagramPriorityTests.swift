import XCTest
@testable import FCTransport

/// Audio against a bulk stream upload on the same connection. Port of
/// FC-JDK's `DatagramPriorityTest`.
///
/// What FUDP guarantees is sender-side: a datagram skips the congestion
/// window, the pacer and any wait for the socket buffer, so it never
/// queues behind stream data inside the sender. What it cannot guarantee
/// on its own is the rest of the path. Loss-based congestion control
/// fills whatever queue sits downstream — here the receiver's socket
/// buffer, on a real network a bottleneck router — and audio waits in
/// that queue behind the upload. `testSenderNeverWaitsBehindUpload`
/// measures that and prints it.
///
/// The mitigation is for the call layer to cap bulk transfers below the
/// path rate while a call is live (`FudpClient.setStreamRateCap`);
/// `testStreamRateCapKeepsAudioFlat` shows it keeps audio delay flat.
final class DatagramPriorityTests: XCTestCase {

    private static let frameMs: UInt64 = 20 // one Opus frame
    private static let frameBytes = 120

    private var client: DatagramTestNode!
    private var server: DatagramTestNode!
    private let delays = DelayLog()

    override func setUp() async throws {
        let delays = self.delays
        (client, server) = try await DatagramTestSupport.makePair(onServerDatagram: { _, _, data in
            delays.add(DatagramTestSupport.ageMicros(data))
        })
        try await DatagramTestSupport.connectWithDatagrams(client, server)

        // Warm up so the idle baseline is steady state.
        client.fudp.setDatagramRate(bitsPerSecond: 100_000_000)
        for _ in 0..<3000 {
            _ = await client.fudp.sendDatagram(DatagramTestSupport.stamped(-1, size: Self.frameBytes))
        }
        client.fudp.setDatagramRate(bitsPerSecond: DatagramBudget.defaultRateBps)
        try await Task.sleep(nanoseconds: 500_000_000)
        _ = delays.drain()
    }

    override func tearDown() async throws {
        client?.close()
        server?.close()
    }

    /// Uncapped upload: every datagram is sent at once, without waiting,
    /// and none is dropped at the sender. The delay and loss it then
    /// meets downstream are printed, not asserted — they come from the
    /// queue the upload's congestion control builds.
    func testSenderNeverWaitsBehindUpload() async throws {
        let idle = await sendAudio(maxMs: 3000, until: nil)
        let idleDelay = await drainDelays()

        let upload = DatagramTestSupport.randomBytes(32 * 1024 * 1024)
        let transfer = uploadAsync(upload)
        try await Task.sleep(nanoseconds: 200_000_000) // let the upload ramp up
        _ = delays.drain()
        let busy = await sendAudio(maxMs: 30_000, until: transfer)
        try await assertUploadComplete(transfer, upload)
        try await Task.sleep(nanoseconds: 1_000_000_000) // let queued audio drain before counting
        let busyDelay = await drainDelays()

        let rtt = client.fudp.transfer.rtt
        report("idle", idle, idleDelay)
        report("uncapped upload", busy, busyDelay)
        print("[DatagramPriorityTests] upload connection: sRTT=\(rtt.smoothedRttMs)ms minRtt=\(rtt.minRttMs)ms "
              + "retransmits=\(client.fudp.transfer.sentPackets.retransmitCount) -- the downstream queue the upload built")

        XCTAssertGreaterThanOrEqual(busy.sent, 50, "the upload must last long enough to measure (sent \(busy.sent))")
        XCTAssertEqual(busy.notSent, 0, "no datagram may be dropped or refused at the sender during the upload")
        // A datagram that waited behind stream data (congestion window,
        // pacer, socket-buffer backpressure) would show as a systematic
        // delay in the median, or as tens to hundreds of ms. Isolated slow
        // calls are the thread being descheduled on a loaded machine. So:
        // median near idle, and a tail bound well clear of that noise and
        // well below a real wait.
        let callP50 = DatagramTestSupport.percentile(busy.callUs, 50)
        let callP99 = DatagramTestSupport.percentile(busy.callUs, 99)
        let idleP50 = DatagramTestSupport.percentile(idle.callUs, 50)
        XCTAssertLessThanOrEqual(callP50, max(idleP50, 100) + 200,
                                 "sendDatagram p50 during the upload (\(callP50)us) vs idle (\(idleP50)us): the sender must not make audio wait")
        XCTAssertLessThan(callP99, 50_000,
                          "sendDatagram p99 during the upload (\(callP99)us): no datagram may wait behind the upload")
        // Not asserted: datagrams lost downstream. The upload overflows the
        // receiver's socket buffer, which drops audio along with stream
        // data. Like the delay, that is the downstream queue, which only
        // the stream cap addresses.
    }

    /// Upload capped at 8 Mbit/s, below what this loopback receiver
    /// drains: no queue builds, and audio delay stays at its idle level.
    func testStreamRateCapKeepsAudioFlat() async throws {
        let idle = await sendAudio(maxMs: 3000, until: nil)
        let idleDelay = await drainDelays()

        let capBps: Int64 = 8_000_000
        client.fudp.setStreamRateCap(bitsPerSecond: capBps)
        let upload = DatagramTestSupport.randomBytes(6 * 1024 * 1024)
        let t0 = DatagramTestSupport.nowNanos()
        let transfer = uploadAsync(upload)
        try await Task.sleep(nanoseconds: 200_000_000)
        _ = delays.drain()
        let busy = await sendAudio(maxMs: 30_000, until: transfer)
        try await assertUploadComplete(transfer, upload)
        let uploadS = Double(DatagramTestSupport.nowNanos() - t0) / 1e9
        let busyDelay = await drainDelays()

        report("idle", idle, idleDelay)
        report("capped upload", busy, busyDelay)
        let mbps = Double(upload.count * 8) / uploadS / 1e6
        print(String(format: "[DatagramPriorityTests] capped upload: %.1f Mbit/s (cap %.1f)", mbps, Double(capBps) / 1e6))

        XCTAssertLessThanOrEqual(mbps, Double(capBps) / 1e6 * 1.15,
                                 "the cap must hold the upload near \(Double(capBps) / 1e6) Mbit/s, measured \(mbps)")
        XCTAssertGreaterThanOrEqual(busy.sent, 50, "the upload must last long enough to measure (sent \(busy.sent))")
        XCTAssertEqual(busy.notSent, 0)
        XCTAssertGreaterThanOrEqual(Double(busyDelay.count), Double(busy.sent) * 0.99,
                                    "loopback loses nothing below the cap (\(busyDelay.count)/\(busy.sent))")
        // The queue an uncapped upload builds costs audio hundreds of ms.
        // With the cap there is none: the median stays at idle and the
        // tail stays an order of magnitude below that.
        let p50Busy = DatagramTestSupport.percentile(busyDelay, 50)
        let p50Idle = DatagramTestSupport.percentile(idleDelay, 50)
        let p99Busy = DatagramTestSupport.percentile(busyDelay, 99)
        XCTAssertLessThanOrEqual(p50Busy, p50Idle + 2_000,
                                 "median audio delay under the capped upload (\(p50Busy)us) must stay within 2 ms of idle (\(p50Idle)us)")
        XCTAssertLessThan(p99Busy, 50_000,
                          "p99 audio delay under the capped upload (\(p99Busy)us): no queue may build")
    }

    // MARK: - helpers

    /// Frames sent, frames refused/dropped at the sender, and
    /// sendDatagram call times (sorted, us).
    private struct Audio {
        let sent: Int
        let notSent: Int
        let callUs: [Int64]
    }

    /// Send one frame every `frameMs` for up to `maxMs`, or until `until` completes.
    private func sendAudio(maxMs: UInt64, until: Task<Int, Error>?) async -> Audio {
        let done = DoneFlag()
        if let until {
            Task { _ = try? await until.value; done.set() }
        }
        var calls: [Int64] = []
        var sent = 0, notSent = 0
        var seq: Int64 = 0
        let start = DatagramTestSupport.nowNanos()
        var next = start
        while (DatagramTestSupport.nowNanos() - start) / 1_000_000 < maxMs && !done.isSet {
            let t = DatagramTestSupport.nowNanos()
            let result = await client.fudp.sendDatagram(DatagramTestSupport.stamped(seq, size: Self.frameBytes))
            seq += 1
            calls.append(Int64(DatagramTestSupport.nowNanos() - t) / 1000)
            if result == .sent { sent += 1 } else { notSent += 1 }
            next += Self.frameMs * 1_000_000
            let now = DatagramTestSupport.nowNanos()
            if next > now { await QuietClock.sleep(nanoseconds: next - now) }
        }
        return Audio(sent: sent, notSent: notSent, callUs: calls.sorted())
    }

    private func drainDelays() async -> [Int64] {
        await QuietClock.sleep(milliseconds: 100)
        return delays.drain().sorted()
    }

    /// The request sends the whole body before its reply can come, so it
    /// runs in its own task.
    private func uploadAsync(_ upload: Data) -> Task<Int, Error> {
        let client = self.client!
        return Task { try await client.request(upload, timeoutMs: 120_000) }
    }

    private func assertUploadComplete(_ transfer: Task<Int, Error>, _ upload: Data) async throws {
        let received = try await transfer.value
        XCTAssertEqual(received, upload.count, "the whole upload must arrive")
    }

    private func report(_ phase: String, _ a: Audio, _ delay: [Int64]) {
        let p = DatagramTestSupport.percentile
        print("[DatagramPriorityTests] \(phase.padding(toLength: 16, withPad: " ", startingAt: 0)) "
              + "sent=\(a.sent) notSent=\(a.notSent) recv=\(delay.count) | "
              + "sendDatagram p50=\(p(a.callUs, 50))us p99=\(p(a.callUs, 99))us max=\(p(a.callUs, 100))us | "
              + "delay p50=\(p(delay, 50))us p99=\(p(delay, 99))us max=\(p(delay, 100))us")
    }
}

/// Receive-side delays, in microseconds.
final class DelayLog: @unchecked Sendable {
    private let lock = NSLock()
    private var values: [Int64] = []

    func add(_ us: Int64) {
        lock.lock(); values.append(us); lock.unlock()
    }

    func drain() -> [Int64] {
        lock.lock(); defer { lock.unlock() }
        let out = values
        values.removeAll()
        return out
    }
}

private final class DoneFlag: @unchecked Sendable {
    private let lock = NSLock()
    private var done = false

    func set() {
        lock.lock(); done = true; lock.unlock()
    }

    var isSet: Bool {
        lock.lock(); defer { lock.unlock() }
        return done
    }
}
