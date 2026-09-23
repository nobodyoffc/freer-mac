import XCTest
@testable import FCTransport

/// 10% loss in each direction on loopback. Datagrams are never
/// retransmitted, so about 10% of them are lost and none arrives twice;
/// meanwhile a stream transfer on the same connection completes exactly
/// as it would without them. Port of FC-JDK's `DatagramLossTest`.
final class DatagramLossTests: XCTestCase {

    func testDatagramsAreNotRetransmittedAndStreamsAreUnaffected() async throws {
        let proxy = LossyProxy(serverPort: DatagramTestSupport.freeUdpPort())
        let seen = SeqCounter()
        let (client, server) = try await DatagramTestSupport.makePair(proxy: proxy, onServerDatagram: { _, _, data in
            seen.record(DatagramTestSupport.seqOf(data))
        })
        defer { proxy.stop(); client.close(); server.close() }
        try await DatagramTestSupport.connectWithDatagrams(client, server)
        let fudp = client.fudp!
        let retransmitsBefore = fudp.transfer.sentPackets.retransmitCount

        proxy.dropRate = 0.10

        // A 1 MB request on the same connection, running while datagrams flow.
        let upload = DatagramTestSupport.randomBytes(1024 * 1024)
        let transfer = Task { try await client.request(upload, timeoutMs: 60_000) }

        // 1000 datagrams at 200/s (5 s), 160 bytes each: 256 kbps, the default budget.
        let total = 1000
        var sent = 0
        var next = DatagramTestSupport.nowNanos()
        for i in 0..<total {
            if await fudp.sendDatagram(DatagramTestSupport.stamped(Int64(i), size: 160)) == .sent { sent += 1 }
            next += 5_000_000
            let now = DatagramTestSupport.nowNanos()
            if next > now { await QuietClock.sleep(nanoseconds: next - now) }
        }

        let received = try await transfer.value
        XCTAssertEqual(received, upload.count, "the server must have received the whole upload")
        let streamRetransmits = fudp.transfer.sentPackets.retransmitCount - retransmitsBefore
        XCTAssertGreaterThan(streamRetransmits, 0, "sanity: the stream did need retransmissions at 10% loss")

        try await Task.sleep(nanoseconds: 500_000_000) // let the last datagrams land
        let delivered = seen.distinct
        let duplicates = seen.duplicates
        let lossPct = 100.0 * Double(sent - delivered) / Double(sent)
        print(String(format: "[DatagramLossTests] sent=%d delivered=%d loss=%.1f%% duplicates=%d streamRetransmits=%lld proxyDropped=%d",
                     sent, delivered, lossPct, duplicates, streamRetransmits, proxy.dropped))

        XCTAssertGreaterThanOrEqual(Double(sent), Double(total) * 0.98, "the budget should pass ~all of them, sent=\(sent)")
        XCTAssertEqual(duplicates, 0, "a datagram must never arrive twice")
        // 1000 trials at p=0.1: 5.0..15.0% is beyond +/-5 sigma. A
        // retransmitting implementation would show ~0%.
        XCTAssertTrue((5.0...15.0).contains(lossPct),
                      "datagram loss should track the 10% link loss (no retransmission), was \(lossPct)%")

        // Datagrams never entered bytes in flight: once the stream is
        // fully ACKed, nothing is left outstanding.
        let deadline = DatagramTestSupport.nowNanos() + 10_000_000_000
        while fudp.transfer.congestion.bytesInFlight != 0 && DatagramTestSupport.nowNanos() < deadline {
            try await Task.sleep(nanoseconds: 50_000_000)
        }
        XCTAssertEqual(fudp.transfer.congestion.bytesInFlight, 0,
                       "bytes in flight must drain to zero; datagrams are not counted")
        // (FC-JDK also checks that everything ran on one connection; a
        // FudpClient is one connection by construction.)
    }

    /// FUDP7 code check: a receiver may list DATAGRAM-only packet
    /// numbers in its ACKs, and those must not count as evidence that a
    /// tracked packet was lost. Before the fix, gap-based detection
    /// measured the gap in packet numbers, so ten datagrams sent after a
    /// stream packet made that packet "lost" as soon as anything after
    /// them was acknowledged.
    func testUntrackedPacketNumbersAreNotLossEvidence() async throws {
        let machinery = TransferMachinery()
        func stream(_ offset: UInt64) -> [StreamFrame] {
            [StreamFrame(streamId: 0, offset: offset, data: Data(count: 100), fin: false)]
        }
        func ack(_ packetNumbers: [Int64]) -> AckFrame {
            let gen = AckGenerator()
            for pn in packetNumbers { gen.onPacketReceived(pn) }
            return gen.generateAckFrame(maxBytes: .max)!
        }

        // pn 0: a stream packet, still in flight. pn 1..10: datagram-only
        // packets (untracked). pn 11: a stream packet that gets ACKed.
        machinery.sentPackets.recordSent(packetNumber: 0, frames: stream(0), size: 150)
        machinery.sentPackets.recordSent(packetNumber: 11, frames: stream(100), size: 150)

        try await Task.sleep(nanoseconds: 100_000_000) // RTT sample ~100 ms, clearly distinct from the 50 ms initial estimate
        machinery.processAckFrame(ack(Array(1...11))) // datagram numbers listed too
        let minRtt = machinery.rtt.minRttMs
        XCTAssertTrue((90..<1000).contains(minRtt),
                      "an ACK whose largest number is untracked must still yield an RTT sample (minRtt=\(minRtt))")

        try await Task.sleep(nanoseconds: 150_000_000) // older than the gap-detection age guard (~sRTT), younger than the 2 s timeout
        XCTAssertTrue(machinery.detectLostPackets().packets.isEmpty,
                      "only one TRACKED packet followed pn 0; ten untracked numbers are no loss evidence")

        // Real loss is still caught: seven tracked packets ACKed past a missing one.
        let lostPn: Int64 = 12
        machinery.sentPackets.recordSent(packetNumber: lostPn, frames: stream(200), size: 150)
        let later = Array(Int64(13)...19)
        for (i, pn) in later.enumerated() {
            machinery.sentPackets.recordSent(packetNumber: pn, frames: stream(300 + UInt64(i) * 100), size: 150)
        }
        try await Task.sleep(nanoseconds: 300_000_000)
        machinery.processAckFrame(ack(later))
        let detection = machinery.detectLostPackets()
        XCTAssertTrue(detection.packets.contains { $0.packetNumber == lostPn },
                      "a tracked packet with 7 tracked successors ACKed must be detected as lost")
        XCTAssertTrue(detection.gapLoss)
    }
}

/// How many times each datagram sequence number arrived.
final class SeqCounter: @unchecked Sendable {
    private let lock = NSLock()
    private var counts: [Int64: Int] = [:]

    func record(_ seq: Int64) {
        lock.lock(); counts[seq, default: 0] += 1; lock.unlock()
    }

    var distinct: Int {
        lock.lock(); defer { lock.unlock() }
        return counts.count
    }

    var duplicates: Int {
        lock.lock(); defer { lock.unlock() }
        return counts.values.filter { $0 > 1 }.count
    }
}
