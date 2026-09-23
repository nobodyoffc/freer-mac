import XCTest
import FCCore
@testable import FCTransport

/// DATAGRAM frame (FUDP7): encoding, packets carrying several frames, and
/// the size limit that keeps every datagram inside one packet. Port of
/// FC-JDK's `DatagramFrameTest`.
final class DatagramFrameTests: XCTestCase {

    func testEncodingRoundTrip() throws {
        for len in [0, 1, 63, 64, 200, 1200, 16383, 16384] {
            let data = DatagramTestSupport.randomBytes(len)
            let wire = DatagramFrame(data: data).encode()

            XCTAssertEqual(DatagramFrame.encodedSize(dataLength: len), wire.count,
                           "encodedSize must match the encoding, len=\(len)")
            XCTAssertEqual(wire.first, 0x10, "type byte")

            // parseAll throws on anything left over, so a clean parse
            // means the frame consumed exactly its own bytes.
            let parsed = try FrameParser.parseAll(wire)
            XCTAssertEqual(parsed, [.datagram(DatagramFrame(data: data))], "len=\(len)")
        }
    }

    func testKnownEncodingVector() {
        // Type 0x10, length 3 (1-byte varint), data. Pinned for cross-client vectors.
        XCTAssertEqual([UInt8](DatagramFrame(data: Data([0x0a, 0x0b, 0x0c])).encode()),
                       [0x10, 0x03, 0x0a, 0x0b, 0x0c])
        // Length 64 needs the 2-byte varint form (0x40 0x40).
        let wire = [UInt8](DatagramFrame(data: Data(count: 64)).encode())
        XCTAssertEqual(wire[0], 0x10)
        XCTAssertEqual(wire[1], 0x40)
        XCTAssertEqual(wire[2], 0x40)
        XCTAssertEqual(wire.count, 67)
    }

    // MARK: - cross-client vectors (fudpVectors.json, tools/vector-gen)

    func testDatagramFrameMatchesVectors() throws {
        let vectors = try FudpVectors.load()
        XCTAssertFalse(vectors.datagramFrame.isEmpty)
        for vector in vectors.datagramFrame {
            let data = Data(fromHex: vector.dataHex)
            XCTAssertEqual(DatagramFrame(data: data).encode().hex, vector.encodedHex, "'\(vector.label)'")
            XCTAssertEqual(try FrameParser.parseAll(Data(fromHex: vector.encodedHex)),
                           [.datagram(DatagramFrame(data: data))], "'\(vector.label)'")
        }
    }

    func testDatagramPayloadMatchesVectors() throws {
        let vectors = try FudpVectors.load()
        XCTAssertFalse(vectors.datagramPayload.isEmpty)
        for vector in vectors.datagramPayload {
            let frameBytes = vector.framesHex.map { Data(fromHex: $0) }
            let payload = FudpPayload.assemble(
                includeTimestamp: vector.includeTimestamp,
                timestamp: vector.timestamp ?? 0,
                includeEpoch: vector.includeEpoch,
                sessionEpoch: vector.sessionEpoch ?? 0,
                frameBytes: frameBytes
            )
            XCTAssertEqual(payload.hex, vector.encodedHex, "'\(vector.label)'")

            let prefix = (vector.includeTimestamp ? 8 : 0) + (vector.includeEpoch ? 8 : 0)
            let frames = try FrameParser.parseAll(payload.dropFirst(prefix))
            XCTAssertEqual(frames.count, frameBytes.count, "'\(vector.label)'")
            let datagrams = frames.compactMap { frame -> String? in
                if case .datagram(let d) = frame { return d.data.hex }
                return nil
            }
            XCTAssertEqual(datagrams, vector.datagramsHex, "'\(vector.label)'")
            XCTAssertEqual(frames.contains { $0.isAckEliciting }, vector.ackEliciting, "'\(vector.label)'")
        }
    }

    func testMaxDatagramSizeMatchesVectors() throws {
        let vectors = try FudpVectors.load()
        XCTAssertFalse(vectors.datagramMaxSize.isEmpty)
        for vector in vectors.datagramMaxSize {
            XCTAssertEqual(FudpClient.maxDatagramSize(maxPacketSize: vector.maxPacketSize),
                           vector.maxDatagramSize, "maxPacketSize=\(vector.maxPacketSize)")
        }
    }

    func testLengthPastEndOfPacketIsRejected() {
        let wire = DatagramFrame(data: Data(count: 10)).encode()
        XCTAssertThrowsError(try FrameParser.parseAll(wire.dropLast()))
    }

    func testNotRetransmittedAndNotAckEliciting() {
        let datagram = ParsedFrame.datagram(DatagramFrame(data: Data(count: 20)))
        XCTAssertFalse(datagram.isAckEliciting)
        XCTAssertEqual(FrameType(rawValue: 0x10), .datagram)
        XCTAssertEqual(FrameType.parse(typeByte: 0x10), .datagram)

        // A packet elicits an ACK when any of its frames does.
        func elicits(_ frames: [ParsedFrame]) -> Bool { frames.contains { $0.isAckEliciting } }
        let small = ParsedFrame.datagram(DatagramFrame(data: Data(count: 5)))
        let ack = ParsedFrame.ack(AckFrame(largestAcknowledged: 3, ackDelay: 0, ranges: [AckRange(gap: 0, length: 0)]))
        let stream = ParsedFrame.stream(StreamFrame(streamId: 4, offset: 0, data: Data(count: 5), fin: false))
        XCTAssertFalse(elicits([small, small]), "DATAGRAM-only packet must not elicit an ACK")
        XCTAssertFalse(elicits([ack, small]), "DATAGRAM + ACK packet must not elicit an ACK")
        XCTAssertTrue(elicits([small, stream]), "a STREAM frame still elicits an ACK")
        // Not retransmitted: only STREAM frames can be tracked for
        // retransmission (SentPacketRecord.frames is [StreamFrame]); the
        // integration tests check datagram packets never enter flight.
    }

    func testPacketWithSeveralFramesRoundTrips() throws {
        var payloads: [Data] = []
        var frames: [Data] = []
        for i in 0..<3 {
            let p = DatagramTestSupport.randomBytes(40 + i)
            payloads.append(p)
            frames.append(DatagramFrame(data: p).encode())
        }
        let ack = AckFrame(largestAcknowledged: 5, ackDelay: 0, ranges: [AckRange(gap: 0, length: 5)])
        frames.append(ack.encode())
        let streamData = DatagramTestSupport.randomBytes(30)
        frames.append(StreamFrame(streamId: 2, offset: 100, data: streamData, fin: true).encode())
        let last = DatagramTestSupport.randomBytes(1)
        payloads.append(last)
        frames.append(DatagramFrame(data: last).encode())

        let plaintext = FudpPayload.assemble(
            includeTimestamp: true, timestamp: 999,
            includeEpoch: true, sessionEpoch: 12345,
            frameBytes: frames
        )
        let parsed = try FudpPayload.parse(plaintext, hasTimestamp: true, hasEpoch: true)

        XCTAssertEqual(parsed.frames.count, 6)
        XCTAssertEqual(parsed.sessionEpoch, 12345)
        var d = 0
        for i in [0, 1, 2, 5] {
            XCTAssertEqual(parsed.frames[i], .datagram(DatagramFrame(data: payloads[d])))
            d += 1
        }
        XCTAssertEqual(parsed.frames[3], .ack(ack))
        guard case .stream(let sf) = parsed.frames[4] else { return XCTFail("expected STREAM at 4") }
        XCTAssertEqual(sf.data, streamData)
        XCTAssertTrue(sf.fin)
    }

    /// The advertised maximum must fit in one packet with the worst-case
    /// prefix (timestamp + session epoch), measured on the real send path.
    func testMaxDatagramFitsInOnePacket() async throws {
        for (maxPacket, expected) in [(1400, 1292), (1350, 1242)] { // VOICE_SPEC §2.2
            let capture = CapturingTransport()
            let client = try FudpClient(
                transport: capture,
                host: "127.0.0.1",
                port: 1,
                peerPubkey: try Secp256k1.publicKey(fromPrivateKey: DatagramTestSupport.randomBytes(32)),
                localPrivkey: DatagramTestSupport.randomBytes(32),
                maxPacketSize: maxPacket
            )
            defer { client.close() }
            let max = client.maxDatagramSize
            XCTAssertGreaterThan(max, 1000, "a \(maxPacket)-byte packet should carry a >1000-byte datagram")
            XCTAssertEqual(max, expected)

            client.enableDatagrams()
            let result = await client.sendDatagram(Data(count: max))
            XCTAssertEqual(result, .sent)
            let wire = try XCTUnwrap(capture.sent.last).count
            XCTAssertEqual(wire, maxPacket, "the maximum should fill the packet exactly, or it wastes room")
            XCTAssertEqual(client.oversizePacketCount, 0)
            print("[DatagramFrameTests] maxPacket=\(maxPacket) maxDatagram=\(max) wire=\(wire)")
        }
    }

    func testSendPathEnforcesSizeCapabilityAndPacking() async throws {
        let received = DatagramInbox()
        let (client, server) = try await DatagramTestSupport.makePair(onServerDatagram: { _, _, data in
            received.put(data)
        })
        defer { client.close(); server.close() }
        _ = try await client.request(Data(count: 8), timeoutMs: 15_000)
        let fudp = client.fudp!
        // The counts below are packet numbers this end has allocated, so
        // they need the connection quiet: a request returns as soon as the
        // response is assembled, while the pump still owes it an ACK.
        try await Task.sleep(nanoseconds: 300_000_000)

        // Capability gate: nothing goes on the wire until enabled.
        var sentBefore = fudp.connection.nextPacketNumberPreview
        let refused = await fudp.sendDatagram(Data(count: 10))
        XCTAssertEqual(refused, .notEnabled)
        XCTAssertEqual(fudp.connection.nextPacketNumberPreview, sentBefore, "a refused datagram must not produce a packet")

        fudp.enableDatagrams()
        fudp.setDatagramRate(bitsPerSecond: 8_000_000) // budget is tested separately
        let max = fudp.maxDatagramSize

        // Largest size goes through intact; one byte more is refused, not fragmented.
        let big = DatagramTestSupport.randomBytes(max)
        let bigResult = await fudp.sendDatagram(big)
        XCTAssertEqual(bigResult, .sent)
        let bigReceived = await received.poll(timeoutMs: 5_000)
        XCTAssertEqual(bigReceived, big)
        let tooLarge = await fudp.sendDatagram(Data(count: max + 1))
        XCTAssertEqual(tooLarge, .tooLarge)
        let ghost = await received.poll(timeoutMs: 300)
        XCTAssertNil(ghost, "an oversized datagram must never arrive")

        // Ten small datagrams sent together share one packet, in order.
        var batch = (0..<10).map { _ in DatagramTestSupport.randomBytes(50) }
        sentBefore = fudp.connection.nextPacketNumberPreview
        var results = await fudp.sendDatagrams(batch)
        XCTAssertEqual(results, Array(repeating: .sent, count: 10))
        XCTAssertEqual(fudp.connection.nextPacketNumberPreview, sentBefore + 1, "10 x 50 bytes must be packed into one packet")
        for expected in batch {
            let got = await received.poll(timeoutMs: 5_000)
            XCTAssertEqual(got, expected)
        }

        // A batch too big for one packet splits across packets, still in order.
        // Two of these fill a packet exactly (each frame adds 3 bytes of framing).
        batch = (0..<5).map { _ in DatagramTestSupport.randomBytes(max / 2 - 3) }
        sentBefore = fudp.connection.nextPacketNumberPreview
        results = await fudp.sendDatagrams(batch)
        XCTAssertEqual(results, Array(repeating: .sent, count: 5))
        XCTAssertEqual(fudp.connection.nextPacketNumberPreview, sentBefore + 3, "5 datagrams, two per packet, need 3 packets")
        for expected in batch {
            let got = await received.poll(timeoutMs: 5_000)
            XCTAssertEqual(got, expected)
        }

        // Nothing sent as a datagram is in flight or awaiting retransmission.
        try await Task.sleep(nanoseconds: 300_000_000)
        XCTAssertEqual(fudp.transfer.congestion.bytesInFlight, 0,
                       "datagram packets must not count toward bytes in flight")
        XCTAssertEqual(fudp.transfer.sentPackets.trackedCount, 0)
    }

    func testRateBudgetDropsExcessAtSender() async throws {
        let (client, server) = try await DatagramTestSupport.makePair()
        defer { client.close(); server.close() }
        try await DatagramTestSupport.connectWithDatagrams(client, server)
        let fudp = client.fudp!

        // Default 256 kbps holds 100 ms of budget = 3200 bytes. A burst of
        // 100 x 200 bytes gets ~16 through; the rest are dropped at once.
        var sent = 0, overBudget = 0
        let start = DatagramTestSupport.nowNanos()
        for _ in 0..<100 {
            switch await fudp.sendDatagram(Data(count: 200)) {
            case .sent:       sent += 1
            case .overBudget: overBudget += 1
            default:          break
            }
        }
        let elapsedMs = (DatagramTestSupport.nowNanos() - start) / 1_000_000
        XCTAssertTrue((15...20).contains(sent), "expected ~16 within budget, got \(sent) in \(elapsedMs)ms")
        XCTAssertEqual(overBudget, 100 - sent)

        // A relay-style raised budget lets the same burst through.
        fudp.setDatagramRate(bitsPerSecond: 8_000_000)
        try await Task.sleep(nanoseconds: 150_000_000)
        sent = 0
        for _ in 0..<50 {
            if await fudp.sendDatagram(Data(count: 200)) == .sent { sent += 1 }
        }
        XCTAssertEqual(sent, 50, "8 Mbps holds 100 KB of budget; 10 KB must all pass")
    }
}

/// Datagrams as a handler saw them, for a test to wait on in order.
final class DatagramInbox: @unchecked Sendable {
    private let lock = NSLock()
    private var items: [Data] = []

    func put(_ data: Data) {
        lock.lock(); items.append(data); lock.unlock()
    }

    func poll(timeoutMs: Int) async -> Data? {
        let deadline = DatagramTestSupport.nowNanos() + UInt64(timeoutMs) * 1_000_000
        while true {
            if let next = take() { return next }
            if DatagramTestSupport.nowNanos() >= deadline { return nil }
            await QuietClock.sleep(nanoseconds: 1_000_000)
        }
    }

    private func take() -> Data? {
        lock.lock(); defer { lock.unlock() }
        return items.isEmpty ? nil : items.removeFirst()
    }
}

/// Transport that records what it is given and never answers.
final class CapturingTransport: DatagramTransport, @unchecked Sendable {
    let datagrams: AsyncStream<FudpConnection.Datagram>
    private let continuation: AsyncStream<FudpConnection.Datagram>.Continuation
    private let lock = NSLock()
    private var _sent: [Data] = []

    init() {
        var captured: AsyncStream<FudpConnection.Datagram>.Continuation!
        datagrams = AsyncStream { captured = $0 }
        continuation = captured
    }

    var sent: [Data] {
        lock.lock(); defer { lock.unlock() }
        return _sent
    }

    func send(_ data: Data) async throws {
        lock.withLock { _sent.append(data) }
    }

    func close() { continuation.finish() }
}
