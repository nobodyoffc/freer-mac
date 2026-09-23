import XCTest
@testable import FCTransport

/// No packet exceeds maxPacketSize, and ACK ranges have holes only where
/// packets were lost. Port of FC-JDK's `PacketSizeBudgetTest`.
///
/// Both failed with data flowing in both directions. The receiver left
/// the peer's ACK-only packets out of its ACK ranges, so every other
/// packet number was a hole: ACK frames hit their 128-range cap while
/// covering only the last ~250 packets. Piggybacked unbudgeted on a full
/// STREAM packet, that made packets over the limit — IP-fragmented on a
/// real network. The crypto overhead was also budgeted 16 bytes short.
final class PacketSizeBudgetTests: XCTestCase {

    private static let maxPacket = DatagramTestSupport.maxPacketSize

    func testBidirectionalBulkStaysWithinMaxPacketSize() async throws {
        for loss in [0.0, 0.10] {
            try await runBidirectional(loss: loss)
        }
    }

    private func runBidirectional(loss: Double) async throws {
        let proxy = LossyProxy(serverPort: DatagramTestSupport.freeUdpPort())
        let (client, server) = try await DatagramTestSupport.makePair(proxy: proxy)
        defer { proxy.stop(); client.close(); server.close() }
        _ = try await client.request(Data(count: 8), timeoutMs: 15_000)

        // Largest ACK frame either side receives, in ranges and bytes. The
        // Mac client has no packet listener to hook, so the proxy decrypts
        // what it forwards with the receiving end's key.
        let probe = AckProbe()
        let (clientPriv, serverPriv) = (client.privkey, server.privkey)
        proxy.inspect = { packet, fromServer in
            probe.inspect(packet, receiverPrivkey: fromServer ? clientPriv : serverPriv)
        }
        proxy.dropRate = loss

        // 4 MB each way at once, so both sides send full STREAM packets
        // while owing ACKs.
        let up = Task { try await client.request(DatagramTestSupport.randomBytes(4 << 20), timeoutMs: 180_000) }
        let down = Task { try await server.request(DatagramTestSupport.randomBytes(4 << 20), timeoutMs: 180_000) }
        let upLength = try await up.value
        let downLength = try await down.value
        XCTAssertEqual(upLength, 4 << 20)
        XCTAssertEqual(downLength, 4 << 20)

        print(String(format: "[PacketSizeBudgetTests] loss=%.0f%% largest packet c->s=%d s->c=%d (limit %d); largest ACK %d ranges / %d bytes",
                     loss * 100, proxy.maxToServer, proxy.maxToClient, Self.maxPacket, probe.maxRanges, probe.maxBytes))

        XCTAssertLessThanOrEqual(proxy.maxToServer, Self.maxPacket, "client sent a \(proxy.maxToServer)-byte packet")
        XCTAssertLessThanOrEqual(proxy.maxToClient, Self.maxPacket, "server sent a \(proxy.maxToClient)-byte packet")
        XCTAssertEqual(client.fudp.oversizePacketCount, 0)
        XCTAssertEqual(server.fudp.oversizePacketCount, 0)
        XCTAssertGreaterThan(probe.frames, 0, "sanity: the probe saw ACK frames")
        if loss == 0.0 {
            // Without loss, holes can only come from momentary reordering
            // between sender tasks; nothing like the old 128.
            XCTAssertLessThanOrEqual(probe.maxRanges, 8, "loss-free ACKs must stay near one range, saw \(probe.maxRanges)")
        }
    }

    /// An ACK is trimmed to its byte budget oldest-first, and stays pending if nothing fits.
    func testAckFrameRespectsItsByteBudget() throws {
        let acks = AckGenerator()
        // Every other packet number: 50 ranges.
        for pn in stride(from: Int64(0), to: 100, by: 2) { acks.onPacketReceived(pn) }

        XCTAssertNil(acks.generateAckFrame(maxBytes: 3), "a frame that cannot hold even one range is not generated")
        XCTAssertTrue(acks.hasPendingAcks, "...and the ACK stays pending for a caller with more room")

        let small = try XCTUnwrap(acks.generateAckFrame(maxBytes: 40))
        XCTAssertLessThanOrEqual(small.encode().count, 40, "frame is \(small.encode().count) bytes")
        XCTAssertEqual(small.encodedSize, small.encode().count)
        XCTAssertEqual(small.largestAcknowledged, 98, "the newest ranges are the ones kept")
        XCTAssertLessThan(small.ranges.count, 50)
        XCTAssertFalse(acks.hasPendingAcks)

        // Non-eliciting packet numbers fill the holes without making an ACK due.
        for pn in stride(from: Int64(1), to: 100, by: 2) { acks.onNonElicitingPacketReceived(pn) }
        XCTAssertFalse(acks.hasPendingAcks, "ACK-only and DATAGRAM-only packets elicit no ACK")
        acks.onPacketReceived(100)
        let full = try XCTUnwrap(acks.generateAckFrame(maxBytes: .max))
        XCTAssertEqual(full.ranges.count, 1, "0..100 is one contiguous range")
        XCTAssertEqual(full.ranges[0].length, 100)
    }

    /// Non-eliciting packets are pruned when recorded, not only when an
    /// ACK is generated: a receive-only datagram flow may never generate
    /// one.
    func testNonElicitingPacketsArePrunedOnInsert() throws {
        final class Clock: @unchecked Sendable {
            let lock = NSLock()
            var ms: Int64 = 1_000_000
            func now() -> Int64 { lock.lock(); defer { lock.unlock() }; return ms }
            func advance(_ by: Int64) { lock.lock(); ms += by; lock.unlock() }
        }
        let clock = Clock()
        let acks = AckGenerator(nowMs: { clock.now() })
        for pn: Int64 in 0..<5_000 { acks.onNonElicitingPacketReceived(pn) }
        clock.advance(AckGenerator.ackRetainMs + 1)
        // Only datagrams arrive, for well past the retention window.
        for pn: Int64 in 5_000..<5_010 { acks.onNonElicitingPacketReceived(pn) }

        acks.onPacketReceived(5_010)
        let frame = try XCTUnwrap(acks.generateAckFrame(maxBytes: .max))
        XCTAssertEqual(Set(frame.acknowledgedPackets()), Set(Int64(5_000)...5_010),
                       "numbers older than the retention window are gone")
    }
}

/// Records the largest ACK frame seen on the wire.
private final class AckProbe: @unchecked Sendable {
    private let lock = NSLock()
    private var _maxRanges = 0
    private var _maxBytes = 0
    private var _frames = 0

    var maxRanges: Int { lock.lock(); defer { lock.unlock() }; return _maxRanges }
    var maxBytes: Int { lock.lock(); defer { lock.unlock() }; return _maxBytes }
    var frames: Int { lock.lock(); defer { lock.unlock() }; return _frames }

    func inspect(_ packet: Data, receiverPrivkey: Data) {
        guard let header = try? PacketHeader.decode(packet), header.packetType != .control,
              let opened = try? AsyTwoWay.open(bundle: Data(packet.dropFirst(PacketHeader.size)),
                                               aad: header.encode(), localPrivkey: receiverPrivkey),
              let payload = try? FudpPayload.parse(opened.plaintext,
                                                   hasTimestamp: header.flags.contains(.hasTimestamp),
                                                   hasEpoch: header.flags.contains(.hasEpoch))
        else { return }
        for case .ack(let ack) in payload.frames {
            lock.lock()
            _frames += 1
            _maxRanges = max(_maxRanges, ack.ranges.count)
            _maxBytes = max(_maxBytes, ack.encodedSize)
            lock.unlock()
        }
    }
}
