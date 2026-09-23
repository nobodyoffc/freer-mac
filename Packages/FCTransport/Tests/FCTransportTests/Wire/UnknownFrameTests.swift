import XCTest
@testable import FCTransport

/// A peer that does not know a frame type loses only the packet carrying
/// it, and the connection survives. Port of FC-JDK's `UnknownFrameTest`.
///
/// This is what happens when a DATAGRAM (0x10) reaches a peer from before
/// FUDP7: its parser fails on the unknown type. To exercise that path on
/// the current code, the sender here puts a type no version knows (0x1f)
/// on the wire. The receiver must drop that packet and nothing else, and
/// must not count the parse failure as a decrypt failure — on the Java
/// nodes those feed a per-address limiter that, after five in a row,
/// drops every packet from the address for a second.
final class UnknownFrameTests: XCTestCase {

    /// A frame with a type byte no FUDP version defines.
    private let unknownFrame = Data([0x1f, 0x02, 0x55, 0x55])

    func testParserRejectsTheWholePacket() {
        // Frames before the unknown one are not delivered either.
        let bytes = DatagramFrame(data: Data("in-bad-packet".utf8)).encode() + unknownFrame
        XCTAssertThrowsError(try FrameParser.parseAll(bytes)) { error in
            guard case FrameParser.Failure.unknownFrameType(0x1f) = error else {
                return XCTFail("expected unknownFrameType(0x1f), got \(error)")
            }
        }
    }

    func testUnknownFrameLosesOnlyItsPacket() async throws {
        let received = DatagramInbox()
        let (client, server) = try await DatagramTestSupport.makePair(onServerDatagram: { _, _, data in
            received.put(data)
        })
        defer { client.close(); server.close() }
        try await DatagramTestSupport.connectWithDatagrams(client, server)
        let fudp = client.fudp!
        let serverFudp = server.fudp!

        // 1. A packet mixing a datagram with an unknown frame is lost whole.
        try await fudp.sendFramesForTest([DatagramFrame(data: Data("in-bad-packet".utf8)).encode(), unknownFrame])
        let after = await fudp.sendDatagram(Data("after".utf8))
        XCTAssertEqual(after, .sent)
        let first = await received.poll(timeoutMs: 3_000)
        XCTAssertNotNil(first, "the next good packet must be delivered")
        XCTAssertEqual(first.map { String(decoding: $0, as: UTF8.self) }, "after",
                       "the datagram in the unparseable packet must not be delivered")

        // 2. A sustained run of them (an old peer receiving 25 pps of
        //    datagrams) must not disturb what follows.
        let burst = 50
        for _ in 0..<burst {
            try await fudp.sendFramesForTest([unknownFrame])
        }
        // Good traffic straight after the burst must get through at once,
        // not after a cooldown.
        let t0 = DatagramTestSupport.nowNanos()
        let stillHere = await fudp.sendDatagram(Data("still-here".utf8))
        XCTAssertEqual(stillHere, .sent)
        let next = await received.poll(timeoutMs: 3_000)
        let waitedMs = (DatagramTestSupport.nowNanos() - t0) / 1_000_000
        XCTAssertNotNil(next, "a datagram after the burst must arrive")
        XCTAssertEqual(next.map { String(decoding: $0, as: UTF8.self) }, "still-here")
        XCTAssertLessThan(waitedMs, 500, "delivery after the burst took \(waitedMs)ms (limiter cooldown?)")

        XCTAssertEqual(serverFudp.frameParseFailCount, Int64(burst + 1), "every bad packet counted as a parse failure")
        XCTAssertEqual(serverFudp.decryptFailCount, 0, "authentic packets are not decrypt failures")
        // (FC-JDK also checks its decrypt-failure limiter never fired. The
        // Mac client has no such limiter: it refuses packets from any
        // other pubkey before decrypting.)

        // 3. The connection itself is untouched: same connection, requests work.
        let length = try await client.request(Data(count: 100), timeoutMs: 5_000)
        XCTAssertEqual(length, 100)
        XCTAssertEqual(serverFudp.connection.remoteConnectionId, fudp.connection.connectionId,
                       "the server must still be on the client's original connection")
        XCTAssertTrue(serverFudp.datagramsEnabled, "nothing may have looked like a peer restart")
    }
}
