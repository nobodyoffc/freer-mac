import XCTest
@testable import FCTransport

final class AppMessageTests: XCTestCase {

    // MARK: - envelope round-trip

    func testEnvelopeEncodeMatchesVectors() throws {
        let vectors = try FudpVectors.load()
        XCTAssertFalse(vectors.appMessage.isEmpty)
        for v in vectors.appMessage {
            let env = AppMessageEnvelope(
                type: MessageType(rawValue: v.typeCode)!,
                messageId: v.messageId,
                flags: AppMessageEnvelope.Flags(rawValue: v.flags),
                payload: Data(fromHex: v.payloadHex)
            )
            XCTAssertEqual(AppMessageCodec.encode(env).hex, v.encodedHex,
                           "envelope encode '\(v.label)'")
        }
    }

    func testEnvelopeDecodeRoundTripsVectors() throws {
        let vectors = try FudpVectors.load()
        for v in vectors.appMessage {
            let parsed = try AppMessageCodec.decode(Data(fromHex: v.encodedHex))
            XCTAssertEqual(parsed.type.rawValue, v.typeCode)
            XCTAssertEqual(parsed.messageId, v.messageId)
            XCTAssertEqual(parsed.flags.rawValue, v.flags)
            XCTAssertEqual(parsed.payload.hex, v.payloadHex,
                           "envelope decode '\(v.label)'")
        }
    }

    // MARK: - per-type payload codecs

    func testPingPayloadRoundTrips() throws {
        let vectors = try FudpVectors.load()
        for v in vectors.appMessage where v.kind == "ping" {
            let ping = PingMessage(timestamp: try XCTUnwrap(v.timestamp))
            XCTAssertEqual(ping.payload().hex, v.payloadHex,
                           "ping payload '\(v.label)'")
            let parsed = try PingMessage.parse(payload: Data(fromHex: v.payloadHex))
            XCTAssertEqual(parsed.timestamp, v.timestamp)
        }
    }

    func testPongPayloadRoundTrips() throws {
        let vectors = try FudpVectors.load()
        for v in vectors.appMessage where v.kind == "pong" {
            let info = Data(fromHex: try XCTUnwrap(v.infoHex))
            let pong = PongMessage(
                echoTimestamp: try XCTUnwrap(v.echoTimestamp),
                replyTimestamp: try XCTUnwrap(v.replyTimestamp),
                info: info
            )
            XCTAssertEqual(pong.payload().hex, v.payloadHex,
                           "pong payload '\(v.label)'")
            let parsed = try PongMessage.parse(payload: Data(fromHex: v.payloadHex))
            XCTAssertEqual(parsed.echoTimestamp, v.echoTimestamp)
            XCTAssertEqual(parsed.replyTimestamp, v.replyTimestamp)
            XCTAssertEqual(parsed.info, info)
        }
    }

    // The old sid+data RequestMessage / ResponseMessage stubs were
    // removed — the actual wire format is `UnifiedCodec` (4B BE
    // headerLen + JSON + binary). Codec parity is exercised by
    // UnifiedCodecTests; the Java vector-gen still emits "request"/
    // "response" entries here but they describe a format no real
    // server speaks, so we no longer consume them.

    // MARK: - end-to-end (envelope + per-type)

    func testFullEncodePipelineForPing() throws {
        let vectors = try FudpVectors.load()
        let v = vectors.appMessage.first { $0.kind == "ping" }!
        let ping = PingMessage(timestamp: try XCTUnwrap(v.timestamp))
        let env = AppMessageEnvelope(
            type: .ping,
            messageId: v.messageId,
            flags: AppMessageEnvelope.Flags(rawValue: v.flags),
            payload: ping.payload()
        )
        XCTAssertEqual(AppMessageCodec.encode(env).hex, v.encodedHex)
    }

    // MARK: - error cases

    func testRejectsTruncatedEnvelope() {
        XCTAssertThrowsError(try AppMessageCodec.decode(Data(repeating: 0, count: 10))) { e in
            guard case AppMessageCodec.Failure.truncated = e else {
                XCTFail("wrong error: \(e)"); return
            }
        }
    }

    func testRejectsUnknownType() {
        var bytes = [UInt8](repeating: 0, count: 11)
        bytes[0] = 0x99  // not a known MessageType
        XCTAssertThrowsError(try AppMessageCodec.decode(Data(bytes))) { e in
            guard case AppMessageCodec.Failure.unknownType = e else {
                XCTFail("wrong error: \(e)"); return
            }
        }
    }

    func testRejectsUnderflowedPayload() {
        // Type=ping, id=0, flags=0, declared payload length=8, but only 4 bytes follow.
        var bytes: [UInt8] = []
        bytes.append(MessageType.ping.rawValue)
        bytes.append(contentsOf: [UInt8](repeating: 0, count: 8))  // messageId
        bytes.append(0)                                            // flags
        bytes.append(0x08)                                         // varint(8)
        bytes.append(contentsOf: [UInt8](repeating: 0, count: 4))  // only 4 bytes

        XCTAssertThrowsError(try AppMessageCodec.decode(Data(bytes))) { e in
            guard case AppMessageCodec.Failure.payloadShorterThanLength = e else {
                XCTFail("wrong error: \(e)"); return
            }
        }
    }
}
