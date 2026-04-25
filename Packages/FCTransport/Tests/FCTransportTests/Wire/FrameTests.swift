import XCTest
@testable import FCTransport

final class FrameTests: XCTestCase {

    // MARK: - StreamFrame

    func testStreamFrameMatchesVectors() throws {
        let vectors = try FudpVectors.load()
        XCTAssertFalse(vectors.streamFrame.isEmpty)
        for vector in vectors.streamFrame {
            let frame = StreamFrame(
                streamId: vector.streamId,
                offset: vector.offset,
                data: Data(fromHex: vector.dataHex),
                fin: vector.fin
            )
            XCTAssertEqual(frame.encode().hex, vector.encodedHex,
                           "'\(vector.label)'")
        }
    }

    /// Type-byte composition: STREAM base 0x08, LEN always set, FIN/OFF
    /// added when present.
    func testStreamFrameTypeByteComposition() {
        // No fin, no offset → 0x08 | 0x02 (LEN) = 0x0A
        let plain = StreamFrame(streamId: 0, offset: 0, data: Data(), fin: false).encode()
        XCTAssertEqual(plain[0], 0x0A)

        // Fin, no offset → 0x08 | 0x02 | 0x01 = 0x0B
        let finOnly = StreamFrame(streamId: 0, offset: 0, data: Data(), fin: true).encode()
        XCTAssertEqual(finOnly[0], 0x0B)

        // No fin, with offset → 0x08 | 0x02 | 0x04 = 0x0E
        let offsetOnly = StreamFrame(streamId: 0, offset: 1, data: Data(), fin: false).encode()
        XCTAssertEqual(offsetOnly[0], 0x0E)

        // Fin + offset → 0x0F
        let both = StreamFrame(streamId: 0, offset: 1, data: Data(), fin: true).encode()
        XCTAssertEqual(both[0], 0x0F)
    }

    // MARK: - AckFrame

    func testAckFrameMatchesVectors() throws {
        let vectors = try FudpVectors.load()
        XCTAssertFalse(vectors.ackFrame.isEmpty)
        for vector in vectors.ackFrame {
            let ranges = vector.ranges.map { AckRange(gap: $0.gap, length: $0.length) }
            let frame = AckFrame(
                largestAcknowledged: vector.largestAcknowledged,
                ackDelay: vector.ackDelay,
                ranges: ranges
            )
            XCTAssertEqual(frame.encode().hex, vector.encodedHex,
                           "'\(vector.label)'")
        }
    }

    // MARK: - PaddingFrame

    func testPaddingFrameMatchesVectors() throws {
        let vectors = try FudpVectors.load()
        for vector in vectors.paddingFrame {
            XCTAssertEqual(PaddingFrame.encode().hex, vector.encodedHex,
                           "'\(vector.label)'")
        }
    }

    // MARK: - FrameType

    func testStreamFrameTypeParsesAcrossFlagRange() {
        for byte in UInt8(0x08)...UInt8(0x0F) {
            XCTAssertEqual(FrameType.parse(typeByte: byte), .stream)
        }
        XCTAssertEqual(FrameType.parse(typeByte: 0x00), .padding)
        XCTAssertEqual(FrameType.parse(typeByte: 0x01), .ack)
        XCTAssertNil(FrameType.parse(typeByte: 0x42))
    }
}
