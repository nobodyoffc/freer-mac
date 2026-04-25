import XCTest
@testable import FCTransport

final class PacketHeaderTests: XCTestCase {

    func testEncodeMatchesVectors() throws {
        let vectors = try FudpVectors.load()
        XCTAssertFalse(vectors.packetHeader.isEmpty)
        for vector in vectors.packetHeader {
            let header = try buildHeader(from: vector)
            XCTAssertEqual(header.encode().hex, vector.encodedHex,
                           "'\(vector.label)'")
        }
    }

    func testDecodeRoundTripsVectors() throws {
        let vectors = try FudpVectors.load()
        for vector in vectors.packetHeader {
            let bytes = Data(fromHex: vector.encodedHex)
            let parsed = try PacketHeader.decode(bytes)
            XCTAssertEqual(parsed.encode().hex, vector.encodedHex,
                           "round-trip '\(vector.label)'")
            XCTAssertEqual(UInt8(parsed.packetType.rawValue) | parsed.flags.rawValue,
                           vector.flags,
                           "flags '\(vector.label)'")
            XCTAssertEqual(parsed.version, vector.version)
            XCTAssertEqual(parsed.connectionId, vector.connectionId)
            XCTAssertEqual(parsed.packetNumber, vector.packetNumber)
        }
    }

    func testRejectsTruncatedHeader() {
        XCTAssertThrowsError(try PacketHeader.decode(Data(repeating: 0, count: 20))) { e in
            guard case PacketHeader.Failure.truncated = e else {
                XCTFail("wrong error: \(e)"); return
            }
        }
    }

    func testHeaderFraming() {
        let header = PacketHeader(
            packetType: .data,
            flags: [.fin, .hasTimestamp, .hasEpoch],
            version: 1,
            connectionId: 0x0123456789ABCDEF,
            packetNumber: 0x10
        )
        let bytes = header.encode()
        XCTAssertEqual(bytes.count, PacketHeader.size)
        XCTAssertEqual(bytes[0], 0x70)  // 0x40 | 0x20 | 0x10 | 0x00
        XCTAssertEqual(bytes.suffix(8).hex, "0000000000000010")
    }

    // MARK: - helper

    private func buildHeader(from vector: FudpVectors.PacketHeaderCase) throws -> PacketHeader {
        let typeBits = vector.flags & 0x03
        guard let packetType = PacketHeader.PacketType(rawValue: typeBits) else {
            XCTFail("unknown packet type bits 0x\(String(typeBits, radix: 16))")
            throw NSError(domain: "test", code: 1)
        }
        let flags = PacketHeader.Flags(rawValue: vector.flags & 0xFC)
        return PacketHeader(
            packetType: packetType,
            flags: flags,
            version: vector.version,
            connectionId: vector.connectionId,
            packetNumber: vector.packetNumber
        )
    }
}
