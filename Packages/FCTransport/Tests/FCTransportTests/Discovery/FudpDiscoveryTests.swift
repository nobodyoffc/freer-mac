import XCTest
@testable import FCTransport

final class FudpDiscoveryTests: XCTestCase {

    // MARK: - request encoding

    func testHelloDatagramShape() throws {
        let bytes = try FudpDiscovery.buildHelloDatagram()
        // Header (21 B) + 1 byte HELLO marker
        XCTAssertEqual(bytes.count, PacketHeader.size + 1)

        // Header round-trips.
        let header = try PacketHeader.decode(bytes)
        XCTAssertEqual(header.packetType, .control)
        XCTAssertEqual(header.version, PacketHeader.currentVersion)
        XCTAssertEqual(header.connectionId, 0)
        XCTAssertEqual(header.packetNumber, 0)

        // Body is a single 0x01 byte.
        let body = bytes.dropFirst(PacketHeader.size)
        XCTAssertEqual(body.first, FudpDiscovery.helloTypeByte)
        XCTAssertEqual(body.first, 0x01)
    }

    // MARK: - response parsing

    /// Helper: build a synthetic PUBLIC_KEY datagram we'd expect from
    /// the server, so the parsing tests don't have to talk to one.
    private func makePublicKeyDatagram(pubkey: Data) -> Data {
        var data = PacketHeader(
            packetType: .control, flags: [],
            version: PacketHeader.currentVersion,
            connectionId: 0, packetNumber: 0
        ).encode()
        data.append(FudpDiscovery.publicKeyTypeByte)
        data.append(pubkey)
        return data
    }

    func testParsesValidPublicKeyDatagram() throws {
        let pubkey = Data((0..<33).map { UInt8($0 + 1) })  // 0x01..0x21
        let datagram = makePublicKeyDatagram(pubkey: pubkey)
        let parsed = try FudpDiscovery.parsePublicKeyDatagram(datagram)
        XCTAssertEqual(parsed, pubkey)
    }

    func testIgnoresTrailingBytesAfterPubkey() throws {
        // Some implementations might pad — anything after the 33 B
        // pubkey is harmless and should be ignored.
        let pubkey = Data(repeating: 0xAB, count: 33)
        var datagram = makePublicKeyDatagram(pubkey: pubkey)
        datagram.append(Data(repeating: 0xFF, count: 8))
        let parsed = try FudpDiscovery.parsePublicKeyDatagram(datagram)
        XCTAssertEqual(parsed, pubkey)
    }

    func testRejectsTooShortDatagram() {
        // Less than the 21 B header.
        XCTAssertThrowsError(try FudpDiscovery.parsePublicKeyDatagram(Data([0, 1, 2]))) { error in
            guard case FudpDiscovery.Failure.truncated = error else {
                XCTFail("expected truncated, got \(error)"); return
            }
        }
    }

    func testRejectsNonControlPacketType() {
        // Build a datagram whose header type bits encode .data (0x00)
        // instead of .control (0x02). The leading byte = type bits = 0.
        var datagram = PacketHeader(
            packetType: .data, flags: [],
            connectionId: 0, packetNumber: 0
        ).encode()
        datagram.append(FudpDiscovery.publicKeyTypeByte)
        datagram.append(Data(repeating: 0, count: 33))
        XCTAssertThrowsError(try FudpDiscovery.parsePublicKeyDatagram(datagram)) { error in
            guard case FudpDiscovery.Failure.unexpectedPacketType = error else {
                XCTFail("expected unexpectedPacketType, got \(error)"); return
            }
        }
    }

    func testRejectsWrongControlByte() {
        // Looks like a control packet but body[0] is CONTROL_CHALLENGE
        // (0x03) instead of PUBLIC_KEY (0x02). Should not be confused
        // for a successful discovery response.
        var datagram = PacketHeader(
            packetType: .control, flags: [],
            connectionId: 0, packetNumber: 0
        ).encode()
        datagram.append(0x03)  // CONTROL_CHALLENGE
        datagram.append(Data(repeating: 0, count: 33))
        XCTAssertThrowsError(try FudpDiscovery.parsePublicKeyDatagram(datagram)) { error in
            guard case FudpDiscovery.Failure.unexpectedControlByte(0x03) = error else {
                XCTFail("expected unexpectedControlByte(0x03), got \(error)"); return
            }
        }
    }

    func testRejectsTruncatedPubkey() {
        // Header + control byte + only 16 B (need 33).
        var datagram = PacketHeader(
            packetType: .control, flags: [],
            connectionId: 0, packetNumber: 0
        ).encode()
        datagram.append(FudpDiscovery.publicKeyTypeByte)
        datagram.append(Data(repeating: 0, count: 16))
        XCTAssertThrowsError(try FudpDiscovery.parsePublicKeyDatagram(datagram)) { error in
            guard case FudpDiscovery.Failure.truncated = error else {
                XCTFail("expected truncated, got \(error)"); return
            }
        }
    }
}
