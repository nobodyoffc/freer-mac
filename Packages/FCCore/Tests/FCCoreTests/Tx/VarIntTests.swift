import XCTest
@testable import FCCore

final class VarIntTests: XCTestCase {

    func testEncodeMatchesVectors() throws {
        let vectors = try TestVectors.load()
        XCTAssertFalse(vectors.varint.isEmpty)
        for vector in vectors.varint {
            XCTAssertEqual(VarInt.encode(vector.value).hex, vector.encodedHex,
                           "encode \(vector.value)")
        }
    }

    func testDecodeRoundTripsVectors() throws {
        let vectors = try TestVectors.load()
        for vector in vectors.varint {
            let bytes = Data(fromHex: vector.encodedHex)
            let (decoded, length) = try VarInt.decode(bytes)
            XCTAssertEqual(decoded, vector.value, "decode \(vector.encodedHex)")
            XCTAssertEqual(length, bytes.count, "consumed bytes for \(vector.value)")
        }
    }

    /// Prefix-byte transitions: 0xFC is the last 1-byte form, 0xFD is the
    /// first 3-byte form, 0x10000 is the first 5-byte form, etc.
    func testPrefixBoundaries() {
        XCTAssertEqual(VarInt.encode(0xFC).hex, "fc")
        XCTAssertEqual(VarInt.encode(0xFD).hex, "fdfd00")
        XCTAssertEqual(VarInt.encode(0xFFFF).hex, "fdffff")
        XCTAssertEqual(VarInt.encode(0x10000).hex, "fe00000100")
        XCTAssertEqual(VarInt.encode(0xFFFFFFFF).hex, "feffffffff")
        XCTAssertEqual(VarInt.encode(0x100000000).hex, "ff0000000001000000")
    }

    func testDecodeRejectsTruncated() {
        XCTAssertThrowsError(try VarInt.decode(Data())) { e in
            guard case VarInt.Failure.truncated = e else {
                XCTFail("expected truncated, got \(e)"); return
            }
        }
        XCTAssertThrowsError(try VarInt.decode(Data([0xFD])))       // missing 2 bytes
        XCTAssertThrowsError(try VarInt.decode(Data([0xFD, 0x01]))) // missing 1 byte
        XCTAssertThrowsError(try VarInt.decode(Data([0xFE, 0x00, 0x00, 0x00])))  // missing 1 byte
        XCTAssertThrowsError(try VarInt.decode(Data([0xFF] + [UInt8](repeating: 0, count: 7))))
    }
}
