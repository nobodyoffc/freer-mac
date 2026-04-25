import XCTest
@testable import FCTransport

final class FudpVarintTests: XCTestCase {

    func testEncodeMatchesVectors() throws {
        let vectors = try FudpVectors.load()
        XCTAssertFalse(vectors.quicVarint.isEmpty)
        for vector in vectors.quicVarint {
            XCTAssertEqual(FudpVarint.encode(vector.value).hex, vector.encodedHex,
                           "encode \(vector.value)")
        }
    }

    func testDecodeRoundTripsVectors() throws {
        let vectors = try FudpVectors.load()
        for vector in vectors.quicVarint {
            let bytes = Data(fromHex: vector.encodedHex)
            let (decoded, length) = try FudpVarint.decode(bytes)
            XCTAssertEqual(decoded, vector.value, "decode \(vector.encodedHex)")
            XCTAssertEqual(length, bytes.count, "consumed \(vector.value)")
        }
    }

    /// 2-bit prefix transitions: 63 is the last 1-byte form, 64 the
    /// first 2-byte form, etc.
    func testPrefixBoundaries() {
        XCTAssertEqual(FudpVarint.encode(63).hex, "3f")
        XCTAssertEqual(FudpVarint.encode(64).hex, "4040")
        XCTAssertEqual(FudpVarint.encode(16383).hex, "7fff")
        XCTAssertEqual(FudpVarint.encode(16384).hex, "80004000")
        XCTAssertEqual(FudpVarint.encode(1073741823).hex, "bfffffff")
        XCTAssertEqual(FudpVarint.encode(1073741824).hex, "c000000040000000")
    }

    func testDecodeRejectsTruncated() {
        XCTAssertThrowsError(try FudpVarint.decode(Data())) { e in
            guard case FudpVarint.Failure.truncated = e else {
                XCTFail("wrong error: \(e)"); return
            }
        }
        // 2-byte prefix but only 1 byte present
        XCTAssertThrowsError(try FudpVarint.decode(Data([0x40])))
        // 4-byte prefix but only 3 bytes present
        XCTAssertThrowsError(try FudpVarint.decode(Data([0x80, 0x00, 0x00])))
        // 8-byte prefix but only 7 bytes present
        XCTAssertThrowsError(try FudpVarint.decode(Data([0xC0, 0, 0, 0, 0, 0, 0])))
    }
}
