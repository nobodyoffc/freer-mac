import XCTest
@testable import FCCore

final class SshWireTests: XCTestCase {

    func testUint32IsBigEndian() {
        XCTAssertEqual(SshWire.uint32(0).hex, "00000000")
        XCTAssertEqual(SshWire.uint32(1).hex, "00000001")
        XCTAssertEqual(SshWire.uint32(0x0b).hex, "0000000b")
        XCTAssertEqual(SshWire.uint32(0xdeadbeef).hex, "deadbeef")
        XCTAssertEqual(SshWire.uint32(.max).hex, "ffffffff")
    }

    /// The exact prefix every `ssh-ed25519` blob starts with, spelled
    /// out so a byte-order regression is obvious rather than subtle.
    func testStringMatchesTheKnownAlgorithmNameEncoding() {
        XCTAssertEqual(
            SshWire.string("ssh-ed25519").hex,
            "0000000b" + "7373682d65643235353139"
        )
    }

    func testEmptyStringIsJustALength() {
        XCTAssertEqual(SshWire.string(Data()).hex, "00000000")
    }

    func testRoundTrip() throws {
        let a = Data(repeating: 0x11, count: 32)
        let b = Data("hello".utf8)
        var reader = SshWire.Reader(SshWire.string(a) + SshWire.string(b) + SshWire.uint32(7))
        XCTAssertEqual(try reader.readString(), a)
        XCTAssertEqual(try reader.readString(), b)
        XCTAssertEqual(try reader.readUInt32(), 7)
        XCTAssertTrue(reader.isAtEnd)
    }

    func testReadByteAdvances() throws {
        var reader = SshWire.Reader(Data([0x0b, 0x0c]))
        XCTAssertEqual(try reader.readByte(), 0x0b)
        XCTAssertEqual(try reader.readByte(), 0x0c)
        XCTAssertThrowsError(try reader.readByte())
    }

    func testTruncatedLengthThrows() {
        var reader = SshWire.Reader(Data([0x00, 0x00, 0x01]))
        XCTAssertThrowsError(try reader.readUInt32()) { error in
            guard case SshWire.Failure.truncated = error else {
                return XCTFail("expected .truncated, got \(error)")
            }
        }
    }

    /// A length header that promises more than the buffer holds — the
    /// shape of a malformed agent request.
    func testTruncatedBodyThrows() {
        var reader = SshWire.Reader(SshWire.uint32(64) + Data(repeating: 0xaa, count: 8))
        XCTAssertThrowsError(try reader.readString()) { error in
            guard case let SshWire.Failure.truncated(needed, available) = error else {
                return XCTFail("expected .truncated, got \(error)")
            }
            XCTAssertEqual(needed, 64)
            XCTAssertEqual(available, 8)
        }
    }

    /// The allocation guard: a hostile length must be refused before
    /// anything tries to reserve that much memory.
    func testAbsurdLengthIsRefusedWithoutAllocating() {
        var reader = SshWire.Reader(SshWire.uint32(0xffff_ffff) + Data([0x00]))
        XCTAssertThrowsError(try reader.readString()) { error in
            guard case let SshWire.Failure.tooLong(n) = error else {
                return XCTFail("expected .tooLong, got \(error)")
            }
            XCTAssertEqual(n, 0xffff_ffff)
        }
    }

    func testReadRestReturnsRemainder() throws {
        var reader = SshWire.Reader(SshWire.string("abc") + Data([0x01, 0x02]))
        _ = try reader.readString()
        XCTAssertEqual(reader.readRest(), Data([0x01, 0x02]))
        XCTAssertEqual(reader.readRest(), Data())
    }
}
