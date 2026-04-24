import XCTest
@testable import FCCore

final class FchAddressTests: XCTestCase {

    func testEncodeFromPubkeyMatchesVectors() throws {
        let vectors = try TestVectors.load()
        XCTAssertFalse(vectors.fchAddress.isEmpty)
        for vector in vectors.fchAddress {
            let pubkey = Data(fromHex: vector.pubkeyHex)
            let address = try FchAddress(publicKey: pubkey)
            XCTAssertEqual(address.fid, vector.fid, "'\(vector.label)'")
            XCTAssertEqual(address.versionByte, vector.versionByte)
            XCTAssertEqual(address.hash160.hex, vector.pubkeyHash160Hex)
        }
    }

    func testEncodeFromHashMatchesVectors() throws {
        let vectors = try TestVectors.load()
        for vector in vectors.fchAddress {
            let hash = Data(fromHex: vector.pubkeyHash160Hex)
            let address = try FchAddress(versionByte: vector.versionByte, hash160: hash)
            XCTAssertEqual(address.fid, vector.fid, "'\(vector.label)'")
        }
    }

    func testDecodeRoundTripsVectors() throws {
        let vectors = try TestVectors.load()
        for vector in vectors.fchAddress {
            let parsed = try FchAddress(fid: vector.fid)
            XCTAssertEqual(parsed.versionByte, vector.versionByte)
            XCTAssertEqual(parsed.hash160.hex, vector.pubkeyHash160Hex)
            XCTAssertEqual(parsed.fid, vector.fid)
        }
    }

    func testDecodeSampleFid() throws {
        let vectors = try TestVectors.load()
        let parsed = try FchAddress(fid: vectors.sampleKey.fid)
        XCTAssertEqual(parsed.versionByte, FchAddress.mainnetVersionByte)
        XCTAssertEqual(parsed.hash160.hex, vectors.sampleKey.pubkeyHash160Hex)
    }

    func testRejectsWrongVersionByte() throws {
        let vectors = try TestVectors.load()
        // Encode a FID with a different version byte, then try to decode it
        // against the mainnet default.
        let hash = Data(fromHex: vectors.fchAddress[0].pubkeyHash160Hex)
        let weirdAddress = try FchAddress(versionByte: 0x00, hash160: hash)
        XCTAssertThrowsError(try FchAddress(fid: weirdAddress.fid)) { e in
            guard case FchAddress.Failure.unexpectedVersionByte(let got, let expected) = e else {
                XCTFail("expected unexpectedVersionByte, got \(e)"); return
            }
            XCTAssertEqual(got, 0x00)
            XCTAssertEqual(expected, 0x23)
        }
        // Accepts any version if the caller opts in
        XCTAssertNoThrow(try FchAddress(fid: weirdAddress.fid, expectedVersionByte: nil))
    }

    func testRejectsBadHashLength() {
        XCTAssertThrowsError(
            try FchAddress(hash160: Data(repeating: 0, count: 19))
        )
    }

    func testRejectsBadBase58() {
        XCTAssertThrowsError(try FchAddress(fid: "not-a-valid-base58!!!"))
    }
}
