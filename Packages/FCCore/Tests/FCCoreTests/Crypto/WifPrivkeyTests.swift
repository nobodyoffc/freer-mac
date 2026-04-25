import XCTest
@testable import FCCore

final class WifPrivkeyTests: XCTestCase {

    /// Round-trip a known privkey through encode → decode → bytes
    /// match. The hex was supplied as the project test fixture; the
    /// WIF was obtained by encoding (compressed=true) here.
    func testRoundTripCompressedTestKey() throws {
        let privHex = "a048f6c843f92bfe036057f7fc2bf2c27353c624cf7ad97e98ed41432f700575"
        let priv = Data(fromHex: privHex)
        let wif = WifPrivkey.encode(privkey: priv, compressed: true)

        // Decoding the WIF we just produced gives us back the same bytes.
        let (decoded, compressed) = try WifPrivkey.decode(wif)
        XCTAssertEqual(decoded.hex, privHex)
        XCTAssertTrue(compressed)

        // L-prefixed (`L` or `K`) is the canonical mainnet-compressed WIF prefix.
        XCTAssertTrue(wif.first == "L" || wif.first == "K",
                      "expected L/K prefix, got '\(wif.prefix(1))'")
    }

    /// `L2bHRej6Fxxipvb4TiR5bu1rkT3tRp8yWEsUy4R1Zb8VMm2x7sd8` is the
    /// project test fixture. Decoding it must return the matching
    /// hex privkey.
    func testDecodesProjectTestFixture() throws {
        let wif = "L2bHRej6Fxxipvb4TiR5bu1rkT3tRp8yWEsUy4R1Zb8VMm2x7sd8"
        let (priv, compressed) = try WifPrivkey.decode(wif)
        XCTAssertEqual(priv.hex,
                       "a048f6c843f92bfe036057f7fc2bf2c27353c624cf7ad97e98ed41432f700575")
        XCTAssertTrue(compressed)
    }

    func testRoundTripUncompressed() throws {
        let priv = Data(repeating: 0x77, count: 32)
        let wif = WifPrivkey.encode(privkey: priv, compressed: false)
        XCTAssertTrue(wif.first == "5", "expected 5-prefix, got '\(wif.prefix(1))'")
        let (decoded, compressed) = try WifPrivkey.decode(wif)
        XCTAssertEqual(decoded, priv)
        XCTAssertFalse(compressed)
    }

    func testRejectsWrongVersion() {
        // A valid Base58Check string but with version byte 0x05 (P2SH)
        // not 0x80 (mainnet WIF).
        let payload = Data([0x05]) + Data(repeating: 0xAB, count: 20)
        let bogus = Base58Check.encode(payload)
        XCTAssertThrowsError(try WifPrivkey.decode(bogus)) { error in
            guard case WifPrivkey.Failure.wrongVersionByte(0x05) = error else {
                XCTFail("expected wrongVersionByte(0x05), got \(error)"); return
            }
        }
    }

    func testRejectsBadPayloadLength() {
        // Mainnet version byte but payload length 30 (not 33 or 34).
        let payload = Data([0x80]) + Data(repeating: 0, count: 29)
        let bogus = Base58Check.encode(payload)
        XCTAssertThrowsError(try WifPrivkey.decode(bogus)) { error in
            guard case WifPrivkey.Failure.wrongPayloadLength = error else {
                XCTFail("expected wrongPayloadLength, got \(error)"); return
            }
        }
    }

    func testRejectsMissingCompressedFlag() {
        // 34 bytes but the last byte before checksum is 0x02 (not 0x01).
        var payload = Data([0x80])
        payload.append(Data(repeating: 0x33, count: 32))
        payload.append(0x02)
        let bogus = Base58Check.encode(payload)
        XCTAssertThrowsError(try WifPrivkey.decode(bogus)) { error in
            guard case WifPrivkey.Failure.missingCompressedFlag = error else {
                XCTFail("expected missingCompressedFlag, got \(error)"); return
            }
        }
    }

    func testRejectsGarbage() {
        XCTAssertThrowsError(try WifPrivkey.decode("not a wif"))
        XCTAssertThrowsError(try WifPrivkey.decode(""))
    }
}
