import XCTest
@testable import FCCore

final class Base58Tests: XCTestCase {

    func testBase58EncodeMatchesVectors() throws {
        let vectors = try TestVectors.load()
        XCTAssertFalse(vectors.base58.isEmpty)
        for vector in vectors.base58 {
            let input = Data(fromHex: vector.inputHex)
            XCTAssertEqual(Base58.encode(input), vector.encoded,
                           "encode '\(vector.label)'")
        }
    }

    func testBase58DecodeRoundTrips() throws {
        let vectors = try TestVectors.load()
        for vector in vectors.base58 {
            let decoded = try Base58.decode(vector.encoded)
            XCTAssertEqual(decoded.hex, vector.inputHex,
                           "decode '\(vector.label)'")
        }
    }

    func testBase58RejectsInvalidCharacter() {
        XCTAssertThrowsError(try Base58.decode("abc0def")) { error in
            guard case Base58.Failure.invalidCharacter = error else {
                XCTFail("expected invalidCharacter, got \(error)"); return
            }
        }
    }

    func testBase58CheckEncodeMatchesVectors() throws {
        let vectors = try TestVectors.load()
        XCTAssertFalse(vectors.base58check.isEmpty)
        for vector in vectors.base58check {
            let payload = Data(fromHex: vector.payloadHex)
            XCTAssertEqual(Base58Check.encode(payload), vector.encoded,
                           "Base58Check encode '\(vector.label)'")
        }
    }

    func testBase58CheckDecodeMatchesVectors() throws {
        let vectors = try TestVectors.load()
        for vector in vectors.base58check {
            let decoded = try Base58Check.decode(vector.encoded)
            XCTAssertEqual(decoded.hex, vector.payloadHex,
                           "Base58Check decode '\(vector.label)'")
        }
    }

    func testBase58CheckRejectsTamperedChecksum() throws {
        let vectors = try TestVectors.load()
        let good = vectors.base58check[0].encoded
        // Flip the last character (part of the checksum)
        let tampered = String(good.dropLast()) + String(good.last == "Z" ? "Y" : "Z")
        XCTAssertThrowsError(try Base58Check.decode(tampered)) { error in
            guard case Base58.Failure.invalidChecksum = error else {
                XCTFail("expected invalidChecksum, got \(error)"); return
            }
        }
    }

    /// End-to-end: the sample key's WIF must decode to
    /// `0x80 || privkey(32) || 0x01`, proving Base58Check + our sample
    /// key line up with freecashj.
    func testSampleKeyWifDecodesToExpectedPayload() throws {
        let vectors = try TestVectors.load()
        let decoded = try Base58Check.decode(vectors.sampleKey.privkeyWif)
        XCTAssertEqual(decoded.count, 34, "WIF compressed payload is 34 bytes")
        XCTAssertEqual(decoded[0], 0x80, "FCH mainnet WIF version byte")
        XCTAssertEqual(
            Data(decoded[1..<33]).hex,
            vectors.sampleKey.privkeyHex,
            "WIF bytes[1..33] should equal the raw privkey"
        )
        XCTAssertEqual(decoded[33], 0x01, "compressed flag")
    }

    /// End-to-end: the sample key's FID must decode to
    /// `version_byte || pubkey_hash160`.
    func testSampleFidDecodesToExpectedPayload() throws {
        let vectors = try TestVectors.load()
        let decoded = try Base58Check.decode(vectors.sampleKey.fid)
        XCTAssertEqual(decoded.count, 21, "legacy FID payload is 21 bytes")
        XCTAssertEqual(decoded[0], 0x23, "FCH mainnet address version byte (35 = 0x23)")
        XCTAssertEqual(
            Data(decoded[1..<21]).hex,
            vectors.sampleKey.pubkeyHash160Hex,
            "FID bytes[1..] should equal the pubkey's hash160"
        )
    }
}
