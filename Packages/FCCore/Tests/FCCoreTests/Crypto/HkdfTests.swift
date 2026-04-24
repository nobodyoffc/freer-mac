import XCTest
@testable import FCCore

final class HkdfTests: XCTestCase {

    func testHkdfSha256MatchesVectors() throws {
        let vectors = try TestVectors.load()
        XCTAssertFalse(vectors.hkdfSha256.isEmpty)
        for vector in vectors.hkdfSha256 {
            let out = Hkdf.sha256(
                ikm: Data(fromHex: vector.ikmHex),
                salt: Data(fromHex: vector.saltHex),
                info: Data(fromHex: vector.infoHex),
                outputLength: vector.outputLength
            )
            XCTAssertEqual(out.hex, vector.outputHex, "hkdf-sha256 '\(vector.label)'")
        }
    }

    func testHkdfSha512MatchesVectors() throws {
        let vectors = try TestVectors.load()
        XCTAssertFalse(vectors.hkdfSha512.isEmpty)
        for vector in vectors.hkdfSha512 {
            let out = Hkdf.sha512(
                ikm: Data(fromHex: vector.ikmHex),
                salt: Data(fromHex: vector.saltHex),
                info: Data(fromHex: vector.infoHex),
                outputLength: vector.outputLength
            )
            XCTAssertEqual(out.hex, vector.outputHex, "hkdf-sha512 '\(vector.label)'")
        }
    }

    /// Sanity: different info strings must produce different outputs.
    /// This is the domain-separation property the Android X25519 path skips
    /// (see android-issues-to-fix.md entry C5).
    func testDifferentInfoProducesDifferentKey() {
        let ikm = Data(repeating: 0xaa, count: 32)
        let salt = Data(repeating: 0xbb, count: 16)
        let k1 = Hkdf.sha256(ikm: ikm, salt: salt, info: Data("context-a".utf8), outputLength: 32)
        let k2 = Hkdf.sha256(ikm: ikm, salt: salt, info: Data("context-b".utf8), outputLength: 32)
        XCTAssertNotEqual(k1, k2)
    }
}
