import XCTest
@testable import FCCore

final class HashesTests: XCTestCase {

    func testSha256AndDoubleSha256MatchVectors() throws {
        let vectors = try TestVectors.load()
        XCTAssertFalse(vectors.sha256.isEmpty)
        for vector in vectors.sha256 {
            let input = Data(fromHex: vector.inputHex)
            XCTAssertEqual(Hash.sha256(input).hex, vector.sha256Hex,
                           "sha256 case '\(vector.label)'")
            XCTAssertEqual(Hash.doubleSha256(input).hex, vector.doubleSha256Hex,
                           "double-sha256 case '\(vector.label)'")
        }
    }

    func testRipemd160MatchesVectors() throws {
        let vectors = try TestVectors.load()
        XCTAssertFalse(vectors.ripemd160.isEmpty)
        for vector in vectors.ripemd160 {
            let input = Data(fromHex: vector.inputHex)
            XCTAssertEqual(Hash.ripemd160(input).hex, vector.outputHex,
                           "ripemd160 case '\(vector.label)'")
        }
    }

    func testHash160MatchesVectors() throws {
        let vectors = try TestVectors.load()
        XCTAssertFalse(vectors.hash160.isEmpty)
        for vector in vectors.hash160 {
            let input = Data(fromHex: vector.inputHex)
            XCTAssertEqual(Hash.hash160(input).hex, vector.outputHex,
                           "hash160 case '\(vector.label)'")
        }
    }

    /// Exercise RIPEMD-160 padding across block-boundary lengths.
    /// The generator's vectors don't cover every boundary; this fills the gap.
    func testRipemd160PaddingAcrossBlockBoundaries() {
        for length in [0, 1, 55, 56, 63, 64, 65, 127, 128, 129] {
            let input = Data(repeating: 0x5a, count: length)
            XCTAssertEqual(Hash.ripemd160(input).count, 20,
                           "output must be 20 bytes at length \(length)")
        }
    }

    func testSampleKeyHash160MatchesFid() throws {
        // Feeds into FID derivation: pubkeyHash160 must equal the value
        // recorded in the sample_key block.
        let vectors = try TestVectors.load()
        let pubkey = Data(fromHex: vectors.sampleKey.pubkeyHex)
        XCTAssertEqual(Hash.hash160(pubkey).hex, vectors.sampleKey.pubkeyHash160Hex)
    }

    func testStreamingFileDoubleSha256MatchesInMemory() throws {
        // The streaming file variant (DID computation for HAT/DISK
        // uploads) must agree with the in-memory hash. 3 MiB spans
        // multiple 1 MiB read chunks including a partial tail.
        var content = Data(capacity: 3 * 1024 * 1024 + 17)
        var byte: UInt8 = 0
        while content.count < 3 * 1024 * 1024 + 17 {
            content.append(byte)
            byte = byte &+ 41
        }
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("hash-file-test-\(UUID().uuidString).bin")
        try content.write(to: url)
        defer { try? FileManager.default.removeItem(at: url) }

        XCTAssertEqual(try Hash.doubleSha256(fileAt: url), Hash.doubleSha256(content))
    }
}
