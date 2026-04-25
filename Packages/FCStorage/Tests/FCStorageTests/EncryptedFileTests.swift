import XCTest
@testable import FCStorage

final class EncryptedFileTests: XCTestCase {

    private struct Sample: Codable, Equatable {
        let label: String
        let count: Int
        let nested: [String: Int]
    }

    private var dir: URL!
    private var key: Data!

    override func setUpWithError() throws {
        dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("EncryptedFileTests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        key = Data(repeating: 0xA5, count: 32)
    }

    override func tearDownWithError() throws {
        if let dir { try? FileManager.default.removeItem(at: dir) }
    }

    private func url(_ name: String = "blob.bin") -> URL {
        dir.appendingPathComponent(name)
    }

    func testRoundTrip() throws {
        let url = self.url()
        let value = Sample(label: "alice", count: 42, nested: ["a": 1, "b": 2])
        try EncryptedFile.write(value, to: url, key: key)
        let restored = try EncryptedFile.read(Sample.self, from: url, key: key)
        XCTAssertEqual(restored, value)
    }

    func testReadMissingFileReturnsNil() throws {
        let restored = try EncryptedFile.read(Sample.self, from: url("does-not-exist"), key: key)
        XCTAssertNil(restored)
    }

    func testWrongKeyFailsDecryption() throws {
        let url = self.url()
        try EncryptedFile.write(Sample(label: "x", count: 1, nested: [:]), to: url, key: key)
        let wrongKey = Data(repeating: 0x77, count: 32)
        XCTAssertThrowsError(try EncryptedFile.read(Sample.self, from: url, key: wrongKey)) { error in
            guard case EncryptedFile.Failure.decryption = error else {
                XCTFail("expected decryption failure, got \(error)"); return
            }
        }
    }

    func testAadBindsToFilename() throws {
        // Default AAD = file's lastPathComponent. Reading the file from
        // a renamed location should fail decryption because the AAD
        // re-derived at read time differs from the one used at write.
        let writeUrl = url("a.bin")
        let renamedUrl = url("b.bin")
        try EncryptedFile.write(Sample(label: "x", count: 1, nested: [:]), to: writeUrl, key: key)
        try FileManager.default.moveItem(at: writeUrl, to: renamedUrl)

        XCTAssertThrowsError(try EncryptedFile.read(Sample.self, from: renamedUrl, key: key)) { error in
            guard case EncryptedFile.Failure.decryption = error else {
                XCTFail("expected decryption failure on AAD mismatch, got \(error)"); return
            }
        }

        // But explicitly passing the original AAD makes it succeed —
        // useful for callers who want to relocate files intentionally.
        let restored = try EncryptedFile.read(
            Sample.self, from: renamedUrl, key: key,
            aad: Data("a.bin".utf8)
        )
        XCTAssertEqual(restored?.label, "x")
    }

    func testRejectsWrongKeyLength() {
        let url = self.url()
        XCTAssertThrowsError(try EncryptedFile.write(
            Sample(label: "x", count: 1, nested: [:]),
            to: url,
            key: Data(repeating: 0, count: 16)
        )) { error in
            guard case EncryptedFile.Failure.wrongKeyLength(16) = error else {
                XCTFail("wrong error: \(error)"); return
            }
        }
    }

    func testTamperedCiphertextFailsTagCheck() throws {
        let url = self.url()
        try EncryptedFile.write(Sample(label: "y", count: 7, nested: [:]), to: url, key: key)
        var blob = try Data(contentsOf: url)
        // Flip a bit somewhere in the middle (after nonce, before tag).
        let target = 12 + max(0, blob.count - 12 - 16) / 2
        blob[target] ^= 0x01
        try blob.write(to: url)
        XCTAssertThrowsError(try EncryptedFile.read(Sample.self, from: url, key: key)) { error in
            guard case EncryptedFile.Failure.decryption = error else {
                XCTFail("expected decryption failure, got \(error)"); return
            }
        }
    }
}
