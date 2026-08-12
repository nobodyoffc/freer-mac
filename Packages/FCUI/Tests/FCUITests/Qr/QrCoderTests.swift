import XCTest
import AppKit
@testable import FCUI

final class QrCoderTests: XCTestCase {

    // MARK: - splitContent

    func testShortContentIsSingleChunk() {
        let s = "FEk41Kqjar45fLDriztUDTUkdki7mmcjWK"
        XCTAssertEqual(QrCoder.splitContent(s), [s])
    }

    func testContentExactlyAtCapacityIsSingleChunk() {
        let s = String(repeating: "a", count: QrCoder.defaultCapacity)
        XCTAssertEqual(QrCoder.splitContent(s), [s])
    }

    func testSplitRespectsCapacityAndRejoins() {
        let s = String(repeating: "x", count: 1000)
        let chunks = QrCoder.splitContent(s)
        XCTAssertEqual(chunks.count, 4) // ceil(1000 / 300)
        XCTAssertEqual(chunks.joined(), s)
        for chunk in chunks {
            XCTAssertLessThanOrEqual(chunk.utf8.count, QrCoder.defaultCapacity)
        }
    }

    func testSplitNeverBreaksMultibyteCharacters() {
        // 3-byte CJK chars + 4-byte emoji: byte boundaries never land
        // mid-character, so every chunk must round-trip through UTF-8
        // and the concatenation must be lossless.
        let s = String(repeating: "自由链测试🔑", count: 40)
        let chunks = QrCoder.splitContent(s, capacity: 100)
        XCTAssertGreaterThan(chunks.count, 1)
        XCTAssertEqual(chunks.joined(), s)
        for chunk in chunks {
            XCTAssertLessThanOrEqual(chunk.utf8.count, 100)
            XCTAssertEqual(String(decoding: Data(chunk.utf8), as: UTF8.self), chunk)
        }
    }

    func testOversizedSingleCharacterIsForceIncluded() {
        // capacity smaller than one emoji (4 bytes) must not loop or
        // drop content — each character just gets its own chunk.
        let s = "🔑🔒"
        let chunks = QrCoder.splitContent(s, capacity: 1)
        XCTAssertEqual(chunks, ["🔑", "🔒"])
    }

    // MARK: - generate ↔ decode round-trip

    func testSingleImageRoundTrip() throws {
        let content = "FEk41Kqjar45fLDriztUDTUkdki7mmcjWK"
        let images = try QrCoder.makeImages(for: content)
        XCTAssertEqual(images.count, 1)

        let decoded = try QrCoder.decode(cgImage: try cgImage(images[0]))
        XCTAssertEqual(decoded, [content])
    }

    func testLongContentRoundTripsAcrossMultipleImages() throws {
        // ~700 bytes of JSON-ish payload → 3 codes; decoding each in
        // order and concatenating must reproduce the original —
        // the merge behaviour the scan UI relies on.
        let content = "{\"op\":\"backup\",\"data\":\""
            + String(repeating: "0123456789abcdef", count: 42)
            + "\"}"
        XCTAssertGreaterThan(content.utf8.count, 2 * QrCoder.defaultCapacity)

        let images = try QrCoder.makeImages(for: content)
        XCTAssertEqual(images.count, 3)

        var merged = ""
        for image in images {
            let payloads = try QrCoder.decode(cgImage: try cgImage(image))
            XCTAssertEqual(payloads.count, 1)
            merged += payloads[0]
        }
        XCTAssertEqual(merged, content)
    }

    func testUnicodeContentRoundTrip() throws {
        let content = "收款地址：FEk41Kqjar45fLDriztUDTUkdki7mmcjWK 🔑"
        let images = try QrCoder.makeImages(for: content)
        let decoded = try QrCoder.decode(cgImage: try cgImage(images[0]))
        XCTAssertEqual(decoded, [content])
    }

    func testDecodeImageFileRoundTrip() throws {
        let content = "file-based decode check"
        let image = try QrCoder.makeImage(for: content)
        let png = try XCTUnwrap(QrCoder.pngData(image))

        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("qrcoder-test-\(UUID().uuidString).png")
        try png.write(to: url)
        defer { try? FileManager.default.removeItem(at: url) }

        XCTAssertEqual(try QrCoder.decodeImage(at: url), [content])
    }

    func testEmptyContentThrows() {
        XCTAssertThrowsError(try QrCoder.makeImages(for: ""))
    }

    // MARK: - helpers

    private func cgImage(_ image: NSImage) throws -> CGImage {
        try XCTUnwrap(image.cgImage(forProposedRect: nil, context: nil, hints: nil))
    }
}
