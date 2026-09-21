import XCTest
@testable import FCUI

final class FileOpeningTests: XCTestCase {

    private var directory: URL!

    override func setUpWithError() throws {
        directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("FileOpeningTests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: directory)
    }

    private func write(_ bytes: String, named name: String) throws -> URL {
        let url = directory.appendingPathComponent(name)
        try bytes.data(using: .utf8)!.write(to: url)
        return url
    }

    /// The case that started this: a file stored under its DID gets a
    /// named twin, so Launch Services has an extension to route on.
    func testDidNamedFileIsStagedUnderItsRealName() throws {
        let did = String(repeating: "a", count: 64)
        let source = try write("hello", named: did)

        let staged = try XCTUnwrap(FileOpening.stagedURL(for: source, named: "notes.pdf"))
        XCTAssertEqual(staged.lastPathComponent, "notes.pdf")
        XCTAssertEqual(try String(contentsOf: staged, encoding: .utf8), "hello")
    }

    /// A second open reuses the staged copy rather than writing the
    /// bytes again.
    func testStagingIsReusedWhileTheSourceIsUnchanged() throws {
        let source = try write("hello", named: String(repeating: "b", count: 64))
        let first = try XCTUnwrap(FileOpening.stagedURL(for: source, named: "notes.pdf"))

        // Mark the staged copy without changing what the reuse check
        // looks at — same byte count, same second. Finding the mark
        // still there proves the second open reused it.
        try "world".data(using: .utf8)!.write(to: first)

        let second = try XCTUnwrap(FileOpening.stagedURL(for: source, named: "notes.pdf"))
        XCTAssertEqual(first, second)
        XCTAssertEqual(try String(contentsOf: second, encoding: .utf8), "world")
    }

    /// A source whose bytes changed is staged again rather than
    /// served from the copy made before the change.
    func testStagingIsRedoneWhenTheSourceChanges() throws {
        let source = try write("hello", named: String(repeating: "d", count: 64))
        let first = try XCTUnwrap(FileOpening.stagedURL(for: source, named: "notes.pdf"))
        XCTAssertEqual(try String(contentsOf: first, encoding: .utf8), "hello")

        try "hello again".data(using: .utf8)!.write(to: source)
        let second = try XCTUnwrap(FileOpening.stagedURL(for: source, named: "notes.pdf"))
        XCTAssertEqual(try String(contentsOf: second, encoding: .utf8), "hello again")
    }

    /// A file registered by reference already sits under a name macOS
    /// can type — staging it would only make a second copy.
    func testFileThatAlreadyHasAnExtensionIsOpenedInPlace() throws {
        let source = try write("hello", named: "report.pdf")
        XCTAssertNil(FileOpening.stagedURL(for: source, named: "something-else.pdf"))
    }

    /// Without an extension to route on there is nothing to gain.
    func testNameWithoutAnExtensionDoesNotStage() throws {
        let source = try write("hello", named: String(repeating: "c", count: 64))
        XCTAssertNil(FileOpening.stagedURL(for: source, named: "notes"))
        XCTAssertNil(FileOpening.stagedURL(for: source, named: nil))
    }

    func testNamesAreMadeSafeForTheFilesystem() {
        XCTAssertEqual(FileOpening.sanitized("reports/2026: Q1.pdf"), "reports-2026- Q1.pdf")
        XCTAssertEqual(FileOpening.sanitized("  .hidden.txt "), "hidden.txt")
        XCTAssertNil(FileOpening.sanitized("   "))

        let long = String(repeating: "x", count: 300) + ".pdf"
        let trimmed = try! XCTUnwrap(FileOpening.sanitized(long))
        XCTAssertEqual(trimmed.count, 104)
        XCTAssertTrue(trimmed.hasSuffix(".pdf"))
    }
}
