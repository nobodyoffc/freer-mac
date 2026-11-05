import XCTest
@testable import FCDomain

/// ``Hat/mergeImport(_:_:)``. Same cases as FC-AJDK `HatMergeImportTest`.
final class HatMergeImportTests: XCTestCase {

    static let id = String(repeating: "5d", count: 32)

    func testHeldFieldsWinAndListsUnion() {
        let held = Hat(size: 10, last: 100, name: "my.pdf", key: "k", leaked: false,
                       cipherIds: ["c1"], locas: ["local:///mine", "(sid)a"], id: Self.id)
        let incoming = Hat(size: 10, last: 200, name: "other.pdf", desc: "d", types: ["application/pdf"],
                           pids: ["p"], key: "k2", leaked: true, cipherIds: ["c2", "c1"],
                           locas: ["local:///theirs", "(sid)b", "(sid)a"], id: Self.id)
        let m = Hat.mergeImport(held, incoming)
        XCTAssertEqual(m.name, "my.pdf")
        XCTAssertEqual(m.key, "k")
        XCTAssertEqual(m.cipherIds, ["c1", "c2"])
        XCTAssertEqual(m.locas, ["local:///mine", "(sid)a", "(sid)b"])
        XCTAssertEqual(m.desc, "d")
        XCTAssertEqual(m.types, ["application/pdf"])
        XCTAssertEqual(m.pids, ["p"])
        XCTAssertEqual(m.leaked, true)
        XCTAssertEqual(m.last, 200)
        XCTAssertEqual(m.size, 10)
    }

    func testAnImportFillsWhatIsMissingAndReplacesAPlaceholderName() {
        let held = Hat(name: String(Self.id.prefix(8)), id: Self.id)
        let incoming = Hat(name: "Report.pdf", key: "k", cipherIds: ["c"], id: Self.id)
        let m = Hat.mergeImport(held, incoming)
        XCTAssertEqual(m.name, "Report.pdf")
        XCTAssertEqual(m.key, "k")
        XCTAssertEqual(m.cipherIds, ["c"])
    }

    func testANewRecordLosesOnlyItsForeignLocalPaths() {
        let incoming = Hat(name: "x", locas: ["local:///theirs", "(sid)a"], id: Self.id)
        XCTAssertEqual(Hat.mergeImport(nil, incoming).locas, ["(sid)a"])
        XCTAssertNil(Hat.mergeImport(nil, Hat(locas: ["local:///only"], id: Self.id)).locas)
    }

    /// Through the store, as the import sheet does it: the held local
    /// sidecar survives and so does the path to the user's own file.
    func testImportingOverAHeldFileKeepsItsBackupLinks() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("HatMergeImport-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let mgr = try ConfigureManager(baseDirectory: dir.appendingPathComponent("vault"))
        let configure = try mgr.createConfigure(password: Data("pwd".utf8), kdfKind: .legacySha256)
        let info = try configure.addMain(privkey: Data(repeating: 0xB4, count: 32), label: "P")
        let session = try configure.unlockMain(fid: info.fid, fapi: FakeDiskServer())

        let file = dir.appendingPathComponent("mine.txt")
        try Data("my file".utf8).write(to: file)
        var held = try session.files.registerFile(at: file)
        held.cipherIds = ["c1"]
        _ = try session.hats.upsert(held)

        var exported = held
        exported.name = "renamed elsewhere.txt"
        exported.cipherIds = nil
        exported.locas = ["local:///Users/someone/else.txt", "(sid)b"]
        let current = try session.hats.hat(id: held.id!)
        _ = try session.hats.upsert(Hat.mergeImport(current, exported), touch: false)

        let after = try XCTUnwrap(try session.hats.hat(id: held.id!))
        XCTAssertEqual(after.name, "mine.txt")
        XCTAssertEqual(after.cipherIds, ["c1"])
        XCTAssertFalse(after.locas?.contains("local:///Users/someone/else.txt") ?? true)
        XCTAssertTrue(after.locas?.contains("(sid)b") ?? false)
        guard case .available = try session.files.resolve(hatId: held.id!) else {
            return XCTFail("the user's own file is still found")
        }
    }
}
