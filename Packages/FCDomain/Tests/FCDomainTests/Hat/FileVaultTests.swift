import XCTest
import FCCore
import FCTransport
@testable import FCDomain

/// Tests for the reference-not-copy file layer.
///
/// The interesting cases are all failure modes that copying would have
/// prevented: the original moves, is deleted, or is edited in place.
/// Each must either heal the record or refuse to serve bytes under a
/// DID they no longer match — never silently hand back wrong content.
final class FileVaultTests: XCTestCase {

    private var baseDir: URL!
    private var workDir: URL!

    override func setUpWithError() throws {
        baseDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("FileVaultTests-\(UUID().uuidString)")
        workDir = baseDir.appendingPathComponent("user-files")
        try FileManager.default.createDirectory(at: workDir, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        if let baseDir { try? FileManager.default.removeItem(at: baseDir) }
    }

    private func makeSession() throws -> ActiveSession {
        let mgr = try ConfigureManager(baseDirectory: baseDir.appendingPathComponent("vault"))
        let configure = try mgr.createConfigure(password: Data("pwd".utf8), kdfKind: .legacySha256)
        let info = try configure.addMain(privkey: Data(repeating: 0xA1, count: 32), label: "A")
        return try configure.unlockMain(fid: info.fid, fapi: MockFapiClient())
    }

    @discardableResult
    private func writeFile(_ name: String, _ contents: String) throws -> URL {
        let url = workDir.appendingPathComponent(name)
        try Data(contents.utf8).write(to: url)
        return url
    }

    private func did(of contents: String) -> String {
        Hash.doubleSha256(Data(contents.utf8)).map { String(format: "%02x", $0) }.joined()
    }

    // MARK: - registration

    func testRegisterReferencesOriginalWithoutCopying() throws {
        let session = try makeSession()
        let file = try writeFile("notes.txt", "hello vault")

        let hat = try session.files.registerFile(at: file)

        XCTAssertEqual(hat.id, did(of: "hello vault"), "id is the content DID")
        XCTAssertEqual(hat.name, "notes.txt")
        XCTAssertEqual(hat.size, Int64("hello vault".utf8.count))
        XCTAssertEqual(hat.locas, ["local://" + file.path])
        XCTAssertEqual(hat.types, ["text/plain"])

        // Nothing was copied into app storage.
        let appCopy = session.files.defaultLocalURL(did: hat.id!)
        XCTAssertFalse(FileManager.default.fileExists(atPath: appCopy.path),
                       "registration must not copy the file")

        // A stamp was recorded so later reads are one stat.
        let record = try XCTUnwrap(session.hats.record(id: hat.id!))
        let stamp = try XCTUnwrap(record.local.stamps[file.path])
        XCTAssertEqual(stamp.size, Int64("hello vault".utf8.count))
        XCTAssertFalse(record.local.appManagedCopy)
    }

    func testRegisteringSameContentTwiceAddsLocationRatherThanDuplicating() throws {
        let session = try makeSession()
        let a = try writeFile("a.txt", "same bytes")
        let b = try writeFile("b.txt", "same bytes")

        let first = try session.files.registerFile(at: a)
        let second = try session.files.registerFile(at: b)

        XCTAssertEqual(first.id, second.id, "identical content is one DID")
        XCTAssertEqual(try session.hats.count(), 1)
        XCTAssertEqual(second.locas, ["local://" + a.path, "local://" + b.path])
    }

    func testRegisterRejectsDirectoryAndMissingFile() throws {
        let session = try makeSession()
        XCTAssertThrowsError(try session.files.registerFile(at: workDir))
        XCTAssertThrowsError(
            try session.files.registerFile(at: workDir.appendingPathComponent("nope.txt")))
    }

    // MARK: - resolution and self-healing

    func testResolveUsesStampWithoutRehashing() throws {
        let session = try makeSession()
        let file = try writeFile("stable.txt", "unchanged")
        let hat = try session.files.registerFile(at: file)

        guard case .available(let url) = try session.files.resolve(hatId: hat.id!) else {
            return XCTFail("expected the file to resolve")
        }
        XCTAssertEqual(url.path, file.path)
    }

    func testDeletedOriginalIsPrunedAndReportedUnavailable() throws {
        let session = try makeSession()
        let file = try writeFile("gone.txt", "will vanish")
        let hat = try session.files.registerFile(at: file)
        try FileManager.default.removeItem(at: file)

        XCTAssertEqual(try session.files.resolve(hatId: hat.id!), .unavailable)

        // The dead claim is gone from both halves of the record.
        let record = try XCTUnwrap(session.hats.record(id: hat.id!))
        XCTAssertEqual(record.wire.localPaths, [])
        XCTAssertTrue(record.local.stamps.isEmpty)
        // The HAT itself survives — it may still be downloadable.
        XCTAssertNotNil(try session.hats.hat(id: hat.id!))
    }

    func testMovedOriginalIsPrunedThenRediscoveredOnReregister() throws {
        let session = try makeSession()
        let file = try writeFile("movable.txt", "portable bytes")
        let hat = try session.files.registerFile(at: file)

        let moved = workDir.appendingPathComponent("moved.txt")
        try FileManager.default.moveItem(at: file, to: moved)
        XCTAssertEqual(try session.files.resolve(hatId: hat.id!), .unavailable)

        // Re-registering at the new path reattaches to the same HAT.
        let again = try session.files.registerFile(at: moved)
        XCTAssertEqual(again.id, hat.id)
        guard case .available(let url) = try session.files.resolve(hatId: hat.id!) else {
            return XCTFail("expected the moved file to resolve")
        }
        XCTAssertEqual(url.path, moved.path)
    }

    /// The case copying was really protecting against: the user edits
    /// the file in place, so its content no longer matches the DID.
    func testEditedInPlaceFileIsDetachedAndReportsNewDid() throws {
        let session = try makeSession()
        let file = try writeFile("draft.txt", "version one")
        let hat = try session.files.registerFile(at: file)

        // Rewrite with different content (and a distinct mtime).
        Thread.sleep(forTimeInterval: 0.01)
        try Data("version two".utf8).write(to: file)

        guard case .modified(let url, let newDid) = try session.files.resolve(hatId: hat.id!) else {
            return XCTFail("expected the edit to be detected")
        }
        XCTAssertEqual(url.path, file.path)
        XCTAssertEqual(newDid, did(of: "version two"))
        XCTAssertNotEqual(newDid, hat.id)

        // The stale reference is detached, so nothing serves the wrong
        // bytes under the old DID.
        let record = try XCTUnwrap(session.hats.record(id: hat.id!))
        XCTAssertEqual(record.wire.localPaths, [])
        XCTAssertNil(record.local.stamps[file.path])
        XCTAssertNil(try session.files.localURL(hatId: hat.id!))

        // And the new content can be registered as its own HAT, which
        // is what a "save as new version" flow would do.
        let v2 = try session.files.registerFile(at: file)
        XCTAssertEqual(v2.id, newDid)
    }

    /// Rewriting identical bytes changes mtime but not content. The
    /// re-hash must conclude the file is still fine and re-stamp it,
    /// rather than detaching a perfectly good reference.
    func testTouchedButUnchangedFileStaysAttached() throws {
        let session = try makeSession()
        let file = try writeFile("touched.txt", "same content")
        let hat = try session.files.registerFile(at: file)
        let originalStamp = try XCTUnwrap(session.hats.record(id: hat.id!)).local.stamps[file.path]

        Thread.sleep(forTimeInterval: 0.01)
        try Data("same content".utf8).write(to: file)   // new mtime, same bytes

        guard case .available(let url) = try session.files.resolve(hatId: hat.id!) else {
            return XCTFail("an unchanged file must stay attached")
        }
        XCTAssertEqual(url.path, file.path)

        let refreshed = try XCTUnwrap(session.hats.record(id: hat.id!)).local.stamps[file.path]
        XCTAssertNotEqual(refreshed?.modifiedAtMs, originalStamp?.modifiedAtMs,
                          "the stamp should be refreshed to the new mtime")
    }

    /// A HAT received over IM carries the *sender's* paths. Those must
    /// never serve local bytes unless the content genuinely matches.
    func testForeignLocalPathIsIgnoredWhenContentDoesNotMatch() throws {
        let session = try makeSession()
        // A file that exists here but holds unrelated content.
        let impostor = try writeFile("impostor.txt", "not the shared file")

        var incoming = Hat(name: "shared.pdf", id: did(of: "the real shared bytes"))
        incoming.locas = ["local://" + impostor.path]
        try session.hats.upsert(incoming)

        XCTAssertEqual(try session.files.resolve(hatId: incoming.id!), .unavailable,
                       "a path whose content doesn't hash to the DID must not be served")
        XCTAssertEqual(try session.hats.hat(id: incoming.id!)?.localPaths, [],
                       "and the bogus claim should be dropped")
        XCTAssertTrue(FileManager.default.fileExists(atPath: impostor.path),
                      "someone else's HAT must never cause a local file to be touched")
    }

    /// If the foreign path happens to hold exactly the right bytes,
    /// using it is correct — content, not provenance, is the authority.
    func testForeignLocalPathIsAdoptedWhenContentMatches() throws {
        let session = try makeSession()
        let file = try writeFile("already-have-it.bin", "identical payload")

        var incoming = Hat(name: "payload.bin", id: did(of: "identical payload"))
        incoming.locas = ["local://" + file.path]
        try session.hats.upsert(incoming)

        guard case .available(let url) = try session.files.resolve(hatId: incoming.id!) else {
            return XCTFail("matching content should resolve")
        }
        XCTAssertEqual(url.path, file.path)
        // A stamp is now recorded, so the next read is a stat.
        let record = try XCTUnwrap(session.hats.record(id: incoming.id!))
        XCTAssertNotNil(record.local.stamps[file.path])
    }

    /// An app copy at data/<did> is found even when no loca lists it —
    /// the fallback Android relies on after a download.
    func testUnlistedAppCopyIsDiscovered() throws {
        let session = try makeSession()
        let contents = "downloaded bytes"
        let hatId = did(of: contents)
        try session.hats.upsert(Hat(name: "dl.bin", id: hatId))

        try FileManager.default.createDirectory(
            at: session.dataDirectory, withIntermediateDirectories: true)
        let appCopy = session.files.defaultLocalURL(did: hatId)
        try Data(contents.utf8).write(to: appCopy)

        guard case .available(let url) = try session.files.resolve(hatId: hatId) else {
            return XCTFail("the app copy should be discovered")
        }
        XCTAssertEqual(url.path, appCopy.path)
        // And recorded, so it shows as local from now on.
        XCTAssertEqual(try session.hats.hat(id: hatId)?.localPaths, [appCopy.path])
    }

    // MARK: - materialize

    func testMaterializeCopiesIntoAppStorage() throws {
        let session = try makeSession()
        let file = try writeFile("pin-me.txt", "keep a copy")
        let hat = try session.files.registerFile(at: file)

        let copy = try session.files.materialize(hatId: hat.id!)
        XCTAssertEqual(copy.path, session.files.defaultLocalURL(did: hat.id!).path)
        XCTAssertEqual(try Data(contentsOf: copy), Data("keep a copy".utf8))

        let record = try XCTUnwrap(session.hats.record(id: hat.id!))
        XCTAssertTrue(record.local.appManagedCopy)
        XCTAssertTrue(record.wire.localPaths.contains(copy.path))

        // The copy survives losing the original.
        try FileManager.default.removeItem(at: file)
        guard case .available(let url) = try session.files.resolve(hatId: hat.id!) else {
            return XCTFail("the app copy should still resolve")
        }
        XCTAssertEqual(url.path, copy.path)
    }

    func testMaterializeIsIdempotent() throws {
        let session = try makeSession()
        let file = try writeFile("once.txt", "copy once")
        let hat = try session.files.registerFile(at: file)

        let first = try session.files.materialize(hatId: hat.id!)
        let second = try session.files.materialize(hatId: hat.id!)
        XCTAssertEqual(first.path, second.path)
    }

    func testMaterializeFailsWithoutLocalBytes() throws {
        let session = try makeSession()
        try session.hats.upsert(Hat(name: "remote-only.bin", id: did(of: "never here")))
        XCTAssertThrowsError(try session.files.materialize(hatId: did(of: "never here")))
    }

    // MARK: - deletion safety

    /// The load-bearing guarantee of reference mode: deleting a HAT
    /// must never delete a file the user owns.
    func testDeleteNeverTouchesReferencedOriginal() throws {
        let session = try makeSession()
        let file = try writeFile("precious.txt", "user's own file")
        let hat = try session.files.registerFile(at: file)

        XCTAssertTrue(try session.files.delete(hatId: hat.id!))
        XCTAssertNil(try session.hats.hat(id: hat.id!))
        XCTAssertTrue(FileManager.default.fileExists(atPath: file.path),
                      "the user's original must survive deleting the HAT")
        XCTAssertEqual(try Data(contentsOf: file), Data("user's own file".utf8))
    }

    func testDeleteRemovesAppManagedCopyOnly() throws {
        let session = try makeSession()
        let file = try writeFile("both.txt", "in two places")
        let hat = try session.files.registerFile(at: file)
        let copy = try session.files.materialize(hatId: hat.id!)

        XCTAssertTrue(try session.files.delete(hatId: hat.id!))
        XCTAssertFalse(FileManager.default.fileExists(atPath: copy.path),
                       "the app-managed copy goes with the HAT")
        XCTAssertTrue(FileManager.default.fileExists(atPath: file.path),
                      "the referenced original does not")
    }

    func testRemoveLocalDataKeepsHatAndOriginal() throws {
        let session = try makeSession()
        let file = try writeFile("keep-hat.txt", "still tracked")
        let hat = try session.files.registerFile(at: file)
        let copy = try session.files.materialize(hatId: hat.id!)

        let after = try XCTUnwrap(session.files.removeLocalData(hatId: hat.id!))
        XCTAssertEqual(after.localPaths, [])
        XCTAssertNotNil(try session.hats.hat(id: hat.id!), "the HAT record stays")
        XCTAssertFalse(FileManager.default.fileExists(atPath: copy.path))
        XCTAssertTrue(FileManager.default.fileExists(atPath: file.path))
    }

    /// Even if a sidecar wrongly claims a user file is app-managed,
    /// paths outside the data directory are never deleted.
    func testAppManagedFlagCannotCauseDeletionOutsideDataDirectory() throws {
        let session = try makeSession()
        let file = try writeFile("mislabelled.txt", "still the user's")
        let hat = try session.files.registerFile(at: file)

        var record = try XCTUnwrap(session.hats.record(id: hat.id!))
        record.local.appManagedCopy = true          // wrong, on purpose
        try session.hats.upsert(record.wire, local: record.local)

        XCTAssertTrue(try session.files.delete(hatId: hat.id!))
        XCTAssertTrue(FileManager.default.fileExists(atPath: file.path),
                      "location, not a flag, decides what may be deleted")
    }

    // MARK: - isolation

    func testDataDirectoriesAreDistinctPerMain() throws {
        let mgr = try ConfigureManager(baseDirectory: baseDir.appendingPathComponent("multi"))
        let configure = try mgr.createConfigure(password: Data("pwd".utf8), kdfKind: .legacySha256)
        let a = try configure.addMain(privkey: Data(repeating: 0xA1, count: 32), label: "A")
        let b = try configure.addMain(privkey: Data(repeating: 0xB2, count: 32), label: "B")
        let sessionA = try configure.unlockMain(fid: a.fid, fapi: MockFapiClient())
        let sessionB = try configure.unlockMain(fid: b.fid, fapi: MockFapiClient())

        XCTAssertNotEqual(sessionA.dataDirectory.path, sessionB.dataDirectory.path)
        XCTAssertTrue(sessionA.dataDirectory.path.contains(a.fid))
        XCTAssertTrue(sessionB.dataDirectory.path.contains(b.fid))
    }
}
