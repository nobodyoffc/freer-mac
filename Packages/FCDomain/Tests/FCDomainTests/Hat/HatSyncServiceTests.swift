import XCTest
import FCCore
import FCTransport
@testable import FCDomain

/// End-to-end tests for the two-HAT DISK flows against an in-process
/// content-addressed server.
///
/// The happy paths matter, but the ones that earn their keep are the
/// misbehaving-server cases: DISK is untrusted, and every fetch is
/// hashed before it is believed.
final class HatSyncServiceTests: XCTestCase {

    private var baseDir: URL!
    private var workDir: URL!
    private var server: FakeDiskServer!

    override func setUpWithError() throws {
        baseDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("HatSyncTests-\(UUID().uuidString)")
        workDir = baseDir.appendingPathComponent("user-files")
        try FileManager.default.createDirectory(at: workDir, withIntermediateDirectories: true)
        server = FakeDiskServer()
    }

    override func tearDownWithError() throws {
        if let baseDir { try? FileManager.default.removeItem(at: baseDir) }
    }

    // MARK: - fixtures

    private struct Fixture {
        let session: ActiveSession
        let sync: HatSyncService
        let pubkey: Data
        let privkey: Data
    }

    private func makeFixture(privkeyByte: UInt8 = 0xA1) throws -> Fixture {
        let mgr = try ConfigureManager(baseDirectory: baseDir.appendingPathComponent("vault-\(privkeyByte)"))
        let configure = try mgr.createConfigure(password: Data("pwd".utf8), kdfKind: .legacySha256)
        let privkey = Data(repeating: privkeyByte, count: 32)
        let info = try configure.addMain(privkey: privkey, label: "A")
        let session = try configure.unlockMain(fid: info.fid, fapi: server)
        let sync = HatSyncService(
            disk: DiskService(fapi: server),
            hats: session.hats,
            files: session.files,
            serviceSid: "disk-svc-1"
        )
        return Fixture(
            session: session,
            sync: sync,
            pubkey: try Secp256k1.publicKey(fromPrivateKey: privkey),
            privkey: privkey
        )
    }

    @discardableResult
    private func writeFile(_ name: String, _ contents: String) throws -> URL {
        let url = workDir.appendingPathComponent(name)
        try Data(contents.utf8).write(to: url)
        return url
    }

    // MARK: - upload

    func testUploadCreatesCipherHatAndLinksIt() async throws {
        let fx = try makeFixture()
        let file = try writeFile("report.txt", "quarterly numbers")
        let raw = try fx.session.files.registerFile(at: file)

        let result = try await fx.sync.upload(hatId: raw.id!, ownPubkey: fx.pubkey)

        // The cipher HAT describes the encrypted copy, not the plaintext.
        XCTAssertTrue(result.cipherHat.isCipherHat)
        XCTAssertEqual(result.cipherHat.rawDid, raw.id)
        XCTAssertNotEqual(result.cipherHat.id, raw.id)
        XCTAssertEqual(result.cipherHat.locas, ["(sid)disk-svc-1"])
        XCTAssertNotNil(result.cipherHat.kCipher)

        // The raw HAT points at it.
        XCTAssertEqual(result.rawHat.cipherIds, [try XCTUnwrap(result.cipherHat.id)])

        // What landed on the server is the cipher file, stored under
        // its own DID — the plaintext never leaves.
        XCTAssertEqual(server.storedDids, [try XCTUnwrap(result.cipherHat.id)])
        let stored = try XCTUnwrap(server.blob(did: result.cipherHat.id!))
        XCTAssertFalse(stored.contains(Data("quarterly numbers".utf8)),
                       "plaintext must not appear on the server")
        XCTAssertEqual(server.putCount, 1)
        XCTAssertEqual(server.carveCount, 0)
    }

    func testCarveUsesPermanentEndpoint() async throws {
        let fx = try makeFixture()
        let file = try writeFile("forever.txt", "permanent record")
        let raw = try fx.session.files.registerFile(at: file)

        try await fx.sync.upload(hatId: raw.id!, permanent: true, ownPubkey: fx.pubkey)
        XCTAssertEqual(server.carveCount, 1)
        XCTAssertEqual(server.putCount, 0)
    }

    func testEachUploadUsesAFreshKey() async throws {
        let fx = try makeFixture()
        let file = try writeFile("twice.txt", "same bytes both times")
        let raw = try fx.session.files.registerFile(at: file)

        let first = try await fx.sync.upload(hatId: raw.id!, ownPubkey: fx.pubkey)
        let second = try await fx.sync.upload(hatId: raw.id!, ownPubkey: fx.pubkey)

        XCTAssertNotEqual(first.symkey, second.symkey)
        XCTAssertNotEqual(first.cipherHat.id, second.cipherHat.id,
                          "a fresh key means a different cipher DID for identical plaintext")
        // Both are linked, so either can serve a download.
        let rawAfter = try XCTUnwrap(fx.session.hats.hat(id: raw.id!))
        XCTAssertEqual(rawAfter.cipherIds?.count, 2)
    }

    func testUploadRejectsHatWithoutLocalBytes() async throws {
        let fx = try makeFixture()
        try fx.session.hats.upsert(Hat(name: "ghost.bin", id: String(repeating: "a", count: 64)))
        do {
            try await fx.sync.upload(hatId: String(repeating: "a", count: 64), ownPubkey: fx.pubkey)
            XCTFail("expected a noLocalBytes failure")
        } catch HatSyncService.Failure.noLocalBytes {
            // expected
        }
    }

    func testUploadRawStoresPlaintextAndTagsLocation() async throws {
        let fx = try makeFixture()
        let file = try writeFile("public.txt", "world readable")
        let raw = try fx.session.files.registerFile(at: file)

        try await fx.sync.uploadRaw(hatId: raw.id!)

        // Stored under the RAW did — it is the content itself.
        XCTAssertEqual(server.storedDids, [raw.id!])
        XCTAssertEqual(server.blob(did: raw.id!), Data("world readable".utf8))
        let after = try XCTUnwrap(fx.session.hats.hat(id: raw.id!))
        XCTAssertTrue(after.remoteLocas.contains("(sid)disk-svc-1"))
        XCTAssertNil(after.cipherIds, "an unencrypted upload has no cipher HAT")
    }

    // MARK: - download, kCipher path (the owner's own data)

    func testDownloadViaKCipherRoundTrip() async throws {
        let fx = try makeFixture()
        let contents = "the original bytes, exactly"
        let file = try writeFile("round.txt", contents)
        let raw = try fx.session.files.registerFile(at: file)
        try await fx.sync.upload(hatId: raw.id!, ownPubkey: fx.pubkey)

        // Lose every local copy, so the fetch must come from DISK.
        try fx.session.files.removeLocalData(hatId: raw.id!)
        try FileManager.default.removeItem(at: file)
        XCTAssertNil(try fx.session.files.localURL(hatId: raw.id!))

        let url = try await fx.sync.download(hatId: raw.id!, privkey: fx.privkey)
        XCTAssertEqual(try Data(contentsOf: url), Data(contents.utf8))

        // And it is registered as an app copy, so it resolves locally now.
        XCTAssertEqual(try fx.session.files.localURL(hatId: raw.id!)?.path, url.path)
    }

    func testDownloadWithoutPrivkeyOrKeyFails() async throws {
        let fx = try makeFixture()
        let file = try writeFile("locked.txt", "needs a key")
        let raw = try fx.session.files.registerFile(at: file)
        try await fx.sync.upload(hatId: raw.id!, ownPubkey: fx.pubkey)
        try fx.session.files.removeLocalData(hatId: raw.id!)
        try FileManager.default.removeItem(at: file)

        do {
            try await fx.sync.download(hatId: raw.id!, privkey: nil)
            XCTFail("expected the download to fail without any key")
        } catch let HatSyncService.Failure.downloadFailed(_, diagnostics) {
            XCTAssertFalse(diagnostics.isEmpty, "the failure must say what was tried")
        }
    }

    func testWrongPrivkeyCannotDecrypt() async throws {
        let fx = try makeFixture()
        let file = try writeFile("mine.txt", "only mine")
        let raw = try fx.session.files.registerFile(at: file)
        try await fx.sync.upload(hatId: raw.id!, ownPubkey: fx.pubkey)
        try fx.session.files.removeLocalData(hatId: raw.id!)
        try FileManager.default.removeItem(at: file)

        let stranger = Data(repeating: 0xC3, count: 32)
        do {
            try await fx.sync.download(hatId: raw.id!, privkey: stranger)
            XCTFail("a stranger's key must not decrypt the file")
        } catch let HatSyncService.Failure.downloadFailed(_, diagnostics) {
            XCTAssertTrue(diagnostics.contains("kCipher"), "diagnostics: \(diagnostics)")
        }
    }

    // MARK: - download, plain-key path (the IM recipient)

    /// The path a recipient takes: they hold the sender's HAT JSON with
    /// a plaintext key and DISK locations, but no cipher HAT of their
    /// own and none of the sender's keys.
    func testRecipientDownloadsWithPlainKeyOnly() async throws {
        let sender = try makeFixture(privkeyByte: 0xA1)
        let contents = "shared over IM"
        let file = try writeFile("shared.txt", contents)
        let raw = try sender.session.files.registerFile(at: file)
        let upload = try await sender.sync.upload(hatId: raw.id!, ownPubkey: sender.pubkey)

        // What the sender puts in the message body.
        let messageHat = try sender.sync.shareableHat(from: upload)
        XCTAssertNotNil(messageHat.key)
        XCTAssertTrue(messageHat.remoteLocas.contains("(sid)disk-svc-1"))

        // A different identity, sharing only the DISK server.
        let recipient = try makeFixture(privkeyByte: 0xB2)
        let received = try Hat.fromJson(messageHat.wireJson())
        try recipient.session.hats.upsert(received)
        XCTAssertNil(try recipient.session.hats.hat(id: upload.cipherHat.id!),
                     "the recipient has no cipher HAT")

        let url = try await recipient.sync.download(hatId: raw.id!, privkey: recipient.privkey)
        XCTAssertEqual(try Data(contentsOf: url), Data(contents.utf8))
    }

    func testPlainKeyPathIsTriedBeforeKCipher() async throws {
        let fx = try makeFixture()
        let file = try writeFile("both-paths.txt", "either way works")
        let raw = try fx.session.files.registerFile(at: file)
        let upload = try await fx.sync.upload(hatId: raw.id!, ownPubkey: fx.pubkey)

        // Attach the plaintext key to the local record, then remove the
        // private key from the equation entirely.
        var withKey = try XCTUnwrap(fx.session.hats.hat(id: raw.id!))
        withKey.key = upload.symkey.map { String(format: "%02x", $0) }.joined()
        try fx.session.hats.upsert(withKey)
        try fx.session.files.removeLocalData(hatId: raw.id!)
        try FileManager.default.removeItem(at: file)

        let url = try await fx.sync.download(hatId: raw.id!, privkey: nil)
        XCTAssertEqual(try Data(contentsOf: url), Data("either way works".utf8))
    }

    // MARK: - direct (unencrypted) path

    func testDirectDownloadOfUnencryptedData() async throws {
        let fx = try makeFixture()
        let contents = "a public consensus document"
        let file = try writeFile("consensus.txt", contents)
        let raw = try fx.session.files.registerFile(at: file)
        try await fx.sync.uploadRaw(hatId: raw.id!)

        try fx.session.files.removeLocalData(hatId: raw.id!)
        try FileManager.default.removeItem(at: file)

        let url = try await fx.sync.download(hatId: raw.id!)
        XCTAssertEqual(try Data(contentsOf: url), Data(contents.utf8))
    }

    // MARK: - the server is not trusted

    /// A public DISK server can return anything. Content that doesn't
    /// hash to the DID we asked for must never reach the output file.
    func testCorruptedDirectDownloadIsRejected() async throws {
        let fx = try makeFixture()
        let file = try writeFile("tamper.txt", "authentic content")
        let raw = try fx.session.files.registerFile(at: file)
        try await fx.sync.uploadRaw(hatId: raw.id!)
        try fx.session.files.removeLocalData(hatId: raw.id!)
        try FileManager.default.removeItem(at: file)

        server.corruptOnGet = true
        do {
            try await fx.sync.download(hatId: raw.id!)
            XCTFail("corrupted content must be rejected")
        } catch let HatSyncService.Failure.downloadFailed(_, diagnostics) {
            XCTAssertTrue(diagnostics.contains("direct"), "diagnostics: \(diagnostics)")
        }
        XCTAssertFalse(
            FileManager.default.fileExists(atPath: fx.session.files.defaultLocalURL(did: raw.id!).path),
            "no output file may survive a failed verification")
    }

    /// Swapping in a *different but internally valid* cipher file is the
    /// subtler attack: it decrypts to nothing useful, and the plaintext
    /// check is what catches it.
    func testSubstitutedCipherFileIsRejected() async throws {
        let fx = try makeFixture()
        let file = try writeFile("victim.txt", "the real payload")
        let raw = try fx.session.files.registerFile(at: file)
        try await fx.sync.upload(hatId: raw.id!, ownPubkey: fx.pubkey)
        try fx.session.files.removeLocalData(hatId: raw.id!)
        try FileManager.default.removeItem(at: file)

        // Another legitimately-encrypted file, uploaded by anyone.
        let decoy = try writeFile("decoy.txt", "unrelated bytes")
        let decoyHat = try fx.session.files.registerFile(at: decoy)
        let decoyUpload = try await fx.sync.upload(hatId: decoyHat.id!, ownPubkey: fx.pubkey)
        server.substituteOnGet = server.blob(did: decoyUpload.cipherHat.id!)

        do {
            try await fx.sync.download(hatId: raw.id!, privkey: fx.privkey)
            XCTFail("a substituted cipher file must be rejected")
        } catch let HatSyncService.Failure.downloadFailed(_, diagnostics) {
            XCTAssertTrue(diagnostics.contains("kCipher"), "diagnostics: \(diagnostics)")
        }
        XCTAssertFalse(
            FileManager.default.fileExists(atPath: fx.session.files.defaultLocalURL(did: raw.id!).path))
    }

    func testServerErrorsSurfaceInDiagnostics() async throws {
        let fx = try makeFixture()
        let file = try writeFile("gone.txt", "will 404")
        let raw = try fx.session.files.registerFile(at: file)
        try await fx.sync.upload(hatId: raw.id!, ownPubkey: fx.pubkey)
        try fx.session.files.removeLocalData(hatId: raw.id!)
        try FileManager.default.removeItem(at: file)

        server.failGet = true
        do {
            try await fx.sync.download(hatId: raw.id!, privkey: fx.privkey)
            XCTFail("expected the download to fail")
        } catch let HatSyncService.Failure.downloadFailed(hatId, diagnostics) {
            XCTAssertEqual(hatId, raw.id)
            XCTAssertFalse(diagnostics.isEmpty)
        }
    }

    func testUploadSurfacesServerRejection() async throws {
        let fx = try makeFixture()
        let file = try writeFile("nope.txt", "server says no")
        let raw = try fx.session.files.registerFile(at: file)
        server.failStore = true

        do {
            try await fx.sync.upload(hatId: raw.id!, ownPubkey: fx.pubkey)
            XCTFail("expected the upload to fail")
        } catch let DiskService.Failure.serverError(code, _) {
            XCTAssertEqual(code, 1)
        }
        // No half-built cipher HAT is left behind.
        let leftovers = try fx.session.hats.cipherHats()
        XCTAssertTrue(leftovers.isEmpty, "no half-built cipher HAT may be left behind")
    }

    // MARK: - existence checks

    func testCheckSingleAndBatch() async throws {
        let fx = try makeFixture()
        let present = server.seed(Data("i am here".utf8))
        let absent = String(repeating: "f", count: 64)

        let one = try await fx.sync.disk.check(did: present)
        XCTAssertEqual(one?.id, present)
        let none = try await fx.sync.disk.check(did: absent)
        XCTAssertNil(none)

        let many = try await fx.sync.disk.check(dids: [present, absent])
        XCTAssertEqual(Set(many.keys), [present])
    }

    /// Chunking matters: the Java client caps a check at 200 ids and
    /// the server rejects more.
    func testCheckChunksLargeIdLists() async throws {
        let fx = try makeFixture()
        let ids = (0..<450).map { String(format: "%064x", $0) }
        _ = try await fx.sync.disk.check(dids: ids)
        XCTAssertEqual(server.checkBatches.count, 3)
        XCTAssertEqual(server.checkBatches.map(\.count), [200, 200, 50])
    }

    // MARK: - location tagging

    /// A `(sid)` location outlives the server changing address, so it
    /// wins over a raw URL whenever one is known.
    func testSidLocationPreferredOverUrl() throws {
        let fx = try makeFixture()
        func sync(sid: String?, url: String?) -> HatSyncService {
            HatSyncService(
                disk: DiskService(fapi: server),
                hats: fx.session.hats,
                files: fx.session.files,
                serviceSid: sid,
                serviceUrl: url
            )
        }
        XCTAssertEqual(sync(sid: "svc-9", url: "1.2.3.4:9000").currentLocation, "(sid)svc-9")
        XCTAssertEqual(sync(sid: nil, url: "1.2.3.4:9000").currentLocation, "fudp://1.2.3.4:9000")
        // An already-prefixed URL isn't double-prefixed.
        XCTAssertEqual(sync(sid: nil, url: "fudp://1.2.3.4:9000").currentLocation, "fudp://1.2.3.4:9000")
        XCTAssertEqual(sync(sid: nil, url: nil).currentLocation, "fudp://unknown")
    }
}
