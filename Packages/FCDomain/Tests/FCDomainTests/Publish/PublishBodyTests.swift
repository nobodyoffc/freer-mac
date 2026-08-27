import XCTest
import FCCore
import FCTransport
@testable import FCDomain

/// The bytes behind `did` — storing a body and getting it back, against
/// an in-process content-addressed DISK.
///
/// The happy path matters, but the cases that earn their keep are the
/// misbehaving-server ones: a `did` is a hash, so a location that
/// serves the wrong bytes must fail rather than be believed. That is
/// the entire argument for hashing the body instead of naming it.
final class PublishBodyTests: XCTestCase {

    private var baseDir: URL!
    private var server: FakeDiskServer!

    override func setUpWithError() throws {
        baseDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("PublishBodyTests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: baseDir, withIntermediateDirectories: true)
        server = FakeDiskServer()
    }

    override func tearDownWithError() throws {
        if let baseDir { try? FileManager.default.removeItem(at: baseDir) }
    }

    private func makeBody(privkeyByte: UInt8 = 0xB2) throws -> (PublishBody, ActiveSession) {
        let mgr = try ConfigureManager(baseDirectory: baseDir.appendingPathComponent("vault-\(privkeyByte)"))
        let configure = try mgr.createConfigure(password: Data("pwd".utf8), kdfKind: .legacySha256)
        let info = try configure.addMain(privkey: Data(repeating: privkeyByte, count: 32), label: "P")
        let session = try configure.unlockMain(fid: info.fid, fapi: server)
        let sync = HatSyncService(
            disk: DiskService(fapi: server), hats: session.hats,
            files: session.files, serviceSid: String(repeating: "1d", count: 32)
        )
        let body = PublishBody(
            files: session.files, hats: session.hats, sync: sync,
            disk: DiskService(fapi: server)
        )
        return (body, session)
    }

    // MARK: - storing

    /// The `did` a carve names is the hash of the body, computed the
    /// same way whether or not anything was stored — which is what lets
    /// a compose form show the pointer before it pays for it.
    func testTheStoredDidIsTheHashOfTheBody() async throws {
        let (body, _) = try makeBody()
        let text = "Why Freecash\n\nAn economic argument."

        let predicted = PublishBody.did(for: text)
        let did = try await body.store(text)
        XCTAssertEqual(did, predicted)
        XCTAssertEqual(did, FakeDiskServer.did(of: Data(text.utf8)))
        XCTAssertTrue(server.storedDids.contains(did))
    }

    /// Content-addressing means the second copy *is* the first: storing
    /// the same text twice is one DID and one HAT, not two.
    func testStoringTheSameTextTwiceIsIdempotent() async throws {
        let (body, session) = try makeBody()
        let first = try await body.store("same words")
        let second = try await body.store("same words")
        XCTAssertEqual(first, second)
        XCTAssertEqual(try session.hats.count(), 1)
    }

    /// A published work is world-readable and permanent, so it goes
    /// through `carve` rather than the expiring `put`, and unencrypted
    /// — no cipher HAT, no key. A body sealed to our own key would be
    /// unreadable by exactly the audience it is published for.
    func testAPublishedBodyIsCarvedInTheClearWithNoCipherHat() async throws {
        let (body, session) = try makeBody()
        let did = try await body.store("public words")

        XCTAssertEqual(server.carveCount, 1)
        XCTAssertEqual(server.putCount, 0, "a catalogue entry must not outlive its body")
        XCTAssertEqual(server.blob(did: did), Data("public words".utf8), "stored in the clear")

        let hat = try XCTUnwrap(try session.hats.hat(id: did))
        XCTAssertNil(hat.kCipher)
        XCTAssertNil(hat.key)
        XCTAssertTrue((hat.cipherIds ?? []).isEmpty)
        XCTAssertTrue(try session.hats.cipherHats().isEmpty)
    }

    func testAnEmptyBodyIsRefused() async throws {
        let (body, _) = try makeBody()
        do {
            _ = try await body.store("")
            XCTFail("expected a throw")
        } catch {
            guard case PublishBody.Failure.emptyBody = error else {
                return XCTFail("expected emptyBody, got \(error)")
            }
        }
        XCTAssertTrue(server.storedDids.isEmpty)
    }

    // MARK: - reading

    /// The first attempt is local, and it costs a `stat` rather than a
    /// fetch — the work we just published is already here.
    func testReadingBackWhatWePublishedNeverTouchesTheServer() async throws {
        let (body, _) = try makeBody()
        let text = "Why Freecash"
        let did = try await body.store(text)

        let before = server.getCount
        let readBack = try await body.read(did: did)
        XCTAssertEqual(readBack, text)
        XCTAssertEqual(server.getCount, before, "a local body is not fetched")
        XCTAssertTrue(body.isLocal(did: did))
    }

    /// A work somebody else published: no HAT, no local bytes, and the
    /// DID is all we have. It comes off our own DISK and is adopted, so
    /// the second read is local.
    func testAForeignBodyIsFetchedVerifiedAndKept() async throws {
        let (body, session) = try makeBody()
        let text = "Somebody else's essay"
        let did = server.seed(Data(text.utf8))

        XCTAssertFalse(body.isLocal(did: did))
        let first = try await body.read(did: did)
        XCTAssertEqual(first, text)
        XCTAssertEqual(server.getCount, 1)
        XCTAssertNotNil(try session.hats.hat(id: did), "a fetched body is kept")

        let second = try await body.read(did: did)
        XCTAssertEqual(second, text)
        XCTAssertEqual(server.getCount, 1, "the second read is local")
    }

    /// The whole point of hashing rather than naming: a server that
    /// serves the wrong bytes is caught, and the caller is told what
    /// each attempt said rather than being handed an empty answer.
    func testBytesThatDoNotHashToTheDidAreRefused() async throws {
        let (body, _) = try makeBody()
        let did = server.seed(Data("the real essay".utf8))
        server.substituteOnGet = Data("something else entirely".utf8)

        do {
            _ = try await body.read(did: did)
            XCTFail("expected a throw")
        } catch {
            guard case PublishBody.Failure.unreachable(_, let diagnostics) = error else {
                return XCTFail("expected unreachable, got \(error)")
            }
            XCTAssertTrue(diagnostics.contains("ownDisk"), "the diagnostics say what was tried")
        }
    }

    /// A record whose bytes are on no DISK we can reach is still a
    /// record — the failure names the `did` and every attempt, because
    /// a fetch that quietly finds nothing cannot be diagnosed.
    func testAnUnreachableBodyFailsWithEveryAttemptNamed() async throws {
        let (body, _) = try makeBody()
        do {
            _ = try await body.read(did: String(repeating: "ee", count: 32))
            XCTFail("expected a throw")
        } catch {
            let text = "\(error)"
            XCTAssertTrue(text.contains("local=noHat"))
            XCTAssertTrue(text.contains("ownDisk="))
        }
    }

    /// The third attempt is the publisher's own DISK, and it only
    /// happens when the app shell supplied a way to reach one. Without
    /// the resolver the failure says so rather than pretending it tried.
    func testThePublishersDiskIsTriedLastAndOnlyWhenResolvable() async throws {
        let (plain, session) = try makeBody()
        let theirs = FakeDiskServer()
        let text = "published somewhere else"
        let did = theirs.seed(Data(text.utf8))

        // Without a resolver: three attempts, one of them not made.
        do {
            _ = try await plain.read(did: did, publisher: "THEM")
            XCTFail("expected a throw")
        } catch {
            XCTAssertFalse("\(error)".contains("publisherDisk"))
        }

        // With one: their server answers, and the bytes still have to
        // hash to the did before they are believed.
        let sync = HatSyncService(
            disk: DiskService(fapi: server), hats: session.hats,
            files: session.files, serviceSid: String(repeating: "1d", count: 32)
        )
        let resolved = PublishBody(
            files: session.files, hats: session.hats, sync: sync,
            disk: DiskService(fapi: server),
            foreignDisk: { fid in fid == "THEM" ? DiskService(fapi: theirs) : nil }
        )
        let fromThem = try await resolved.read(did: did, publisher: "THEM")
        XCTAssertEqual(fromThem, text)
        XCTAssertTrue(resolved.isLocal(did: did), "and it is kept, so the next read is local")
    }

    /// Bytes that hash correctly but are not text are the right file
    /// for the wrong kind of record — a `did` says nothing about what
    /// is behind it, which is what Image, Sound and Video will use.
    func testBytesThatAreNotTextAreReportedAsSuch() async throws {
        let (body, _) = try makeBody()
        let did = server.seed(Data([0xFF, 0xFE, 0x00, 0x80]))
        do {
            _ = try await body.read(did: did)
            XCTFail("expected a throw")
        } catch {
            guard case PublishBody.Failure.notUtf8 = error else {
                return XCTFail("expected notUtf8, got \(error)")
            }
        }
    }

    // MARK: - files

    /// The image case: the body is a file the user picked, and the
    /// Phase 8.4 decision applies — it is hashed where it lies and
    /// referenced, never copied into app storage.
    func testAFileIsReferencedNotCopiedAndUploadsUnderItsOwnDid() async throws {
        let (body, session) = try makeBody()
        let picture = baseDir.appendingPathComponent("cover.png")
        let bytes = Data([0x89, 0x50, 0x4E, 0x47] + Array(repeating: UInt8(7), count: 512))
        try bytes.write(to: picture)

        let did = try await body.storeFile(at: picture, types: ["image/png"])

        XCTAssertEqual(did, FakeDiskServer.did(of: bytes))
        XCTAssertEqual(server.blob(did: did), bytes)
        XCTAssertEqual(server.carveCount, 1)
        XCTAssertEqual(server.putCount, 0)

        // Referenced: the HAT points at the user's own file, and no
        // copy was made in the vault's data directory.
        let hat = try XCTUnwrap(try session.hats.hat(id: did))
        XCTAssertTrue(
            (hat.locas ?? []).contains { $0.hasSuffix(picture.standardizedFileURL.path) },
            "the original path is the location"
        )
        XCTAssertFalse(
            FileManager.default.fileExists(atPath: session.files.defaultLocalURL(did: did).path),
            "a referenced file is not duplicated into app storage"
        )
    }

    /// A draft registers the file and uploads nothing — the same
    /// bargain `storeLocally` makes for text.
    func testAFileDraftRegistersWithoutUploading() async throws {
        let (body, session) = try makeBody()
        let picture = baseDir.appendingPathComponent("draft.png")
        try Data(repeating: 3, count: 64).write(to: picture)

        let did = try body.storeFileLocally(at: picture)
        XCTAssertNotNil(try session.hats.hat(id: did))
        XCTAssertTrue(server.storedDids.isEmpty, "nothing is paid for until publish")
        XCTAssertTrue(body.isLocal(did: did))
    }

    /// `fetchURL` is the generic read the image, sound and video panes
    /// use — same three attempts, same hash check, no UTF-8 decode.
    func testFetchURLReturnsVerifiedBytesForANonTextBody() async throws {
        let (body, _) = try makeBody()
        let bytes = Data([0xFF, 0xD8, 0xFF, 0xE0] + Array(repeating: UInt8(9), count: 128))
        let did = server.seed(bytes)

        let url = try await body.fetchURL(did: did)
        XCTAssertEqual(try Data(contentsOf: url), bytes)

        // And the same guard as everywhere else: wrong bytes are refused.
        let other = server.seed(Data("different".utf8))
        server.substituteOnGet = Data("wrong".utf8)
        do {
            _ = try await body.fetchURL(did: other)
            XCTFail("expected a throw")
        } catch {
            guard case PublishBody.Failure.unreachable = error else {
                return XCTFail("expected unreachable, got \(error)")
            }
        }
    }

    /// Sound and video take the same road as an image: one file layer,
    /// three protocols. The bytes are opaque to it — what makes a file
    /// a sound is the record that points at it, not anything here.
    func testTheFilePathIsIndifferentToWhatTheBytesAre() async throws {
        let (body, session) = try makeBody()
        var dids: [String] = []
        for (name, bytes) in [
            ("track.m4a", Data([0x00, 0x00, 0x00, 0x20, 0x66, 0x74, 0x79, 0x70])),
            ("clip.mp4", Data([0x00, 0x00, 0x00, 0x18, 0x66, 0x74, 0x79, 0x70])),
            ("cover.png", Data([0x89, 0x50, 0x4E, 0x47]))
        ] {
            let file = baseDir.appendingPathComponent(name)
            try bytes.write(to: file)
            let did = try await body.storeFile(at: file)
            XCTAssertEqual(did, FakeDiskServer.did(of: bytes))
            XCTAssertEqual(server.blob(did: did), bytes)
            dids.append(did)
        }
        XCTAssertEqual(Set(dids).count, 3, "different bytes, different DIDs")
        XCTAssertEqual(try session.hats.count(), 3)
    }
}
