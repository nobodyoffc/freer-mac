import XCTest
import FCCore
import FCTransport
@testable import FCDomain

/// Sharing a file in a chat, against the same in-process DISK the
/// Phase 8.4 tests use: the sender uploads and sends a reference, and a
/// receiver who holds none of the sender's keys opens it anyway.
final class FileShareServiceTests: XCTestCase {

    private var baseDir: URL!
    private var workDir: URL!
    private var server: FakeDiskServer!

    private let t0 = Date(timeIntervalSince1970: 1_755_100_000)

    override func setUpWithError() throws {
        baseDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("FileShareTests-\(UUID().uuidString)")
        workDir = baseDir.appendingPathComponent("user-files")
        try FileManager.default.createDirectory(at: workDir, withIntermediateDirectories: true)
        server = FakeDiskServer()
    }

    override func tearDownWithError() throws {
        server = nil
        if let baseDir { try? FileManager.default.removeItem(at: baseDir) }
    }

    // MARK: - fixtures

    private struct Peer {
        let session: ActiveSession
        let share: FileShareService
        let pubkey: Data
    }

    private func makePeer(_ byte: UInt8, label: String) throws -> Peer {
        let mgr = try ConfigureManager(baseDirectory: baseDir.appendingPathComponent("vault-\(label)"))
        let configure = try mgr.createConfigure(password: Data("pwd".utf8), kdfKind: .legacySha256)
        let privkey = Data(repeating: byte, count: 32)
        let info = try configure.addMain(privkey: privkey, label: label)
        let session = try configure.unlockMain(fid: info.fid, fapi: server)
        let sync = HatSyncService(
            disk: DiskService(fapi: server),
            hats: session.hats,
            files: session.files,
            serviceSid: "disk-svc-1"
        )
        return Peer(
            session: session,
            share: FileShareService(files: session.files, hats: session.hats, sync: sync),
            pubkey: try Secp256k1.publicKey(fromPrivateKey: privkey)
        )
    }

    private func writeFile(_ name: String, _ contents: String) throws -> URL {
        let url = workDir.appendingPathComponent(name)
        try Data(contents.utf8).write(to: url)
        return url
    }

    private func roomConversation(_ id: String = "room_b4c9a1f2e8d73065b4c9") -> Conversation {
        var conversation = Conversation(
            id: Conversation.id(type: .room, targetId: id), targetId: id, type: .room
        )
        conversation.unreadCount = 0
        return conversation
    }

    // MARK: - the round trip

    /// The property that makes file share work at all: the message body
    /// carries the plaintext file key, so a receiver holding **none** of
    /// the sender's keys can fetch and decrypt.
    func testAReceiverWithNoKeysOpensTheSharedFile() async throws {
        let alice = try makePeer(0xA1, label: "alice")
        let bob = try makePeer(0xB2, label: "bob")
        let conversation = roomConversation()
        let url = try writeFile("notes.txt", "the quick brown fox")

        var preparedId: String?
        let message = try await alice.share.share(
            fileAt: url,
            in: conversation,
            as: alice.session.liveFid,
            ownPubkey: alice.pubkey,
            onPrepared: { hat in preparedId = hat.id },
            now: t0
        )

        XCTAssertEqual(message.contentType, .hat)
        XCTAssertEqual(message.type, .room)
        XCTAssertNotNil(preparedId, "the bubble can be drawn before the upload finishes")

        // Bob has never seen this HAT and holds no key of Alice's.
        let offer = try XCTUnwrap(bob.share.offer(in: message))
        XCTAssertEqual(offer.name, "notes.txt")
        XCTAssertTrue(offer.hasKey)
        XCTAssertFalse(offer.isDownloaded)

        let landed = try await bob.share.download(message)
        XCTAssertEqual(try String(contentsOf: landed, encoding: .utf8), "the quick brown fox")
        XCTAssertEqual(bob.share.offer(in: message)?.isDownloaded, true)
    }

    /// The shared HAT carries a key; **our own stored copy does not**.
    /// A plaintext file key sitting in the local store would be a key at
    /// rest that nothing needs.
    func testTheLocalRecordKeepsNoPlaintextKey() async throws {
        let alice = try makePeer(0xA1, label: "alice")
        let url = try writeFile("secret.txt", "for the room only")
        let message = try await alice.share.share(
            fileAt: url, in: roomConversation(), as: alice.session.liveFid,
            ownPubkey: alice.pubkey, now: t0
        )

        let shared = try Hat.fromJson(try XCTUnwrap(message.content))
        XCTAssertFalse((shared.key ?? "").isEmpty, "the wire copy carries the key")

        let stored = try XCTUnwrap(try alice.session.hats.hat(id: try XCTUnwrap(shared.id)))
        XCTAssertTrue((stored.key ?? "").isEmpty, "the local copy does not")
    }

    /// Accepting merges the offer into our own store, which is what
    /// makes it downloadable — `HatSyncService` fetches by id, so a HAT
    /// that only ever existed inside a message body could not be.
    func testAcceptMergesTheOfferIntoTheStore() async throws {
        let alice = try makePeer(0xA1, label: "alice")
        let bob = try makePeer(0xB2, label: "bob")
        let url = try writeFile("shared.txt", "hello")
        let message = try await alice.share.share(
            fileAt: url, in: roomConversation(), as: alice.session.liveFid,
            ownPubkey: alice.pubkey, now: t0
        )
        let id = try XCTUnwrap(try Hat.fromJson(try XCTUnwrap(message.content)).id)

        XCTAssertNil(try bob.session.hats.hat(id: id))
        let accepted = try XCTUnwrap(try bob.share.accept(message))
        XCTAssertEqual(accepted.id, id)
        XCTAssertNotNil(try bob.session.hats.hat(id: id))
        XCTAssertFalse((try bob.session.hats.hat(id: id)?.key ?? "").isEmpty)
    }

    /// Accepting the same offer twice must not clobber what we have
    /// already learned locally — where the bytes are, above all.
    func testAcceptingTwiceKeepsLocalState() async throws {
        let alice = try makePeer(0xA1, label: "alice")
        let bob = try makePeer(0xB2, label: "bob")
        let url = try writeFile("twice.txt", "same file")
        let message = try await alice.share.share(
            fileAt: url, in: roomConversation(), as: alice.session.liveFid,
            ownPubkey: alice.pubkey, now: t0
        )

        _ = try await bob.share.download(message)
        XCTAssertEqual(bob.share.offer(in: message)?.isDownloaded, true)

        try bob.share.accept(message)
        XCTAssertEqual(
            bob.share.offer(in: message)?.isDownloaded, true,
            "a repeat offer does not forget that we already have the bytes"
        )
    }

    // MARK: - non-shares

    func testNonHatMessagesAreNotOffers() throws {
        let bob = try makePeer(0xB2, label: "bob")
        var text = ImMessage.text(type: .p2p, from: "F-a", to: "F-b", "just words", now: t0)
        text.setId(fudpId: 7)
        XCTAssertNil(bob.share.offer(in: text))
        XCTAssertNil(try bob.share.accept(text))
    }

    func testAMalformedHatBodyIsIgnoredRatherThanFatal() throws {
        let bob = try makePeer(0xB2, label: "bob")
        var broken = ImMessage.hat(type: .p2p, from: "F-a", to: "F-b", hatJson: "not json", now: t0)
        broken.setId(fudpId: 8)
        XCTAssertNil(bob.share.offer(in: broken))
        XCTAssertNil(try bob.share.accept(broken))

        // …and downloading one says so rather than crashing.
        let expectation = expectation(description: "throws")
        Task {
            do {
                _ = try await bob.share.download(broken)
                XCTFail("expected a throw")
            } catch {
                XCTAssertEqual(error as? FileShareService.Failure, .notAFileShare)
            }
            expectation.fulfill()
        }
        wait(for: [expectation], timeout: 5)
    }

    /// A HAT offered without a key can only be fetched if it happens to
    /// be public, and the pane needs to know which case it is looking
    /// at.
    func testAnOfferWithoutAKeyIsFlagged() throws {
        let bob = try makePeer(0xB2, label: "bob")
        let hat = Hat(size: 12, name: "public.txt", id: String(repeating: "ab", count: 32))
        var message = ImMessage.hat(
            type: .p2p, from: "F-a", to: "F-b", hatJson: hat.wireJson(), now: t0
        )
        message.setId(fudpId: 9)

        let offer = try XCTUnwrap(bob.share.offer(in: message))
        XCTAssertFalse(offer.hasKey)
        XCTAssertEqual(offer.name, "public.txt")
    }

    // MARK: - metadata

    /// The MIME guess is cosmetic — nothing routes on it — but a wrong
    /// icon on every file would be noticed.
    func testMimeTypeGuess() {
        XCTAssertEqual(FileShareService.mimeTypes(for: URL(fileURLWithPath: "/a/b.png")), ["image/png"])
        XCTAssertEqual(FileShareService.mimeTypes(for: URL(fileURLWithPath: "/a/b.JPG")), ["image/jpeg"])
        XCTAssertEqual(FileShareService.mimeTypes(for: URL(fileURLWithPath: "/a/b.pdf")), ["application/pdf"])
        XCTAssertNil(FileShareService.mimeTypes(for: URL(fileURLWithPath: "/a/README")))
        XCTAssertNil(FileShareService.mimeTypes(for: URL(fileURLWithPath: "/a/b.unknown-ext")))
    }
}
