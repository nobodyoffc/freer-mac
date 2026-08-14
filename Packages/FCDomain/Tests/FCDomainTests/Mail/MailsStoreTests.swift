import XCTest
import FCCore
import FCTransport
@testable import FCDomain

/// `MailsStore` on a real per-main `ActiveSession` — ordering, the
/// unread set, deletion visibility, and the invariant that matters most:
/// a plaintext body cannot be persisted.
final class MailsStoreTests: XCTestCase {

    private var baseDir: URL!
    /// Held for the test's lifetime: `ConfigureSession` keeps only a weak
    /// reference to its manager, so letting this go out of scope makes
    /// every later `unlockMain` report a locked vault.
    private var manager: ConfigureManager!
    private var configure: ConfigureSession!
    private var session: ActiveSession!

    override func setUpWithError() throws {
        baseDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("MailsStoreTests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: baseDir, withIntermediateDirectories: true)

        manager = try ConfigureManager(baseDirectory: baseDir)
        configure = try manager.createConfigure(
            password: Data("pwd".utf8), kdfKind: .legacySha256
        )
        let info = try configure.addMain(privkey: Data(repeating: 0xA1, count: 32), label: "A")
        session = try configure.unlockMain(fid: info.fid, fapi: MockFapiClient())
    }

    override func tearDownWithError() throws {
        session = nil
        configure = nil
        manager = nil
        if let baseDir { try? FileManager.default.removeItem(at: baseDir) }
    }

    private var store: MailsStore { session.mails }

    private func mail(
        id: String? = nil, from: String = "F-them", to: String = "F-me",
        height: Int64? = nil, active: Bool? = true, unread: Bool? = nil
    ) -> Mail {
        Mail(cipher: "sealed", from: from, to: to, lastHeight: height,
             active: active, unread: unread, id: id)
    }

    // MARK: - basics

    func testUpsertAndGetRoundTrip() throws {
        try store.upsert(mail(id: "m1"))
        let loaded = try XCTUnwrap(try store.get(id: "m1"))
        XCTAssertEqual(loaded.from, "F-them")
        XCTAssertEqual(try store.all().count, 1)
    }

    /// An id-less mail gets Android's derivation on the way in, so a
    /// draft saved twice is one row, not two.
    func testUpsertDerivesMissingId() throws {
        let draft = Mail(from: "F-me", to: "F-them", content: nil)
        try store.upsert(draft)
        try store.upsert(draft)
        XCTAssertEqual(try store.all().count, 1)
        XCTAssertNotNil(try store.all().first?.id)
    }

    /// The store is the boundary the plaintext must not cross. Even
    /// handed a fully decrypted mail, it persists only the cipher.
    ///
    /// The `decrypted` flag survives, though: it says whether the body
    /// opened, not what the body was, and a list needs it to tell "not
    /// read yet" from "needs a key you don't have here".
    func testPlaintextBodyIsNeverPersisted() throws {
        var m = mail(id: "m1")
        m.content = "the body"
        m.decrypted = true
        try store.upsert(m)

        let loaded = try XCTUnwrap(try store.get(id: "m1"))
        XCTAssertNil(loaded.content)
        XCTAssertEqual(loaded.decrypted, true)
        XCTAssertEqual(loaded.cipher, "sealed")
    }

    /// A draft that was never encrypted keeps its body — there is no
    /// cipher to fall back to, and silently dropping it would lose what
    /// the user typed.
    func testDraftWithoutCipherKeepsItsBody() throws {
        var draft = Mail.draft(from: "F-me", to: "F-them", content: "unsent thoughts")
        draft.lastHeight = nil
        try store.upsert(draft)
        let id = try XCTUnwrap(draft.id)
        XCTAssertEqual(try store.get(id: id)?.content, "unsent thoughts")
    }

    func testRemove() throws {
        try store.upsert(mail(id: "m1"))
        XCTAssertTrue(try store.remove(id: "m1"))
        XCTAssertFalse(try store.remove(id: "m1"))
        XCTAssertEqual(try store.all().count, 0)
    }

    func testRemoveAllCountsOnlyWhatExisted() throws {
        try store.upsert(mail(id: "m1"))
        try store.upsert(mail(id: "m2"))
        XCTAssertEqual(try store.removeAll(ids: ["m1", "m2", "ghost"]), 2)
    }

    // MARK: - ordering

    /// `lastHeight` descending then id descending — the same sort
    /// `MailManager.makeFcdsl` asks the server for, so a locally merged
    /// page doesn't reshuffle when it syncs.
    func testOrderingIsHeightThenIdDescending() throws {
        try store.upsert(mail(id: "a", height: 100))
        try store.upsert(mail(id: "c", height: 200))
        try store.upsert(mail(id: "b", height: 200))
        XCTAssertEqual(try store.all().compactMap(\.id), ["c", "b", "a"])
    }

    /// A just-broadcast mail carries the unconfirmed sentinel and must
    /// sit at the top, where the user is looking for it.
    func testUnconfirmedMailSortsFirst() throws {
        try store.upsert(mail(id: "confirmed", height: 4_100_000))
        try store.upsert(mail(id: "justSent", height: MailsStore.unconfirmedHeight))
        try store.upsert(mail(id: "noHeight", height: nil))
        let ids = try store.all().compactMap(\.id)
        XCTAssertEqual(ids.first, "noHeight", "no height sorts as unconfirmed, then by id desc")
        XCTAssertEqual(ids.last, "confirmed")
    }

    /// The sync watermark ignores the sentinel — resuming from
    /// 999 999 999 would skip every real mail forever.
    func testHighestKnownHeightIgnoresTheSentinel() throws {
        try store.upsert(mail(id: "a", height: 4_100_000))
        try store.upsert(mail(id: "b", height: MailsStore.unconfirmedHeight))
        XCTAssertEqual(try store.highestKnownHeight(), 4_100_000)
    }

    func testHighestKnownHeightIsNilOnAnEmptyMailbox() throws {
        XCTAssertNil(try store.highestKnownHeight())
        try store.upsert(mail(id: "only", height: MailsStore.unconfirmedHeight))
        XCTAssertNil(try store.highestKnownHeight(), "an unsent mail is not a watermark")
    }

    // MARK: - deletion

    /// A deleted mail is kept, not dropped: the chain can recover it, and
    /// Recover would be a blind operation if the row were gone.
    func testDeletedMailsAreKeptButSegregated() throws {
        try store.upsert(mail(id: "live", height: 1, active: true))
        try store.upsert(mail(id: "dead", height: 2, active: false))

        XCTAssertEqual(try store.active().compactMap(\.id), ["live"])
        XCTAssertEqual(try store.deleted().compactMap(\.id), ["dead"])
        XCTAssertEqual(try store.all().count, 2)
    }

    // MARK: - unread

    func testUnreadCountAndMarking() throws {
        try store.upsert(mail(id: "u1", height: 3, unread: true))
        try store.upsert(mail(id: "u2", height: 2, unread: true))
        try store.upsert(mail(id: "read", height: 1, unread: false))
        XCTAssertEqual(try store.unreadCount(), 2)

        XCTAssertTrue(try store.markRead(id: "u1"))
        XCTAssertFalse(try store.markRead(id: "u1"), "already read")
        XCTAssertFalse(try store.markRead(id: "ghost"))
        XCTAssertEqual(try store.unreadCount(), 1)

        XCTAssertEqual(try store.markAllRead(), 1)
        XCTAssertEqual(try store.unreadCount(), 0)
    }

    /// A deleted mail does not keep the unread badge lit — it is not
    /// something the user can go and read.
    func testDeletedUnreadMailIsNotCounted() throws {
        try store.upsert(mail(id: "d", active: false, unread: true))
        XCTAssertEqual(try store.unreadCount(), 0)
    }

    // MARK: - search

    func testSearchCoversAddressingButNotTheSealedBody() throws {
        try store.upsert(Mail(cipher: "sealed", from: "F-alice", to: "F-me",
                              fromName: "Alice", id: "m1"))
        try store.upsert(Mail(cipher: "sealed", from: "F-carol", to: "F-me", id: "m2"))

        XCTAssertEqual(try store.search("alice").compactMap(\.id), ["m1"])
        XCTAssertEqual(try store.search("F-me").count, 2)
        XCTAssertEqual(try store.search("   ").count, 2, "a blank query is not a filter")
        // The body is ciphertext at rest, so it cannot be searched here.
        XCTAssertEqual(try store.search("sealed").count, 0)
    }

    // MARK: - isolation

    /// Mail is per-main, like every other store: a second identity under
    /// the same password sees none of it.
    func testMailsAreIsolatedPerMain() throws {
        let other = try configure.addMain(privkey: Data(repeating: 0xB2, count: 32), label: "B")
        let otherSession = try configure.unlockMain(fid: other.fid, fapi: MockFapiClient())

        try store.upsert(mail(id: "m1"))
        XCTAssertEqual(try otherSession.mails.all().count, 0)
        XCTAssertEqual(try store.all().count, 1)
    }
}
