import XCTest
import FCCore
import FCTransport
@testable import FCDomain

/// On-chain mail sync against a staged `base.search`: the one query
/// that covers both directions, the decrypt-and-flag pass, the deletion
/// rule that keeps rows instead of dropping them, unread bookkeeping,
/// and the incremental early exit.
final class MailSyncTests: XCTestCase {

    private var baseDir: URL!
    private var manager: ConfigureManager!

    /// The correspondent. Their key encrypts the inbound mail we stage,
    /// so every decrypt in these tests runs for real.
    private let peerPrivkey = Data(repeating: 0xC3, count: 32)
    private let strangerPrivkey = Data(repeating: 0xD4, count: 32)

    override func setUpWithError() throws {
        baseDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("MailSyncTests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: baseDir, withIntermediateDirectories: true)
        manager = try ConfigureManager(baseDirectory: baseDir)
    }

    override func tearDownWithError() throws {
        manager = nil
        if let baseDir { try? FileManager.default.removeItem(at: baseDir) }
    }

    // MARK: - fixtures

    private func makeSession(fapi: any FapiCalling) throws -> ActiveSession {
        let configure = try manager.createConfigure(
            password: Data("mail-sync".utf8), kdfKind: .legacySha256
        )
        let info = try configure.addMain(
            privkey: Hash.sha256(Data("mailbox-owner".utf8)), label: "owner"
        )
        return try configure.unlockMain(fid: info.fid, fapi: fapi)
    }

    private func fid(of privkey: Data) throws -> String {
        try FchAddress(publicKey: Secp256k1.publicKey(fromPrivateKey: privkey)).fid
    }

    /// One `mail` index row, sealed for real between `senderPriv` and
    /// `recipientPub` so `parseDetail` has something genuine to open.
    private func record(
        id: String,
        from: String,
        to: String,
        senderPriv: Data,
        recipientPub: Data,
        body: String = "hello there",
        lastHeight: Int64 = 4_100_000,
        active: Bool = true,
        noticeFee: Int64 = 10_000
    ) throws -> [String: Any] {
        var mail = Mail(from: from, to: to, content: body)
        try mail.encryptContent(privkey: senderPriv, recipientPubkey: recipientPub)
        return [
            "id": id,
            "alg": mail.alg as Any,
            "cipher": try XCTUnwrap(mail.cipher),
            "from": from,
            "to": to,
            "birthTime": 1_755_100_000,
            "birthHeight": lastHeight,
            "lastHeight": lastHeight,
            "active": active,
            "noticeFee": noticeFee
        ]
    }

    /// Replies to `base.search` with one page and no cursor.
    private func stageOnePage(_ mock: MockFapiClient, _ rows: [[String: Any]]) {
        mock.responder = { call in
            guard call.api == "base.search" else {
                XCTFail("unexpected api \(call.api)")
                return FapiResponse(code: 1, message: "unexpected")
            }
            return try makeResponse(data: rows)
        }
    }

    // MARK: - the query

    /// One query covers the inbox and the outbox: `equals` over both
    /// `from` and `to` against our own FID. And no `active` filter —
    /// deleted mail must come back too, or a delete carved on another
    /// device would never reach this one.
    func testQueryAsksForBothDirectionsAndBothStates() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        stageOnePage(mock, [])

        _ = try await session.mailService.syncOnChainMails(
            fid: session.mainFid, privkey: try session.livePrikey(), into: session.mails
        )

        let call = try XCTUnwrap(mock.recorded.first { $0.api == "base.search" })
        let dsl = try XCTUnwrap(
            JSONSerialization.jsonObject(with: try XCTUnwrap(call.fcdsl)) as? [String: Any]
        )
        XCTAssertEqual(dsl["entity"] as? String, "mail")

        let query = try XCTUnwrap(dsl["query"] as? [String: Any])
        let equals = try XCTUnwrap(query["equals"] as? [String: Any])
        XCTAssertEqual(equals["fields"] as? [String], ["from", "to"])
        XCTAssertEqual(equals["values"] as? [String], [session.mainFid])
        XCTAssertNil(query["terms"], "no active filter — deleted mail must come back too")

        let sort = try XCTUnwrap(dsl["sort"] as? [[String: String]])
        XCTAssertEqual(sort.map { $0["field"] }, ["lastHeight", "id"])
        XCTAssertEqual(sort.map { $0["order"] }, ["desc", "desc"])
    }

    /// A FID with no mail answers 404, which is not an error.
    func testNotFoundIsAnEmptyMailboxNotAFailure() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        mock.responder = { _ in try makeResponse(code: 404) }

        let result = try await session.mailService.syncOnChainMails(
            fid: session.mainFid, privkey: try session.livePrikey(), into: session.mails
        )
        XCTAssertEqual(result.total, 0)
        XCTAssertEqual(try session.mails.all().count, 0)
    }

    func testServerErrorIsSurfaced() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        mock.responder = { _ in try makeResponse(code: 500, data: nil) }

        do {
            _ = try await session.mailService.syncOnChainMails(
                fid: session.mainFid, privkey: try session.livePrikey(), into: session.mails
            )
            XCTFail("expected a failure")
        } catch let error as MailService.Failure {
            guard case .fapiNonZeroCode(_, 500, _) = error else {
                XCTFail("wrong failure: \(error)"); return
            }
        }
    }

    // MARK: - merge

    func testInboxAndOutboxBothMergeAndDecrypt() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        let me = session.mainFid
        let mePriv = try session.livePrikey()
        let myPub = try Secp256k1.publicKey(fromPrivateKey: mePriv)
        let peer = try fid(of: peerPrivkey)
        let peerPub = try Secp256k1.publicKey(fromPrivateKey: peerPrivkey)

        stageOnePage(mock, [
            try record(id: "in-1", from: peer, to: me,
                       senderPriv: peerPrivkey, recipientPub: myPub,
                       body: "from them", lastHeight: 4_100_010),
            try record(id: "out-1", from: me, to: peer,
                       senderPriv: mePriv, recipientPub: peerPub,
                       body: "from me", lastHeight: 4_100_000)
        ])

        let result = try await session.mailService.syncOnChainMails(
            fid: me, privkey: mePriv, into: session.mails
        )
        XCTAssertEqual(result.merged, 2)
        XCTAssertEqual(result.undecryptable, 0)

        let inbound = try XCTUnwrap(try session.mails.get(id: "in-1"))
        XCTAssertEqual(inbound.from, peer)
        XCTAssertEqual(inbound.decrypted, true)
        XCTAssertEqual(inbound.onChain, true)
        XCTAssertEqual(inbound.noticeFee, 10_000)
        XCTAssertNil(inbound.content, "the body is never persisted in the clear")
        XCTAssertTrue(inbound.isIncoming(for: me))

        // The outbound one decrypts too — that is the AsyTwoWay payoff.
        let outbound = try XCTUnwrap(try session.mails.get(id: "out-1"))
        XCTAssertEqual(outbound.decrypted, true)
        XCTAssertFalse(outbound.isIncoming(for: me))

        // Newest first.
        XCTAssertEqual(try session.mails.all().compactMap(\.id), ["in-1", "out-1"])
    }

    /// The mail we can't open is the one that must not disappear: unlike
    /// a contact, whose FID lives inside the ciphertext, this row still
    /// says truthfully who wrote and when.
    func testUndecryptableMailIsKeptAndFlagged() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        let me = session.mainFid
        let peer = try fid(of: peerPrivkey)
        let strangerPub = try Secp256k1.publicKey(fromPrivateKey: strangerPrivkey)

        stageOnePage(mock, [
            // Sealed to a stranger — we hold no key for it.
            try record(id: "opaque", from: peer, to: me,
                       senderPriv: peerPrivkey, recipientPub: strangerPub)
        ])

        let result = try await session.mailService.syncOnChainMails(
            fid: me, privkey: try session.livePrikey(), into: session.mails
        )
        XCTAssertEqual(result.merged, 1)
        XCTAssertEqual(result.undecryptable, 1)
        XCTAssertEqual(result.failureReasons.count, 1)

        let row = try XCTUnwrap(try session.mails.get(id: "opaque"))
        XCTAssertEqual(row.decrypted, false)
        XCTAssertEqual(row.from, peer, "we still know who it came from")
        XCTAssertNotNil(row.cipher, "and we keep the ciphertext, in case a key turns up")
    }

    /// Watch-only: no key at all. Everything still lands, flagged.
    func testWatchOnlySyncStoresRowsWithoutDecrypting() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        let me = session.mainFid
        let peer = try fid(of: peerPrivkey)
        let myPub = try Secp256k1.publicKey(fromPrivateKey: try session.livePrikey())

        stageOnePage(mock, [
            try record(id: "m1", from: peer, to: me,
                       senderPriv: peerPrivkey, recipientPub: myPub)
        ])

        let result = try await session.mailService.syncOnChainMails(
            fid: me, privkey: nil, into: session.mails
        )
        XCTAssertEqual(result.merged, 1)
        XCTAssertEqual(result.undecryptable, 0, "we never tried, so nothing failed")
        XCTAssertEqual(try session.mails.get(id: "m1")?.decrypted, false)
    }

    /// A row that failed only because the last sync ran without a key is
    /// retried once a key is available.
    func testAFailedRowIsRetriedWhenAKeyArrives() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        let me = session.mainFid
        let peer = try fid(of: peerPrivkey)
        let myPub = try Secp256k1.publicKey(fromPrivateKey: try session.livePrikey())

        stageOnePage(mock, [
            try record(id: "m1", from: peer, to: me,
                       senderPriv: peerPrivkey, recipientPub: myPub)
        ])

        _ = try await session.mailService.syncOnChainMails(
            fid: me, privkey: nil, into: session.mails
        )
        XCTAssertEqual(try session.mails.get(id: "m1")?.decrypted, false)

        _ = try await session.mailService.syncOnChainMails(
            fid: me, privkey: try session.livePrikey(), into: session.mails
        )
        XCTAssertEqual(try session.mails.get(id: "m1")?.decrypted, true)
    }

    /// A row already known to open is not decrypted again — observable
    /// because a later sync with the *wrong* key leaves the flag alone
    /// instead of clearing it.
    func testKnownGoodRowsAreNotReDecrypted() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        let me = session.mainFid
        let peer = try fid(of: peerPrivkey)
        let myPub = try Secp256k1.publicKey(fromPrivateKey: try session.livePrikey())

        stageOnePage(mock, [
            try record(id: "m1", from: peer, to: me,
                       senderPriv: peerPrivkey, recipientPub: myPub)
        ])
        _ = try await session.mailService.syncOnChainMails(
            fid: me, privkey: try session.livePrikey(), into: session.mails
        )

        let result = try await session.mailService.syncOnChainMails(
            fid: me, privkey: strangerPrivkey, into: session.mails
        )
        XCTAssertEqual(result.undecryptable, 0)
        XCTAssertEqual(try session.mails.get(id: "m1")?.decrypted, true)
    }

    /// Some indexers omit `to` on a note to self; Android patches it the
    /// same way rather than leaving a mail addressed to nobody.
    func testMissingRecipientFallsBackToTheSender() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        let me = session.mainFid
        stageOnePage(mock, [["id": "self-1", "from": me, "lastHeight": 4_100_000, "active": true]])

        _ = try await session.mailService.syncOnChainMails(
            fid: me, privkey: try session.livePrikey(), into: session.mails
        )
        XCTAssertEqual(try session.mails.get(id: "self-1")?.to, me)
    }

    // MARK: - deletion

    /// Deleted mail is kept and flagged, not removed — the chain can
    /// recover it, and Recover would have nothing to act on otherwise.
    /// This is the deliberate divergence from the contact and secret
    /// syncs, which drop their rows.
    func testDeletedMailIsKeptSegregatedNotRemoved() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        let me = session.mainFid
        let peer = try fid(of: peerPrivkey)
        let myPub = try Secp256k1.publicKey(fromPrivateKey: try session.livePrikey())

        stageOnePage(mock, [
            try record(id: "live", from: peer, to: me,
                       senderPriv: peerPrivkey, recipientPub: myPub, lastHeight: 4_100_010),
            try record(id: "dead", from: peer, to: me,
                       senderPriv: peerPrivkey, recipientPub: myPub,
                       lastHeight: 4_100_020, active: false)
        ])

        let result = try await session.mailService.syncOnChainMails(
            fid: me, privkey: try session.livePrikey(), into: session.mails
        )
        XCTAssertEqual(result.merged, 2)
        XCTAssertEqual(result.deleted, 1)

        XCTAssertEqual(try session.mails.all().count, 2)
        XCTAssertEqual(try session.mails.active().compactMap(\.id), ["live"])
        XCTAssertEqual(try session.mails.deleted().compactMap(\.id), ["dead"])
    }

    /// A mail deleted on another device arrives as `active: false` and
    /// must flip the local row, which is why the sync cannot filter the
    /// query to active rows only.
    func testARemoteDeleteFlipsAnExistingRow() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        let me = session.mainFid
        let peer = try fid(of: peerPrivkey)
        let myPub = try Secp256k1.publicKey(fromPrivateKey: try session.livePrikey())

        let alive = try record(id: "m1", from: peer, to: me,
                               senderPriv: peerPrivkey, recipientPub: myPub)
        stageOnePage(mock, [alive])
        _ = try await session.mailService.syncOnChainMails(
            fid: me, privkey: try session.livePrikey(), into: session.mails
        )
        XCTAssertFalse(try XCTUnwrap(session.mails.get(id: "m1")).isDeleted)

        var deletedRow = alive
        deletedRow["active"] = false
        deletedRow["lastHeight"] = 4_100_100
        stageOnePage(mock, [deletedRow])
        _ = try await session.mailService.syncOnChainMails(
            fid: me, privkey: try session.livePrikey(), into: session.mails, incremental: false
        )
        XCTAssertTrue(try XCTUnwrap(session.mails.get(id: "m1")).isDeleted)
    }

    /// Newest-first sort means the first sighting of an id is its
    /// freshest state; a stale duplicate later in the page is ignored.
    func testDuplicateIdsResolveNewestFirst() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        let me = session.mainFid
        let peer = try fid(of: peerPrivkey)
        let myPub = try Secp256k1.publicKey(fromPrivateKey: try session.livePrikey())

        var newest = try record(id: "m1", from: peer, to: me,
                                senderPriv: peerPrivkey, recipientPub: myPub,
                                lastHeight: 4_100_100, active: false)
        newest["active"] = false
        let stale = try record(id: "m1", from: peer, to: me,
                               senderPriv: peerPrivkey, recipientPub: myPub,
                               lastHeight: 4_100_000, active: true)
        stageOnePage(mock, [newest, stale])

        _ = try await session.mailService.syncOnChainMails(
            fid: me, privkey: try session.livePrikey(), into: session.mails
        )
        XCTAssertEqual(try session.mails.all().count, 1)
        XCTAssertTrue(try XCTUnwrap(session.mails.get(id: "m1")).isDeleted)
    }

    // MARK: - unread

    /// New incoming mail lights the badge; our own sent mail does not.
    /// Android's `markEntityAsNew` marks everything new, which leaves
    /// your outbox unread after a fresh sync.
    func testOnlyIncomingMailArrivesUnread() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        let me = session.mainFid
        let mePriv = try session.livePrikey()
        let myPub = try Secp256k1.publicKey(fromPrivateKey: mePriv)
        let peer = try fid(of: peerPrivkey)
        let peerPub = try Secp256k1.publicKey(fromPrivateKey: peerPrivkey)

        stageOnePage(mock, [
            try record(id: "in-1", from: peer, to: me,
                       senderPriv: peerPrivkey, recipientPub: myPub, lastHeight: 4_100_020),
            try record(id: "out-1", from: me, to: peer,
                       senderPriv: mePriv, recipientPub: peerPub, lastHeight: 4_100_010),
            try record(id: "in-dead", from: peer, to: me,
                       senderPriv: peerPrivkey, recipientPub: myPub,
                       lastHeight: 4_100_000, active: false)
        ])

        let result = try await session.mailService.syncOnChainMails(
            fid: me, privkey: mePriv, into: session.mails
        )
        XCTAssertEqual(result.newUnread, 1)
        XCTAssertEqual(try session.mails.get(id: "in-1")?.unread, true)
        XCTAssertEqual(try session.mails.get(id: "out-1")?.unread, false)
        XCTAssertEqual(try session.mails.get(id: "in-dead")?.unread, false)
        XCTAssertEqual(try session.mails.unreadCount(), 1)
    }

    /// Read state is local. A re-sync must never relight a mail the user
    /// has already opened.
    func testResyncDoesNotRelightReadMail() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        let me = session.mainFid
        let peer = try fid(of: peerPrivkey)
        let myPub = try Secp256k1.publicKey(fromPrivateKey: try session.livePrikey())

        stageOnePage(mock, [
            try record(id: "m1", from: peer, to: me,
                       senderPriv: peerPrivkey, recipientPub: myPub)
        ])
        _ = try await session.mailService.syncOnChainMails(
            fid: me, privkey: try session.livePrikey(), into: session.mails
        )
        XCTAssertTrue(try session.mails.markRead(id: "m1"))

        let result = try await session.mailService.syncOnChainMails(
            fid: me, privkey: try session.livePrikey(), into: session.mails, incremental: false
        )
        XCTAssertEqual(result.newUnread, 0)
        XCTAssertEqual(try session.mails.get(id: "m1")?.unread, false)
        XCTAssertEqual(try session.mails.unreadCount(), 0)
    }

    // MARK: - names

    func testContactCidsAreCachedOntoRows() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        let me = session.mainFid
        let peer = try fid(of: peerPrivkey)
        let myPub = try Secp256k1.publicKey(fromPrivateKey: try session.livePrikey())

        try session.contacts.upsert(Contact(id: peer, cid: "alice"))
        stageOnePage(mock, [
            try record(id: "m1", from: peer, to: me,
                       senderPriv: peerPrivkey, recipientPub: myPub)
        ])

        _ = try await session.mailService.syncOnChainMails(
            fid: me, privkey: try session.livePrikey(),
            into: session.mails, contacts: session.contacts
        )
        let row = try XCTUnwrap(try session.mails.get(id: "m1"))
        XCTAssertEqual(row.fromName, "alice")
        XCTAssertNil(row.toName, "we are not in our own address book")
        XCTAssertEqual(row.counterpartyName(for: me), "alice")
    }

    /// A contact with no CID contributes no name — the FID is already on
    /// the row, and duplicating it into every record buys nothing.
    func testContactWithoutACidLeavesTheNameEmpty() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        let me = session.mainFid
        let peer = try fid(of: peerPrivkey)
        let myPub = try Secp256k1.publicKey(fromPrivateKey: try session.livePrikey())

        try session.contacts.upsert(Contact(id: peer, memo: "no cid"))
        stageOnePage(mock, [
            try record(id: "m1", from: peer, to: me,
                       senderPriv: peerPrivkey, recipientPub: myPub)
        ])

        _ = try await session.mailService.syncOnChainMails(
            fid: me, privkey: try session.livePrikey(),
            into: session.mails, contacts: session.contacts
        )
        XCTAssertNil(try session.mails.get(id: "m1")?.fromName)
        XCTAssertEqual(try session.mails.get(id: "m1")?.counterpartyName(for: me), peer)
    }

    // MARK: - paging

    /// With no watermark the walk follows the cursor to the end.
    func testFullWalkFollowsTheCursor() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        let me = session.mainFid
        stagePages(mock, [
            [row(id: "a", from: me, height: 5_000), row(id: "b", from: me, height: 4_990)],
            [row(id: "c", from: me, height: 4_980)]
        ])

        let records = try await session.mailService.fetchOnChainMailRecords(
            fid: me, newerThanHeight: nil, pageSize: 2
        )
        XCTAssertEqual(records.compactMap(\.id), ["a", "b", "c"])
        XCTAssertEqual(mock.recorded.count, 2)
    }

    /// An incremental sync stops as soon as a page drops below the
    /// watermark's reorg window. Height-descending order makes that a
    /// safe early exit, and it is what keeps a re-sync cheap on a
    /// mailbox with years in it.
    func testIncrementalWalkStopsBelowTheWatermark() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        let me = session.mainFid
        stagePages(mock, [
            [row(id: "a", from: me, height: 5_000), row(id: "b", from: me, height: 4_990)],
            [row(id: "c", from: me, height: 4_980)]
        ])

        // floor = 5030 - 30 = 5000; the page ends at 4990 < 5000 → stop.
        let records = try await session.mailService.fetchOnChainMailRecords(
            fid: me, newerThanHeight: 5_030, pageSize: 2
        )
        XCTAssertEqual(records.compactMap(\.id), ["a", "b"])
        XCTAssertEqual(mock.recorded.count, 1, "the second page must not be fetched")
    }

    /// The window is real: a page that ends inside it keeps paging, so a
    /// reorg that rewrote recent heights is still picked up.
    func testTheReorgWindowKeepsPagingJustBelowTheWatermark() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        let me = session.mainFid
        stagePages(mock, [
            [row(id: "a", from: me, height: 5_000), row(id: "b", from: me, height: 4_990)],
            [row(id: "c", from: me, height: 4_900)]
        ])

        // floor = 5000 - 30 = 4970; the page ends at 4990 ≥ 4970 → keep going.
        let records = try await session.mailService.fetchOnChainMailRecords(
            fid: me, newerThanHeight: 5_000, pageSize: 2
        )
        XCTAssertEqual(records.compactMap(\.id), ["a", "b", "c"])
        XCTAssertEqual(mock.recorded.count, 2)
    }

    // MARK: - paging helpers

    private func row(id: String, from: String, height: Int64) -> [String: Any] {
        ["id": id, "from": from, "to": from, "lastHeight": height, "active": true]
    }

    /// Serves `pages` in order, setting the `last` cursor on every page
    /// but the final one.
    private func stagePages(_ mock: MockFapiClient, _ pages: [[[String: Any]]]) {
        let counter = PageCounter()
        mock.responder = { _ in
            let index = counter.next()
            guard index < pages.count else {
                XCTFail("asked for page \(index), only \(pages.count) staged")
                return FapiResponse(code: 404, message: "no more")
            }
            var resp = try makeResponse(data: pages[index])
            if index < pages.count - 1 {
                resp.last = [String(index)]
            }
            return resp
        }
    }
}

private final class PageCounter: @unchecked Sendable {
    private var value = 0
    func next() -> Int {
        defer { value += 1 }
        return value
    }
}
