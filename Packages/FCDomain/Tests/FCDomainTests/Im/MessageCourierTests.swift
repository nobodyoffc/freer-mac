import XCTest
import FCCore
import FCTransport
import FCStorage
@testable import FCDomain

/// Delivery over DOCK, end to end: a message leaves one device's outbox,
/// sits at a DOCK, and arrives in another device's transcript — the
/// phase's "sent while the recipient was offline" clause, exercised
/// against a DOCK that behaves like one.
final class MessageCourierTests: XCTestCase {

    private var baseDir: URL!
    private var manager: ConfigureManager!
    private var server: FakeDock!

    /// Alice sends, Bob is offline and collects later.
    private let alicePriv = Data(repeating: 0xA1, count: 32)
    private let bobPriv = Data(repeating: 0xB2, count: 32)

    private let t0 = Date(timeIntervalSince1970: 1_755_100_000)
    private func at(_ seconds: TimeInterval) -> Date { t0.addingTimeInterval(seconds) }

    override func setUpWithError() throws {
        baseDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("MessageCourierTests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: baseDir, withIntermediateDirectories: true)
        manager = try ConfigureManager(baseDirectory: baseDir)
        server = FakeDock()
    }

    override func tearDownWithError() throws {
        server = nil
        manager = nil
        if let baseDir { try? FileManager.default.removeItem(at: baseDir) }
    }

    private func makeSession(privkey: Data, label: String) throws -> ActiveSession {
        let configure = try manager.createConfigure(
            password: Data("\(label)-pwd".utf8), kdfKind: .legacySha256
        )
        let info = try configure.addMain(privkey: privkey, label: label)
        let session = try configure.unlockMain(fid: info.fid, fapi: server)
        try acceptTheCast(session)
        return session
    }

    /// Consent, stated once for the whole cast.
    ///
    /// These suites are about moving messages, and they all assume the
    /// two ends are already talking. Since the stranger gate landed that
    /// assumption has to be made explicit: an unaccepted FID's first P2P
    /// message is **held**, not filed. That rule is tested where it
    /// belongs, in `ContactPolicyTests`.
    private func acceptTheCast(_ session: ActiveSession) throws {
        for privkey in [alicePriv, bobPriv] {
            let fid = try FchAddress(publicKey: Secp256k1.publicKey(fromPrivateKey: privkey)).fid
            try session.contactPolicy.mutate(liveFid: session.liveFid) { $0.allow(fid) }
        }
    }

    private func pubkey(_ privkey: Data) throws -> Data {
        try Secp256k1.publicKey(fromPrivateKey: privkey)
    }

    // MARK: - the round trip

    /// The whole point of the sub-phase. Alice sends while Bob is not
    /// there; the message waits at a DOCK; Bob starts up and finds it.
    func testAMessageSentToAnAbsentPeerArrivesOnTheirNextCollect() async throws {
        let alice = try makeSession(privkey: alicePriv, label: "alice")
        let bob = try makeSession(privkey: bobPriv, label: "bob")
        server.homeByFid[bob.liveFid] = [ServiceName.dock: "https://dock.bob"]

        // Alice opens a thread and says something.
        let conversationId = Conversation.id(type: .p2p, targetId: bob.liveFid)
        var thread = Conversation(id: conversationId, targetId: bob.liveFid, type: .p2p)
        thread.unreadCount = 0
        try alice.conversations.upsert(thread)
        let sent = try alice.chat.sendText(
            "meet me at the usual place", in: conversationId, as: alice.liveFid,
            keys: .init(privkey: alicePriv, recipientPubkey: try pubkey(bobPriv)), now: t0
        )

        // It is queued and unsent.
        XCTAssertEqual(try alice.outbox.count(), 1)
        XCTAssertEqual(
            try alice.messages.get(messageId: sent.id!, in: conversationId)?.status, .pending
        )

        // The outbox drains onto Bob's DOCK.
        let report = try await alice.courier.drainOutbox(
            as: alice.liveFid, ownDockUrl: "https://dock.alice", now: at(1)
        )
        XCTAssertEqual(report, .init(attempted: 1, sent: 1, retrying: 0, failed: 0))
        XCTAssertEqual(try alice.outbox.count(), 0)

        let afterSend = try XCTUnwrap(
            try alice.messages.get(messageId: sent.id!, in: conversationId)
        )
        XCTAssertEqual(afterSend.status, .sent)
        XCTAssertEqual(afterSend.deliveryMethod, .dockStored)
        XCTAssertNotNil(afterSend.dockId)
        // Storing a message for someone is evidence they were *not*
        // reachable, so it must not mark them present.
        XCTAssertFalse(try XCTUnwrap(try alice.peers.get(fid: bob.liveFid)).isOnline(now: at(1)))

        // Bob starts up and collects.
        let received = try await bob.courier.collect(
            as: bob.liveFid, recipientIds: [bob.liveFid], privkey: bobPriv, now: at(60)
        )
        XCTAssertEqual(received, .init(fetched: 1, filed: 1, sealed: 0, other: 0))

        let bobsThread = Conversation.id(type: .p2p, targetId: alice.liveFid)
        let inbox = try bob.chat.page(bobsThread).messages
        XCTAssertEqual(inbox.map(\.content), ["meet me at the usual place"])
        XCTAssertEqual(inbox.first?.unread, true)
        XCTAssertEqual(inbox.first?.deliveryMethod, .dockStored)
        XCTAssertEqual(try bob.conversations.get(id: bobsThread)?.unreadCount, 1)
    }

    /// **A message another drain is already attempting is left alone.**
    /// Several things call `drainOutbox` — a thirty-second timer, and
    /// every screen that sends something — and without a claim both
    /// passes put the same envelope on the recipient's DOCK.
    func testAMessageAnotherDrainHasClaimedIsNotSentAgain() async throws {
        let alice = try makeSession(privkey: alicePriv, label: "alice")
        let bob = try makeSession(privkey: bobPriv, label: "bob")
        server.homeByFid[bob.liveFid] = [ServiceName.dock: "https://dock.bob"]

        let conversationId = Conversation.id(type: .p2p, targetId: bob.liveFid)
        try alice.conversations.upsert(
            Conversation(id: conversationId, targetId: bob.liveFid, type: .p2p)
        )
        let sent = try alice.chat.sendText(
            "only once", in: conversationId, as: alice.liveFid,
            keys: .init(privkey: alicePriv, recipientPubkey: try pubkey(bobPriv)), now: t0
        )

        let id = try XCTUnwrap(sent.id)

        // What a second drain would see while the first is on the wire:
        // the message claimed, and so not due to be attempted again.
        let outbox = alice.outbox
        var dueDuringTheAttempt: [String]?
        var claimDuringTheAttempt: QueuedMessage??
        server.onPut = {
            dueDuringTheAttempt = try? outbox.due(now: self.at(1)).map(\.id)
            claimDuringTheAttempt = try? outbox.claim(id: id, now: self.at(1))
        }

        _ = try await alice.courier.drainOutbox(
            as: alice.liveFid, ownDockUrl: "https://dock.alice", now: at(1)
        )

        XCTAssertEqual(dueDuringTheAttempt, [], "claimed, so no longer up for attempt")
        XCTAssertEqual(claimDuringTheAttempt, .some(.none), "and a second claim loses")
        XCTAssertEqual(server.items.count, 1, "the envelope went once")
    }

    /// A delivery writes two rows — the message's new status and the
    /// removal of its outbox entry — and they are one fact. Either half
    /// alone is a bug with no way back: a message shown as sent that is
    /// still queued goes out twice, and one taken off the queue while it
    /// still says "sending" says that for ever.
    func testDeliveryMovesTheMessageAndTheOutboxTogether() async throws {
        let alice = try makeSession(privkey: alicePriv, label: "alice")
        let bob = try makeSession(privkey: bobPriv, label: "bob")
        server.homeByFid[bob.liveFid] = [ServiceName.dock: "https://dock.bob"]

        let conversationId = Conversation.id(type: .p2p, targetId: bob.liveFid)
        try alice.conversations.upsert(
            Conversation(id: conversationId, targetId: bob.liveFid, type: .p2p)
        )
        let sent = try alice.chat.sendText(
            "together or not at all", in: conversationId, as: alice.liveFid,
            keys: .init(privkey: alicePriv, recipientPubkey: try pubkey(bobPriv)), now: t0
        )
        let id = try XCTUnwrap(sent.id)

        _ = try await alice.courier.drainOutbox(
            as: alice.liveFid, ownDockUrl: "https://dock.alice", now: at(1)
        )

        XCTAssertEqual(try alice.messages.get(messageId: id, in: conversationId)?.status, .sent)
        XCTAssertNil(try alice.outbox.get(id: id))
        // And a second drain finds nothing left to do, so nothing is
        // delivered twice.
        let again = try await alice.courier.drainOutbox(
            as: alice.liveFid, ownDockUrl: "https://dock.alice", now: at(2)
        )
        XCTAssertEqual(again.attempted, 0)
        XCTAssertEqual(server.items.count, 1)
    }

    // MARK: - replay and misaddressing (FIMP0V3 §3.5)

    /// Sends one text from Alice to Bob and returns the envelope as it sits
    /// on the DOCK, signed by Alice.
    private func aliceSendsBob(_ alice: ActiveSession, _ bob: ActiveSession, _ text: String) async throws -> Data {
        server.homeByFid[bob.liveFid] = [ServiceName.dock: "https://dock.bob"]
        let conversationId = Conversation.id(type: .p2p, targetId: bob.liveFid)
        var thread = Conversation(id: conversationId, targetId: bob.liveFid, type: .p2p)
        thread.unreadCount = 0
        try alice.conversations.upsert(thread)
        _ = try alice.chat.sendText(
            text, in: conversationId, as: alice.liveFid,
            keys: .init(privkey: alicePriv, recipientPubkey: try pubkey(bobPriv)), now: t0
        )
        _ = try await alice.courier.drainOutbox(as: alice.liveFid, ownDockUrl: "https://dock.alice", now: at(1))
        return try XCTUnwrap(server.items.last).payload
    }

    /// The same signed bytes, put back on the DOCK under a new item id,
    /// verify as well as they did the first time. They are taken in once.
    func testAReplayedEnvelopeIsTakenInOnce() async throws {
        let alice = try makeSession(privkey: alicePriv, label: "alice")
        let bob = try makeSession(privkey: bobPriv, label: "bob")
        let envelope = try await aliceSendsBob(alice, bob, "only once")

        let first = try await bob.courier.collect(as: bob.liveFid, recipientIds: [bob.liveFid], privkey: bobPriv, now: at(60))
        XCTAssertEqual(first.filed, 1)

        server.items.append(.init(id: "replayed-1", recipients: [bob.liveFid], payload: envelope))
        let again = try await bob.courier.collect(as: bob.liveFid, recipientIds: [bob.liveFid], privkey: bobPriv, now: at(120))
        XCTAssertEqual(again.filed, 0)
        XCTAssertEqual(again.fetched, 1)
        let thread = Conversation.id(type: .p2p, targetId: alice.liveFid)
        XCTAssertEqual(try bob.chat.page(thread).messages.count, 1)
        XCTAssertTrue(server.items.isEmpty, "the replay addressed to Bob alone is cleared too")
    }

    /// Alice's message to Bob, validly signed, stored for Carol instead.
    func testASignedMessageForSomeoneElseIsDropped() async throws {
        let alice = try makeSession(privkey: alicePriv, label: "alice")
        let bob = try makeSession(privkey: bobPriv, label: "bob")
        let carolPriv = Data(repeating: 0xC3, count: 32)
        let carol = try makeSession(privkey: carolPriv, label: "carol")
        let envelope = try await aliceSendsBob(alice, bob, "for Bob")
        server.items.removeAll()
        server.items.append(.init(id: "misdirected-1", recipients: [carol.liveFid], payload: envelope))

        let received = try await carol.courier.collect(as: carol.liveFid, recipientIds: [carol.liveFid], privkey: carolPriv, now: at(60))
        XCTAssertEqual(received.fetched, 1)
        XCTAssertEqual(received.filed + received.sealed + received.held, 0)
        XCTAssertTrue(try carol.conversations.visible().isEmpty)
        XCTAssertTrue(try carol.messageRequests.pending().isEmpty)
    }

    func testSeenMessagesArePrunedAfterRetention() throws {
        let alice = try makeSession(privkey: alicePriv, label: "alice")
        let store = alice.seenMessages
        try store.markSeen(sender: "F-old", id: "0000000000000001", now: t0)
        try store.markSeen(sender: "F-new", id: "0000000000000002", now: at(300 * 86_400))
        let later = t0.addingTimeInterval(Double(SeenMessagesStore.retentionMs) / 1000 + 1)
        XCTAssertEqual(try store.prune(now: later), 1)
        XCTAssertFalse(try store.hasSeen(sender: "F-old", id: "0000000000000001"))
        XCTAssertTrue(try store.hasSeen(sender: "F-new", id: "0000000000000002"))
    }

    /// Taking delivery deletes the item: the sender paid for its
    /// storage, and leaving read items to expire would spend their money
    /// on nothing — as well as handing back the same message forever.
    func testCollectingDeletesWhatItFiled() async throws {
        let alice = try makeSession(privkey: alicePriv, label: "alice")
        let bob = try makeSession(privkey: bobPriv, label: "bob")
        server.homeByFid[bob.liveFid] = [ServiceName.dock: "https://dock.bob"]
        try await send(from: alice, to: bob, "one")

        XCTAssertEqual(server.items.count, 1)
        _ = try await bob.courier.collect(
            as: bob.liveFid, recipientIds: [bob.liveFid], privkey: bobPriv, now: at(60)
        )
        XCTAssertTrue(server.items.isEmpty)

        // …and a second collect finds nothing rather than the same
        // message again.
        let again = try await bob.courier.collect(
            as: bob.liveFid, recipientIds: [bob.liveFid], privkey: bobPriv, now: at(90)
        )
        XCTAssertEqual(again.fetched, 0)
        XCTAssertEqual(try bob.chat.page(Conversation.id(type: .p2p, targetId: alice.liveFid)).messages.count, 1)
    }

    /// **A message we could not store is not a message we have had.**
    /// Filing is what earns the right to delete the DOCK's copy; when
    /// the store refuses the write, the remote copy is the only one
    /// left. It has to survive, stay unseen, and arrive on a later pass
    /// once the store is writable again.
    func testAMessageThatCannotBeStoredStaysOnTheDock() async throws {
        let alice = try makeSession(privkey: alicePriv, label: "alice")
        let bob = try makeSession(privkey: bobPriv, label: "bob")
        server.homeByFid[bob.liveFid] = [ServiceName.dock: "https://dock.bob"]
        try await send(from: alice, to: bob, "the only copy")
        XCTAssertEqual(server.items.count, 1)

        // Read-only store: the database file *and* its directory, or
        // SQLite just writes the journal alongside it and succeeds.
        let settingDir = bob.dataDirectory.deletingLastPathComponent()
        let store = settingDir.appendingPathComponent("store.sqlite")
        for sidecar in ["store.sqlite-wal", "store.sqlite-shm"] {
            let url = settingDir.appendingPathComponent(sidecar)
            if FileManager.default.fileExists(atPath: url.path) {
                try FileManager.default.setAttributes(
                    [.posixPermissions: 0o400], ofItemAtPath: url.path
                )
            }
        }
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o400], ofItemAtPath: store.path
        )
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o500], ofItemAtPath: settingDir.path
        )

        let refused = try await bob.courier.collect(
            as: bob.liveFid, recipientIds: [bob.liveFid], privkey: bobPriv, now: at(60)
        )
        XCTAssertEqual(refused.filed, 0)
        XCTAssertEqual(
            server.items.count, 1,
            "the DOCK copy is the only copy left — deleting it loses the message"
        )

        try FileManager.default.setAttributes(
            [.posixPermissions: 0o700], ofItemAtPath: settingDir.path
        )
        for sidecar in ["store.sqlite-wal", "store.sqlite-shm"] {
            let url = settingDir.appendingPathComponent(sidecar)
            if FileManager.default.fileExists(atPath: url.path) {
                try FileManager.default.setAttributes(
                    [.posixPermissions: 0o600], ofItemAtPath: url.path
                )
            }
        }
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o600], ofItemAtPath: store.path
        )

        let retried = try await bob.courier.collect(
            as: bob.liveFid, recipientIds: [bob.liveFid], privkey: bobPriv, now: at(120)
        )
        XCTAssertEqual(retried.filed, 1, "the message is neither seen nor skipped, so it arrives")
        XCTAssertEqual(
            try bob.chat.page(Conversation.id(type: .p2p, targetId: alice.liveFid))
                .messages.map(\.content),
            ["the only copy"]
        )
        XCTAssertTrue(server.items.isEmpty, "and now it is safe to delete")
    }

    /// A group's messages are addressed to the group, so a fetch that
    /// asked only for our own FID would collect none of them.
    func testGroupMessagesAreCollectedUnderTheGroupId() async throws {
        let alice = try makeSession(privkey: alicePriv, label: "alice")
        let bob = try makeSession(privkey: bobPriv, label: "bob")
        let squareId = "8e7d6c5b" + String(repeating: "0", count: 56)
        server.homeByFid[squareId] = [ServiceName.dock: "https://dock.square"]

        // Alice speaks in a square (unencrypted, so Bob needs no key).
        var thread = Conversation(
            id: Conversation.id(type: .square, targetId: squareId),
            targetId: squareId, type: .square
        )
        thread.unreadCount = 0
        try alice.conversations.upsert(thread)
        try alice.squares.upsert(Square(
            name: "The Square", members: [alice.liveFid, bob.liveFid],
            home: [ServiceName.dock: "https://dock.square"], id: squareId
        ))
        try alice.chat.sendText("hello all", in: thread.id, as: alice.liveFid, now: t0)
        _ = try await alice.courier.drainOutbox(as: alice.liveFid, ownDockUrl: "https://dock.alice", now: at(1))

        // Bob is a member, so his fetch names the square as well.
        try bob.squares.upsert(Square(
            name: "The Square", members: [alice.liveFid, bob.liveFid], id: squareId
        ))
        let ids = try bob.dockRecipientIds()
        XCTAssertEqual(Set(ids), [bob.liveFid, squareId])

        let received = try await bob.courier.collect(
            as: bob.liveFid, recipientIds: ids, privkey: bobPriv, now: at(60)
        )
        XCTAssertEqual(received.filed, 1)
        XCTAssertEqual(
            try bob.chat.page(Conversation.id(type: .square, targetId: squareId)).messages.map(\.content),
            ["hello all"]
        )
    }

    /// A message we cannot open is filed sealed rather than lost — the
    /// cue to go and ask for the key version it names.
    func testAMessageSealedToAKeyWeLackIsFiledSealed() async throws {
        let alice = try makeSession(privkey: alicePriv, label: "alice")
        let bob = try makeSession(privkey: bobPriv, label: "bob")
        let roomId = "room_b4c9a1f2e8d73065b4c9"
        server.homeByFid[roomId] = [ServiceName.dock: "https://dock.room"]

        var thread = Conversation(
            id: Conversation.id(type: .room, targetId: roomId), targetId: roomId, type: .room
        )
        thread.unreadCount = 0
        try alice.conversations.upsert(thread)
        try alice.rooms.upsert(Room(
            owner: alice.liveFid, members: [alice.liveFid, bob.liveFid],
            active: true, home: [ServiceName.dock: "https://dock.room"], id: roomId
        ))
        try alice.symkeys.rotate(for: roomId, now: t0)
        try alice.chat.sendText("room secret", in: thread.id, as: alice.liveFid, now: t0)
        _ = try await alice.courier.drainOutbox(as: alice.liveFid, ownDockUrl: nil, now: at(1))

        // Bob has the room but not its key.
        try bob.rooms.upsert(Room(
            owner: alice.liveFid, members: [alice.liveFid, bob.liveFid], active: true, id: roomId
        ))
        let received = try await bob.courier.collect(
            as: bob.liveFid, recipientIds: [bob.liveFid, roomId], privkey: bobPriv, now: at(60)
        )
        XCTAssertEqual(received, .init(fetched: 1, filed: 0, sealed: 1, other: 0))

        let stored = try bob.chat.page(Conversation.id(type: .room, targetId: roomId)).messages
        XCTAssertEqual(stored.count, 1, "kept, not dropped")
        XCTAssertTrue(try XCTUnwrap(stored.first).isSealed)
        XCTAssertEqual(stored.first?.symkeyVersion, 1, "and it says which key it needs")
    }

    /// **The key arrives after the message, and the message opens.**
    ///
    /// The whole path, with nothing stubbed: Alice sends into a room Bob
    /// cannot read, Bob files it sealed, Bob asks for the key, Alice's
    /// router answers, and Bob's *collect* of that answer has to go back
    /// and open the row it already filed.
    ///
    /// This is the regression the user hit. Every piece worked except the
    /// last one: the key landed in ``SymkeyStore``, ``SignalRouter``
    /// returned `learnedKeyFor`, and ``MessageCourier`` dropped it — so
    /// the transcript kept saying the key was not held while it sat in
    /// the store. Asking again could not help, because the asking had
    /// already succeeded.
    func testAKeyArrivingAfterTheMessageOpensWhatWasFiledSealed() async throws {
        let alice = try makeSession(privkey: alicePriv, label: "alice")
        let bob = try makeSession(privkey: bobPriv, label: "bob")
        server.homeByFid[alice.liveFid] = [ServiceName.dock: "https://dock.alice"]
        server.homeByFid[bob.liveFid] = [ServiceName.dock: "https://dock.bob"]
        // Each has to be able to seal to the other: the request and the
        // share are both P2P, and the courier seals what it queued clear.
        server.pubkeyByFid[alice.liveFid] = try pubkey(alicePriv).map { String(format: "%02x", $0) }.joined()
        server.pubkeyByFid[bob.liveFid] = try pubkey(bobPriv).map { String(format: "%02x", $0) }.joined()
        // The router seals its answer with ``ActiveSession/knownPubkey(of:)``,
        // which reads the address book and not the chain — so Alice has
        // to actually know Bob to be able to answer him.
        try alice.contacts.upsert(Contact(id: bob.liveFid, pubkey: try pubkey(bobPriv)))

        let roomId = "room_b4c9a1f2e8d73065b4c9"
        server.homeByFid[roomId] = [ServiceName.dock: "https://dock.room"]
        let room = Room(
            owner: alice.liveFid, members: [alice.liveFid, bob.liveFid],
            active: true, home: [ServiceName.dock: "https://dock.room"], id: roomId
        )
        let conversationId = Conversation.id(type: .room, targetId: roomId)

        // Alice owns the room, holds its key, and says something.
        try alice.rooms.upsert(room)
        var thread = Conversation(id: conversationId, targetId: roomId, type: .room)
        thread.unreadCount = 0
        try alice.conversations.upsert(thread)
        try alice.symkeys.rotate(for: roomId, now: t0)
        try alice.chat.sendText("the usual place", in: conversationId, as: alice.liveFid, now: t0)
        _ = try await alice.courier.drainOutbox(as: alice.liveFid, ownDockUrl: nil, now: at(1))

        // Bob is in the room and holds no key, so it files sealed.
        try bob.rooms.upsert(room)
        let sealedCollect = try await bob.courier.collect(
            as: bob.liveFid, recipientIds: [bob.liveFid, roomId], privkey: bobPriv, now: at(60)
        )
        XCTAssertEqual(sealedCollect.sealed, 1)
        XCTAssertTrue(try XCTUnwrap(bob.chat.page(conversationId).messages.first).isSealed)

        // Bob asks Alice for it, over the real request/answer path.
        for ask in KeyExchange.requests(
            entityId: roomId, kind: .symkey, from: bob.liveFid, to: [alice.liveFid]
        ) {
            try bob.outbox.enqueue(ask, in: Conversation.id(type: .p2p, targetId: alice.liveFid))
        }
        let askSent = try await bob.courier.drainOutbox(as: bob.liveFid, ownDockUrl: nil)
        XCTAssertEqual(askSent.sent, 1)

        // Alice's router answers it, and the share goes out.
        let answered = try await alice.courier.collect(
            as: alice.liveFid, recipientIds: [alice.liveFid], privkey: alicePriv
        )
        XCTAssertEqual(answered.routed, 1, "the request was answered")
        _ = try await alice.courier.drainOutbox(as: alice.liveFid, ownDockUrl: nil)

        // Bob collects the key — and the row he already filed opens.
        _ = try await bob.courier.collect(
            as: bob.liveFid, recipientIds: [bob.liveFid, roomId], privkey: bobPriv
        )
        XCTAssertNotNil(try bob.symkeys.key(for: roomId, version: 1), "the key landed")

        let stored = try bob.chat.page(conversationId).messages
        XCTAssertEqual(stored.count, 1, "opened in place, not filed a second time")
        XCTAssertFalse(try XCTUnwrap(stored.first).isSealed)
        XCTAssertEqual(stored.first?.content, "the usual place")
        XCTAssertEqual(
            try bob.conversations.get(id: conversationId)?.lastMessageContent,
            "the usual place",
            "and the thread's preview stops showing a row that said nothing"
        )
    }

    // MARK: - one identity, two devices

    /// **A→A, end to end.** Two Macs signed in as the same FID: the first
    /// owns a room and holds its key, the second was set up later and
    /// holds nothing. The second asks its own FID, and the key comes back.
    ///
    /// Every hop is the real one — the request built by ``KeyExchange``,
    /// the put onto our own DOCK, both devices collecting that FID, the
    /// session's own router answering with our own derived pubkey (there
    /// is no contact row for ourselves), and the share landing.
    ///
    /// Runs on the wall clock, not the fixture times: the outbox stamps
    /// what it queues — including the reply the courier queues for the
    /// router — with `Date()`, so a drain at a fixture time finds
    /// nothing due.
    ///
    /// The asking device collects **first**, which is the race it wins
    /// in practice: it is awake and polls right after the put. Its copy
    /// of its own question must be left on the DOCK, or the device that
    /// can answer never sees it.
    func testASecondDeviceGetsTheKeyByAskingItsOwnFid() async throws {
        let mac1 = try makeSession(privkey: alicePriv, label: "mac1")
        let mac2 = try makeSession(privkey: alicePriv, label: "mac2")
        let me = mac1.liveFid
        XCTAssertEqual(mac2.liveFid, me, "one identity")
        server.homeByFid[me] = [ServiceName.dock: "https://dock.alice"]

        let roomId = "room_b4c9a1f2e8d73065b4c9"
        let room = Room(owner: me, name: "Mine", members: [me, "F-carol"], active: true, id: roomId)
        try mac1.rooms.upsert(room)
        try mac2.rooms.upsert(room)
        let key = Data(repeating: 0x7E, count: 32)
        _ = try mac1.symkeys.store(key, for: roomId, version: 1, allowOverwrite: true)
        XCTAssertFalse(try mac2.symkeys.has(entityId: roomId))

        // mac2 asks its own FID.
        let asks = KeyExchange.requests(entityId: roomId, kind: .symkey, from: me, to: [me])
        XCTAssertEqual(asks.count, 1)
        for ask in asks {
            try mac2.outbox.enqueue(ask, in: Conversation.id(type: .p2p, targetId: me))
        }
        let sent = try await mac2.courier.drainOutbox(as: me, ownDockUrl: "https://dock.alice")
        XCTAssertEqual(sent.sent, 1)
        XCTAssertEqual(server.items.count, 1)

        // mac2 reads its own question back first. It has no key, so it
        // answers nothing — and it must not reap the item.
        let echo = try await mac2.courier.collect(
            as: me, recipientIds: [me], privkey: alicePriv
        )
        XCTAssertEqual(echo.fetched, 1)
        XCTAssertEqual(try mac2.outbox.count(), 0, "no answer from the device without the key")
        XCTAssertEqual(server.items.count, 1, "our own question is left for our other device")

        // mac1 collects the same item and answers it.
        let asked = try await mac1.courier.collect(
            as: me, recipientIds: [me], privkey: alicePriv
        )
        XCTAssertEqual(asked.routed, 1)
        XCTAssertEqual(try mac1.outbox.count(), 1, "the share is queued")
        _ = try await mac1.courier.drainOutbox(as: me, ownDockUrl: "https://dock.alice")

        // mac1 collecting its own answer back leaves it in place too —
        // the share is for mac2. (This cursor-less collect also re-reads
        // the request and answers it again; in the app the per-DOCK
        // cursor stops the re-read, and a second share of a held version
        // is a no-op for the receiver either way.)
        _ = try await mac1.courier.collect(as: me, recipientIds: [me], privkey: alicePriv)
        XCTAssertTrue(
            server.items.contains { item in
                (try? ImMessage.fromWireBytes(item.payload))?.contentType == .symkey
            },
            "our own share is left for our other device"
        )

        // mac2 collects, and now holds the key.
        _ = try await mac2.courier.collect(as: me, recipientIds: [me], privkey: alicePriv)
        XCTAssertEqual(try mac2.symkeys.key(for: roomId, version: 1), key)
    }

    /// The delete rule still applies to everything that is not our own
    /// traffic: a P2P message someone else sent us is reaped once read.
    /// (``testCollectingDeletesWhatItFiled`` pins the filed case; this
    /// pins that the self-sender carve-out did not widen.)
    func testASignalFromSomeoneElseIsStillDeletedOnceRead() async throws {
        let alice = try makeSession(privkey: alicePriv, label: "alice")
        let bob = try makeSession(privkey: bobPriv, label: "bob")
        server.homeByFid[alice.liveFid] = [ServiceName.dock: "https://dock.alice"]
        server.pubkeyByFid[alice.liveFid] = try pubkey(alicePriv).map { String(format: "%02x", $0) }.joined()
        let roomId = "room_b4c9a1f2e8d73065b4c9"

        let ask = KeyExchange.request(entityId: roomId, from: bob.liveFid, to: alice.liveFid)
        try bob.outbox.enqueue(ask, in: Conversation.id(type: .p2p, targetId: alice.liveFid))
        _ = try await bob.courier.drainOutbox(as: bob.liveFid, ownDockUrl: "https://dock.bob")
        XCTAssertEqual(server.items.count, 1)

        _ = try await alice.courier.collect(
            as: alice.liveFid, recipientIds: [alice.liveFid], privkey: alicePriv
        )
        XCTAssertTrue(server.items.isEmpty)
    }

    // MARK: - failure handling

    /// No address and no DOCK of our own is **permanent**: nothing about
    /// waiting produces one.
    func testNoRouteFailsPermanently() async throws {
        let alice = try makeSession(privkey: alicePriv, label: "alice")
        let bob = try makeSession(privkey: bobPriv, label: "bob")
        // No home for Bob, and Alice has no DOCK.
        let conversationId = Conversation.id(type: .p2p, targetId: bob.liveFid)
        var thread = Conversation(id: conversationId, targetId: bob.liveFid, type: .p2p)
        thread.unreadCount = 0
        try alice.conversations.upsert(thread)
        let sent = try alice.chat.sendText(
            "into the void", in: conversationId, as: alice.liveFid,
            keys: .init(privkey: alicePriv, recipientPubkey: try pubkey(bobPriv)), now: t0
        )

        let report = try await alice.courier.drainOutbox(as: alice.liveFid, ownDockUrl: nil, now: at(1))
        XCTAssertEqual(report, .init(attempted: 1, sent: 0, retrying: 0, failed: 1))
        XCTAssertEqual(try alice.outbox.count(), 0, "not retried forever")
        XCTAssertEqual(
            try alice.messages.get(messageId: sent.id!, in: conversationId)?.status, .failed
        )
    }

    /// A DOCK that is there but refuses is **transient**: the address
    /// was real, the network was not, so the message stays queued and
    /// backs off.
    func testARefusingDockIsRetried() async throws {
        let alice = try makeSession(privkey: alicePriv, label: "alice")
        let bob = try makeSession(privkey: bobPriv, label: "bob")
        server.homeByFid[bob.liveFid] = [ServiceName.dock: "https://dock.bob"]
        server.refusePuts = true

        let conversationId = Conversation.id(type: .p2p, targetId: bob.liveFid)
        var thread = Conversation(id: conversationId, targetId: bob.liveFid, type: .p2p)
        thread.unreadCount = 0
        try alice.conversations.upsert(thread)
        try alice.chat.sendText(
            "will not land yet", in: conversationId, as: alice.liveFid,
            keys: .init(privkey: alicePriv, recipientPubkey: try pubkey(bobPriv)), now: t0
        )

        let report = try await alice.courier.drainOutbox(
            as: alice.liveFid, ownDockUrl: "https://dock.alice", now: at(1)
        )
        XCTAssertEqual(report, .init(attempted: 1, sent: 0, retrying: 1, failed: 0))
        XCTAssertEqual(try alice.outbox.count(), 1, "still queued")
        XCTAssertTrue(try alice.outbox.due(now: at(1)).isEmpty, "and backed off")

        // The DOCK comes back; the next drain gets it out.
        server.refusePuts = false
        let later = try await alice.courier.drainOutbox(
            as: alice.liveFid, ownDockUrl: "https://dock.alice", now: at(30)
        )
        XCTAssertEqual(later.sent, 1)
        XCTAssertEqual(try alice.outbox.count(), 0)
    }

    /// Rubbish at the DOCK is skipped, not fatal — one bad item must not
    /// stop a collect.
    func testUndecodableItemsAreSkipped() async throws {
        let bob = try makeSession(privkey: bobPriv, label: "bob")
        server.items.append(FakeDock.Item(
            id: "junk-1", recipients: [bob.liveFid], payload: Data([0x00, 0x01])
        ))
        let received = try await bob.courier.collect(
            as: bob.liveFid, recipientIds: [bob.liveFid], privkey: bobPriv, now: at(1)
        )
        XCTAssertEqual(received.fetched, 1)
        XCTAssertEqual(received.other, 1)
        XCTAssertEqual(received.filed, 0)
    }

    /// A collect over several DOCKs sums one report per server. `held`
    /// and `routed` used to fall back to their defaults in the sum, so
    /// the app's poller — which always takes that path — reported every
    /// message request and every routed signal as zero.
    func testSummingReportsKeepsEveryCount() {
        let a = MessageCourier.ReceiveReport(fetched: 5, filed: 1, sealed: 1, held: 1, routed: 1, other: 2)
        let b = MessageCourier.ReceiveReport(fetched: 7, filed: 2, sealed: 0, held: 3, routed: 2, other: 1)
        XCTAssertEqual(
            a.adding(b),
            MessageCourier.ReceiveReport(fetched: 12, filed: 3, sealed: 1, held: 4, routed: 3, other: 3)
        )
    }

    /// The DOCK put is hashed with a **single** SHA-256 — the file
    /// endpoints hash twice, and this one does not. Matching the
    /// endpoint is the only thing that matters, and hashing twice would
    /// have every put rejected.
    func testPutIsStampedWithASingleSha256() async throws {
        let alice = try makeSession(privkey: alicePriv, label: "alice")
        let bob = try makeSession(privkey: bobPriv, label: "bob")
        server.homeByFid[bob.liveFid] = [ServiceName.dock: "https://dock.bob"]
        try await send(from: alice, to: bob, "check the hash")

        let put = try XCTUnwrap(server.lastPut)
        let expected = Hash.sha256(put.payload).map { String(format: "%02x", $0) }.joined()
        XCTAssertEqual(put.dataHash, expected)
        XCTAssertNotEqual(
            put.dataHash,
            Hash.doubleSha256(put.payload).map { String(format: "%02x", $0) }.joined(),
            "not the file endpoints' double hash"
        )
    }

    /// The put says who it is for, what kind of payload it is, and —
    /// when the recipient's DOCK is not ours — which DOCK to forward to.
    func testPutCarriesRecipientsTypeAndForwardTarget() async throws {
        let alice = try makeSession(privkey: alicePriv, label: "alice")
        let bob = try makeSession(privkey: bobPriv, label: "bob")
        server.homeByFid[bob.liveFid] = [ServiceName.dock: "https://dock.bob"]
        try await send(from: alice, to: bob, "hello")

        let put = try XCTUnwrap(server.lastPut)
        XCTAssertEqual(put.params["recipients"] as? [String], [bob.liveFid])
        XCTAssertEqual(put.params["dataType"] as? String, "IM")
        XCTAssertEqual(put.params["targetDockUrl"] as? String, "https://dock.bob")
    }

    /// Forwarding to yourself is just storing, so the field is dropped
    /// when the target DOCK *is* ours.
    func testForwardTargetIsDroppedWhenItIsOurOwnDock() async throws {
        let alice = try makeSession(privkey: alicePriv, label: "alice")
        let bob = try makeSession(privkey: bobPriv, label: "bob")
        server.homeByFid[bob.liveFid] = [ServiceName.dock: "https://dock.shared"]
        try await send(from: alice, to: bob, "same dock", ownDockUrl: "https://dock.shared")

        XCTAssertNil(try XCTUnwrap(server.lastPut).params["targetDockUrl"])
    }

    // MARK: - helpers

    private func send(
        from alice: ActiveSession,
        to bob: ActiveSession,
        _ text: String,
        ownDockUrl: String? = "https://dock.alice"
    ) async throws {
        let conversationId = Conversation.id(type: .p2p, targetId: bob.liveFid)
        if try alice.conversations.get(id: conversationId) == nil {
            var thread = Conversation(id: conversationId, targetId: bob.liveFid, type: .p2p)
            thread.unreadCount = 0
            try alice.conversations.upsert(thread)
        }
        try alice.chat.sendText(
            text, in: conversationId, as: alice.liveFid,
            keys: .init(privkey: alicePriv, recipientPubkey: try pubkey(bobPriv)), now: t0
        )
        _ = try await alice.courier.drainOutbox(
            as: alice.liveFid, ownDockUrl: ownDockUrl, now: at(1)
        )
    }
}

/// A DOCK that behaves like one: it takes items, hands them to whoever
/// they are addressed to, and forgets them when deleted. Also answers
/// `base.freerByIds` so a recipient's `home` can be resolved.
private final class FakeDock: FapiCalling, @unchecked Sendable {

    struct Item {
        let id: String
        let recipients: [String]
        let payload: Data
    }

    struct Put {
        let params: [String: Any]
        let payload: Data
        let dataHash: String?
    }

    var items: [Item] = []
    var homeByFid: [String: [String: String]] = [:]
    /// Published pubkeys, hex. A clear P2P message is sealed to one on
    /// its way out.
    var pubkeyByFid: [String: String] = [:]
    var refusePuts = false
    var lastPut: Put?
    /// Run at the start of `dock.put`, so a test can see the state of
    /// things *while* a delivery is on the wire.
    var onPut: (() -> Void)?
    private var nextId = 1

    func call(
        api: String, params: Data?, fcdsl: Data?, binary: Data?,
        sid: String?, via: String?, maxCost: Int64?, timeoutMs: Int
    ) async throws -> FapiClient.Reply {
        try await handle(api: api, params: params, fcdsl: fcdsl, binary: binary, dataHash: nil)
    }

    func callWithHashedBinary(
        api: String, params: Data?, binary: Data, dataHash: String?,
        sid: String?, via: String?, maxCost: Int64?, timeoutMs: Int
    ) async throws -> FapiClient.Reply {
        try await handle(api: api, params: params, fcdsl: nil, binary: binary, dataHash: dataHash)
    }

    private func handle(
        api: String, params: Data?, fcdsl: Data?, binary: Data?, dataHash: String?
    ) async throws -> FapiClient.Reply {
        func json(_ data: Data?) -> [String: Any] {
            guard let data,
                  let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
            else { return [:] }
            return obj
        }

        switch api {
        case "base.freerByIds":
            let ids = json(fcdsl)["ids"] as? [String] ?? []
            var out: [String: Any] = [:]
            for id in ids {
                var record: [String: Any] = ["id": id]
                if let home = homeByFid[id] { record["home"] = home }
                if let pubkey = pubkeyByFid[id] { record["pubkey"] = pubkey }
                out[id] = record
            }
            return reply(out.isEmpty ? nil : out)

        case "dock.put":
            onPut?()
            let p = json(params)
            lastPut = Put(params: p, payload: binary ?? Data(), dataHash: dataHash)
            if refusePuts { return reply(nil, code: 500, message: "dock is full") }
            let id = "dock-\(nextId)"
            nextId += 1
            items.append(Item(
                id: id,
                recipients: p["recipients"] as? [String] ?? [],
                payload: binary ?? Data()
            ))
            return reply(["id": id, "size": (binary?.count ?? 0)])

        case "dock.fetch":
            let wanted = Set(json(params)["recipientIds"] as? [String] ?? [])
            let matching = items.filter { !Set($0.recipients).isDisjoint(with: wanted) }
            guard !matching.isEmpty else { return reply(nil, code: 404, message: "nothing waiting") }
            return reply(matching.map {
                [
                    "id": $0.id,
                    "recipients": $0.recipients,
                    "dataType": "IM",
                    "dataBase64": $0.payload.base64EncodedString(),
                ]
            })

        case "dock.delete":
            let id = json(params)["id"] as? String
            let before = items.count
            items.removeAll { $0.id == id }
            return items.count == before
                ? reply(nil, code: 404, message: "no such item")
                : reply(["deleted": true])

        default:
            return reply(nil, code: 404, message: "unhandled \(api)")
        }
    }

    private func reply(_ data: Any?, code: Int = 0, message: String = "ok") -> FapiClient.Reply {
        var response = FapiResponse(code: code, message: message)
        if let data {
            response.data = try? JSONSerialization.data(
                withJSONObject: data, options: [.fragmentsAllowed]
            )
        }
        return FapiClient.Reply(response: response, binary: nil, messageId: 1)
    }
}
