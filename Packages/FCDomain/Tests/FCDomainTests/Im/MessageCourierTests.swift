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
        return try configure.unlockMain(fid: info.fid, fapi: server)
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
    var refusePuts = false
    var lastPut: Put?
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
                out[id] = record
            }
            return reply(out.isEmpty ? nil : out)

        case "dock.put":
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
