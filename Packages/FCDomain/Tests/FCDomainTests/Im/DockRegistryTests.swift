import XCTest
import FCCore
import FCTransport
import FCStorage
@testable import FCDomain

/// Delivery across **more than one** DOCK server — the shape the network
/// actually has, and the one a single connection cannot serve.
///
/// Every party declares its own DOCK in its `home`: a FID's in
/// `freer.home`, a square's in `square.home`. So a message to a square
/// belongs on the square's server, a message to a person belongs on
/// theirs, and neither is ours. These tests run three servers at once
/// and assert the traffic lands on the right one.
final class DockRegistryTests: XCTestCase {

    private var baseDir: URL!
    private var manager: ConfigureManager!
    private var network: DockNetwork!

    private let alicePriv = Data(repeating: 0xA1, count: 32)
    private let bobPriv = Data(repeating: 0xB2, count: 32)

    /// Own-DOCK addresses as Settings holds them — bare `host:port`.
    private let aliceDock = "dock.alice:8500"
    private let bobDock = "dock.bob:8500"
    /// The same servers as a `home` map spells them. A home value is a
    /// SID or a scheme-qualified URL and never a bare host:port, so
    /// these deliberately differ from the two above: reconciling the two
    /// spellings is exactly what ``FudpUrl`` is for.
    private let aliceDockHome = "fudp://dock.alice:8500"
    private let bobDockHome = "fudp://dock.bob:8500"
    private let squareDock = "https://dock.square"

    private let squareId = "8e7d6c5b" + String(repeating: "0", count: 56)

    private let t0 = Date(timeIntervalSince1970: 1_755_100_000)
    private func at(_ seconds: TimeInterval) -> Date { t0.addingTimeInterval(seconds) }

    override func setUpWithError() throws {
        baseDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("DockRegistryTests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: baseDir, withIntermediateDirectories: true)
        manager = try ConfigureManager(baseDirectory: baseDir)
        network = DockNetwork()
    }

    override func tearDownWithError() throws {
        network = nil
        manager = nil
        if let baseDir { try? FileManager.default.removeItem(at: baseDir) }
    }

    /// A session whose own DOCK is `ownDock`, wired to the shared
    /// network so it can reach the others by URL.
    private func makeSession(
        privkey: Data, label: String, ownDock: String
    ) async throws -> ActiveSession {
        let configure = try manager.createConfigure(
            password: Data("\(label)-pwd".utf8), kdfKind: .legacySha256
        )
        let info = try configure.addMain(privkey: privkey, label: label)
        let session = try configure.unlockMain(fid: info.fid, fapi: network.server(at: ownDock))
        let network = self.network!
        await session.dockRegistry.configure(
            ownDockUrl: ownDock,
            ownClient: network.server(at: ownDock),
            connect: { url in try network.connect(to: url) }
        )
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

    // MARK: - sending

    /// The failure this whole seam exists for: a message for someone on
    /// a *different* server must go to that server, over a connection to
    /// it — not be handed to ours with a note asking it to forward.
    func testAMessageGoesDirectlyToTheRecipientsOwnDock() async throws {
        let alice = try await makeSession(privkey: alicePriv, label: "alice", ownDock: aliceDock)
        let bob = try await makeSession(privkey: bobPriv, label: "bob", ownDock: bobDock)
        network.homeByFid[bob.liveFid] = [ServiceName.dock: bobDockHome]

        try await sendP2P(from: alice, to: bob, "over here")

        XCTAssertEqual(network.items(at: bobDock).count, 1, "landed on Bob's DOCK")
        XCTAssertTrue(network.items(at: aliceDock).isEmpty, "and not on ours")
        // A direct put is one hop: there is nothing to forward to,
        // because the connection already ends at the target.
        XCTAssertNil(network.lastPut(at: bobDock)?.params["targetDockUrl"])
    }

    /// A square's messages belong on the square's server, whoever sends
    /// them and whatever server the sender is configured with.
    func testASquareMessageGoesToTheSquaresOwnDock() async throws {
        let alice = try await makeSession(privkey: alicePriv, label: "alice", ownDock: aliceDock)
        try await sendToSquare(from: alice, "hello all")

        XCTAssertEqual(network.items(at: squareDock).count, 1)
        XCTAssertTrue(network.items(at: aliceDock).isEmpty)
    }

    /// When the recipient's DOCK *is* ours, the same route resolves to
    /// the connection we already hold and the put is a plain local
    /// store — no second socket, no forwarding field.
    func testARecipientOnOurOwnDockIsAPlainLocalStore() async throws {
        let alice = try await makeSession(privkey: alicePriv, label: "alice", ownDock: aliceDock)
        let bob = try await makeSession(privkey: bobPriv, label: "bob", ownDock: aliceDock)
        // Spelled differently from Alice's own — the same machine.
        network.homeByFid[bob.liveFid] = [ServiceName.dock: "fudp://dock.alice:8500"]

        try await sendP2P(from: alice, to: bob, "same roof")

        XCTAssertEqual(network.items(at: aliceDock).count, 1)
        XCTAssertNil(network.lastPut(at: aliceDock)?.params["targetDockUrl"])
        XCTAssertEqual(network.connectAttempts, 0, "the existing connection was reused")
    }

    // MARK: - receiving

    /// The other half of the reported failure: nothing arrives, because
    /// a group's messages rest on the group's DOCK and we were only ever
    /// asking our own.
    func testCollectPollsEveryGroupsDockAndNotJustOurOwn() async throws {
        let alice = try await makeSession(privkey: alicePriv, label: "alice", ownDock: aliceDock)
        let bob = try await makeSession(privkey: bobPriv, label: "bob", ownDock: bobDock)
        network.homeByFid[bob.liveFid] = [ServiceName.dock: bobDockHome]

        try await sendToSquare(from: alice, "hello all")
        try await sendP2P(from: alice, to: bob, "and privately")

        // Bob is a member of the square, so his registry knows to ask
        // the square's server for it.
        try bob.squares.upsert(Square(
            name: "The Square", members: [alice.liveFid, bob.liveFid],
            home: [ServiceName.dock: squareDock], id: squareId
        ))
        await bob.refreshDockRegistry()

        let targets = await bob.dockRegistry.fetchTargets()
        XCTAssertEqual(
            Set(targets.map(\.dockUrl)),
            ["fudp://dock.bob:8500", "fudp://dock.square:8500"]
        )

        let received = try await bob.courier.collect(as: bob.liveFid, privkey: bobPriv, now: at(60))
        XCTAssertEqual(received.filed, 2, "the square message and the private one")
        XCTAssertEqual(
            try bob.chat.page(Conversation.id(type: .square, targetId: squareId)).messages.map(\.content),
            ["hello all"]
        )
        XCTAssertEqual(
            try bob.chat.page(Conversation.id(type: .p2p, targetId: alice.liveFid)).messages.map(\.content),
            ["and privately"]
        )
    }

    /// A group's item is one copy that every member fetches. Deleting it
    /// after *we* have read it takes it from everyone who has not — so
    /// only items addressed to us alone are cleared, and the per-DOCK
    /// cursor is what stops the rest coming back.
    func testGroupItemsSurviveCollectionButOurOwnAreCleared() async throws {
        let alice = try await makeSession(privkey: alicePriv, label: "alice", ownDock: aliceDock)
        let bob = try await makeSession(privkey: bobPriv, label: "bob", ownDock: bobDock)
        network.homeByFid[bob.liveFid] = [ServiceName.dock: bobDockHome]

        try await sendToSquare(from: alice, "for the whole square")
        try await sendP2P(from: alice, to: bob, "for you only")

        try bob.squares.upsert(Square(
            name: "The Square", members: [alice.liveFid, bob.liveFid],
            home: [ServiceName.dock: squareDock], id: squareId
        ))
        await bob.refreshDockRegistry()
        _ = try await bob.courier.collect(as: bob.liveFid, privkey: bobPriv, now: at(60))

        XCTAssertEqual(
            network.items(at: squareDock).count, 1,
            "left for the members who have not read it yet"
        )
        XCTAssertTrue(
            network.items(at: bobDock).isEmpty,
            "addressed to us alone, so taking delivery clears it"
        )
    }

    /// One unreachable server must not silence the others. The failure
    /// is remembered so the next pass leaves it alone, rather than
    /// spending a timeout on it every cycle.
    func testAnUnreachableDockIsSkippedWithoutStoppingTheRest() async throws {
        let alice = try await makeSession(privkey: alicePriv, label: "alice", ownDock: aliceDock)
        let bob = try await makeSession(privkey: bobPriv, label: "bob", ownDock: bobDock)
        network.homeByFid[bob.liveFid] = [ServiceName.dock: bobDockHome]

        try await sendP2P(from: alice, to: bob, "still gets through")
        try bob.squares.upsert(Square(
            name: "The Square", members: [alice.liveFid, bob.liveFid],
            home: [ServiceName.dock: squareDock], id: squareId
        ))
        await bob.refreshDockRegistry()

        network.refuseConnections.insert("fudp://dock.square:8500")
        let received = try await bob.courier.collect(as: bob.liveFid, privkey: bobPriv, now: at(60))
        XCTAssertEqual(received.filed, 1, "the reachable DOCK still delivered")

        // Cooling down: the dead server is not dialled again straight away.
        let before = network.connectAttempts
        _ = await bob.dockRegistry.client(for: squareDock, now: at(61))
        XCTAssertEqual(network.connectAttempts, before, "not retried during the cooldown")

        // …and it is retried once the cooldown has passed.
        _ = await bob.dockRegistry.client(
            for: squareDock, now: at(60 + DockRegistry.retryCooldown + 1)
        )
        XCTAssertEqual(network.connectAttempts, before + 1)
    }

    /// One fetch per server, not per entity: a group hosted on our own
    /// DOCK shares the round trip with our P2P inbox.
    func testEntitiesSharingAServerShareOneFetch() async throws {
        let alice = try await makeSession(privkey: alicePriv, label: "alice", ownDock: aliceDock)
        try alice.squares.upsert(Square(
            name: "The Square", members: [alice.liveFid],
            home: [ServiceName.dock: aliceDockHome], id: squareId
        ))
        await alice.refreshDockRegistry()

        let targets = await alice.dockRegistry.fetchTargets()
        XCTAssertEqual(targets.count, 1)
        XCTAssertEqual(targets.first?.dockUrl, "fudp://dock.alice:8500")
        XCTAssertEqual(Set(targets.first?.recipientIds ?? []), [alice.liveFid, squareId])
    }

    // MARK: - helpers

    private func sendP2P(
        from alice: ActiveSession, to bob: ActiveSession, _ text: String
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
        _ = try await alice.courier.drainOutbox(as: alice.liveFid, now: at(1))
    }

    private func sendToSquare(from alice: ActiveSession, _ text: String) async throws {
        let conversationId = Conversation.id(type: .square, targetId: squareId)
        if try alice.conversations.get(id: conversationId) == nil {
            var thread = Conversation(id: conversationId, targetId: squareId, type: .square)
            thread.unreadCount = 0
            try alice.conversations.upsert(thread)
        }
        try alice.squares.upsert(Square(
            name: "The Square", members: [alice.liveFid],
            home: [ServiceName.dock: squareDock], id: squareId
        ))
        try alice.chat.sendText(text, in: conversationId, as: alice.liveFid, now: t0)
        _ = try await alice.courier.drainOutbox(as: alice.liveFid, now: at(1))
    }
}

// MARK: - a network of DOCKs

/// Several DOCK servers, each with its own store, addressed by URL —
/// what the single-server fake could not express.
private final class DockNetwork: @unchecked Sendable {

    struct Item {
        let id: String
        let recipients: [String]
        let payload: Data
    }

    struct Put {
        let params: [String: Any]
        let payload: Data
    }

    /// Every FID's `home`, answered by whichever server is asked —
    /// the chain is the same wherever you read it from.
    var homeByFid: [String: [String: String]] = [:]
    /// URLs that refuse to accept a connection at all.
    var refuseConnections: Set<String> = []
    /// How many times opening a new client was *attempted* — successes
    /// and refusals alike, so a test can prove a connection was reused
    /// or a cooldown respected. Counting only successes would make a
    /// refused dial indistinguishable from one never made.
    private(set) var connectAttempts = 0

    private var servers: [String: DockServer] = [:]
    private var nextId = 1

    enum Failure: Error { case unreachable(String) }

    func server(at url: String) -> DockServer {
        let key = FudpUrl.normalize(url) ?? url
        if let existing = servers[key] { return existing }
        let server = DockServer(network: self)
        servers[key] = server
        return server
    }

    /// What ``DockRegistry`` calls to open a client for a URL.
    func connect(to url: String) throws -> DockServer {
        let key = FudpUrl.normalize(url) ?? url
        connectAttempts += 1
        if refuseConnections.contains(key) { throw Failure.unreachable(key) }
        return server(at: key)
    }

    func items(at url: String) -> [Item] { server(at: url).items }
    func lastPut(at url: String) -> Put? { server(at: url).lastPut }

    func mintId() -> String {
        defer { nextId += 1 }
        return "dock-\(nextId)"
    }
}

/// One DOCK server: takes items, hands them to whoever they are
/// addressed to, and answers `base.freerByIds` from the shared chain.
private final class DockServer: FapiCalling, @unchecked Sendable {

    var items: [DockNetwork.Item] = []
    var lastPut: DockNetwork.Put?

    private unowned let network: DockNetwork

    init(network: DockNetwork) { self.network = network }

    func call(
        api: String, params: Data?, fcdsl: Data?, binary: Data?,
        sid: String?, via: String?, maxCost: Int64?, timeoutMs: Int
    ) async throws -> FapiClient.Reply {
        handle(api: api, params: params, fcdsl: fcdsl, binary: binary)
    }

    func callWithHashedBinary(
        api: String, params: Data?, binary: Data, dataHash: String?,
        sid: String?, via: String?, maxCost: Int64?, timeoutMs: Int
    ) async throws -> FapiClient.Reply {
        handle(api: api, params: params, fcdsl: nil, binary: binary)
    }

    private func handle(
        api: String, params: Data?, fcdsl: Data?, binary: Data?
    ) -> FapiClient.Reply {
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
                if let home = network.homeByFid[id] { record["home"] = home }
                out[id] = record
            }
            return reply(out.isEmpty ? nil : out)

        case "dock.put":
            let p = json(params)
            lastPut = DockNetwork.Put(params: p, payload: binary ?? Data())
            let id = network.mintId()
            items.append(DockNetwork.Item(
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
