import XCTest
import FCCore
import FCTransport
import FCStorage
@testable import FCDomain

/// ``FirstFchBoard``: posting when you have nothing, and reading what
/// other people posted when you have something.
///
/// The board is one inbox everyone shares, so almost every rule here is
/// about *not showing* something: a post that is not a request, a second
/// post from the same asker, and an asker who has since been funded.
final class FirstFchBoardTests: XCTestCase {

    private var baseDir: URL!
    private var manager: ConfigureManager!
    private var chain: FakeChain!

    private let alicePriv = Data(repeating: 0xA1, count: 32)
    private let bobPriv = Data(repeating: 0xB2, count: 32)

    private let boardDock = "fudp://dock.board:8500"

    override func setUpWithError() throws {
        baseDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("FirstFchBoardTests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: baseDir, withIntermediateDirectories: true)
        manager = try ConfigureManager(baseDirectory: baseDir)
        chain = FakeChain()
        chain.homeByFid[NobodyBoard.defaultNobodyFid] = [ServiceName.dock: boardDock]
    }

    override func tearDownWithError() throws {
        chain = nil
        manager = nil
        if let baseDir { try? FileManager.default.removeItem(at: baseDir) }
    }

    /// A session whose every FAPI call — chain lookups and the board's
    /// DOCK alike — is answered by the one fake server.
    private func makeSession(privkey: Data, label: String) async throws -> ActiveSession {
        let configure = try manager.createConfigure(
            password: Data("\(label)-pwd".utf8), kdfKind: .legacySha256
        )
        let info = try configure.addMain(privkey: privkey, label: label)
        let server = chain.server
        let session = try configure.unlockMain(fid: info.fid, fapi: server)
        await session.dockRegistry.configure(
            ownDockUrl: "dock.own:8500", ownClient: server, connect: { _ in server }
        )
        return session
    }

    // MARK: - asking

    /// The post goes to the board's own DOCK, addressed to the board,
    /// with the body sealed — and it is *not* a conversation: nothing is
    /// filed, nothing is queued, nothing appears in the chat list.
    func testPostingLandsOnTheBoardsDockAndCreatesNoConversation() async throws {
        let bob = try await makeSession(privkey: bobPriv, label: "bob")

        try await bob.firstFchBoard.post(
            note: "just installed", as: bob.liveFid, privkey: bobPriv
        )

        XCTAssertEqual(chain.items.count, 1)
        let item = try XCTUnwrap(chain.items.first)
        XCTAssertEqual(item.recipients, [NobodyBoard.defaultNobodyFid])

        let posted = try ImMessage.fromWireBytes(item.payload)
        XCTAssertTrue(posted.isSealed, "a DOCK is a third party — nothing travels open")
        XCTAssertEqual(posted.targetId, NobodyBoard.defaultNobodyFid)

        XCTAssertTrue(try bob.conversations.all().isEmpty, "the board is not a chat")
        XCTAssertTrue(try bob.outbox.due(now: Date()).isEmpty, "and not an outbox entry")
    }

    // MARK: - reading

    func testAHelperReadsWhatANewcomerPosted() async throws {
        let bob = try await makeSession(privkey: bobPriv, label: "bob")
        let alice = try await makeSession(privkey: alicePriv, label: "alice")
        try await bob.firstFchBoard.post(note: "hello", as: bob.liveFid, privkey: bobPriv)

        let result = await alice.firstFchBoard.fetch()
        XCTAssertNil(result.error)
        XCTAssertEqual(result.requests.map(\.requesterFid), [bob.liveFid])
        XCTAssertEqual(result.requests.first?.note, "hello")
    }

    /// Someone who asked three times is one row, at their newest post —
    /// a helper is looking at a list of people, not a list of messages.
    func testOnlyTheNewestPostPerAskerIsShown() async throws {
        let bob = try await makeSession(privkey: bobPriv, label: "bob")
        let alice = try await makeSession(privkey: alicePriv, label: "alice")
        try await bob.firstFchBoard.post(note: "first try", as: bob.liveFid, privkey: bobPriv)
        try await bob.firstFchBoard.post(note: "still nothing", as: bob.liveFid, privkey: bobPriv)

        let result = await alice.firstFchBoard.fetch()
        XCTAssertEqual(result.requests.count, 1)
        XCTAssertEqual(result.requests.first?.note, "still nothing")
    }

    /// An asker who now holds coins was already helped — or is farming —
    /// and either way is no longer a request anybody can answer.
    func testAFundedAskerIsNoLongerShown() async throws {
        let bob = try await makeSession(privkey: bobPriv, label: "bob")
        let alice = try await makeSession(privkey: alicePriv, label: "alice")
        try await bob.firstFchBoard.post(note: "hello", as: bob.liveFid, privkey: bobPriv)

        chain.balanceByFid[bob.liveFid] = 101_000_000
        let result = await alice.firstFchBoard.fetch()
        XCTAssertNil(result.error)
        XCTAssertTrue(result.requests.isEmpty)
    }

    /// The watermark covers **everything retrieved**, not just what
    /// survived the filters. A cursor that only counted shown rows would
    /// re-read every answered ask on the board forever.
    func testTheCursorMovesPastPostsThatWereFilteredOut() async throws {
        let bob = try await makeSession(privkey: bobPriv, label: "bob")
        let alice = try await makeSession(privkey: alicePriv, label: "alice")
        try await bob.firstFchBoard.post(note: "hello", as: bob.liveFid, privkey: bobPriv)
        chain.balanceByFid[bob.liveFid] = 101_000_000

        let first = await alice.firstFchBoard.fetch()
        XCTAssertTrue(first.requests.isEmpty)
        XCTAssertGreaterThan(first.maxCreateTime, 0)

        // Reading again from that watermark asks the server for nothing
        // older, and the funded post is behind it.
        let second = await alice.firstFchBoard.fetch(newerThan: first.maxCreateTime)
        XCTAssertTrue(second.requests.isEmpty)
        XCTAssertEqual(second.maxCreateTime, first.maxCreateTime)
        XCTAssertEqual(chain.lastFetchGt, String(first.maxCreateTime))
    }

    /// Chatter, spam and another protocol's traffic all land in the same
    /// inbox. Only the template is a row.
    func testNonTemplatePostsAreNotRows() async throws {
        let alice = try await makeSession(privkey: alicePriv, label: "alice")
        var noise = ImMessage.text(
            type: .p2p, from: "FMallory", to: NobodyBoard.defaultNobodyFid, "send me your key"
        )
        noise.setId(fudpId: ImMessage.newFudpId())
        try noise.sealBody(privkey: Data(repeating: 0x99, count: 32), recipientPubkey: NobodyBoard.pubkey)
        chain.store(try noise.toWireBytes(), for: [NobodyBoard.defaultNobodyFid])

        let result = await alice.firstFchBoard.fetch()
        XCTAssertNil(result.error)
        XCTAssertTrue(result.requests.isEmpty)
        XCTAssertGreaterThan(result.maxCreateTime, 0, "still read past it")
    }

    /// Reading a nobody's inbox is a fetch for an inbox that is not ours,
    /// which a DOCK may simply refuse. A refusal and an empty board are
    /// the same blank screen unless the reason is carried out.
    func testARefusedReadIsReportedRatherThanLookingEmpty() async throws {
        let alice = try await makeSession(privkey: alicePriv, label: "alice")
        chain.refuseFetch = true

        let result = await alice.firstFchBoard.fetch()
        XCTAssertTrue(result.requests.isEmpty)
        XCTAssertNotNil(result.error)
    }

    /// No board record on chain means no address to read or write, and
    /// both sides say so rather than silently doing nothing.
    func testAnUnreachableBoardIsAnError() async throws {
        let bob = try await makeSession(privkey: bobPriv, label: "bob")
        chain.homeByFid[NobodyBoard.defaultNobodyFid] = nil

        let result = await bob.firstFchBoard.fetch()
        XCTAssertNotNil(result.error)
        do {
            try await bob.firstFchBoard.post(note: nil, as: bob.liveFid, privkey: bobPriv)
            XCTFail("posting into nowhere should throw")
        } catch {}
    }

    // MARK: - per-identity state

    /// Funding somebody, or deciding not to, has to outlive the window
    /// it was decided in — otherwise every visit to a shared list means
    /// working through the same faces again.
    func testAnAnsweredAskerIsHiddenButStillReported() async throws {
        let bob = try await makeSession(privkey: bobPriv, label: "bob")
        let alice = try await makeSession(privkey: alicePriv, label: "alice")
        try await bob.firstFchBoard.post(note: "hello", as: bob.liveFid, privkey: bobPriv)

        try alice.firstFchBoardState.dismiss(
            [bob.liveFid], reason: .funded, fid: alice.liveFid
        )

        let result = await alice.firstFchBoard.fetch()
        XCTAssertTrue(result.requests.isEmpty, "not a row, and not a nudge")
        XCTAssertEqual(result.dismissed.map(\.request.requesterFid), [bob.liveFid])
        XCTAssertEqual(result.dismissed.first?.dismissal.reason, .funded)
    }

    /// The decision hides *the asker*, not the post — so asking again
    /// inside the window changes nothing.
    func testPostingAgainInsideTheWindowStaysHidden() async throws {
        let bob = try await makeSession(privkey: bobPriv, label: "bob")
        let alice = try await makeSession(privkey: alicePriv, label: "alice")
        try await bob.firstFchBoard.post(note: "first", as: bob.liveFid, privkey: bobPriv)
        try alice.firstFchBoardState.dismiss(
            [bob.liveFid], reason: .skipped, fid: alice.liveFid
        )
        try await bob.firstFchBoard.post(note: "asking again", as: bob.liveFid, privkey: bobPriv)

        let result = await alice.firstFchBoard.fetch()
        XCTAssertTrue(result.requests.isEmpty)
        XCTAssertEqual(result.dismissed.first?.request.note, "asking again")
    }

    /// Skipping somebody is not a promise never to help them.
    func testTheDecisionLapses() async throws {
        let bob = try await makeSession(privkey: bobPriv, label: "bob")
        let alice = try await makeSession(privkey: alicePriv, label: "alice")
        try await bob.firstFchBoard.post(note: "hello", as: bob.liveFid, privkey: bobPriv)

        let decidedAt = Date()
        try alice.firstFchBoardState.dismiss(
            [bob.liveFid], reason: .skipped, fid: alice.liveFid, now: decidedAt
        )

        let sixDays = decidedAt.addingTimeInterval(6 * 24 * 60 * 60)
        let stillHidden = await alice.firstFchBoard.fetch(now: sixDays)
        XCTAssertTrue(stillHidden.requests.isEmpty)

        let eightDays = decidedAt.addingTimeInterval(8 * 24 * 60 * 60)
        let back = await alice.firstFchBoard.fetch(now: eightDays)
        XCTAssertEqual(back.requests.map(\.requesterFid), [bob.liveFid])
    }

    func testRestoreUndoesADecision() async throws {
        let bob = try await makeSession(privkey: bobPriv, label: "bob")
        let alice = try await makeSession(privkey: alicePriv, label: "alice")
        try await bob.firstFchBoard.post(note: "hello", as: bob.liveFid, privkey: bobPriv)

        try alice.firstFchBoardState.dismiss(
            [bob.liveFid], reason: .skipped, fid: alice.liveFid
        )
        let hidden = await alice.firstFchBoard.fetch()
        XCTAssertTrue(hidden.requests.isEmpty)

        try alice.firstFchBoardState.restore([bob.liveFid], fid: alice.liveFid)
        let restored = await alice.firstFchBoard.fetch()
        XCTAssertEqual(restored.requests.map(\.requesterFid), [bob.liveFid])
    }

    /// A later decision replaces the earlier one outright rather than
    /// extending it: funding somebody you had skipped should record that
    /// you funded them.
    func testFundingOverwritesASkip() throws {
        let store = FirstFchBoardStore(kv: try makeKV())
        try store.dismiss(["FBob"], reason: .skipped, fid: "FMe")
        try store.dismiss(["FBob"], reason: .funded, fid: "FMe")
        XCTAssertEqual(store.get(fid: "FMe").dismissed["FBob"]?.reason, .funded)
    }

    // MARK: - keeping the row bounded

    /// Expiry alone does not bound the row — a week of a busy public
    /// board can still be more names than belong in a settings blob.
    func testTheRowIsCappedAndDropsTheSoonestToExpire() {
        let now = FirstFchBoardStore.millis(Date())
        var dismissed: [String: BoardDismissal] = [:]
        // 600 live entries, each expiring one second after the last.
        for i in 0..<600 {
            dismissed["F\(i)"] = BoardDismissal(
                reason: .skipped, until: now + 1_000 + Int64(i) * 1_000
            )
        }
        let trimmed = FirstFchBoardStore.trimmed(dismissed, now: now)
        XCTAssertEqual(trimmed.count, FirstFchBoardStore.maxDismissals)
        // The hundred nearest expiry went; the newest decisions survive.
        XCTAssertNil(trimmed["F0"])
        XCTAssertNil(trimmed["F99"])
        XCTAssertNotNil(trimmed["F100"])
        XCTAssertNotNil(trimmed["F599"])
    }

    func testLapsedEntriesAreDroppedOnEveryWrite() throws {
        let store = FirstFchBoardStore(kv: try makeKV())
        let longAgo = Date().addingTimeInterval(-30 * 24 * 60 * 60)
        try store.dismiss(["FOld"], reason: .skipped, fid: "FMe", now: longAgo)
        XCTAssertNotNil(store.get(fid: "FMe").dismissed["FOld"])

        try store.dismiss(["FNew"], reason: .skipped, fid: "FMe")
        XCTAssertNil(
            store.get(fid: "FMe").dismissed["FOld"],
            "a write is the only thing that grows this row, so it is where it gets trimmed"
        )
        XCTAssertNotNil(store.get(fid: "FMe").dismissed["FNew"])
    }

    /// Adding a field must not orphan rows written before it existed:
    /// Swift's synthesised `Decodable` ignores property defaults, so a
    /// missing key would otherwise reset the cursor and the asked-once
    /// flag along with it.
    func testARowWrittenWithoutTheDismissedFieldStillDecodes() throws {
        let legacy = Data(#"{"cursor":42,"checkAtLogin":true,"askedAt":7}"#.utf8)
        let state = try JSONDecoder().decode(FirstFchBoardState.self, from: legacy)
        XCTAssertEqual(state.cursor, 42)
        XCTAssertEqual(state.askedAt, 7)
        XCTAssertTrue(state.checkAtLogin)
        XCTAssertTrue(state.dismissed.isEmpty)
    }

    func testStateIsPerFidAndDefaultsToOffAndUnasked() async throws {
        let bob = try await makeSession(privkey: bobPriv, label: "bob")
        let store = bob.firstFchBoardState

        let fresh = store.get(fid: bob.liveFid)
        XCTAssertEqual(fresh.cursor, 0)
        XCTAssertFalse(fresh.hasAsked)
        XCTAssertFalse(fresh.checkAtLogin, "helping newcomers is opted into, never assumed")

        try store.mutate(fid: bob.liveFid) { $0.askedAt = 42; $0.checkAtLogin = true }
        XCTAssertTrue(store.get(fid: bob.liveFid).hasAsked)
        XCTAssertFalse(store.get(fid: "FSomeoneElse").hasAsked)
    }
}

private extension FirstFchBoardTests {

    /// A throwaway encrypted store for the tests that exercise the
    /// dismissal row without needing a session or a server.
    func makeKV() throws -> EncryptedKVStore {
        let path = baseDir.appendingPathComponent("\(UUID().uuidString).sqlite").path
        return try EncryptedKVStore(
            databasePath: path, vaultKey: Data(repeating: 0x5A, count: 32)
        )
    }
}

// MARK: - fakes

/// One server standing in for the whole network: the chain index and the
/// board's DOCK, since a board read needs both and the test does not care
/// which socket answered.
private final class FakeChain: @unchecked Sendable {

    struct Item {
        let id: String
        let recipients: [String]
        let payload: Data
        let createTime: Int64
    }

    var homeByFid: [String: [String: String]] = [:]
    var balanceByFid: [String: Int64] = [:]
    var items: [Item] = []
    var refuseFetch = false
    /// The `createTime > …` the last fetch asked for, so a test can prove
    /// the watermark reached the server rather than being applied here.
    var lastFetchGt: String?

    private var nextId = 1
    private var clock: Int64 = 1_755_100_000_000

    lazy var server: FakeServer = FakeServer(chain: self)

    func store(_ payload: Data, for recipients: [String]) {
        clock += 1_000
        nextId += 1
        items.append(Item(
            id: "dock-\(nextId)", recipients: recipients, payload: payload, createTime: clock
        ))
    }
}

private final class FakeServer: FapiCalling, @unchecked Sendable {

    private unowned let chain: FakeChain

    init(chain: FakeChain) { self.chain = chain }

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
                if let home = chain.homeByFid[id] { record["home"] = home }
                if let balance = chain.balanceByFid[id] { record["balance"] = balance }
                out[id] = record
            }
            return reply(out.isEmpty ? nil : out)

        case "dock.put":
            let recipients = json(params)["recipients"] as? [String] ?? []
            chain.store(binary ?? Data(), for: recipients)
            return reply(["id": chain.items.last?.id ?? "", "size": (binary?.count ?? 0)])

        case "dock.fetch":
            if chain.refuseFetch {
                return reply(nil, code: 400, message: "this inbox is not yours")
            }
            let query = json(fcdsl)
            let gt = ((query["query"] as? [String: Any])?["range"] as? [String: Any])?["gt"] as? String
            chain.lastFetchGt = gt
            let floor = Int64(gt ?? "") ?? 0
            let wanted = Set(json(params)["recipientIds"] as? [String] ?? [])
            let matching = chain.items
                .filter { !Set($0.recipients).isDisjoint(with: wanted) && $0.createTime > floor }
                .sorted { $0.createTime > $1.createTime }
            guard !matching.isEmpty else { return reply(nil, code: 404, message: "nothing waiting") }
            return reply(matching.map {
                [
                    "id": $0.id,
                    "recipients": $0.recipients,
                    "createTime": $0.createTime,
                    "dataType": "IM",
                    "dataBase64": $0.payload.base64EncodedString(),
                ]
            })

        default:
            return reply(nil)
        }
    }

    private func reply(_ data: Any?, code: Int = 0, message: String = "ok") -> FapiClient.Reply {
        var response = FapiResponse(code: code, message: message)
        if let data {
            response.data = try? JSONSerialization.data(
                withJSONObject: data, options: [.sortedKeys, .fragmentsAllowed]
            )
        }
        return FapiClient.Reply(response: response, binary: nil, messageId: 1)
    }
}
