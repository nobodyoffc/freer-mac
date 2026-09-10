import XCTest
import FCCore
import FCTransport
import FCStorage
@testable import FCDomain

/// Routing the traffic that is not a message: room notifications, key
/// shares and key requests.
///
/// Everything here used to be counted and dropped by the courier, so
/// these tests are also the proof that a room invitation arrives at all.
final class SignalRouterTests: XCTestCase {

    private var baseDir: URL!
    private var manager: ConfigureManager!
    private var configure: ConfigureSession!
    private var session: ActiveSession!

    /// We are Alice. Bob owns the room; Carol is a member; Mallory is
    /// not.
    private let alicePriv = Data(repeating: 0xA1, count: 32)
    private let bobPriv = Data(repeating: 0xB2, count: 32)
    private let carolPriv = Data(repeating: 0xC3, count: 32)
    private let bob = "F-bob"
    private let carol = "F-carol"
    private let mallory = "F-mallory"
    private let roomId = "room_b4c9a1f2e8d73065b4c9"

    private let t0 = Date(timeIntervalSince1970: 1_755_100_000)
    private func at(_ seconds: TimeInterval) -> Date { t0.addingTimeInterval(seconds) }

    override func setUpWithError() throws {
        baseDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("SignalRouterTests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: baseDir, withIntermediateDirectories: true)

        manager = try ConfigureManager(baseDirectory: baseDir)
        configure = try manager.createConfigure(password: Data("pwd".utf8), kdfKind: .legacySha256)
        let info = try configure.addMain(privkey: alicePriv, label: "A")
        session = try configure.unlockMain(fid: info.fid, fapi: MockFapiClient())
    }

    override func tearDownWithError() throws {
        session = nil
        configure = nil
        manager = nil
        if let baseDir { try? FileManager.default.removeItem(at: baseDir) }
    }

    private var me: String { session.liveFid }

    private func pubkey(_ privkey: Data) throws -> Data {
        try Secp256k1.publicKey(fromPrivateKey: privkey)
    }

    private func router() throws -> SignalRouter {
        SignalRouter(
            rooms: session.rooms,
            teams: session.teams,
            symkeys: session.symkeys,
            invites: session.roomInvites,
            roomService: try session.roomService,
            roomConversations: session.roomConversations,
            privkey: alicePriv,
            pubkeys: { fid in
                switch fid {
                case self.bob: return try self.pubkey(self.bobPriv)
                case self.carol: return try self.pubkey(self.carolPriv)
                // Our own FID resolves too, as it does in the app: a
                // request from our other device is a request from us.
                case self.me: return try self.pubkey(self.alicePriv)
                default: return nil
                }
            }
        )
    }

    /// A room Bob owns, that we and Carol are in.
    private func bobsRoom() throws {
        try session.rooms.upsert(
            Room(owner: bob, name: "Bob's place", members: [bob, me, carol], id: roomId)
        )
    }

    /// A key share as `sender` would build it, sealed to us.
    private func share(
        _ key: Data, version: Int64, for entityId: String, from sender: String
    ) throws -> ImMessage {
        let cipher = try AsyOneWayCipher.encrypt(
            plaintext: key, toPubkey: try pubkey(alicePriv)
        )
        var m = ImMessage.symkey(
            type: .p2p, from: sender, to: me,
            symkeyData: SymkeyShare.payload(entityId: entityId, cipher: cipher),
            version: version, now: t0
        )
        m.id = ImMessage.hexId(fudpId: 9_001)
        return m
    }

    // MARK: - key shares

    func testAKeyForARoomWeAreInIsStored() throws {
        try bobsRoom()
        let key = Data(repeating: 0x7E, count: 32)

        let outcome = try router().route(
            try share(key, version: 1, for: roomId, from: bob), as: me, now: at(10)
        )
        XCTAssertEqual(outcome.learnedKeyFor, roomId)
        XCTAssertEqual(try session.symkeys.key(for: roomId, version: 1), key)
    }

    /// **A key for something we are not in is not a key we want.** It
    /// would sit in the store forever, and taking it is how a room
    /// nobody invited us to appears out of nowhere.
    func testAKeyForAnEntityWeAreNotInIsRefused() throws {
        let outcome = try router().route(
            try share(Data(repeating: 0x01, count: 32), version: 1, for: roomId, from: mallory),
            as: me, now: at(10)
        )
        XCTAssertNil(outcome.learnedKeyFor)
        XCTAssertFalse(try session.symkeys.has(entityId: roomId))
    }

    /// The rule that makes a rotation safe: only the **owner** may
    /// replace a key at a version we already hold. Without it any member
    /// could push a bogus v1 and make the whole history unreadable.
    func testOnlyTheOwnerCanReplaceAVersionWeAlreadyHold() throws {
        try bobsRoom()
        let original = Data(repeating: 0x7E, count: 32)
        _ = try session.symkeys.store(original, for: roomId, version: 1, allowOverwrite: true)

        // Carol is a member, not the owner.
        _ = try router().route(
            try share(Data(repeating: 0xEE, count: 32), version: 1, for: roomId, from: carol),
            as: me, now: at(10)
        )
        XCTAssertEqual(try session.symkeys.key(for: roomId, version: 1), original)

        // Bob owns it, so his answer wins.
        let replacement = Data(repeating: 0xAB, count: 32)
        _ = try router().route(
            try share(replacement, version: 1, for: roomId, from: bob), as: me, now: at(20)
        )
        XCTAssertEqual(try session.symkeys.key(for: roomId, version: 1), replacement)
    }

    /// A rotation is additive, so a new version from anyone in the room
    /// lands without touching the old one.
    func testANewVersionIsStoredBesideTheOldOne() throws {
        try bobsRoom()
        let v1 = Data(repeating: 0x11, count: 32)
        _ = try session.symkeys.store(v1, for: roomId, version: 1, allowOverwrite: true)

        let v2 = Data(repeating: 0x22, count: 32)
        _ = try router().route(
            try share(v2, version: 2, for: roomId, from: bob), as: me, now: at(10)
        )
        XCTAssertEqual(try session.symkeys.key(for: roomId, version: 1), v1)
        XCTAssertEqual(try session.symkeys.key(for: roomId, version: 2), v2)
    }

    // MARK: - key requests

    private func request(for entityId: String, from sender: String) -> ImMessage {
        var m = KeyExchange.request(entityId: entityId, from: sender, to: me, now: t0)
        m.id = ImMessage.hexId(fudpId: 9_100)
        return m
    }

    /// A member who lost the key asks, and we answer with one sealed to
    /// them — the reply is *queued*, not sent, so it goes out with
    /// everything else.
    func testAMemberAskingForAKeyIsAnswered() throws {
        try bobsRoom()
        let key = Data(repeating: 0x5A, count: 32)
        _ = try session.symkeys.store(key, for: roomId, version: 3, allowOverwrite: true)

        let outcome = try router().route(request(for: roomId, from: carol), as: me, now: at(10))
        let reply = try XCTUnwrap(outcome.outbound.first)
        XCTAssertEqual(reply.contentType, .symkey)
        XCTAssertEqual(reply.targetId, carol)
        XCTAssertEqual(reply.symkeyVersion, 3)

        // What travels is the key, sealed so only Carol can open it.
        let (entityId, cipher) = try XCTUnwrap(SymkeyShare.parse(try XCTUnwrap(reply.content)))
        XCTAssertEqual(entityId, roomId)
        XCTAssertEqual(try AsyCipher.decrypt(cipherString: cipher, privkey: carolPriv), key)
    }

    /// **Membership is checked against what this device already knows**,
    /// never against what the request says. Otherwise asking politely
    /// would be enough to be let in.
    func testANonMemberAskingForAKeyGetsNothing() throws {
        try bobsRoom()
        _ = try session.symkeys.store(
            Data(repeating: 0x5A, count: 32), for: roomId, version: 1, allowOverwrite: true
        )
        let outcome = try router().route(request(for: roomId, from: mallory), as: me, now: at(10))
        XCTAssertTrue(outcome.outbound.isEmpty)
    }

    /// Being asked for something we do not have is silence, not an
    /// error: two members answering the same request is the normal case.
    func testBeingAskedForAKeyWeDoNotHoldAnswersNothing() throws {
        try bobsRoom()
        let outcome = try router().route(request(for: roomId, from: carol), as: me, now: at(10))
        XCTAssertTrue(outcome.outbound.isEmpty)
    }

    // MARK: - room info requests

    private func roomInfoRequest(for roomId: String, from sender: String) -> ImMessage {
        var m = KeyExchange.roomInfoRequest(roomId: roomId, from: sender, to: me, now: t0)
        m.id = ImMessage.hexId(fudpId: 9_150)
        return m
    }

    /// Somebody in the room asks what it looks like, and the answer is a
    /// `ROOM_INFO` — the same envelope an invitation uses, so it carries
    /// the membership and the key together.
    func testAMemberAskingForRoomDetailsGetsThem() throws {
        try bobsRoom()
        _ = try session.symkeys.store(
            Data(repeating: 0x3C, count: 32), for: roomId, version: 2, allowOverwrite: true
        )

        let outcome = try router().route(roomInfoRequest(for: roomId, from: carol), as: me, now: at(10))
        let reply = try XCTUnwrap(outcome.outbound.first)
        XCTAssertEqual(reply.contentType, .roomInfo)
        XCTAssertEqual(reply.targetId, carol)
        // P2P, because the asker may be someone who cannot read the
        // room's own channel — which is usually exactly why they asked.
        XCTAssertEqual(reply.type, .p2p)

        let info = try RoomInfo.fromJson(try XCTUnwrap(reply.content))
        XCTAssertEqual(info.id, roomId)
        XCTAssertEqual(info.symkeyVersion, 2)
        XCTAssertNotNil(info.symkey, "the key travels with the details")
    }

    /// **Any member may answer, and that is not a hole**: the receiving
    /// side strips `members` and `owner` from a non-owner's `ROOM_INFO`
    /// and keeps only the name and the key. This test pins that we are
    /// willing to answer as a plain member, since that answer delivers
    /// the part that was usually missing.
    func testANonOwnerStillAnswersARoomInfoRequest() throws {
        try bobsRoom()  // Bob owns it; we are only a member.
        let outcome = try router().route(roomInfoRequest(for: roomId, from: carol), as: me, now: at(10))
        XCTAssertEqual(outcome.outbound.count, 1)
    }

    func testARoomInfoRequestFromANonMemberIsRefused() throws {
        try bobsRoom()
        let outcome = try router().route(
            roomInfoRequest(for: roomId, from: mallory), as: me, now: at(10)
        )
        XCTAssertTrue(outcome.outbound.isEmpty)
    }

    func testARoomInfoRequestForARoomWeDoNotHaveAnswersNothing() throws {
        let outcome = try router().route(
            roomInfoRequest(for: "room_unknown0000000000", from: carol), as: me, now: at(10)
        )
        XCTAssertTrue(outcome.outbound.isEmpty)
    }

    // MARK: - asking our own other devices

    /// A request from our own FID is a request from **our other device**
    /// — one signed in as this identity without the key — and it is
    /// answered exactly like a member's: both parties are members, we
    /// hold the key, so a share goes back, sealed to our own pubkey.
    ///
    /// This is the re-installed owner's only way back in, so the room
    /// here is one **we** own: nobody else holds its key.
    func testARequestFromOurOwnFidIsAnswered() throws {
        try session.rooms.upsert(
            Room(owner: me, name: "Mine", members: [me, carol], id: roomId)
        )
        let key = Data(repeating: 0x6B, count: 32)
        _ = try session.symkeys.store(key, for: roomId, version: 2, allowOverwrite: true)

        let outcome = try router().route(request(for: roomId, from: me), as: me, now: at(10))
        let reply = try XCTUnwrap(outcome.outbound.first)
        XCTAssertEqual(reply.contentType, .symkey)
        XCTAssertEqual(reply.senderId, me)
        XCTAssertEqual(reply.targetId, me, "back to our own FID, where the other device collects")
        XCTAssertEqual(reply.type, .p2p)
        XCTAssertEqual(reply.symkeyVersion, 2)

        let (entityId, cipher) = try XCTUnwrap(SymkeyShare.parse(try XCTUnwrap(reply.content)))
        XCTAssertEqual(entityId, roomId)
        XCTAssertEqual(try AsyCipher.decrypt(cipherString: cipher, privkey: alicePriv), key)
    }

    /// The same for room details: our other device asking about a room
    /// we are in gets the `ROOM_INFO`, key included.
    func testARoomInfoRequestFromOurOwnFidIsAnswered() throws {
        try bobsRoom()
        _ = try session.symkeys.store(
            Data(repeating: 0x3C, count: 32), for: roomId, version: 4, allowOverwrite: true
        )
        let outcome = try router().route(roomInfoRequest(for: roomId, from: me), as: me, now: at(10))
        let reply = try XCTUnwrap(outcome.outbound.first)
        XCTAssertEqual(reply.contentType, .roomInfo)
        XCTAssertEqual(reply.targetId, me)
        let info = try RoomInfo.fromJson(try XCTUnwrap(reply.content))
        XCTAssertEqual(info.symkeyVersion, 4)
        XCTAssertNotNil(info.symkey)
    }

    /// The device that *sent* the request collects its own copy too, and
    /// holds no key — that is why it asked. It must stay silent rather
    /// than answer itself with nothing, or loop.
    func testOurOwnRequestReadBackWithoutTheKeyAnswersNothing() throws {
        try session.rooms.upsert(
            Room(owner: me, name: "Mine", members: [me, carol], id: roomId)
        )
        let outcome = try router().route(request(for: roomId, from: me), as: me, now: at(10))
        XCTAssertTrue(outcome.outbound.isEmpty)
    }

    /// **Not a trust rule.** A share whose sender FID is ours is not
    /// thereby from the owner: a FID in a message is written by whoever
    /// sent it. In a room Bob owns, "from us" must not replace a version
    /// we already hold — the acceptance side is exactly as strict as it
    /// was before self-requests existed.
    func testAShareClaimingToBeFromUsCannotOverwriteInSomeoneElsesRoom() throws {
        try bobsRoom()
        let original = Data(repeating: 0x11, count: 32)
        _ = try session.symkeys.store(original, for: roomId, version: 1, allowOverwrite: true)

        _ = try router().route(
            try share(Data(repeating: 0xEE, count: 32), version: 1, for: roomId, from: me),
            as: me, now: at(10)
        )
        XCTAssertEqual(try session.symkeys.key(for: roomId, version: 1), original)
    }

    // MARK: - asking several people at once

    /// Asking is addressed to exactly the people chosen — **our own FID
    /// included**. It used to be dropped, on the theory that asking
    /// ourselves is a no-op; it is how a second device signed in as this
    /// identity reaches the first one, which holds the key.
    func testRequestsAreBuiltForEveryoneChosenIncludingUs() {
        let asks = KeyExchange.requests(
            entityId: roomId, kind: .symkey, from: me, to: [bob, carol, me], now: t0
        )
        XCTAssertEqual(asks.compactMap(\.targetId), [bob, carol, me])
        XCTAssertTrue(asks.allSatisfy { $0.requestType == .symkey && $0.type == .p2p })
        XCTAssertTrue(asks.allSatisfy { $0.senderId == me })
        XCTAssertTrue(asks.allSatisfy { $0.id != nil }, "queueable")
    }

    /// A request to ourselves alone — the re-installed owner's case — is
    /// emitted, for both kinds.
    func testARequestToOnlyOurselvesIsEmitted() {
        for kind in [RequestType.symkey, .roomInfo] {
            let asks = KeyExchange.requests(entityId: roomId, kind: kind, from: me, to: [me], now: t0)
            XCTAssertEqual(asks.count, 1, "\(kind)")
            XCTAssertEqual(asks.first?.targetId, me)
            XCTAssertEqual(asks.first?.requestType, kind)
            XCTAssertEqual(asks.first?.content, roomId)
        }
    }

    /// The same FID twice is one question, not two paid-for puts.
    func testRequestsDropDuplicates() {
        let asks = KeyExchange.requests(
            entityId: roomId, kind: .symkey, from: me, to: [me, bob, me, bob], now: t0
        )
        XCTAssertEqual(asks.compactMap(\.targetId), [me, bob])
    }

    func testRoomInfoRequestsCarryTheirOwnRequestType() {
        let asks = KeyExchange.requests(
            entityId: roomId, kind: .roomInfo, from: me, to: [bob], now: t0
        )
        XCTAssertEqual(asks.first?.requestType, .roomInfo)
        XCTAssertEqual(asks.first?.content, roomId)
    }

    // MARK: - room notifications

    /// An invitation to a room we do not have is **stored, not applied**
    /// — and storing it is the point: a collect that runs in the
    /// background is exactly when one arrives, and a dialog nobody saw
    /// would have lost it.
    func testAnInvitationIsKeptForAPersonToAnswer() throws {
        var info = RoomInfo(name: "Somewhere new", owner: bob, members: [bob, me])
        info.id = roomId
        var message = ImMessage.roomNotice(
            .roomInfo, from: bob, to: me, content: info.wireJson(), now: t0
        )
        message.type = .p2p
        message.id = ImMessage.hexId(fudpId: 9_200)

        let outcome = try router().route(message, as: me, now: at(10))
        XCTAssertEqual(outcome.invitation?.from, bob)

        let stored = try XCTUnwrap(try session.roomInvites.get(roomId: roomId))
        XCTAssertEqual(stored.from, bob)
        XCTAssertEqual(stored.name, "Somewhere new")
        // Not joined: the room itself is still not in the store.
        XCTAssertNil(try session.rooms.get(id: roomId))
    }

    /// The owner announces a new membership, and the row the chat list
    /// draws follows it. Nothing else would ever bring the two back
    /// together: a room has no chain to sync from, so a member added on
    /// the owner's device and applied here would otherwise leave this
    /// header counting the room as it was.
    func testAnOwnersUpdateReachesTheConversationRow() throws {
        try bobsRoom()
        try session.roomConversations.sync(roomId)
        XCTAssertEqual(
            try session.conversations.get(type: .room, targetId: roomId)?.memberNum, 3
        )

        var info = RoomInfo(name: "Bob's other place", owner: bob, members: [bob, me, carol, mallory])
        info.id = roomId
        var message = ImMessage.roomNotice(
            .roomInfo, from: bob, to: me, content: info.wireJson(), now: t0
        )
        message.type = .p2p
        message.id = ImMessage.hexId(fudpId: 9_250)

        _ = try router().route(message, as: me, now: at(10))
        let row = try XCTUnwrap(try session.conversations.get(type: .room, targetId: roomId))
        XCTAssertEqual(row.memberNum, 4)
        XCTAssertEqual(row.displayName, "Bob's other place")
    }

    /// Anything else is left alone rather than guessed at.
    func testAnUnrelatedSignalDoesNothing() throws {
        var m = ImMessage.make(type: .p2p, from: bob, to: me, contentType: .typing, now: t0)
        m.id = ImMessage.hexId(fudpId: 9_300)
        XCTAssertEqual(try router().route(m, as: me, now: at(10)), .nothing)
    }
}
