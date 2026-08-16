import XCTest
import FCCore
import FCTransport
import FCStorage
@testable import FCDomain

/// Rooms: the membership model, and the owner checks that are the only
/// thing standing between a room and whoever knows its id.
final class RoomServiceTests: XCTestCase {

    private var baseDir: URL!
    private var manager: ConfigureManager!
    private var configure: ConfigureSession!
    private var session: ActiveSession!

    /// Alice owns the room, Bob is a member, Mallory is neither.
    private let alicePriv = Data(repeating: 0xA1, count: 32)
    private let bobPriv = Data(repeating: 0xB2, count: 32)
    private let malloryPriv = Data(repeating: 0xC3, count: 32)
    private let alice = "F-alice"
    private let bob = "F-bob"
    private let carol = "F-carol"
    private let mallory = "F-mallory"

    private let t0 = Date(timeIntervalSince1970: 1_755_100_000)
    private func at(_ seconds: TimeInterval) -> Date { t0.addingTimeInterval(seconds) }

    override func setUpWithError() throws {
        baseDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("RoomServiceTests-\(UUID().uuidString)")
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

    private var rooms: RoomsStore { session.rooms }
    private var symkeys: SymkeyStore { session.symkeys }
    private var service: RoomService {
        RoomService(rooms: rooms, symkeys: symkeys).withPrivkey(alicePriv)
    }

    /// Pubkeys for the cast, so room keys can be sealed to them.
    private func pubkeys(_ fid: String) throws -> Data? {
        switch fid {
        case bob: return try Secp256k1.publicKey(fromPrivateKey: bobPriv)
        case mallory: return try Secp256k1.publicKey(fromPrivateKey: malloryPriv)
        case carol: return try Secp256k1.publicKey(fromPrivateKey: Data(repeating: 0xD4, count: 32))
        default: return nil
        }
    }

    @discardableResult
    private func aliceRoom(with members: [String] = [], now: Date? = nil) throws -> Room {
        try service.create(
            name: "The Usual Place", owner: alice, invite: members,
            pubkeys: pubkeys, now: now ?? t0
        ).room
    }

    // MARK: - the model

    /// The id carries an underscore, which is not incidental: it becomes
    /// the entity id in a symkey storage key and the target of a
    /// conversation id, and both of those join with `_`.
    func testRoomIdShapeAndTheUnderscoreItImplies() throws {
        let id = Room.generateId(owner: alice, now: t0, random: 7)
        XCTAssertTrue(id.hasPrefix("room_"))
        XCTAssertEqual(id.count, "room_".count + 24)
        XCTAssertEqual(id, Room.generateId(owner: alice, now: t0, random: 7), "same inputs, same id")
        XCTAssertNotEqual(id, Room.generateId(owner: alice, now: t0, random: 8))

        // The pieces downstream that have to survive it.
        XCTAssertEqual(
            SymkeyStore.parse(storageKey: SymkeyStore.storageKey(entityId: id, version: 3))?.entityId,
            id
        )
        XCTAssertEqual(Conversation.id(type: .room, targetId: id), "ROOM_\(id)")
    }

    /// The owner is a member from the start and cannot be removed — a
    /// room with no owner has nobody who can speak for its membership.
    func testOwnerIsAMemberAndCannotBeRemoved() {
        var room = Room.create(owner: alice, name: "r", now: t0)
        XCTAssertTrue(room.isMember(alice))
        XCTAssertTrue(room.isOwner(alice))
        XCTAssertFalse(room.removeMember(alice, now: t0))
        XCTAssertTrue(room.isMember(alice))
        XCTAssertFalse(room.addPendingMember(alice))
    }

    func testMembershipBookkeeping() {
        var room = Room.create(owner: alice, name: "r", now: t0)
        XCTAssertTrue(room.addMember(bob, now: t0))
        XCTAssertFalse(room.addMember(bob, now: t0), "already a member")
        XCTAssertTrue(room.addPendingMember(bob))
        XCTAssertTrue(room.isPendingMember(bob))
        XCTAssertTrue(room.confirmMember(bob))
        XCTAssertFalse(room.confirmMember(bob))
        XCTAssertEqual(room.memberCount, 2)
        XCTAssertEqual(room.others(than: alice), [bob])

        XCTAssertTrue(room.removeMember(bob, now: t0))
        XCTAssertFalse(room.removeMember(bob, now: t0))
    }

    /// `RoomInfo` is what crosses the wire; local preferences are ours
    /// and an update from the owner has no business overwriting them.
    func testRoomInfoRoundTripLeavesLocalPreferencesAlone() throws {
        var room = Room.create(owner: alice, name: "Old Name", desc: "old", now: t0)
        room.addMember(bob, now: t0)
        room.muted = true
        room.pinned = true
        room.home = ["dock": "https://dock.example", "road": "https://road.example"]

        let json = RoomInfo.from(room).wireJson()
        var info = try RoomInfo.fromJson(json)
        XCTAssertEqual(info.wireJson(), json, "field order survives a round trip")
        info.name = "New Name"
        info.members = [alice, bob, carol]

        info.apply(to: &room, now: at(60))
        XCTAssertEqual(room.name, "New Name")
        XCTAssertEqual(room.members, [alice, bob, carol])
        XCTAssertEqual(room.muted, true)
        XCTAssertEqual(room.pinned, true)
        XCTAssertEqual(room.home?["dock"], "https://dock.example")
    }

    // MARK: - creating and inviting

    func testCreateGeneratesAKeyAndOneInvitationPerMember() throws {
        let (room, invitations) = try service.create(
            name: "The Usual Place", owner: alice, invite: [bob, carol],
            pubkeys: pubkeys, now: t0
        )
        let roomId = try XCTUnwrap(room.id)

        XCTAssertEqual(room.members, [alice, bob, carol])
        XCTAssertEqual(room.pendingMembers, [bob, carol], "invited, not yet confirmed")
        XCTAssertEqual(try symkeys.currentVersion(for: roomId), 1)
        XCTAssertEqual(room.symkeyVersion, 1)
        XCTAssertEqual(try rooms.get(id: roomId)?.name, "The Usual Place")

        XCTAssertEqual(invitations.count, 2)
        XCTAssertEqual(Set(invitations.compactMap(\.targetId)), [bob, carol])
        for invitation in invitations {
            XCTAssertEqual(invitation.contentType, .roomInfo)
            // Control traffic is P2P: an invitation has to reach someone
            // who is not in the room yet.
            XCTAssertEqual(invitation.type, .p2p)
            let info = try RoomInfo.fromJson(try XCTUnwrap(invitation.content))
            XCTAssertEqual(info.id, roomId)
            XCTAssertEqual(info.owner, alice)
            XCTAssertNotNil(info.symkey, "the invitation carries the key")
        }
    }

    /// A member whose pubkey we cannot find is still invited — just
    /// without a key, which they can ask for. Failing the whole creation
    /// over one unresolved contact would be the worse trade.
    func testAMemberWithNoPubkeyIsStillInvited() throws {
        let (_, invitations) = try service.create(
            name: "r", owner: alice, invite: ["F-unknown"], pubkeys: pubkeys, now: t0
        )
        let info = try RoomInfo.fromJson(try XCTUnwrap(invitations.first?.content))
        XCTAssertNil(info.symkey)
        XCTAssertEqual(info.members, [alice, "F-unknown"])
    }

    func testAddMembersInvitesEveryoneWithTheNewMembership() throws {
        let room = try aliceRoom(with: [bob])
        let roomId = try XCTUnwrap(room.id)

        let (added, outbound) = try service.addMembers(
            [carol], to: roomId, as: alice, pubkeys: pubkeys, now: at(60)
        )
        XCTAssertEqual(added, [carol])
        XCTAssertEqual(Set(outbound.compactMap(\.targetId)), [bob, carol])
        XCTAssertEqual(try rooms.get(id: roomId)?.members, [alice, bob, carol])
    }

    func testOnlyTheOwnerChangesMembership() throws {
        let roomId = try XCTUnwrap(try aliceRoom(with: [bob]).id)
        XCTAssertThrowsError(
            try service.addMembers([carol], to: roomId, as: bob, pubkeys: pubkeys, now: t0)
        ) { XCTAssertEqual($0 as? RoomService.Failure, .notTheOwner(roomId: roomId)) }
        XCTAssertThrowsError(try service.removeMember(bob, from: roomId, as: bob, pubkeys: pubkeys))
        XCTAssertThrowsError(try service.disband(roomId, as: bob))
    }

    // MARK: - removal rotates the key

    /// A removed member keeps every key they ever held and everything
    /// those keys open — nothing can claw that back — so removal can
    /// only mean "from here on". Without the rotation it means nothing.
    func testRemovingAMemberRotatesTheKey() throws {
        let roomId = try XCTUnwrap(try aliceRoom(with: [bob, carol]).id)
        let oldKey = try XCTUnwrap(try symkeys.currentKey(for: roomId))

        let (removed, outbound) = try service.removeMember(
            bob, from: roomId, as: alice, pubkeys: pubkeys, now: at(60)
        )
        XCTAssertTrue(removed)
        XCTAssertEqual(try symkeys.currentVersion(for: roomId), 2)
        XCTAssertNotEqual(try symkeys.currentKey(for: roomId), oldKey)
        // The old key survives, so what was said before still opens.
        XCTAssertEqual(try symkeys.key(for: roomId, version: 1), oldKey)
        XCTAssertEqual(try rooms.get(id: roomId)?.members, [alice, carol])

        // Bob is told he is out; Carol gets the new membership and key.
        let removedNotice = try XCTUnwrap(outbound.first { $0.contentType == .roomRemoved })
        XCTAssertEqual(removedNotice.targetId, bob)
        XCTAssertEqual(removedNotice.content, roomId)
        let update = try XCTUnwrap(outbound.first { $0.contentType == .roomInfo })
        XCTAssertEqual(update.targetId, carol)
        XCTAssertEqual(try RoomInfo.fromJson(try XCTUnwrap(update.content)).symkeyVersion, 2)
    }

    func testRemovingSomeoneWhoIsNotAMemberChangesNothing() throws {
        let roomId = try XCTUnwrap(try aliceRoom(with: [bob]).id)
        let (removed, outbound) = try service.removeMember(
            mallory, from: roomId, as: alice, pubkeys: pubkeys, now: t0
        )
        XCTAssertFalse(removed)
        XCTAssertTrue(outbound.isEmpty)
        XCTAssertEqual(try symkeys.currentVersion(for: roomId), 1, "no needless rotation")
    }

    // MARK: - resetting the key

    /// The owner's "reset key": a rotation everyone is told about, with
    /// the new key riding in the same `ROOM_INFO` an invitation uses —
    /// because a member needs the membership and the key together.
    func testResettingTheKeyRotatesAndTellsEveryMember() throws {
        let roomId = try XCTUnwrap(try aliceRoom(with: [bob, carol]).id)
        let oldKey = try XCTUnwrap(try symkeys.currentKey(for: roomId))

        let (version, outbound) = try service.resetSymkey(
            roomId, as: alice, pubkeys: pubkeys, now: at(60)
        )
        XCTAssertEqual(version, 2)
        XCTAssertNotEqual(try symkeys.currentKey(for: roomId), oldKey)
        // Additive as ever: what was said under v1 still opens.
        XCTAssertEqual(try symkeys.key(for: roomId, version: 1), oldKey)
        XCTAssertEqual(try rooms.get(id: roomId)?.symkeyVersion, 2)

        XCTAssertEqual(Set(outbound.compactMap(\.targetId)), [bob, carol])
        for message in outbound {
            XCTAssertEqual(message.contentType, .roomInfo)
            let info = try RoomInfo.fromJson(try XCTUnwrap(message.content))
            XCTAssertEqual(info.symkeyVersion, 2)
            XCTAssertNotNil(info.symkey, "the new key has to travel with it")
        }
    }

    /// An owner whose device lost the room's key reaches this from the
    /// composer's key fork. It must **not** reuse the version the lost
    /// key had: two different keys under one version is the one state
    /// the store cannot represent.
    func testResettingWithNoKeyHeldStillTakesTheNextVersion() throws {
        let roomId = try XCTUnwrap(try aliceRoom(with: [bob]).id)
        XCTAssertEqual(try symkeys.removeAll(for: roomId), 1)
        XCTAssertFalse(try symkeys.has(entityId: roomId))

        let (version, _) = try service.resetSymkey(
            roomId, as: alice, pubkeys: pubkeys, now: at(60)
        )
        XCTAssertEqual(version, 1, "nothing is held, so the next version is the first one")
        XCTAssertTrue(try symkeys.has(entityId: roomId))
    }

    /// Only the owner. A member with the room in their store must not be
    /// able to rotate everyone else out of it.
    func testAMemberCannotResetTheKey() throws {
        let roomId = try XCTUnwrap(try aliceRoom(with: [bob]).id)
        XCTAssertThrowsError(
            try service.resetSymkey(roomId, as: bob, pubkeys: pubkeys, now: at(60))
        )
        XCTAssertEqual(try symkeys.currentVersion(for: roomId), 1)
    }

    // MARK: - leaving and disbanding

    func testLeavingTellsTheOwnerAndTakesEffectLocallyAtOnce() throws {
        // Bob's own device: he holds a room Alice owns.
        let bobsService = RoomService(rooms: rooms, symkeys: symkeys).withPrivkey(bobPriv)
        var room = Room.create(owner: alice, name: "r", now: t0)
        room.addMember(bob, now: t0)
        try rooms.upsert(room)
        let roomId = try XCTUnwrap(room.id)

        let leave = try XCTUnwrap(try bobsService.leave(roomId, as: bob, now: at(60)))
        XCTAssertEqual(leave.contentType, .roomLeave)
        XCTAssertEqual(leave.targetId, alice)
        XCTAssertEqual(leave.content, roomId)
        // Leaving is our decision; it must not wait on the owner being
        // online to take effect on our own screen.
        let after = try XCTUnwrap(try rooms.get(id: roomId))
        XCTAssertTrue(after.isInactive)
        XCTAssertFalse(after.isMember(bob))
    }

    func testTheOwnerDisbandsRatherThanLeaves() throws {
        let roomId = try XCTUnwrap(try aliceRoom(with: [bob]).id)
        XCTAssertThrowsError(try service.leave(roomId, as: alice)) {
            XCTAssertEqual($0 as? RoomService.Failure, .ownerCannotLeave)
        }

        let outbound = try service.disband(roomId, as: alice, now: at(60))
        XCTAssertEqual(outbound.map(\.contentType), [.roomDisband])
        XCTAssertEqual(outbound.first?.targetId, bob)
        XCTAssertTrue(try XCTUnwrap(try rooms.get(id: roomId)).isInactive)
        // Disbanding ends the conversation; it does not burn the
        // transcript, so the keys stay.
        XCTAssertTrue(try symkeys.has(entityId: roomId))
        XCTAssertTrue(try service.disband(roomId, as: alice, now: at(90)).isEmpty, "already closed")
    }

    // MARK: - inbound: the owner checks

    private func notice(_ type: ContentType, from: String, content: String) -> ImMessage {
        var m = ImMessage.roomNotice(type, from: from, to: alice, content: content, now: t0)
        m.id = "0000000000000001"
        return m
    }

    /// "This room is over" is only meaningful from the owner. A client
    /// that believed it from anyone else could be shut down by any
    /// stranger who learned a room id.
    func testDisbandFromANonOwnerIsIgnored() throws {
        let roomId = try XCTUnwrap(try aliceRoom(with: [bob]).id)
        // Bob's device holds Alice's room; Mallory claims to close it.
        let handled = try service.handle(
            notice(.roomDisband, from: mallory, content: roomId), as: bob, now: at(60)
        )
        XCTAssertEqual(handled, .ignored(reason: "sender is not the owner"))
        XCTAssertFalse(try XCTUnwrap(try rooms.get(id: roomId)).isInactive)

        let real = try service.handle(
            notice(.roomDisband, from: alice, content: roomId), as: bob, now: at(60)
        )
        XCTAssertEqual(real, .disbanded)
        XCTAssertTrue(try XCTUnwrap(try rooms.get(id: roomId)).isInactive)
    }

    /// Nor is "you are out".
    func testRemovedFromANonOwnerIsIgnored() throws {
        let roomId = try XCTUnwrap(try aliceRoom(with: [bob]).id)
        XCTAssertEqual(
            try service.handle(notice(.roomRemoved, from: mallory, content: roomId), as: bob, now: at(60)),
            .ignored(reason: "sender is not the owner")
        )
        // The owner cannot be removed from their own room, even by a
        // message that really is from them.
        XCTAssertEqual(
            try service.handle(notice(.roomRemoved, from: alice, content: roomId), as: alice, now: at(60)),
            .ignored(reason: "the owner cannot be removed")
        )
        XCTAssertEqual(
            try service.handle(notice(.roomRemoved, from: alice, content: roomId), as: bob, now: at(60)),
            .removed
        )
        let after = try XCTUnwrap(try rooms.get(id: roomId))
        XCTAssertTrue(after.isInactive)
        XCTAssertFalse(after.isMember(bob))
    }

    /// Our own disband comes back to us off the room channel; acting on
    /// it again would be harmless but noisy, and Android guards it too.
    func testOwnDisbandEchoIsIgnored() throws {
        let roomId = try XCTUnwrap(try aliceRoom(with: [bob]).id)
        XCTAssertEqual(
            try service.handle(notice(.roomDisband, from: alice, content: roomId), as: alice, now: at(60)),
            .ignored(reason: "own echo")
        )
        XCTAssertFalse(try XCTUnwrap(try rooms.get(id: roomId)).isInactive)
    }

    /// Only the owner acts on a leave — everyone else finds out from the
    /// `ROOM_INFO` that follows it. And a leave forces the same rotation
    /// a removal does, without the redundant "you are out" notice.
    func testLeaveIsActedOnByTheOwnerAndRotatesTheKey() throws {
        let roomId = try XCTUnwrap(try aliceRoom(with: [bob, carol]).id)

        XCTAssertEqual(
            try service.handle(notice(.roomLeave, from: bob, content: roomId), as: carol, now: at(60)),
            .ignored(reason: "not the owner")
        )

        let handled = try service.handle(
            notice(.roomLeave, from: bob, content: roomId), as: alice, pubkeys: pubkeys, now: at(60)
        )
        guard case .memberLeft(let fid, let outbound) = handled else {
            return XCTFail("expected memberLeft, got \(handled)")
        }
        XCTAssertEqual(fid, bob)
        XCTAssertFalse(outbound.contains { $0.contentType == .roomRemoved }, "they know they left")
        XCTAssertEqual(outbound.map(\.targetId), [carol])
        XCTAssertEqual(try symkeys.currentVersion(for: roomId), 2)
        XCTAssertEqual(try rooms.get(id: roomId)?.members, [alice, carol])
    }

    func testAcceptClearsPendingOnlyForTheOwnerAndOnlyForAMember() throws {
        let roomId = try XCTUnwrap(try aliceRoom(with: [bob]).id)

        XCTAssertEqual(
            try service.handle(notice(.roomAccept, from: mallory, content: roomId), as: alice, now: at(60)),
            .ignored(reason: "not a member")
        )
        XCTAssertEqual(
            try service.handle(notice(.roomAccept, from: bob, content: roomId), as: carol, now: at(60)),
            .ignored(reason: "not the owner")
        )
        XCTAssertEqual(
            try service.handle(notice(.roomAccept, from: bob, content: roomId), as: alice, now: at(60)),
            .memberConfirmed(fid: bob)
        )
        XCTAssertNil(try rooms.get(id: roomId)?.pendingMembers)
        XCTAssertEqual(
            try service.handle(notice(.roomAccept, from: bob, content: roomId), as: alice, now: at(90)),
            .ignored(reason: "not pending")
        )
    }

    // MARK: - inbound room info

    private func infoMessage(_ info: RoomInfo, from: String) -> ImMessage {
        var m = ImMessage.roomNotice(.roomInfo, from: from, to: alice, content: info.wireJson(), now: t0)
        m.id = "0000000000000002"
        return m
    }

    /// For a room we have, the sender must be a member of **the room we
    /// already hold** — not merely someone who says so in the payload.
    func testRoomInfoFromANonMemberIsIgnored() throws {
        let roomId = try XCTUnwrap(try aliceRoom(with: [bob]).id)
        var claim = RoomInfo.from(try XCTUnwrap(try rooms.get(id: roomId)))
        claim.owner = mallory
        claim.members = [mallory]

        XCTAssertEqual(
            try service.handle(infoMessage(claim, from: mallory), as: bob, now: at(60)),
            .ignored(reason: "sender is not a member")
        )
        XCTAssertEqual(try rooms.get(id: roomId)?.owner, alice)
        XCTAssertEqual(try rooms.get(id: roomId)?.members, [alice, bob])
    }

    /// A member may update the name; only the owner may rewrite who is
    /// in the room.
    func testOnlyTheOwnerMayRewriteTheMemberList() throws {
        let roomId = try XCTUnwrap(try aliceRoom(with: [bob, carol]).id)
        var fromBob = RoomInfo.from(try XCTUnwrap(try rooms.get(id: roomId)))
        fromBob.name = "Bob's Rename"
        fromBob.members = [bob]
        fromBob.owner = bob

        guard case .updated(let updated) = try service.handle(
            infoMessage(fromBob, from: bob), as: carol, now: at(60)
        ) else { return XCTFail("expected updated") }

        XCTAssertEqual(updated.name, "Bob's Rename", "a member may rename")
        XCTAssertEqual(updated.owner, alice, "but not take ownership")
        XCTAssertEqual(updated.members, [alice, bob, carol], "nor rewrite the membership")
    }

    /// A `ROOM_INFO` for a room we do not have is an invitation, and
    /// joining is a person's decision — so it is handed back rather than
    /// applied.
    func testRoomInfoForAnUnknownRoomIsAnInvitationNotAJoin() throws {
        let info = RoomInfo(
            name: "Somewhere Else", owner: mallory, symkeyVersion: 1,
            members: [mallory, alice], id: "room_ffffffffffffffffffffffff"
        )
        let handled = try service.handle(infoMessage(info, from: mallory), as: alice, now: at(60))
        XCTAssertEqual(handled, .invitation(from: mallory, roomInfoJson: info.wireJson()))
        XCTAssertNil(try rooms.get(id: "room_ffffffffffffffffffffffff"))
    }

    func testMalformedRoomInfoIsIgnored() throws {
        var m = ImMessage.roomNotice(.roomInfo, from: mallory, to: alice, content: "not json", now: t0)
        m.id = "0000000000000003"
        XCTAssertEqual(try service.handle(m, as: alice, now: t0), .ignored(reason: "malformed room info"))
    }

    // MARK: - accepting an invitation

    func testAcceptingAnInvitationStoresTheKeyAndConfirmsToTheOwner() throws {
        // Alice creates and invites Bob; Bob's device accepts.
        let (room, invitations) = try service.create(
            name: "The Usual Place", owner: alice, invite: [bob], pubkeys: pubkeys, now: t0
        )
        let roomId = try XCTUnwrap(room.id)
        let key = try XCTUnwrap(try symkeys.currentKey(for: roomId))
        let json = try XCTUnwrap(invitations.first?.content)

        // A separate device, with its own stores and Bob's key.
        let (bobsRooms, bobsSymkeys) = try otherDevice()
        let bobsService = RoomService(rooms: bobsRooms, symkeys: bobsSymkeys).withPrivkey(bobPriv)

        let (joined, accept) = try bobsService.acceptInvite(roomInfoJson: json, as: bob, now: at(60))
        XCTAssertEqual(joined.id, roomId)
        XCTAssertEqual(joined.owner, alice)
        XCTAssertTrue(joined.isMember(bob))
        XCTAssertEqual(try bobsSymkeys.key(for: roomId, version: 1), key, "same key, both ends")

        let confirm = try XCTUnwrap(accept)
        XCTAssertEqual(confirm.contentType, .roomAccept)
        XCTAssertEqual(confirm.targetId, alice)
        XCTAssertEqual(confirm.content, roomId)
    }

    /// An invitation names its own owner, and that field is written by
    /// whoever sent it. A stranger who learns a room id must not be able
    /// to offer an "invitation" to a room you are already in and take it
    /// over on one tap — Android issue C12.
    func testAnInvitationCannotChangeTheOwnerOfARoomWeAlreadyHave() throws {
        let roomId = try XCTUnwrap(try aliceRoom(with: [bob]).id)
        let hijack = RoomInfo(
            name: "The Usual Place", owner: mallory, symkeyVersion: 1,
            members: [mallory], id: roomId
        )
        XCTAssertThrowsError(
            try service.acceptInvite(roomInfoJson: hijack.wireJson(), as: bob, now: at(60))
        ) { XCTAssertEqual($0 as? RoomService.Failure, .invitationOwnerMismatch(roomId: roomId)) }

        let unchanged = try XCTUnwrap(try rooms.get(id: roomId))
        XCTAssertEqual(unchanged.owner, alice)
        XCTAssertEqual(unchanged.members, [alice, bob])
    }

    /// A re-invitation from the room's actual owner is legitimate — it
    /// is how a member who lost the room gets back in.
    func testAReInviteFromTheRealOwnerIsHonoured() throws {
        let roomId = try XCTUnwrap(try aliceRoom(with: [bob]).id)
        try rooms.mutate(id: roomId) { $0.active = false }

        var again = RoomInfo.from(try XCTUnwrap(try rooms.get(id: roomId)))
        again.name = "Back Again"
        let (room, _) = try service.acceptInvite(roomInfoJson: again.wireJson(), as: bob, now: at(60))
        XCTAssertFalse(room.isInactive)
        XCTAssertEqual(room.name, "Back Again")
    }

    func testAcceptingRubbishThrows() throws {
        XCTAssertThrowsError(try service.acceptInvite(roomInfoJson: "{}", as: bob, now: t0)) {
            XCTAssertEqual($0 as? RoomService.Failure, .malformedInvitation)
        }
    }

    func testRejectingSendsALeaveToTheOwner() throws {
        let info = RoomInfo(name: "No Thanks", owner: alice, members: [alice, bob], id: "room_abc")
        let leave = try XCTUnwrap(try service.rejectInvite(roomInfoJson: info.wireJson(), as: bob, now: t0))
        XCTAssertEqual(leave.contentType, .roomLeave)
        XCTAssertEqual(leave.targetId, alice)
        XCTAssertEqual(leave.content, "room_abc")
        XCTAssertNil(try rooms.get(id: "room_abc"), "declining does not create the room")
    }

    // MARK: - the store

    func testStoreSeparatesActiveClosedAndOwned() throws {
        let mine = try XCTUnwrap(try aliceRoom(with: [bob]).id)
        var theirs = Room.create(owner: bob, name: "Bob's", now: at(30))
        theirs.addMember(alice, now: at(30))
        try rooms.upsert(theirs)
        try service.disband(mine, as: alice, now: at(60))

        XCTAssertEqual(try rooms.closed().map(\.id), [mine])
        XCTAssertEqual(try rooms.active().map(\.id), [theirs.id])
        XCTAssertEqual(try rooms.owned(by: alice).map(\.id), [mine])
        XCTAssertEqual(try rooms.search("Usual").map(\.id), [mine])
        XCTAssertEqual(try rooms.all().count, 2)
        XCTAssertTrue(try rooms.remove(id: mine))
        XCTAssertFalse(try rooms.remove(id: mine))
    }

    func testStoreRefusesARoomWithNoId() {
        XCTAssertThrowsError(try rooms.upsert(Room(owner: alice))) {
            XCTAssertEqual($0 as? RoomsStore.Failure, .roomHasNoId)
        }
    }

    // MARK: - helpers

    /// Independent stores, standing in for another person's device.
    private func otherDevice() throws -> (RoomsStore, SymkeyStore) {
        let dir = baseDir.appendingPathComponent("bob-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let kv = try EncryptedKVStore(
            databasePath: dir.appendingPathComponent("store.sqlite").path,
            vaultKey: Data(repeating: 0x7B, count: 32)
        )
        return (RoomsStore(kv: kv), SymkeyStore(kv: kv))
    }
}
