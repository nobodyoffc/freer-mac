import XCTest
import FCCore
import FCTransport
@testable import FCDomain

/// Who runs a team, and how a team reaches somebody it wants in it: the
/// owner and manager ops the indexer checks, the `[TEAM_INVITE]` notice
/// Android sends, and the offers a member answers.
final class TeamGovernanceTests: XCTestCase {

    private var baseDir: URL!
    private var manager: ConfigureManager!
    private var mock: MockFapiClient!
    private var session: ActiveSession!

    private let alice = "F-alice"
    private let bob = "F-bob"
    private let carol = "F-carol"
    private let bobPriv = Data(repeating: 0xB2, count: 32)
    private let teamId = "3f9c1a2b0000000000000000000000000000000000000000000000000000tid1"
    private let otherTeamId = "3f9c1a2b0000000000000000000000000000000000000000000000000000tid2"

    private let t0 = Date(timeIntervalSince1970: 1_755_100_000)
    private func at(_ seconds: TimeInterval) -> Date { t0.addingTimeInterval(seconds) }

    override func setUpWithError() throws {
        baseDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("TeamGovernanceTests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: baseDir, withIntermediateDirectories: true)
        manager = try ConfigureManager(baseDirectory: baseDir)
        mock = MockFapiClient()
        let configure = try manager.createConfigure(password: Data("pwd".utf8), kdfKind: .legacySha256)
        let info = try configure.addMain(privkey: Data(repeating: 0xA1, count: 32), label: "A")
        session = try configure.unlockMain(fid: info.fid, fapi: mock)
    }

    override func tearDownWithError() throws {
        session = nil
        mock = nil
        manager = nil
        if let baseDir { try? FileManager.default.removeItem(at: baseDir) }
    }

    private var me: String { session.liveFid }

    // MARK: - the notice, as Android writes it

    /// The exact bytes `ImManager.sendTeamInviteNotification` sends, so an
    /// Android invitation reads here and a Mac one reads there.
    func testANoticeIsAndroidsTextExactly() {
        let invite = TeamNotice(kind: .invitation, teamId: teamId, teamName: "The Team")
        XCTAssertEqual(invite.text, "[TEAM_INVITE]\(teamId)|The Team")
        let transfer = TeamNotice(kind: .transfer, teamId: teamId, teamName: nil)
        // Android writes the id where the name would go.
        XCTAssertEqual(transfer.text, "[TEAM_TRANSFER]\(teamId)|\(teamId)")

        XCTAssertEqual(TeamNotice.parse(invite.text), invite)
        let parsed = TeamNotice.parse(transfer.text)
        XCTAssertEqual(parsed?.kind, .transfer)
        XCTAssertNil(parsed?.teamName, "an id standing in for a name is no name")
    }

    func testANoticeKeepsAPipeInTheName() {
        XCTAssertEqual(TeamNotice.parse("[TEAM_INVITE]\(teamId)|A|B")?.teamName, "A|B")
    }

    func testTextThatIsNotANoticeIsNotParsed() {
        XCTAssertNil(TeamNotice.parse("hello"))
        XCTAssertNil(TeamNotice.parse("[TEAM_INVITE]"))
        XCTAssertNil(TeamNotice.parse("[TEAM_INVITE]|name"))
        XCTAssertNil(TeamNotice.parse("[TEAM_INVITE]two words|name"))
        XCTAssertNil(TeamNotice.parse("[TEAM_INVITE]" + String(repeating: "a", count: 200)))
        XCTAssertNil(TeamNotice.parse(" [TEAM_INVITE]\(teamId)|x"))
    }

    // MARK: - plans

    private var team: Team {
        Team(
            owner: me, members: [me, bob, carol], managers: [me, carol],
            invitees: [alice], active: true, id: teamId
        )
    }

    /// The parser adds any member to `managers` and skips the owner; a
    /// manager named again is the same set. Only a member who is not yet
    /// a manager changes anything.
    func testAppointingNamesOnlyMembersWhoAreNotYetManagers() {
        let plan = TeamGovernance.appoint(team, fids: [bob, carol, me, alice, bob, " "])
        XCTAssertEqual(plan.effective, [bob])
        XCTAssertEqual(plan.skipped, [carol, me, alice])
    }

    func testTheOwnersAppointmentCannotBeCancelled() {
        let plan = TeamGovernance.cancelAppointment(team, fids: [me, carol, bob])
        XCTAssertEqual(plan.effective, [carol])
    }

    func testTheOwnerCannotBeDismissed() {
        let plan = TeamGovernance.dismiss(team, fids: [me, bob, alice])
        XCTAssertEqual(plan.effective, [bob])
        XCTAssertEqual(plan.skipped, [me, alice])
    }

    func testOnlyAnOutstandingInvitationCanBeWithdrawn() {
        let plan = TeamGovernance.withdrawInvitation(team, fids: [alice, bob])
        XCTAssertEqual(plan.effective, [alice])
    }

    /// The owner is a manager whatever `managers` says.
    func testTheOwnerAlwaysManages() {
        var bare = team
        bare.managers = nil
        XCTAssertTrue(TeamGovernance.canManage(bare, me))
        XCTAssertTrue(TeamGovernance.canManage(team, carol))
        XCTAssertFalse(TeamGovernance.canManage(team, bob))
    }

    // MARK: - refusals

    /// **Only an invitee may join.** Typing a team id into a join form
    /// is not a way in; the parser rejects it after the fee.
    func testJoiningNeedsAnInvitation() {
        let open = Team(owner: alice, consensusId: "c", members: [alice], active: true, id: teamId)
        XCTAssertEqual(TeamGovernance.joinRefusal(open, fid: me), .notInvited(teamId: teamId))

        var invited = open
        invited.invitees = [me]
        XCTAssertNil(TeamGovernance.joinRefusal(invited, fid: me))

        var noConsensus = invited
        noConsensus.consensusId = nil
        XCTAssertEqual(TeamGovernance.joinRefusal(noConsensus, fid: me), .noConsensus(teamId: teamId))

        var gone = invited
        gone.active = false
        XCTAssertEqual(TeamGovernance.joinRefusal(gone, fid: me), .disbanded(teamId))
    }

    func testOnlyTheTransfereeTakesOver() {
        var offered = Team(owner: alice, members: [alice], transferee: bob, active: true, id: teamId)
        XCTAssertEqual(TeamGovernance.takeOverRefusal(offered, fid: me), .notTheTransferee(teamId: teamId))
        offered.transferee = me
        XCTAssertNil(TeamGovernance.takeOverRefusal(offered, fid: me))
        offered.transferee = nil
        XCTAssertEqual(TeamGovernance.takeOverRefusal(offered, fid: me), .noTransferPending(teamId: teamId))
    }

    /// Naming the owner is how an offer is withdrawn — and when nothing
    /// is on offer it withdraws nothing.
    func testTransferringToTheOwnerOnlyMeansSomethingWhileAnOfferIsOut() {
        var owned = team
        XCTAssertEqual(TeamGovernance.transferRefusal(owned, to: me), .noTransferPending(teamId: teamId))
        XCTAssertNil(TeamGovernance.transferRefusal(owned, to: bob))

        owned.transferee = bob
        XCTAssertNil(TeamGovernance.transferRefusal(owned, to: me), "withdrawing the offer")
        XCTAssertEqual(
            TeamGovernance.transferRefusal(owned, to: bob),
            .alreadyOffered(teamId: teamId, to: bob)
        )
        XCTAssertEqual(TeamGovernance.transferRefusal(owned, to: "  "), .noTransferee)
    }

    // MARK: - carves refused before they are paid for

    func testAppointingRefusesANonOwner() async throws {
        stageTeam(["id": teamId, "owner": alice, "members": [alice, me, bob], "managers": [alice, me], "active": true])
        await assertRefused(.notTheOwner(teamId: teamId)) {
            _ = try await self.session.carveTeamAppointOnChain(teamId: self.teamId, fids: [self.bob])
        }
    }

    func testAppointingNobodyNewIsRefused() async throws {
        stageTeam(["id": teamId, "owner": me, "members": [me, bob], "managers": [me, bob], "active": true])
        await assertRefused(.nothingToChange(.appoint, skipped: [bob])) {
            _ = try await self.session.carveTeamAppointOnChain(teamId: self.teamId, fids: [self.bob])
        }
    }

    /// A manager may dismiss; a plain member may not.
    func testDismissingNeedsAManager() async throws {
        stageTeam(["id": teamId, "owner": alice, "members": [alice, me, bob], "managers": [alice], "active": true])
        await assertRefused(.notAManager(teamId: teamId)) {
            _ = try await self.session.carveTeamDismissOnChain(teamId: self.teamId, fids: [self.bob])
        }
    }

    func testTakingOverRefusesSomebodyTheTeamWasNotOffered() async throws {
        stageTeam(["id": teamId, "owner": alice, "members": [alice], "transferee": bob, "active": true])
        await assertRefused(.notTheTransferee(teamId: teamId)) {
            _ = try await self.session.carveTeamTakeOverOnChain(teamId: self.teamId)
        }
    }

    /// One team the signer does not own sinks the parser's whole op.
    func testDisbandingRefusesATeamWeDoNotOwn() async throws {
        stageTeam(["id": teamId, "owner": alice, "members": [alice, me], "active": true])
        await assertRefused(.notTheOwner(teamId: teamId)) {
            _ = try await self.session.carveTeamDisbandOnChain(teamIds: [self.teamId])
        }
    }

    func testCancellingATransferThatIsNotPendingIsRefused() async throws {
        stageTeam(["id": teamId, "owner": me, "members": [me], "active": true])
        await assertRefused(.noTransferPending(teamId: teamId)) {
            _ = try await self.session.carveTeamCancelTransferOnChain(teamId: self.teamId)
        }
    }

    /// The carve names only the effective FIDs — the skipped ones never
    /// reach the chain.
    func testAppointCarvesOnlyWhoItWouldChange() async throws {
        let box = Box()
        stageTeam(
            ["id": teamId, "owner": me, "members": [me, bob, carol], "managers": [me, carol], "active": true],
            funded: true, onBroadcast: { box.value = $0 }
        )
        _ = try await session.carveTeamAppointOnChain(teamId: teamId, fids: [bob, carol])
        let raw = Data(fromHex: try XCTUnwrap(box.value))
        XCTAssertNotNil(raw.range(of: Data(#""op":"appoint","tid":"\#(teamId)","list":["\#(bob)"]"#.utf8)))
    }

    /// The only way the protocol withdraws a transfer: name the owner.
    func testCancellingATransferNamesTheOwner() async throws {
        let box = Box()
        stageTeam(
            ["id": teamId, "owner": me, "members": [me, bob], "transferee": bob, "active": true],
            funded: true, onBroadcast: { box.value = $0 }
        )
        _ = try await session.carveTeamCancelTransferOnChain(teamId: teamId)
        let raw = Data(fromHex: try XCTUnwrap(box.value))
        XCTAssertNotNil(raw.range(of: Data(#""op":"transfer","tid":"\#(teamId)","transferee":"\#(me)""#.utf8)))
        XCTAssertNotNil(raw.range(of: Data(#""confirm":"I transfer the team to the transferee.""#.utf8)))
    }

    /// Taking over quotes the consensus the chain holds now.
    func testTakingOverQuotesTheCurrentConsensus() async throws {
        let box = Box()
        stageTeam(
            ["id": teamId, "owner": alice, "consensusId": "current", "members": [alice], "transferee": me, "active": true],
            funded: true, onBroadcast: { box.value = $0 }
        )
        _ = try await session.carveTeamTakeOverOnChain(teamId: teamId)
        let raw = Data(fromHex: try XCTUnwrap(box.value))
        XCTAssertNotNil(raw.range(of: Data(#""op":"take over","tid":"\#(teamId)","consensusId":"current""#.utf8)))
    }

    // MARK: - offers

    func testANoticeRaisesAnUnconfirmedOffer() throws {
        let store = session.teamOffers
        let raised = try store.note(
            TeamNotice(kind: .invitation, teamId: teamId, teamName: "T"), from: alice, for: me, now: at(0)
        )
        XCTAssertTrue(raised)
        let offer = try XCTUnwrap(store.get(fid: me, teamId: teamId))
        XCTAssertFalse(offer.isOnChain)
        XCTAssertEqual(offer.notifiedBy, alice)
        XCTAssertEqual(try store.waiting(fid: me, now: at(1)).count, 1)
    }

    /// An invitation belongs to the identity it names, not the vault.
    func testAnOfferIsPerIdentity() throws {
        try session.teamOffers.note(
            TeamNotice(kind: .invitation, teamId: teamId, teamName: nil), from: alice, for: "F-other", now: at(0)
        )
        XCTAssertTrue(try session.teamOffers.waiting(fid: me, now: at(1)).isEmpty)
    }

    /// Setting one aside is a decision a resend does not undo.
    func testAResentNoticeDoesNotUnignore() throws {
        let store = session.teamOffers
        let notice = TeamNotice(kind: .invitation, teamId: teamId, teamName: nil)
        try store.note(notice, from: alice, for: me, now: at(0))
        try store.setIgnored(true, fid: me, teamId: teamId)
        XCTAssertFalse(try store.note(notice, from: alice, for: me, now: at(10)))
        XCTAssertTrue(try XCTUnwrap(store.get(fid: me, teamId: teamId)).isIgnored)
        XCTAssertTrue(try store.waiting(fid: me, now: at(11)).isEmpty)
    }

    func testTheChainConfirmsAndFillsInANotice() throws {
        let store = session.teamOffers
        try store.note(TeamNotice(kind: .invitation, teamId: teamId, teamName: "Claimed"), from: alice, for: me, now: at(0))
        let fresh = try store.reconcile(
            invited: [Team(owner: alice, stdName: "Real", consensusId: "c", members: [alice], invitees: [me], active: true, id: teamId)],
            transfers: [], for: me, now: at(60)
        )
        XCTAssertEqual(fresh, 0, "already on screen")
        let offer = try XCTUnwrap(store.get(fid: me, teamId: teamId))
        XCTAssertTrue(offer.isOnChain)
        XCTAssertEqual(offer.teamName, "Real", "the chain's name, not the sender's")
        XCTAssertEqual(offer.owner, alice)
        XCTAssertEqual(offer.consensusId, "c")
    }

    /// Whatever the reason — joined, withdrawn, disbanded — once the
    /// chain stops listing it there is nothing to answer.
    func testAnOfferTheChainStopsListingGoes() throws {
        let store = session.teamOffers
        let invited = Team(owner: alice, members: [alice], invitees: [me], active: true, id: teamId)
        XCTAssertEqual(try store.reconcile(invited: [invited], transfers: [], for: me, now: at(0)), 1)
        try store.reconcile(invited: [], transfers: [], for: me, now: at(60))
        XCTAssertNil(try store.get(fid: me, teamId: teamId))
    }

    /// A notice announced before its carve confirmed is the ordinary
    /// case, so it waits — for a week, not forever.
    func testAnUnconfirmedNoticeWaitsAWeek() throws {
        let store = session.teamOffers
        try store.note(TeamNotice(kind: .invitation, teamId: teamId, teamName: nil), from: alice, for: me, now: at(0))
        try store.reconcile(invited: [], transfers: [], for: me, now: at(3_600))
        XCTAssertNotNil(try store.get(fid: me, teamId: teamId))
        try store.reconcile(invited: [], transfers: [], for: me, now: at(8 * 24 * 3_600))
        XCTAssertNil(try store.get(fid: me, teamId: teamId))
    }

    /// Taking a team over also makes the taker a member, so a team
    /// offering both is offering the transfer. A member can be handed a
    /// team; a member cannot be invited to one.
    func testATransferOutranksAnInvitationAndMembersAreOnlyOfferedTransfers() throws {
        let store = session.teamOffers
        let both = Team(owner: alice, members: [alice], transferee: me, invitees: [me], active: true, id: teamId)
        let memberInvite = Team(owner: alice, members: [alice, me], invitees: [me], active: true, id: otherTeamId)
        try store.reconcile(invited: [both, memberInvite], transfers: [both], for: me, now: at(0))
        XCTAssertEqual(try store.get(fid: me, teamId: teamId)?.kind, .transfer)
        XCTAssertNil(try store.get(fid: me, teamId: otherTeamId))
    }

    func testAnAnsweredOfferHidesWhileItConfirms() throws {
        let store = session.teamOffers
        try store.reconcile(
            invited: [Team(owner: alice, members: [alice], invitees: [me], active: true, id: teamId)],
            transfers: [], for: me, now: at(0)
        )
        try store.markAnswered(fid: me, teamId: teamId, now: at(10))
        XCTAssertTrue(try store.waiting(fid: me, now: at(20)).isEmpty)
        // A join that never made it does not bury the invitation.
        XCTAssertEqual(try store.waiting(fid: me, now: at(10 + 25 * 3_600)).count, 1)
    }

    /// A notice costs its sender nothing, so the unconfirmed ones are
    /// bounded.
    func testUnconfirmedNoticesAreCapped() throws {
        let store = session.teamOffers
        for i in 0..<(TeamOffersStore.maxUnconfirmed + 5) {
            try store.note(
                TeamNotice(kind: .invitation, teamId: "team\(i)", teamName: nil),
                from: alice, for: me, now: at(TimeInterval(i))
            )
        }
        let kept = try store.all(fid: me)
        XCTAssertEqual(kept.count, TeamOffersStore.maxUnconfirmed)
        XCTAssertNil(try store.get(fid: me, teamId: "team0"), "the oldest go first")
    }

    // MARK: - the receive path

    private func incoming(_ text: String, from sender: String, at seconds: TimeInterval) -> ImMessage {
        var m = ImMessage.text(type: .p2p, from: sender, to: me, text, now: at(seconds))
        m.id = ImMessage.hexId(fudpId: Int64(seconds) &+ 7_000)
        return m
    }

    /// **From a stranger, and still seen.** An invitation usually comes
    /// from somebody not yet accepted; held as a message request it would
    /// be a line of protocol in the one place least likely to be read.
    func testANoticeFromAStrangerIsASignalNotAHeldMessage() throws {
        let notice = TeamNotice(kind: .invitation, teamId: teamId, teamName: "T").text
        let received = try session.chat.receive(incoming(notice, from: alice, at: 10), as: me, now: at(10))
        guard case .signal = received else { return XCTFail("expected a signal, got \(received)") }
        XCTAssertEqual(try session.messageRequests.count(from: alice), 0)
        XCTAssertTrue(try session.conversations.visible().isEmpty)
    }

    func testANoticeFromABlockedSenderIsDropped() throws {
        try session.contactPolicy.mutate(liveFid: me) { $0.block(alice) }
        let notice = TeamNotice(kind: .invitation, teamId: teamId, teamName: "T").text
        let received = try session.chat.receive(incoming(notice, from: alice, at: 10), as: me, now: at(10))
        guard case .ignored = received else { return XCTFail("expected it dropped, got \(received)") }
    }

    func testTheRouterRecordsANoticeAsAnOffer() throws {
        let notice = TeamNotice(kind: .transfer, teamId: teamId, teamName: "T")
        let outcome = try router().route(incoming(notice.text, from: alice, at: 10), as: me, now: at(10))
        XCTAssertEqual(outcome.teamNotice, notice)
        XCTAssertEqual(try session.teamOffers.get(fid: me, teamId: teamId)?.kind, .transfer)
    }

    func testAnInvitationToATeamWeAreInIsStale() throws {
        try session.teams.upsert(Team(owner: alice, members: [alice, me], active: true, id: teamId))
        let notice = TeamNotice(kind: .invitation, teamId: teamId, teamName: "T")
        let outcome = try router().route(incoming(notice.text, from: alice, at: 10), as: me, now: at(10))
        XCTAssertNil(outcome.teamNotice)
        XCTAssertNil(try session.teamOffers.get(fid: me, teamId: teamId))
    }

    /// Sent silently, as Android sends it: sealed to the recipient, in
    /// the outbox, and no row in any transcript.
    func testNoticesAreQueuedSealedWithoutATranscriptRow() async throws {
        // A real FID: the address book refuses anything else.
        let bobPub = try Secp256k1.publicKey(fromPrivateKey: bobPriv)
        let realBob = try FchAddress(publicKey: bobPub).fid
        try session.contacts.upsert(Contact(id: realBob, pubkey: bobPub))
        mock.responder = { _ in try makeResponse(code: 404) }

        let sent = try await session.queueTeamNotices(
            .invitation, teamId: teamId, teamName: "T", to: [realBob, carol, me], now: at(0)
        )
        XCTAssertEqual(sent.queued, [realBob])
        XCTAssertEqual(sent.unreachable, [carol], "no published key, nowhere to seal to")

        let queued = try session.outbox.all()
        XCTAssertEqual(queued.count, 1)
        var message = try XCTUnwrap(queued.first?.message)
        XCTAssertEqual(queued.first?.conversationId, Conversation.id(type: .p2p, targetId: realBob))
        XCTAssertTrue(message.isSealed)
        XCTAssertTrue(message.openBody(privkey: bobPriv))
        XCTAssertEqual(TeamNotice.parse(message.content)?.teamId, teamId)
        XCTAssertNil(try session.conversations.get(id: Conversation.id(type: .p2p, targetId: realBob)))
    }

    // MARK: - the sync that sees a dismissal

    /// A dismissed member is taken out of `members`, so a sync asking
    /// only about `members` never showed them the team again.
    func testTheTeamSyncAlsoAsksAboutExMembers() async throws {
        try session.conversations.upsert({
            var c = Conversation(id: Conversation.id(type: .team, targetId: teamId), targetId: teamId, type: .team)
            c.leftGroup = false
            return c
        }())
        var served = false
        mock.responder = { [teamId, alice, me] call in
            guard call.api == "base.search" else { return try makeResponse(code: 0) }
            defer { served = true }
            if served { return try makeResponse(code: 404) }
            return try makeResponse(code: 0, data: [[
                "id": teamId, "owner": alice, "members": [alice],
                "exMembers": [me], "active": true, "lastHeight": 10,
            ]])
        }
        let result = try await GroupService(fapi: mock).syncTeams(
            fid: me, into: session.teams, conversations: session.conversations
        )
        XCTAssertEqual(result.left, 1)
        XCTAssertEqual(try session.conversations.get(id: Conversation.id(type: .team, targetId: teamId))?.leftGroup, true)

        let dsl = try XCTUnwrap(
            try JSONSerialization.jsonObject(with: try XCTUnwrap(mock.recorded.first?.fcdsl)) as? [String: Any]
        )
        let terms = try XCTUnwrap((dsl["query"] as? [String: Any])?["terms"] as? [String: Any])
        XCTAssertEqual(terms["fields"] as? [String], ["members", "exMembers"])
    }

    func testOffersAreReadFromInviteesAndTransferee() async throws {
        mock.responder = { _ in try makeResponse(code: 404) }
        _ = try await session.refreshTeamOffers(now: at(0))
        let fields = try mock.recorded.filter { $0.api == "base.search" }.map { call -> [String] in
            let dsl = try XCTUnwrap(try JSONSerialization.jsonObject(with: try XCTUnwrap(call.fcdsl)) as? [String: Any])
            let terms = (dsl["query"] as? [String: Any])?["terms"] as? [String: Any]
            return terms?["fields"] as? [String] ?? []
        }
        XCTAssertEqual(fields, [["invitees"], ["transferee"]])
    }

    // MARK: - helpers

    private func router() throws -> SignalRouter {
        SignalRouter(
            rooms: session.rooms,
            teams: session.teams,
            symkeys: session.symkeys,
            invites: session.roomInvites,
            roomService: try session.roomService,
            roomConversations: session.roomConversations,
            privkey: Data(repeating: 0xA1, count: 32),
            teamOffers: session.teamOffers
        )
    }

    private func assertRefused(
        _ expected: TeamGovernanceFailure,
        file: StaticString = #filePath, line: UInt = #line,
        _ body: @escaping () async throws -> Void
    ) async {
        do {
            try await body()
            XCTFail("expected \(expected)", file: file, line: line)
        } catch let failure as ActiveSession.Failure {
            guard case .underlying(let inner) = failure,
                  let governance = inner as? TeamGovernanceFailure
            else { return XCTFail("expected \(expected), got \(failure)", file: file, line: line) }
            XCTAssertEqual(governance, expected, file: file, line: line)
        } catch {
            XCTFail("expected \(expected), got \(error)", file: file, line: line)
        }
    }

    /// The team as `getByIds` returns it, and — for a carve that should
    /// go through — a funded wallet and a broadcast sink beside it.
    private func stageTeam(
        _ row: [String: Any],
        funded: Bool = false,
        onBroadcast: @escaping @Sendable (String) -> Void = { _ in }
    ) {
        let id = row["id"] as? String ?? teamId
        let owner = session.mainFid
        mock.responder = { call in
            switch call.api {
            case DirectoryService.getByIdsApi:
                return try makeResponse(code: 0, data: [id: row])
            case "base.cashValid" where funded:
                let h160 = try FchAddress(fid: owner).hash160
                let txid = String(repeating: "ab", count: 32)
                return try makeResponse(
                    data: [[
                        "id": try Cash.makeId(birthTxId: txid, birthIndex: 0),
                        "owner": owner,
                        "value": Int64(10_000_000),
                        "type": "P2PKH",
                        "birthTxId": txid,
                        "birthIndex": 0,
                        "lockScript": Cash.canonicalP2PKHLockScript(hash160: h160),
                    ]],
                    bestHeight: 3_500_000
                )
            case "base.broadcastTx" where funded:
                let params = try JSONSerialization.jsonObject(with: call.params!) as? [String: Any]
                onBroadcast((params?["rawTx"] as? String) ?? "")
                return try makeResponse(data: "team-txid-001")
            default:
                return try makeResponse(code: 404)
            }
        }
    }
}

/// A box for a value a `@Sendable` closure writes.
private final class Box: @unchecked Sendable {
    var value: String?
}
