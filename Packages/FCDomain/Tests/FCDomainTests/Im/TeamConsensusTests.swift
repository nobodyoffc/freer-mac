import XCTest
import FCCore
import FCTransport
@testable import FCDomain

/// A team's consensus document, and the two chain facts that make it
/// fragile: `home` is replaced wholesale on update, and agreement is
/// tracked as a negative set that only the chain fills in.
final class TeamConsensusTests: XCTestCase {

    private var baseDir: URL!
    private var manager: ConfigureManager!
    private var mock: MockFapiClient!
    private var session: ActiveSession!

    private let teamId = "3f9c1a2b0000000000000000000000000000000000000000000000000000tid1"
    private let dockSid = String(repeating: "a", count: 64)
    private let diskSid = String(repeating: "b", count: 64)
    private let otherDiskSid = String(repeating: "c", count: 64)

    override func setUpWithError() throws {
        baseDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("TeamConsensusTests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: baseDir, withIntermediateDirectories: true)
        manager = try ConfigureManager(baseDirectory: baseDir)
        mock = MockFapiClient()
        let configure = try manager.createConfigure(password: Data("pwd".utf8), kdfKind: .legacySha256)
        let info = try configure.addMain(privkey: Data(repeating: 0xB2, count: 32), label: "A")
        session = try configure.unlockMain(fid: info.fid, fapi: mock)
    }

    override func tearDownWithError() throws {
        session = nil
        mock = nil
        manager = nil
        if let baseDir { try? FileManager.default.removeItem(at: baseDir) }
    }

    private var me: String { session.liveFid }
    private var service: GroupService { GroupService(fapi: mock) }

    // MARK: - home is merged, never rebuilt

    /// The defect this whole file exists for. The parser does
    /// `if (hist.getHome() != null) team.setHome(hist.getHome())`, so a
    /// form that builds a fresh map holding only DOCK **deletes** the
    /// team's DISK entry — after which no member can fetch the consensus
    /// document they are on chain as having agreed to.
    func testUpdatingTheDockKeepsTheDiskEntry() {
        let stored = [
            ServiceName.dock: HomeServiceResolver.sidPrefix + dockSid,
            ServiceName.disk: HomeServiceResolver.sidPrefix + diskSid,
        ]
        let merged = GroupHome.merged(
            over: stored, changing: [ServiceName.dock: otherDiskSid]
        )
        XCTAssertEqual(
            merged?[ServiceName.disk], HomeServiceResolver.sidPrefix + diskSid,
            "the DISK entry must survive an update that only names the DOCK"
        )
        XCTAssertEqual(merged?[ServiceName.dock], HomeServiceResolver.sidPrefix + otherDiskSid)
    }

    /// A nil is "this update says nothing about that key", which is as
    /// close to clearing as the op gets — the entry stays.
    func testANilChangeLeavesTheStoredEntryAlone() {
        let stored = [ServiceName.dock: HomeServiceResolver.sidPrefix + dockSid]
        let merged = GroupHome.merged(
            over: stored,
            changing: [ServiceName.dock: nil, ServiceName.disk: diskSid]
        )
        XCTAssertEqual(merged?[ServiceName.dock], HomeServiceResolver.sidPrefix + dockSid)
        XCTAssertEqual(merged?[ServiceName.disk], HomeServiceResolver.sidPrefix + diskSid)
    }

    /// An update that changes nothing about `home` omits it, rather than
    /// re-announcing a DOCK move that is not one.
    func testAnUnchangedHomeIsOmitted() {
        let stored = [ServiceName.dock: HomeServiceResolver.sidPrefix + dockSid]
        XCTAssertNil(GroupHome.merged(over: stored, changing: [ServiceName.dock: dockSid]))
        XCTAssertNil(GroupHome.merged(over: nil, changing: [:]))
    }

    /// **A bare sid and a prefixed one are the same service.** A picker
    /// that hands back the bare form must not read as a change — that
    /// carves a fee for nothing, and stores a value shaped unlike every
    /// other client's.
    func testABareSidFromAPickerIsNormalisedAndReadsAsUnchanged() {
        let stored = [ServiceName.dock: HomeServiceResolver.sidPrefix + dockSid]
        XCTAssertNil(
            GroupHome.merged(over: stored, changing: [ServiceName.dock: dockSid]),
            "picking the server already stored is not a change"
        )
        let fresh = GroupHome.merged(over: nil, changing: [ServiceName.dock: dockSid])
        XCTAssertEqual(fresh?[ServiceName.dock], HomeServiceResolver.sidPrefix + dockSid)
    }

    /// A direct URL is not a service id and is carved exactly as typed.
    func testADirectUrlIsLeftAlone() {
        let merged = GroupHome.merged(
            over: nil, changing: [ServiceName.dock: "https://dock.example"]
        )
        XCTAssertEqual(merged?[ServiceName.dock], "https://dock.example")
    }

    // MARK: - finding the team's DISK

    func testDiskSidReadsBothHomeShapes() {
        XCTAssertEqual(
            TeamConsensus.diskSid(of: Team(home: [ServiceName.disk: diskSid], id: teamId)),
            diskSid
        )
        XCTAssertEqual(
            TeamConsensus.diskSid(of: Team(
                home: [ServiceName.disk: HomeServiceResolver.sidPrefix + diskSid], id: teamId
            )),
            diskSid
        )
        XCTAssertNil(TeamConsensus.diskSid(of: Team(home: [:], id: teamId)))
        XCTAssertNil(TeamConsensus.diskSid(of: nil))
    }

    // MARK: - the id is the content

    func testTheIdIsTheHashOfTheText() throws {
        let text = "who decides, and how"
        let expected = Hex.encode(Hash.doubleSha256(Data(text.utf8)))
        XCTAssertEqual(TeamConsensus.id(for: text), expected)

        let stored = try session.teamConsensus.storeText(text)
        XCTAssertEqual(stored, expected, "storing must not change the id")
        XCTAssertNotNil(session.teamConsensus.localURL(consensusId: stored))
    }

    /// Editing one word makes a different document. That is the whole
    /// mechanism behind "every member must agree again".
    func testEditingTheTextChangesTheId() {
        XCTAssertNotEqual(TeamConsensus.id(for: "a"), TeamConsensus.id(for: "b"))
    }

    func testAnEmptyDocumentIsRefused() {
        XCTAssertThrowsError(try session.teamConsensus.storeText(""))
    }

    /// With no DISK to ask, the failure has to say *that* — not
    /// "download failed", which names a step that never ran.
    func testNoDiskIsNotADownloadFailure() async {
        do {
            _ = try await session.teamConsensus.fetch(
                consensusId: String(repeating: "d", count: 64), diskSids: []
            )
            XCTFail("expected a throw")
        } catch let failure as TeamConsensus.Failure {
            guard case .notHere = failure else {
                return XCTFail("expected .notHere, got \(failure)")
            }
        } catch {
            XCTFail("unexpected \(error)")
        }
    }

    /// Local bytes are found without any DISK being involved at all —
    /// the first step of the read order, and the only free one.
    func testAReadPrefersTheLocalCopy() async throws {
        let id = try session.teamConsensus.storeText(TeamConsensus.template)
        let text = try await session.teamConsensus.readText(consensusId: id, diskSids: [])
        XCTAssertEqual(text, TeamConsensus.template)
    }

    // MARK: - a consensus that is not prose

    /// The defect this section exists for: an owner on another client
    /// carves a PDF, and the Mac reported "not UTF-8 text" about bytes
    /// it had already fetched, verified and stored. Nothing on the
    /// chain promises prose, so a read has to come back with the file.
    func testAConsensusThatIsAPdfComesBackAsAFileRatherThanAnError() async throws {
        let bytes = pdfBytes
        let id = try registerLocalDocument(bytes, named: "consensus.pdf")

        let document = try await session.teamConsensus.read(consensusId: id, diskSids: [])

        XCTAssertNil(document.text, "a PDF is not prose and must not be decoded into any")
        XCTAssertEqual(document.kind?.fileExtension, "pdf")
        XCTAssertEqual(document.kind?.label, "a PDF")
        XCTAssertEqual(document.byteCount, Int64(bytes.count))
        XCTAssertEqual(try Data(contentsOf: document.url), bytes)
    }

    /// Unrecognised bytes are still a document. Failing to name a file
    /// is not a reason to withhold it.
    func testBytesNothingRecognisesStillComeBackAsAFile() async throws {
        let bytes = Data([0x00, 0x01, 0x02, 0xFF, 0xFD, 0x7F, 0x00])
        let id = try registerLocalDocument(bytes, named: "consensus.bin")

        let document = try await session.teamConsensus.read(consensusId: id, diskSids: [])

        XCTAssertNil(document.text)
        XCTAssertNil(document.kind, "nothing should be guessed from bytes nothing recognises")
    }

    /// `readText` keeps its contract for the callers that have nothing
    /// to offer but prose.
    func testReadTextStillRefusesBytesThatAreNotText() async throws {
        let id = try registerLocalDocument(pdfBytes, named: "consensus.pdf")
        do {
            _ = try await session.teamConsensus.readText(consensusId: id, diskSids: [])
            XCTFail("expected a throw")
        } catch let failure as TeamConsensus.Failure {
            guard case .notUtf8 = failure else {
                return XCTFail("expected .notUtf8, got \(failure)")
            }
        }
    }

    /// The office formats are zips, and which one is read out of the
    /// entry names rather than by unpacking.
    func testTheZipOfficeFormatsAreToldApartByTheirEntryNames() {
        var docx = Data([0x50, 0x4B, 0x03, 0x04])
        docx.append(Data("[Content_Types].xml……word/document.xml".utf8))
        XCTAssertEqual(TeamConsensus.sniff(docx)?.fileExtension, "docx")

        var plain = Data([0x50, 0x4B, 0x03, 0x04])
        plain.append(Data("readme.txt".utf8))
        XCTAssertEqual(TeamConsensus.sniff(plain)?.fileExtension, "zip")
    }

    /// **No encoding guessing.** Every legacy decoder turns arbitrary
    /// bytes into something, and something is worse than nothing when
    /// the screen it lands on says "this is what your team agreed to".
    func testADecodeNeverGuessesPastUtf8AndAMarkedUtf16() {
        XCTAssertEqual(TeamConsensus.decodeText(Data("héllo".utf8)), "héllo")
        // GB18030 bytes for 共识 — decodable by a guesser, and not text
        // this client is willing to invent.
        XCTAssertNil(TeamConsensus.decodeText(Data([0xB9, 0xB2, 0xCA, 0xB6])))
        var utf16 = Data([0xFF, 0xFE])
        utf16.append(Data("ok".utf16.flatMap { [UInt8($0 & 0xFF), UInt8($0 >> 8)] }))
        XCTAssertEqual(TeamConsensus.decodeText(utf16), "ok")
    }

    /// A PDF's first two lines: the version, then the binary comment
    /// every writer emits so that transports stop treating the file as
    /// text. Those four high bytes are *not* valid UTF-8 — which is the
    /// whole reason this file needs a fixture rather than a string.
    private var pdfBytes: Data {
        var bytes = Data("%PDF-1.7\n%".utf8)
        bytes.append(contentsOf: [0xE2, 0xE3, 0xCF, 0xD3, 0x0A])
        bytes.append(Data("1 0 obj".utf8))
        return bytes
    }

    /// Store bytes on this device under their own hash, the way a
    /// finished download is adopted, and hand back the id.
    private func registerLocalDocument(_ bytes: Data, named name: String) throws -> String {
        let id = Hex.encode(Hash.doubleSha256(bytes))
        try FileManager.default.createDirectory(
            at: session.files.dataDirectory, withIntermediateDirectories: true
        )
        let url = session.files.defaultLocalURL(did: id)
        try bytes.write(to: url, options: .atomic)
        _ = try session.files.registerFile(at: url, name: name)
        return id
    }

    /// The template's newlines are its bytes. Android's build collapsed
    /// them into spaces and flattened the document without anyone
    /// noticing until it was carved.
    func testTheTemplateKeepsItsLineBreaks() {
        XCTAssertTrue(TeamConsensus.template.contains("\n\n"))
        XCTAssertTrue(TeamConsensus.template.contains("## Who may join"))
    }

    // MARK: - who owes a signature

    /// A member listed in `notAgreeMembers` owes one, and the id being
    /// replaced is captured from the row about to be overwritten — the
    /// only instant it exists on this device.
    func testTheOutgoingConsensusIdIsCapturedBeforeItIsLost() throws {
        let store = session.consensusSignatures
        let cached = Team(
            consensusId: "old-consensus",
            members: [me, "F-owner"],
            home: [ServiceName.disk: HomeServiceResolver.sidPrefix + diskSid],
            id: teamId
        )
        let fresh = Team(
            owner: "F-owner",
            consensusId: "new-consensus",
            members: [me, "F-owner"],
            notAgreeMembers: [me],
            home: [ServiceName.disk: HomeServiceResolver.sidPrefix + otherDiskSid],
            id: teamId
        )
        let request = try XCTUnwrap(store.reconcile(team: fresh, cached: cached, as: me))
        XCTAssertEqual(request.consensusId, "new-consensus")
        XCTAssertEqual(request.previousConsensusId, "old-consensus")
        // And where the old document still lives, since the team moved.
        XCTAssertEqual(request.previousDiskSid, diskSid)
    }

    /// A later sync that changes something unrelated must not overwrite
    /// the captured id with the current one — that would leave the
    /// member comparing a document against itself.
    func testALaterSyncDoesNotClobberTheCapturedId() throws {
        let store = session.consensusSignatures
        let cached = Team(consensusId: "old", members: [me], id: teamId)
        let fresh = Team(
            owner: "F-owner", consensusId: "new",
            members: [me], notAgreeMembers: [me], id: teamId
        )
        _ = try store.reconcile(team: fresh, cached: cached, as: me)

        var renamed = fresh
        renamed.stdName = "Renamed"
        let after = try XCTUnwrap(store.reconcile(team: renamed, cached: fresh, as: me))
        XCTAssertEqual(after.previousConsensusId, "old")
        XCTAssertEqual(after.teamName, "Renamed")
    }

    /// Postponing is an answer, and a later sync must not undo it.
    func testPostponingSurvivesTheNextSync() throws {
        let store = session.consensusSignatures
        let fresh = Team(
            owner: "F-owner", consensusId: "new",
            members: [me], notAgreeMembers: [me], id: teamId
        )
        _ = try store.reconcile(team: fresh, cached: nil, as: me)
        XCTAssertTrue(try store.postpone(teamId: teamId))
        XCTAssertTrue(try XCTUnwrap(store.reconcile(team: fresh, cached: fresh, as: me)).isPostponed)
        XCTAssertTrue(try store.outstanding().isEmpty)
        XCTAssertEqual(try store.all().count, 1)
    }

    /// **Self-clearing.** The signature landing from another device, a
    /// dismissal, or the owner reverting all look the same from here:
    /// the chain stops listing us, so the row goes.
    func testTheRowClearsItselfWhenTheChainStopsListingUs() throws {
        let store = session.consensusSignatures
        let owing = Team(
            owner: "F-owner", consensusId: "new",
            members: [me], notAgreeMembers: [me], id: teamId
        )
        _ = try store.reconcile(team: owing, cached: nil, as: me)
        XCTAssertNotNil(try store.get(teamId: teamId))

        var signed = owing
        signed.notAgreeMembers = nil
        XCTAssertNil(try store.reconcile(team: signed, cached: owing, as: me))
        XCTAssertNil(try store.get(teamId: teamId))
    }

    /// The owner is never in `notAgreeMembers` — their update *is* their
    /// signature — so an owner is never prompted.
    func testAnOwnerIsNeverAsked() throws {
        let store = session.consensusSignatures
        let team = Team(
            owner: me, consensusId: "new",
            members: [me, "F-bob"], notAgreeMembers: ["F-bob"], id: teamId
        )
        XCTAssertNil(try store.reconcile(team: team, cached: nil, as: me))
    }

    /// A disbanded team asks nothing of anybody.
    func testADisbandedTeamAsksNothing() throws {
        let store = session.consensusSignatures
        let team = Team(
            owner: "F-owner", consensusId: "new", members: [me],
            notAgreeMembers: [me], active: false, id: teamId
        )
        XCTAssertNil(try store.reconcile(team: team, cached: nil, as: me))
    }

    /// The obligation is discovered by the ordinary refresh, not by a
    /// message — which is what makes it survive being offline.
    func testTheTeamSyncRecordsTheObligation() async throws {
        try session.teams.upsert(Team(consensusId: "old", members: [me], id: teamId))
        var served = false
        mock.responder = { [teamId, me] call in
            guard call.api == "base.search" else { return try makeResponse(code: 0) }
            defer { served = true }
            if served { return try makeResponse(code: 404) }
            return try makeResponse(code: 0, data: [[
                "id": teamId,
                "owner": "F-owner",
                "consensusId": "new",
                "members": [me, "F-owner"],
                "notAgreeMembers": [me],
                "active": true,
            ]])
        }
        let result = try await service.syncTeams(
            fid: me, into: session.teams, signatures: session.consensusSignatures
        )
        XCTAssertEqual(result.awaitingSignature, 1)
        let request = try XCTUnwrap(session.consensusSignatures.get(teamId: teamId))
        XCTAssertEqual(request.consensusId, "new")
        XCTAssertEqual(request.previousConsensusId, "old")
    }

    // MARK: - refusing carves the chain would waste

    /// Signing re-reads the team, and refuses when the chain no longer
    /// lists us. The parser would reject the carve anyway — after the
    /// fee was spent.
    func testAgreeingRefusesWhenTheChainNoLongerAsks() async throws {
        stageTeamByIds([
            "id": teamId, "owner": "F-owner", "consensusId": "new",
            "members": [me, "F-owner"], "active": true,
        ])
        do {
            _ = try await session.carveTeamAgreeConsensusOnChain(teamId: teamId)
            XCTFail("expected a throw")
        } catch let failure as ActiveSession.Failure {
            guard case .underlying(let inner) = failure,
                  case TeamConsensusFailure.nothingToSign = inner
            else { return XCTFail("expected .nothingToSign, got \(failure)") }
        }
    }

    /// **The indexer skips an existing member silently, and the fee is
    /// paid anyway** — and the team is re-indexed, bumping its
    /// `lastTxId`/`lastTime`/`lastHeight` for a write that changed
    /// nothing. So a carve naming nobody new is refused here.
    func testInvitingSomebodyAlreadyInTheTeamIsRefused() async throws {
        stageTeamByIds([
            "id": teamId, "owner": "F-owner", "consensusId": "c",
            "members": [me, "F-bob"], "active": true,
        ])
        let plan = await session.planTeamInvite(teamId: teamId, fids: ["F-bob"])
        XCTAssertEqual(plan.alreadyIn, ["F-bob"])
        XCTAssertTrue(plan.isEmpty)

        do {
            _ = try await session.carveTeamInviteOnChain(teamId: teamId, fids: ["F-bob"])
            XCTFail("expected a throw")
        } catch let failure as ActiveSession.Failure {
            guard case .underlying(let inner) = failure,
                  case TeamConsensusFailure.nobodyNewToInvite = inner
            else { return XCTFail("expected .nobodyNewToInvite, got \(failure)") }
        }
    }

    /// Someone already invited but not yet joined is dropped from the
    /// carve — re-adding a FID to a set is not a second invitation.
    func testAlreadyInvitedIsDroppedButGenuinelyNewSurvives() async {
        stageTeamByIds([
            "id": teamId, "owner": "F-owner", "consensusId": "c",
            "members": ["F-owner"], "invitees": ["F-bob"], "active": true,
        ])
        let plan = await session.planTeamInvite(teamId: teamId, fids: ["F-bob", "F-carol"])
        XCTAssertEqual(plan.alreadyInvited, ["F-bob"])
        XCTAssertEqual(plan.toInvite, ["F-carol"])
    }

    /// **Wrongly excluding somebody is worse than a wasted fee**, so a
    /// chain read that fails degrades to no filtering at all.
    func testAFailedMembershipReadDoesNotDropAnybody() async {
        mock.responder = { _ in try makeResponse(code: 500) }
        let plan = await session.planTeamInvite(teamId: teamId, fids: ["F-bob"])
        XCTAssertEqual(plan.toInvite, ["F-bob"])
    }

    // MARK: - the presence check decides whether money is spent

    /// **A DISK that answers "not here" must not read as "already
    /// there".** This is the check the whole no-unbacked-id rule rests
    /// on: say yes and the upload is skipped, the carve proceeds, and
    /// the team's consensus points at bytes nobody holds.
    func testADiskThatDoesNotHoldTheDocumentSaysSo() async throws {
        let disk = MockFapiClient()
        disk.responder = { call in
            // An empty map is the server saying it has none of them.
            guard call.api == "disk.check" else { return try makeResponse(code: 0) }
            return try makeResponse(code: 0, data: [String: String]())
        }
        let consensus = consensusService(over: disk)
        let placed = try await consensus.place(
            consensusId: TeamConsensus.id(for: "not stored anywhere"),
            onDiskSid: diskSid,
            fallbackDiskSid: nil
        )
        XCTAssertEqual(placed, .unavailable(hadOtherDisk: false))
    }

    /// A document already on the target DISK is not re-uploaded.
    /// **Carving is a payment**: re-storing what is already there
    /// charges the owner for nothing, every time they rename the team.
    func testADocumentAlreadyOnTheDiskIsNotReUploaded() async throws {
        let id = TeamConsensus.id(for: "already up there")
        let disk = MockFapiClient()
        disk.responder = { call in
            guard call.api == "disk.check" else {
                XCTFail("nothing but the presence check should be called")
                return try makeResponse(code: 0)
            }
            return try makeResponse(code: 0, data: [id: ["id": id, "size": 12]])
        }
        let consensus = consensusService(over: disk)
        let placed = try await consensus.place(
            consensusId: id, onDiskSid: diskSid, fallbackDiskSid: nil
        )
        XCTAssertEqual(placed, .alreadyThere)
    }

    /// A team whose `home` carries no DISK has nowhere the document
    /// could have been pulled from, and that is **not** a loss worth
    /// warning about — there was never a copy there to move.
    func testABlankFallbackDiskIsAPlainNotFound() async throws {
        let disk = MockFapiClient()
        disk.responder = { call in
            guard call.api == "disk.check" else { return try makeResponse(code: 0) }
            return try makeResponse(code: 0, data: [String: String]())
        }
        let consensus = consensusService(over: disk)
        for fallback in [nil, "", diskSid] as [String?] {
            let placed = try await consensus.place(
                consensusId: TeamConsensus.id(for: "gone"),
                onDiskSid: diskSid,
                fallbackDiskSid: fallback
            )
            XCTAssertEqual(
                placed, .unavailable(hadOtherDisk: false),
                "a blank or identical fallback is nothing to have lost"
            )
        }
    }

    /// A ``TeamConsensus`` whose only DISK is `client`.
    private func consensusService(over client: MockFapiClient) -> TeamConsensus {
        TeamConsensus(files: session.files, hats: session.hats) { _ in
            DiskService(fapi: client)
        }
    }

    /// `base.getByIds` answers with a map keyed by id.
    private func stageTeamByIds(_ row: [String: Any]) {
        let id = row["id"] as? String ?? teamId
        mock.responder = { call in
            guard call.api == DirectoryService.getByIdsApi else {
                return try makeResponse(code: 0)
            }
            return try makeResponse(code: 0, data: [id: row])
        }
    }
}
