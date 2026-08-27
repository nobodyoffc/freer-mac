import XCTest
import FCCore
@testable import FCDomain

/// The proof model and its FEIP builders: the four ops' wire shapes,
/// the guards that run before anything is paid for, and the derived
/// state that decides which actions a row offers.
final class ProofTests: XCTestCase {

    private func opData(_ carve: String) throws -> [String: Any] {
        let root = try XCTUnwrap(
            JSONSerialization.jsonObject(with: Data(carve.utf8)) as? [String: Any]
        )
        return try XCTUnwrap(root["data"] as? [String: Any])
    }

    // MARK: - envelope

    func testEnvelopeIsSn14Ver1() throws {
        let carve = try ProofFeip.issueCarve(title: "t", content: "c")
        let root = try XCTUnwrap(
            JSONSerialization.jsonObject(with: Data(carve.utf8)) as? [String: Any]
        )
        XCTAssertEqual(root["type"] as? String, "FEIP")
        XCTAssertEqual(root["sn"] as? String, "14")
        XCTAssertEqual(root["ver"] as? String, "1")
        XCTAssertEqual(root["name"] as? String, "Proof")
    }

    /// The registry and the builder must agree — the builder spells its
    /// own sn/ver (see ``FeipProtocol``'s note), so nothing but a test
    /// keeps the two from drifting.
    func testBuilderAgreesWithTheProtocolRegistry() {
        XCTAssertEqual(ProofFeip.sn, FeipProtocol.proof.sn)
        XCTAssertEqual(ProofFeip.ver, FeipProtocol.proof.ver)
        XCTAssertEqual(ProofFeip.protocolName, FeipProtocol.proof.protocolName)
    }

    // MARK: - ops

    func testIssueOpCarriesEveryField() throws {
        let carve = try ProofFeip.issueCarve(
            title: "Receipt", content: "Paid in full",
            cosigners: ["FID-A", "FID-B"],
            transferable: true, allSignsRequired: true
        )
        let data = try opData(carve)
        XCTAssertEqual(data["op"] as? String, "issue")
        XCTAssertEqual(data["title"] as? String, "Receipt")
        XCTAssertEqual(data["content"] as? String, "Paid in full")
        XCTAssertEqual(data["cosigners"] as? [String], ["FID-A", "FID-B"])
        XCTAssertEqual(data["transferable"] as? Bool, true)
        XCTAssertEqual(data["allSignsRequired"] as? Bool, true)
    }

    /// An empty cosigner list is omitted, not sent as `[]`: it reads the
    /// same to the indexer and every byte saved is content budget.
    func testEmptyCosignersAreOmitted() throws {
        let data = try opData(try ProofFeip.issueCarve(
            title: "t", content: "c", cosigners: []
        ))
        XCTAssertNil(data["cosigners"])
    }

    func testSignTransferAndDestroyOps() throws {
        var data = try XCTUnwrap(
            JSONSerialization.jsonObject(
                with: Data(try ProofFeip.signOp(proofId: "p1").utf8)
            ) as? [String: Any]
        )
        XCTAssertEqual(data["op"] as? String, "sign")
        XCTAssertEqual(data["proofId"] as? String, "p1")

        data = try XCTUnwrap(
            JSONSerialization.jsonObject(
                with: Data(try ProofFeip.transferOp(proofId: "p1").utf8)
            ) as? [String: Any]
        )
        XCTAssertEqual(data["op"] as? String, "transfer")
        XCTAssertEqual(data["proofId"] as? String, "p1")
        // The recipient is read off the transaction output, never the
        // payload — a transfer op naming one would be a different
        // protocol.
        XCTAssertNil(data["recipient"])
        XCTAssertNil(data["to"])

        data = try XCTUnwrap(
            JSONSerialization.jsonObject(
                with: Data(try ProofFeip.destroyOp(proofIds: ["a", "b"]).utf8)
            ) as? [String: Any]
        )
        XCTAssertEqual(data["op"] as? String, "destroy")
        XCTAssertEqual(data["proofIds"] as? [String], ["a", "b"])
    }

    func testDestroyWithNoIdsThrows() {
        XCTAssertThrowsError(try ProofFeip.destroyOp(proofIds: []))
    }

    // MARK: - guards

    func testEmptyTitleOrContentIsRefused() {
        XCTAssertThrowsError(try ProofFeip.issueCarve(title: "  ", content: "c"))
        XCTAssertThrowsError(try ProofFeip.issueCarve(title: "t", content: "\n\t "))
    }

    /// The limit is checked against the whole encoded carve, not the
    /// body — and one byte either side of it must decide the outcome.
    func testTheSizeLimitIsCheckedOnTheWholeCarve() throws {
        func fits(contentBytes: Int) -> Bool {
            let content = String(repeating: "x", count: contentBytes)
            return (try? ProofFeip.issueCarve(title: "t", content: content)) != nil
        }
        // Find the boundary through the same budget the UI shows, then
        // prove the builder agrees with it exactly.
        let headroom = ProofFeip.remainingContentBytes(title: "t", content: "")
        XCTAssertTrue(fits(contentBytes: headroom))
        XCTAssertFalse(fits(contentBytes: headroom + 1))
    }

    /// The budget must be measured on encoded bytes: a quotation mark
    /// costs two after JSON escaping, so a character count would
    /// promise room that isn't there.
    func testRemainingBudgetAccountsForJsonEscaping() {
        let plain = ProofFeip.remainingContentBytes(title: "t", content: "aaaa")
        let quoted = ProofFeip.remainingContentBytes(title: "t", content: "\"\"\"\"")
        XCTAssertEqual(plain - quoted, 4, "each escaped quote must cost one extra byte")
    }

    func testCosignersEatIntoTheContentBudget() {
        let alone = ProofFeip.remainingContentBytes(title: "t", content: "c")
        let withCosigners = ProofFeip.remainingContentBytes(
            title: "t", content: "c", cosigners: [String(repeating: "F", count: 34)]
        )
        XCTAssertLessThan(withCosigners, alone)
    }

    // MARK: - derived state

    private func proof(
        invited: [String]? = nil,
        signed: [String]? = nil,
        transferable: Bool? = true,
        active: Bool? = true,
        destroyed: Bool? = false,
        onChain: Bool? = true,
        owner: String = "me",
        issuer: String = "me"
    ) -> Proof {
        Proof(
            id: "p1", title: "t", content: "c",
            cosignersInvited: invited, cosignersSigned: signed,
            transferable: transferable, active: active, destroyed: destroyed,
            issuer: issuer, owner: owner, onChain: onChain
        )
    }

    func testFullySignedIsVacuousWithNoCosigners() {
        XCTAssertTrue(proof(invited: nil).isFullySigned)
        XCTAssertTrue(proof(invited: []).isFullySigned)
    }

    func testFullySignedNeedsEveryInvitedSignature() {
        XCTAssertFalse(proof(invited: ["a", "b"], signed: ["a"]).isFullySigned)
        XCTAssertTrue(proof(invited: ["a", "b"], signed: ["b", "a"]).isFullySigned)
        XCTAssertEqual(proof(invited: ["a", "b"], signed: ["a"]).cosignersPending, ["b"])
    }

    func testAwaitsSignatureOnlyFromAnUnsignedInvitee() {
        let p = proof(invited: ["a", "b"], signed: ["a"])
        XCTAssertTrue(p.awaitsSignature(from: "b"))
        XCTAssertFalse(p.awaitsSignature(from: "a"), "already signed")
        XCTAssertFalse(p.awaitsSignature(from: "c"), "never invited")
    }

    /// A draft has no chain record to countersign against, so it asks
    /// nobody for a signature however its lists read.
    func testADraftNeverAsksForASignature() {
        let draft = proof(invited: ["b"], onChain: false)
        XCTAssertFalse(draft.awaitsSignature(from: "b"))
    }

    /// All five of Android's pay-icon conditions, each denied alone.
    func testCanTransferNeedsEveryCondition() {
        XCTAssertTrue(proof().canTransfer(as: "me"))
        XCTAssertFalse(proof(onChain: nil).canTransfer(as: "me"), "unconfirmed")
        XCTAssertFalse(proof(owner: "you").canTransfer(as: "me"), "not the owner")
        XCTAssertFalse(proof(transferable: false).canTransfer(as: "me"))
        XCTAssertFalse(proof(active: false).canTransfer(as: "me"))
        XCTAssertFalse(proof(destroyed: true).canTransfer(as: "me"))
        XCTAssertFalse(
            proof(invited: ["a"], signed: []).canTransfer(as: "me"),
            "a half-signed proof carries signatures collected for the current holder"
        )
    }

    func testCanDestroyIsTheOwnersAlone() {
        XCTAssertTrue(proof().canDestroy(as: "me"))
        XCTAssertFalse(proof(owner: "you").canDestroy(as: "me"))
        XCTAssertFalse(proof(destroyed: true).canDestroy(as: "me"))
        XCTAssertFalse(proof(onChain: false).canDestroy(as: "me"), "nothing on chain to retire")
    }

    func testMatchesSearchesTheSameFieldsTheIndexDoes() {
        let p = Proof(
            id: "abc123", title: "Lease", content: "Twelve months",
            cosignersInvited: ["FIDCOSIGN"],
            issuer: "FIDISSUER", owner: "FIDOWNER"
        )
        XCTAssertTrue(p.matches(query: "lease"))
        XCTAssertTrue(p.matches(query: "TWELVE"))
        XCTAssertTrue(p.matches(query: "fidissuer"))
        XCTAssertTrue(p.matches(query: "fidowner"))
        XCTAssertTrue(p.matches(query: "fidcosign"))
        XCTAssertTrue(p.matches(query: "abc"))
        XCTAssertFalse(p.matches(query: "mortgage"))
        XCTAssertFalse(p.matches(query: "   "))
    }

    // MARK: - local id

    /// The id of an unchanged draft must survive a save/reload — that
    /// stability is the only thing it is for.
    func testLocalIdIsStableAndFieldSensitive() {
        let a = Proof.localId(title: "t", content: "c", cosigners: ["x"], transferable: true)
        let b = Proof.localId(title: "t", content: "c", cosigners: ["x"], transferable: true)
        XCTAssertEqual(a, b)
        XCTAssertEqual(a.count, 64, "sha256x2, hex")
        XCTAssertNotEqual(a, Proof.localId(title: "t", content: "c!", cosigners: ["x"], transferable: true))
        XCTAssertNotEqual(a, Proof.localId(title: "t", content: "c", cosigners: nil, transferable: true))
        XCTAssertNotEqual(a, Proof.localId(title: "t", content: "c", cosigners: ["x"], transferable: false))
    }

    /// A draft is the issuer's, is off-chain, and does not claim to be
    /// in force — the last of which Android gets wrong by writing
    /// `active = true` on a proof nobody has countersigned.
    func testCreateLocalIsADraftThatClaimsNothing() {
        let draft = Proof.createLocal(
            title: "t", content: "c", cosigners: ["a"],
            transferable: true, issuer: "me"
        )
        XCTAssertEqual(draft.onChain, false)
        XCTAssertEqual(draft.issuer, "me")
        XCTAssertEqual(draft.owner, "me")
        XCTAssertNil(draft.active)
        XCTAssertEqual(draft.cosignersInvited, ["a"])
    }

    // MARK: - decoding

    /// The three states of `onChain` must survive a round trip through
    /// the wire, because collapsing nil into false tells the user to
    /// pay again for a carve they already broadcast.
    func testOnChainDecodesAsThreeStates() throws {
        func decode(_ json: String) throws -> Proof {
            try JSONDecoder().decode(Proof.self, from: Data(json.utf8))
        }
        XCTAssertEqual(try decode(#"{"id":"a","onChain":true}"#).onChain, true)
        XCTAssertEqual(try decode(#"{"id":"a","onChain":false}"#).onChain, false)
        XCTAssertNil(try decode(#"{"id":"a"}"#).onChain)
    }

    /// A server row carries none of our local bookkeeping; decoding must
    /// not fail for its absence.
    func testDecodingASparseServerRow() throws {
        let row = try JSONDecoder().decode(
            Proof.self,
            from: Data(#"{"id":"x","title":"T","lastHeight":900}"#.utf8)
        )
        XCTAssertEqual(row.id, "x")
        XCTAssertEqual(row.lastHeight, 900)
        XCTAssertNil(row.content)
        XCTAssertEqual(row.name, "T")
    }

    /// The predicate that decides which tab a row belongs on. An absent
    /// flag is the common case on chain rows, and treating it as
    /// "destroyed" would put the entire live list on the Destroyed tab.
    func testIsDestroyedTreatsAnAbsentFlagAsNotDestroyed() {
        XCTAssertTrue(Proof(id: "a", destroyed: true).isDestroyed)
        XCTAssertFalse(Proof(id: "a", destroyed: false).isDestroyed)
        XCTAssertFalse(Proof(id: "a").isDestroyed, "absent is not destroyed")
    }

    /// Live and Destroyed are complements: every row belongs on exactly
    /// one of them, so the two lists can never be equal unless one is
    /// empty.
    func testLiveAndDestroyedPartitionEveryRow() {
        let rows = [
            Proof(id: "a", destroyed: true),
            Proof(id: "b", destroyed: false),
            Proof(id: "c")
        ]
        let live = rows.filter { !$0.isDestroyed }.map(\.id)
        let destroyed = rows.filter(\.isDestroyed).map(\.id)
        XCTAssertEqual(live, ["b", "c"])
        XCTAssertEqual(destroyed, ["a"])
        XCTAssertTrue(Set(live).isDisjoint(with: Set(destroyed)))
        XCTAssertEqual(live.count + destroyed.count, rows.count)
    }

    // MARK: - draft editing

    /// Editing a draft moves its key, because the id is a digest of the
    /// text that will be carved. The pane deletes the old row; what this
    /// pins is that the id actually moves, since an id that didn't would
    /// leave two drafts claiming to be the same proof.
    func testEditingADraftChangesItsId() {
        let before = Proof.createLocal(
            title: "Lease", content: "Twelve months", cosigners: [],
            transferable: false, issuer: "me"
        )
        let after = Proof.createLocal(
            title: "Lease", content: "Twenty-four months", cosigners: [],
            transferable: false, issuer: "me"
        )
        XCTAssertNotEqual(before.id, after.id)
    }

    /// The flag the issue op carries but the chain index does not store.
    /// Android drops it between saving a draft and carving it, so a
    /// proof issued from a draft always carved `false` however the
    /// issuer ticked it.
    func testADraftRemembersAllSignsRequired() {
        let draft = Proof.createLocal(
            title: "t", content: "c", cosigners: ["a"],
            transferable: false, allSignsRequired: true, issuer: "me"
        )
        XCTAssertEqual(draft.allSignsRequired, true)

        // Meaningless without cosigners, so not remembered either.
        let solo = Proof.createLocal(
            title: "t", content: "c", cosigners: [],
            transferable: false, allSignsRequired: true, issuer: "me"
        )
        XCTAssertNil(solo.allSignsRequired)
    }

    /// It is local bookkeeping, so it must survive the store round trip
    /// — that is the whole reason it exists as a field.
    func testAllSignsRequiredSurvivesEncoding() throws {
        let draft = Proof.createLocal(
            title: "t", content: "c", cosigners: ["a"],
            transferable: false, allSignsRequired: true, issuer: "me"
        )
        let back = try JSONDecoder().decode(
            Proof.self, from: try JSONEncoder().encode(draft)
        )
        XCTAssertEqual(back.allSignsRequired, true)
        XCTAssertEqual(back.id, draft.id)
    }

    /// A chain record never carries it — `active` is what the index
    /// exposes instead — and its absence must not fail the decode.
    func testAChainRowHasNoAllSignsRequired() throws {
        let row = try JSONDecoder().decode(
            Proof.self, from: Data(#"{"id":"x","active":false}"#.utf8)
        )
        XCTAssertNil(row.allSignsRequired)
        XCTAssertEqual(row.active, false)
    }

    func testNameFallsBackToTheId() {
        XCTAssertEqual(Proof(id: "abc").name, "abc")
        XCTAssertEqual(Proof(id: "abc", title: "").name, "abc")
    }
}
