import XCTest
import FCCore
@testable import FCDomain

/// The code record and its carve builders: what the wire says, what the
/// lifecycle means, and what the size guard refuses.
final class CodeTests: XCTestCase {

    // MARK: - decode

    func testDecodesAChainRowFieldForField() throws {
        let json = """
        {"id":"cid1","name":"freer-mac","ver":"1.4.2","did":"D1",
         "desc":"a mac client","langs":["swift","c"],
         "home":{"git":"https://example.com/freer.git"},
         "protocols":["pid1","pid2"],
         "owner":"FID1","waiters":["FIDA","FIDB"],
         "birthTime":1000,"birthHeight":10,
         "lastTxId":"tx1","lastTime":2000,"lastHeight":20,
         "tCdd":4200,"tRate":4.5,"active":true,"closed":false}
        """
        let code = try JSONDecoder().decode(Code.self, from: Data(json.utf8))
        XCTAssertEqual(code.id, "cid1")
        XCTAssertEqual(code.ver, "1.4.2")
        XCTAssertEqual(code.langs, ["swift", "c"])
        XCTAssertEqual(code.protocols, ["pid1", "pid2"])
        XCTAssertEqual(code.home?["git"], "https://example.com/freer.git")
        XCTAssertEqual(code.waiters, ["FIDA", "FIDB"])
        XCTAssertEqual(code.tCdd, 4200)
        XCTAssertEqual(code.tRate, 4.5)
        XCTAssertEqual(code.displayName, "freer-mac")
    }

    /// `ver` is a string on the wire, but a publisher versioning `1` may
    /// well have carved it unquoted. A whole page must not fail over a
    /// missing pair of quotes.
    func testAnUnquotedVerStillDecodes() throws {
        let code = try JSONDecoder().decode(Code.self, from: Data(#"{"id":"c1","ver":2}"#.utf8))
        XCTAssertEqual(code.ver, "2")
    }

    /// A single-element list is exactly the thing an indexer or a
    /// hand-rolled publisher flattens to a scalar.
    func testAListThatArrivedAsABareStringStillDecodes() throws {
        let json = #"{"id":"c1","langs":"swift","protocols":"pid1","waiters":"FIDA"}"#
        let code = try JSONDecoder().decode(Code.self, from: Data(json.utf8))
        XCTAssertEqual(code.langs, ["swift"])
        XCTAssertEqual(code.protocols, ["pid1"])
        XCTAssertEqual(code.waiters, ["FIDA"])
    }

    /// A row with no id is dropped by the service, not thrown on — so
    /// decode has to survive it.
    func testAMissingIdDecodesEmptyRatherThanThrowing() throws {
        let code = try JSONDecoder().decode(Code.self, from: Data(#"{"name":"x"}"#.utf8))
        XCTAssertEqual(code.id, "")
        XCTAssertEqual(code.displayName, "x", "the name still labels it")
    }

    // MARK: - lifecycle

    /// `closed` outranks `active`. A list that reads them the other way
    /// round shows a closed record as live.
    func testStateReadsClosedBeforeActive() {
        func code(active: Bool?, closed: Bool?, onChain: Bool?) -> Code {
            Code(id: "c", active: active, closed: closed, onChain: onChain)
        }
        XCTAssertEqual(code(active: true, closed: true, onChain: true).state, .closed)
        XCTAssertEqual(code(active: false, closed: true, onChain: true).state, .closed)
        XCTAssertEqual(code(active: false, closed: false, onChain: true).state, .stopped)
        XCTAssertEqual(code(active: true, closed: false, onChain: true).state, .live)
        // A record the indexer has said nothing about is live, not
        // stopped: `active` absent is not `active` false.
        XCTAssertEqual(code(active: nil, closed: nil, onChain: true).state, .live)
        XCTAssertEqual(code(active: nil, closed: nil, onChain: nil).state, .broadcast)
        XCTAssertEqual(code(active: nil, closed: nil, onChain: false).state, .draft)
    }

    /// A closed record is past recovering — that is the entire
    /// difference between `stop` and `close`, and it is the one gate
    /// that keeps a user from paying a miner fee for nothing.
    func testRecoverIsOfferedForStoppedButNeverForClosed() {
        let stopped = Code(id: "c", owner: "ME", active: false, closed: false, onChain: true)
        let closed = Code(id: "c", owner: "ME", active: false, closed: true, onChain: true)
        XCTAssertTrue(stopped.canRecover(as: "ME"))
        XCTAssertFalse(closed.canRecover(as: "ME"))
        XCTAssertTrue(stopped.canClose(as: "ME"))
        XCTAssertFalse(closed.canClose(as: "ME"))
        XCTAssertFalse(closed.canStop(as: "ME"))
        XCTAssertFalse(closed.canUpdate(as: "ME"))
    }

    func testOnlyTheOwnerCarves() {
        let mine = Code(id: "c", owner: "ME", active: true, closed: false, onChain: true)
        XCTAssertTrue(mine.canStop(as: "ME"))
        XCTAssertFalse(mine.canStop(as: "YOU"))
        XCTAssertFalse(mine.canClose(as: "YOU"))
        XCTAssertFalse(mine.canUpdate(as: "YOU"))
    }

    /// A draft has never been on the chain, so there is nothing to stop,
    /// recover or close — but it is still editable.
    func testADraftIsEditableButNotCarveable() {
        let draft = Code.createLocal(name: "Draft", owner: "ME")
        XCTAssertTrue(draft.canUpdate(as: "ME"))
        XCTAssertFalse(draft.canStop(as: "ME"))
        XCTAssertFalse(draft.canClose(as: "ME"))
        XCTAssertFalse(draft.canRecover(as: "ME"))
    }

    /// Android writes `setActive(true)` on a locally saved record no
    /// chain has seen. `active` is the indexer's verdict; a draft has no
    /// indexer behind it.
    func testADraftDoesNotClaimToBeInForce() {
        let draft = Code.createLocal(name: "Draft", owner: "ME")
        XCTAssertNil(draft.active)
        XCTAssertEqual(draft.onChain, false)
        XCTAssertEqual(draft.state, .draft)
    }

    // MARK: - local id

    /// Android's `"local_" + currentTimeMillis()` gives the same draft a
    /// new key on every save; hashing the payload keeps an unchanged
    /// draft on one row.
    func testTheLocalIdIsStableForAnUnchangedDraftAndMovesWhenEdited() {
        let a = Code.createLocal(name: "C", ver: "1", desc: "d", owner: "ME")
        let b = Code.createLocal(name: "C", ver: "1", desc: "d", owner: "ME")
        let c = Code.createLocal(name: "C", ver: "2", desc: "d", owner: "ME")
        XCTAssertEqual(a.id, b.id)
        XCTAssertNotEqual(a.id, c.id)
        XCTAssertEqual(a.id.count, 64, "sha256x2, hex")
    }

    /// Adding a protocol to the list is an edit like any other, and the
    /// key has to move with it — that list is the point of the record.
    func testTheLocalIdCoversTheProtocolList() {
        let none = Code.createLocal(name: "C", owner: "ME")
        let one = Code.createLocal(name: "C", protocols: ["pid1"], owner: "ME")
        let two = Code.createLocal(name: "C", protocols: ["pid1", "pid2"], owner: "ME")
        XCTAssertNotEqual(none.id, one.id)
        XCTAssertNotEqual(one.id, two.id)
    }

    /// The id must not depend on who is looking at it: the owner is not
    /// part of what the publish op carves.
    func testTheLocalIdIgnoresTheOwner() {
        let mine = Code.createLocal(name: "C", owner: "ME")
        let yours = Code.createLocal(name: "C", owner: "YOU")
        XCTAssertEqual(mine.id, yours.id)
    }

    /// Empty entries never reach the record, so a list of blanks and a
    /// nil list are the same draft.
    func testCreateLocalPrunesEmptyListEntries() {
        let draft = Code.createLocal(
            name: "C", langs: ["", "  "], protocols: [""], waiters: [], owner: "ME"
        )
        XCTAssertNil(draft.langs)
        XCTAssertNil(draft.protocols)
        XCTAssertNil(draft.waiters)
    }

    // MARK: - search

    func testMatchesTheFieldsAndroidSearches() {
        let code = Code(
            id: "cid1", name: "freer-mac", ver: "1.4.2", desc: "a mac client",
            langs: ["swift"], protocols: ["pid1"],
            waiters: ["FIDWAITER"], owner: "FIDOWNER"
        )
        for needle in ["freer", "mac client", "swift", "pid1", "FIDOWNER", "cid1", "fidwaiter"] {
            XCTAssertTrue(code.matches(query: needle), "should match \(needle)")
        }
        XCTAssertFalse(code.matches(query: "elephant"))
        XCTAssertFalse(code.matches(query: "   "))
    }

    // MARK: - carve builders

    func testTheEnvelopeIsSn2Ver1AndNamedCode() throws {
        let json = CodeFeip.envelope(opJson: try CodeFeip.stopOp(codeIds: ["c1"]))
        XCTAssertTrue(json.contains(#""sn":"2""#))
        XCTAssertTrue(json.contains(#""ver":"1""#))
        XCTAssertTrue(json.contains(#""name":"Code""#))
        XCTAssertTrue(json.contains(#""op":"stop""#))
        XCTAssertTrue(json.contains(#""codeIds":["c1"]"#))
    }

    /// The subject field is `codeId`/`codeIds`, not `pid`/`pids`. The two
    /// records are otherwise the same shape, which makes this exactly the
    /// sort of thing a port copies wrong.
    func testTheRecordIsNamedByCodeIdNotPid() throws {
        let update = try CodeFeip.updateOp(codeId: "c1", name: "C")
        XCTAssertTrue(update.contains(#""codeId":"c1""#))
        XCTAssertFalse(update.contains("pid"))

        for json in [
            try CodeFeip.stopOp(codeIds: ["c1"]),
            try CodeFeip.recoverOp(codeIds: ["c1"]),
            try CodeFeip.closeOp(codeIds: ["c1"])
        ] {
            XCTAssertTrue(json.contains(#""codeIds":["c1"]"#), json)
            XCTAssertFalse(json.contains("pids"), json)
        }
    }

    /// Empty values are omitted, not sent as `""` or `[]` — every
    /// omitted byte is OP_RETURN budget the description can use.
    func testEmptyFieldsAreOmitted() throws {
        let op = try CodeFeip.publishOp(
            name: "C", ver: "  ", did: nil, desc: "",
            langs: ["", "  "], home: [:], protocols: [], waiters: ["", ""]
        )
        XCTAssertEqual(op, #"{"name":"C","op":"publish"}"#)
    }

    /// Blank entries inside a list that does have content are dropped
    /// rather than carved as empty strings.
    func testListEntriesAreTrimmedAndBlanksDropped() throws {
        let op = try CodeFeip.publishOp(
            name: "C", langs: [" swift ", "", "c"], protocols: ["  pid1  "]
        )
        XCTAssertTrue(op.contains(#""langs":["swift","c"]"#), op)
        XCTAssertTrue(op.contains(#""protocols":["pid1"]"#), op)
    }

    /// `ProtocolOpData.rate` is a primitive `int`, so Gson writes
    /// `"rate":0` into every protocol op Android sends (Android issue
    /// C20). `CodeOpData.rate` is a boxed `Integer` and stays null — the
    /// same bug is one keyword away, so the absence is pinned.
    func testNoOpCarriesAStrayRateField() throws {
        for json in [
            try CodeFeip.publishOp(name: "C"),
            try CodeFeip.updateOp(codeId: "c1", name: "C"),
            try CodeFeip.stopOp(codeIds: ["c1"]),
            try CodeFeip.recoverOp(codeIds: ["c1"]),
            try CodeFeip.closeOp(codeIds: ["c1"])
        ] {
            XCTAssertFalse(json.contains("rate"), json)
        }
    }

    func testCloseCarriesItsStatementOnlyWhenThereIsOne() throws {
        XCTAssertFalse(try CodeFeip.closeOp(codeIds: ["c1"], closeStatement: "  ")
            .contains("closeStatement"))
        XCTAssertTrue(try CodeFeip.closeOp(codeIds: ["c1"], closeStatement: "superseded")
            .contains(#""closeStatement":"superseded""#))
    }

    func testIdListOpsRefuseAnEmptyList() {
        XCTAssertThrowsError(try CodeFeip.stopOp(codeIds: []))
        XCTAssertThrowsError(try CodeFeip.recoverOp(codeIds: [""]))
        XCTAssertThrowsError(try CodeFeip.closeOp(codeIds: []))
    }

    func testPublishNeedsAName() {
        XCTAssertThrowsError(try CodeFeip.publishCarve(name: "   "))
        XCTAssertThrowsError(try CodeFeip.updateCarve(codeId: "c1", name: ""))
        XCTAssertThrowsError(try CodeFeip.updateOp(codeId: "", name: "C"))
    }

    func testRatingIsOneToFive() {
        XCTAssertThrowsError(try CodeFeip.rateOp(codeId: "c1", rate: 0))
        XCTAssertThrowsError(try CodeFeip.rateOp(codeId: "c1", rate: 6))
        XCTAssertNoThrow(try CodeFeip.rateOp(codeId: "c1", rate: 5))
    }

    /// The size guard is what stands between a long description and a
    /// transaction that cannot relay.
    func testAnOversizeRegistrationIsRefused() {
        XCTAssertThrowsError(try CodeFeip.publishCarve(
            name: "C", desc: String(repeating: "x", count: CodeFeip.maxOpReturnSize)
        )) { error in
            guard case CodeFeip.Failure.tooLarge = error else {
                return XCTFail("expected tooLarge, got \(error)")
            }
        }
    }

    /// The budget is measured on the *encoded* envelope, and with the
    /// `desc` key present even when the description is empty — otherwise
    /// the first keystroke would spend bytes the counter promised were
    /// free.
    func testTheDescBudgetShrinksByExactlyWhatIsTyped() {
        let empty = CodeFeip.remainingDescBytes(name: "C", desc: "")
        let one = CodeFeip.remainingDescBytes(name: "C", desc: "a")
        XCTAssertEqual(empty - one, 1)

        let full = CodeFeip.remainingDescBytes(
            name: "C", desc: String(repeating: "a", count: 100)
        )
        XCTAssertEqual(empty - full, 100)

        // An update carries a codeId the publish does not, so it has less
        // room for prose.
        XCTAssertLessThan(
            CodeFeip.remainingDescBytes(
                codeId: String(repeating: "f", count: 64), name: "C", desc: ""
            ),
            empty
        )
    }

    /// A protocol id is 64 hex characters, so the list eats the budget
    /// faster than anything the user types. The counter has to say so
    /// before the Publish button is pressed.
    func testEachProtocolIdCostsTheBudgetItsFullLength() {
        let none = CodeFeip.remainingDescBytes(name: "C", desc: "x")
        let one = CodeFeip.remainingDescBytes(
            name: "C", desc: "x", protocols: [String(repeating: "a", count: 64)]
        )
        // 64 characters, two quotes, the `"protocols":[]` key and its
        // comma — the exact overhead is JSON's, but it is at least the id.
        XCTAssertGreaterThan(none - one, 64)
    }

    /// The budget and the guard have to agree, or the form enables a
    /// button the builder then refuses.
    func testTheBudgetAgreesWithTheSizeGuard() throws {
        let room = CodeFeip.remainingDescBytes(name: "C", desc: "")
        XCTAssertNoThrow(try CodeFeip.publishCarve(
            name: "C", desc: String(repeating: "a", count: room)
        ))
        XCTAssertThrowsError(try CodeFeip.publishCarve(
            name: "C", desc: String(repeating: "a", count: room + 1)
        ))
    }
}
