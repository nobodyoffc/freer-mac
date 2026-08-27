import XCTest
import FCCore
@testable import FCDomain

/// The protocol record and its carve builders: what the wire says, what
/// the lifecycle means, and what the size guard refuses.
final class ProtocolTests: XCTestCase {

    // MARK: - decode

    func testDecodesAChainRowFieldForField() throws {
        let json = """
        {"id":"pid1","type":"FEIP","sn":"12","ver":"3","did":"D1",
         "name":"Contact","lang":"en","desc":"the contact protocol",
         "prePid":"pid0","home":{"spec":"https://example.com/feip12"},
         "owner":"FID1","waiters":["FIDA","FIDB"],
         "birthTxId":"tx0","birthTime":1000,"birthHeight":10,
         "lastTxId":"tx1","lastTime":2000,"lastHeight":20,
         "tCdd":4200,"tRate":4.5,"active":true,"closed":false}
        """
        let spec = try JSONDecoder().decode(ProtocolSpec.self, from: Data(json.utf8))
        XCTAssertEqual(spec.id, "pid1")
        XCTAssertEqual(spec.sn, "12")
        XCTAssertEqual(spec.ver, "3")
        XCTAssertEqual(spec.prePid, "pid0")
        XCTAssertEqual(spec.home?["spec"], "https://example.com/feip12")
        XCTAssertEqual(spec.waiters, ["FIDA", "FIDB"])
        XCTAssertEqual(spec.tCdd, 4200)
        XCTAssertEqual(spec.tRate, 4.5)
        XCTAssertEqual(spec.displayName, "Contact")
    }

    /// `sn` and `ver` are strings on the wire, but a publisher numbering
    /// their own protocol may well have carved them unquoted. A whole
    /// page must not fail over a missing pair of quotes.
    func testUnquotedSnAndVerStillDecode() throws {
        let json = #"{"id":"pid1","sn":12,"ver":3}"#
        let spec = try JSONDecoder().decode(ProtocolSpec.self, from: Data(json.utf8))
        XCTAssertEqual(spec.sn, "12")
        XCTAssertEqual(spec.ver, "3")
    }

    /// A row with no id is dropped by the service, not thrown on — so
    /// decode has to survive it.
    func testAMissingIdDecodesEmptyRatherThanThrowing() throws {
        let spec = try JSONDecoder().decode(ProtocolSpec.self, from: Data(#"{"name":"x"}"#.utf8))
        XCTAssertEqual(spec.id, "")
    }

    // MARK: - lifecycle

    /// `closed` outranks `active`. A list that reads them the other way
    /// round shows a closed protocol as live.
    func testStateReadsClosedBeforeActive() {
        func spec(active: Bool?, closed: Bool?, onChain: Bool?) -> ProtocolSpec {
            ProtocolSpec(id: "p", active: active, closed: closed, onChain: onChain)
        }
        XCTAssertEqual(spec(active: true, closed: true, onChain: true).state, .closed)
        XCTAssertEqual(spec(active: false, closed: true, onChain: true).state, .closed)
        XCTAssertEqual(spec(active: false, closed: false, onChain: true).state, .stopped)
        XCTAssertEqual(spec(active: true, closed: false, onChain: true).state, .live)
        // A record the indexer has said nothing about is live, not
        // stopped: `active` absent is not `active` false.
        XCTAssertEqual(spec(active: nil, closed: nil, onChain: true).state, .live)
        XCTAssertEqual(spec(active: nil, closed: nil, onChain: nil).state, .broadcast)
        XCTAssertEqual(spec(active: nil, closed: nil, onChain: false).state, .draft)
    }

    /// A closed protocol is past recovering — that is the entire
    /// difference between `stop` and `close`, and it is the one gate
    /// that keeps a user from paying a miner fee for nothing.
    func testRecoverIsOfferedForStoppedButNeverForClosed() {
        let stopped = ProtocolSpec(id: "p", owner: "ME", active: false, closed: false, onChain: true)
        let closed = ProtocolSpec(id: "p", owner: "ME", active: false, closed: true, onChain: true)
        XCTAssertTrue(stopped.canRecover(as: "ME"))
        XCTAssertFalse(closed.canRecover(as: "ME"))
        XCTAssertTrue(stopped.canClose(as: "ME"))
        XCTAssertFalse(closed.canClose(as: "ME"))
        XCTAssertFalse(closed.canStop(as: "ME"))
        XCTAssertFalse(closed.canUpdate(as: "ME"))
    }

    func testOnlyTheOwnerCarves() {
        let mine = ProtocolSpec(id: "p", owner: "ME", active: true, closed: false, onChain: true)
        XCTAssertTrue(mine.canStop(as: "ME"))
        XCTAssertFalse(mine.canStop(as: "YOU"))
        XCTAssertFalse(mine.canClose(as: "YOU"))
        XCTAssertFalse(mine.canUpdate(as: "YOU"))
    }

    /// A draft has never been on the chain, so there is nothing to stop,
    /// recover or close — but it is still editable.
    func testADraftIsEditableButNotCarveable() {
        let draft = ProtocolSpec.createLocal(name: "Draft", owner: "ME")
        XCTAssertTrue(draft.canUpdate(as: "ME"))
        XCTAssertFalse(draft.canStop(as: "ME"))
        XCTAssertFalse(draft.canClose(as: "ME"))
        XCTAssertFalse(draft.canRecover(as: "ME"))
    }

    /// Android writes `active = true` on a locally saved record no chain
    /// has seen. `active` is the indexer's verdict; a draft has no
    /// indexer behind it.
    func testADraftDoesNotClaimToBeInForce() {
        let draft = ProtocolSpec.createLocal(name: "Draft", owner: "ME")
        XCTAssertNil(draft.active)
        XCTAssertEqual(draft.onChain, false)
        XCTAssertEqual(draft.state, .draft)
    }

    // MARK: - local id

    /// Android's `"local_" + currentTimeMillis()` gives the same draft a
    /// new key on every save; hashing the payload keeps an unchanged
    /// draft on one row.
    func testTheLocalIdIsStableForAnUnchangedDraftAndMovesWhenEdited() {
        let a = ProtocolSpec.createLocal(name: "P", ver: "1", desc: "d", owner: "ME")
        let b = ProtocolSpec.createLocal(name: "P", ver: "1", desc: "d", owner: "ME")
        let c = ProtocolSpec.createLocal(name: "P", ver: "2", desc: "d", owner: "ME")
        XCTAssertEqual(a.id, b.id)
        XCTAssertNotEqual(a.id, c.id)
        XCTAssertEqual(a.id.count, 64, "sha256x2, hex")
    }

    /// The id must not depend on who is looking at it: the owner is not
    /// part of what the publish op carves.
    func testTheLocalIdIgnoresTheOwner() {
        let mine = ProtocolSpec.createLocal(name: "P", owner: "ME")
        let yours = ProtocolSpec.createLocal(name: "P", owner: "YOU")
        XCTAssertEqual(mine.id, yours.id)
    }

    // MARK: - search

    func testMatchesTheFieldsAndroidSearches() {
        let spec = ProtocolSpec(
            id: "pid1", type: "FEIP", sn: "12",
            name: "Contact", desc: "the contact protocol",
            owner: "FIDOWNER", waiters: ["FIDWAITER"]
        )
        for needle in ["contact", "FEIP", "12", "FIDOWNER", "pid1", "fidwaiter"] {
            XCTAssertTrue(spec.matches(query: needle), "should match \(needle)")
        }
        XCTAssertFalse(spec.matches(query: "elephant"))
        XCTAssertFalse(spec.matches(query: "   "))
    }

    // MARK: - carve builders

    func testTheEnvelopeIsSn1Ver7AndNamedFeipProtocol() throws {
        let json = ProtocolFeip.envelope(opJson: try ProtocolFeip.stopOp(pids: ["p1"]))
        XCTAssertTrue(json.contains(#""sn":"1""#))
        XCTAssertTrue(json.contains(#""ver":"7""#))
        XCTAssertTrue(json.contains(#""name":"FeipProtocol""#))
        XCTAssertTrue(json.contains(#""op":"stop""#))
        XCTAssertTrue(json.contains(#""pids":["p1"]"#))
    }

    /// The payload's `sn` is the publisher's own number for the protocol
    /// being registered; the envelope's is always 1. Both appear in one
    /// carve and they are not the same value.
    func testThePayloadSnIsNotTheEnvelopeSn() throws {
        let json = try ProtocolFeip.publishCarve(sn: "12", name: "Contact")
        XCTAssertTrue(json.contains(#""sn":"1","ver":"7""#), "envelope")
        XCTAssertTrue(json.contains(#""sn":"12""#), "payload")
    }

    /// `preDid` going out, `prePid` coming back. Preserved rather than
    /// tidied, because both clients have to spell it the wire's way.
    func testPublishSpellsThePreviousLinkPreDid() throws {
        let op = try ProtocolFeip.publishOp(name: "P", preDid: "pid0")
        XCTAssertTrue(op.contains(#""preDid":"pid0""#))
        XCTAssertFalse(op.contains("prePid"))
    }

    /// Empty values are omitted, not sent as `""` or `[]` — every
    /// omitted byte is OP_RETURN budget the description can use.
    func testEmptyFieldsAreOmitted() throws {
        let op = try ProtocolFeip.publishOp(
            sn: "", name: "P", type: "  ", ver: nil, did: nil,
            desc: "", lang: nil, home: [:], preDid: "", waiters: ["", ""]
        )
        XCTAssertEqual(op, #"{"name":"P","op":"publish"}"#)
    }

    /// Android's `ProtocolOpData.rate` is a primitive `int`, so Gson
    /// writes `"rate":0` into every publish, update, stop, close and
    /// recover — a field those ops do not define, on a size-capped
    /// payload (Android issue C20).
    func testNoOpCarriesAStrayRateField() throws {
        for json in [
            try ProtocolFeip.publishOp(name: "P"),
            try ProtocolFeip.updateOp(pid: "p1", name: "P"),
            try ProtocolFeip.stopOp(pids: ["p1"]),
            try ProtocolFeip.recoverOp(pids: ["p1"]),
            try ProtocolFeip.closeOp(pids: ["p1"])
        ] {
            XCTAssertFalse(json.contains("rate"), json)
        }
    }

    func testCloseCarriesItsStatementOnlyWhenThereIsOne() throws {
        XCTAssertFalse(try ProtocolFeip.closeOp(pids: ["p1"], closeStatement: "  ")
            .contains("closeStatement"))
        XCTAssertTrue(try ProtocolFeip.closeOp(pids: ["p1"], closeStatement: "superseded")
            .contains(#""closeStatement":"superseded""#))
    }

    func testIdListOpsRefuseAnEmptyList() {
        XCTAssertThrowsError(try ProtocolFeip.stopOp(pids: []))
        XCTAssertThrowsError(try ProtocolFeip.recoverOp(pids: [""]))
        XCTAssertThrowsError(try ProtocolFeip.closeOp(pids: []))
    }

    func testPublishNeedsAName() {
        XCTAssertThrowsError(try ProtocolFeip.publishCarve(name: "   "))
        XCTAssertThrowsError(try ProtocolFeip.updateCarve(pid: "p1", name: ""))
        XCTAssertThrowsError(try ProtocolFeip.updateOp(pid: "", name: "P"))
    }

    func testRatingIsOneToFive() {
        XCTAssertThrowsError(try ProtocolFeip.rateOp(pid: "p1", rate: 0))
        XCTAssertThrowsError(try ProtocolFeip.rateOp(pid: "p1", rate: 6))
        XCTAssertNoThrow(try ProtocolFeip.rateOp(pid: "p1", rate: 5))
    }

    /// The size guard is what stands between a long description and a
    /// transaction that cannot relay.
    func testAnOversizeRegistrationIsRefused() {
        XCTAssertThrowsError(try ProtocolFeip.publishCarve(
            name: "P", desc: String(repeating: "x", count: ProtocolFeip.maxOpReturnSize)
        )) { error in
            guard case ProtocolFeip.Failure.tooLarge = error else {
                return XCTFail("expected tooLarge, got \(error)")
            }
        }
    }

    /// The budget is measured on the *encoded* envelope, and with the
    /// `desc` key present even when the description is empty — otherwise
    /// the first keystroke would spend bytes the counter promised were
    /// free.
    func testTheDescBudgetShrinksByExactlyWhatIsTyped() {
        let empty = ProtocolFeip.remainingDescBytes(name: "P", desc: "")
        let one = ProtocolFeip.remainingDescBytes(name: "P", desc: "a")
        XCTAssertEqual(empty - one, 1)

        let full = ProtocolFeip.remainingDescBytes(
            name: "P", desc: String(repeating: "a", count: 100)
        )
        XCTAssertEqual(empty - full, 100)

        // An update carries a pid the publish does not, so it has less
        // room for prose.
        XCTAssertLessThan(
            ProtocolFeip.remainingDescBytes(pid: String(repeating: "f", count: 64), name: "P", desc: ""),
            empty
        )
    }

    /// The budget and the guard have to agree, or the form enables a
    /// button the builder then refuses.
    func testTheBudgetAgreesWithTheSizeGuard() throws {
        let room = ProtocolFeip.remainingDescBytes(name: "P", desc: "")
        XCTAssertNoThrow(try ProtocolFeip.publishCarve(
            name: "P", desc: String(repeating: "a", count: room)
        ))
        XCTAssertThrowsError(try ProtocolFeip.publishCarve(
            name: "P", desc: String(repeating: "a", count: room + 1)
        ))
    }
}
