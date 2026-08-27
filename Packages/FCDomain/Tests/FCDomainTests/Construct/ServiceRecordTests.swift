import XCTest
import FCCore
@testable import FCDomain

/// The `Service` record and its FEIP builders.
///
/// Named `ServiceRecordTests` rather than `ServiceTests` because the
/// model shares a file — and a name — with the SID→URL discovery half
/// that predates the Construct phase; `ServiceDiscoveryTests` lives in
/// `Directory/`.
final class ServiceRecordTests: XCTestCase {

    // MARK: - decoding

    func testDecodesTheWireRecordFieldForField() throws {
        let json = """
        {"stdName":"DOCK@No1_NrC7","localNames":{"zh":"码头"},
         "desc":"store and forward","type":"FAPI@No1_NrC7",
         "components":["DOCK@No1_NrC7","DISK@No1_NrC7"],"ver":"3",
         "home":{"API":"https://cid.cash/APIP"},
         "waiters":["FIDW"],"protocols":["p1"],"codes":["c1"],
         "services":["s1"],
         "pricePerKB":"0.0001","currency":"FCH","maxDataSize":"262144",
         "minCredit":"1","dataExpiresInDays":"30",
         "owner":"FIDO","birthTime":1700000000,"birthHeight":900000,
         "lastTxId":"tx1","lastTime":1700000100,"lastHeight":900001,
         "tCdd":4242,"tRate":4.5,"active":true,"closed":false,
         "id":"sid-1"}
        """
        let s = try JSONDecoder().decode(Service.self, from: Data(json.utf8))
        XCTAssertEqual(s.stdName, "DOCK@No1_NrC7")
        XCTAssertEqual(s.localNames?["zh"], "码头")
        XCTAssertEqual(s.desc, "store and forward")
        XCTAssertEqual(s.type, "FAPI@No1_NrC7")
        XCTAssertEqual(s.components, ["DOCK@No1_NrC7", "DISK@No1_NrC7"])
        XCTAssertEqual(s.ver, "3")
        XCTAssertEqual(s.home?["API"], "https://cid.cash/APIP")
        XCTAssertEqual(s.waiters, ["FIDW"])
        XCTAssertEqual(s.protocols, ["p1"])
        XCTAssertEqual(s.codes, ["c1"])
        XCTAssertEqual(s.services, ["s1"])
        XCTAssertEqual(s.pricePerKB, "0.0001")
        XCTAssertEqual(s.currency, "FCH")
        XCTAssertEqual(s.maxDataSize, "262144")
        XCTAssertEqual(s.minCredit, "1")
        XCTAssertEqual(s.dataExpiresInDays, "30")
        XCTAssertEqual(s.owner, "FIDO")
        XCTAssertEqual(s.birthTime, 1_700_000_000)
        XCTAssertEqual(s.lastHeight, 900_001)
        XCTAssertEqual(s.tCdd, 4242)
        XCTAssertEqual(s.tRate, 4.5)
        XCTAssertEqual(s.active, true)
        XCTAssertEqual(s.closed, false)
        XCTAssertEqual(s.sid, "sid-1")
    }

    /// The discovery half has to keep working: it is on the message
    /// path, and growing the model must not have moved it.
    func testTheDiscoveryHalfStillReadsTheSameFields() throws {
        let s = Service(
            components: ["DOCK@No1_NrC7"],
            home: ["api": "https://x/APIP"],
            maxDataSize: "262144"
        )
        XCTAssertEqual(s.apiUrl, "https://x/APIP", "still case-insensitive on the key")
        XCTAssertTrue(s.offers("dock@no1_nrc7"), "still case-insensitive on the component")
        XCTAssertEqual(s.itemSizeLimit, 262_144)
        XCTAssertTrue(s.isActive, "a missing flag is not a retirement")
    }

    /// `isActive` and `state` answer different questions and are allowed
    /// to disagree — one is "may I route here", the other is "where is
    /// this in its lifecycle".
    func testIsActiveAndStateDisagreeOnAClosedRecordOnPurpose() {
        let closed = Service(active: true, closed: true, onChain: true, id: "s")
        XCTAssertTrue(closed.isActive, "discovery reads the active flag it was given")
        XCTAssertEqual(closed.state, .closed, "the lifecycle ranks closed above active")
    }

    func testAPriceThatArrivedUnquotedStillDecodes() throws {
        let json = #"{"id":"s","pricePerKB":0.001,"maxDataSize":262144,"ver":3}"#
        let s = try JSONDecoder().decode(Service.self, from: Data(json.utf8))
        XCTAssertEqual(s.pricePerKB, "0.001")
        XCTAssertEqual(s.maxDataSize, "262144")
        XCTAssertEqual(s.itemSizeLimit, 262_144)
        XCTAssertEqual(s.ver, "3")
    }

    func testASingleEntryListFlattenedToAStringStillDecodes() throws {
        let json = #"{"id":"s","components":"DOCK@No1_NrC7","codes":"c1"}"#
        let s = try JSONDecoder().decode(Service.self, from: Data(json.utf8))
        XCTAssertEqual(s.components, ["DOCK@No1_NrC7"])
        XCTAssertEqual(s.codes, ["c1"])
    }

    /// A row with no id is unusable but must not fail the page it
    /// arrived in — the registry drops it instead.
    func testAMissingIdDecodesEmptyRatherThanThrowing() throws {
        let s = try JSONDecoder().decode(Service.self, from: Data(#"{"stdName":"X"}"#.utf8))
        XCTAssertNil(s.id)
        XCTAssertEqual(s.sid, "")
        XCTAssertEqual(s.displayName, "X", "the name still labels it")
    }

    // MARK: - lifecycle

    func testStateRanksClosedAboveEverything() {
        XCTAssertEqual(Service(onChain: false, id: "s").state, .draft)
        XCTAssertEqual(Service(onChain: nil, id: "s").state, .broadcast)
        XCTAssertEqual(Service(active: true, onChain: true, id: "s").state, .live)
        XCTAssertEqual(Service(active: false, onChain: true, id: "s").state, .stopped)
        XCTAssertEqual(
            Service(active: false, closed: true, onChain: true, id: "s").state, .closed
        )
        XCTAssertEqual(
            Service(active: true, closed: true, onChain: true, id: "s").state, .closed,
            "closed outranks active"
        )
    }

    func testOnlyTheOwnerCarves() {
        let s = Service(owner: "ME", active: true, onChain: true, id: "s")
        XCTAssertTrue(s.canUpdate(as: "ME"))
        XCTAssertTrue(s.canStop(as: "ME"))
        XCTAssertTrue(s.canClose(as: "ME"))
        for op in [s.canUpdate, s.canStop, s.canRecover, s.canClose] {
            XCTAssertFalse(op("YOU"))
        }
    }

    func testAClosedServiceIsNeverRecoverable() {
        let s = Service(owner: "ME", active: false, closed: true, onChain: true, id: "s")
        XCTAssertFalse(s.canRecover(as: "ME"), "close is the op recover does not undo")
        XCTAssertFalse(s.canStop(as: "ME"))
        XCTAssertFalse(s.canClose(as: "ME"))
        XCTAssertFalse(s.canUpdate(as: "ME"))
    }

    func testADraftDoesNotClaimToBeActive() {
        let draft = Service.createLocal(stdName: "DOCK@ME", owner: "ME")
        XCTAssertNil(draft.active, "no indexer has seen it — Android writes true here")
        XCTAssertEqual(draft.state, .draft)
        XCTAssertEqual(draft.closed, false)
    }

    func testMatchesLooksAtTheFieldsAReaderCanSee() {
        let s = Service(
            stdName: "DOCK@No1_NrC7",
            localNames: ["zh": "码头"],
            desc: "store and forward",
            type: "FAPI@No1_NrC7",
            components: ["DISK@No1_NrC7"],
            home: ["API": "https://cid.cash/APIP"],
            codes: ["c1"],
            owner: "FIDO",
            id: "sid-1"
        )
        for needle in ["dock", "码头", "forward", "fapi@", "disk", "cid.cash", "c1", "fido", "sid-1"] {
            XCTAssertTrue(s.matches(query: needle), "should match \(needle)")
        }
        XCTAssertFalse(s.matches(query: "nothing here"))
        XCTAssertFalse(s.matches(query: "  "), "a blank query matches nothing, not everything")
    }

    // MARK: - the local id

    func testTheLocalIdIsStableForAnUnchangedDraft() {
        let a = Service.createLocal(stdName: "DOCK@ME", desc: "d", owner: "ME")
        let b = Service.createLocal(stdName: "DOCK@ME", desc: "d", owner: "ME")
        XCTAssertEqual(a.sid, b.sid, "Android's currentTimeMillis id moves on every save")
        XCTAssertEqual(a.sid.count, 64, "sha256x2, hex")
    }

    func testTheLocalIdMovesWhenAnyCarvedFieldMoves() {
        let base = Service.createLocal(stdName: "DOCK@ME", owner: "ME")
        let others = [
            Service.createLocal(stdName: "DOCK@YOU", owner: "ME"),
            Service.createLocal(stdName: "DOCK@ME", desc: "d", owner: "ME"),
            Service.createLocal(stdName: "DOCK@ME", components: ["DOCK@No1_NrC7"], owner: "ME"),
            Service.createLocal(stdName: "DOCK@ME", codes: ["c1"], owner: "ME"),
            Service.createLocal(stdName: "DOCK@ME", services: ["s1"], owner: "ME"),
            Service.createLocal(
                stdName: "DOCK@ME",
                pricing: .init(pricePerKB: "0.001"),
                owner: "ME"
            )
        ]
        for other in others {
            XCTAssertNotEqual(base.sid, other.sid)
        }
    }

    /// A price is part of the payload, so it has to be part of the key —
    /// otherwise editing only the prices leaves the draft filed under
    /// the old digest and the pane shows two rows for one draft.
    func testTheLocalIdCoversThePricing() {
        let a = Service.createLocal(
            stdName: "DOCK@ME", pricing: .init(pricePerKB: "0.001"), owner: "ME"
        )
        let b = Service.createLocal(
            stdName: "DOCK@ME", pricing: .init(pricePerKB: "0.002"), owner: "ME"
        )
        XCTAssertNotEqual(a.sid, b.sid)
    }

    func testCreateLocalPrunesEmptyListEntriesAndBlankPrices() {
        let draft = Service.createLocal(
            stdName: "DOCK@ME",
            components: ["  ", ""],
            waiters: [],
            pricing: .init(pricePerKB: "  ", currency: "FCH"),
            owner: "ME"
        )
        XCTAssertNil(draft.components, "a whitespace-only entry is not a component")
        XCTAssertNil(draft.waiters)
        XCTAssertNil(draft.pricePerKB, "what the draft shows is what it will carve")
        XCTAssertEqual(draft.currency, "FCH")
    }

    // MARK: - the envelope

    func testTheEnvelopeIsSnFiveVerThreeNamedService() throws {
        let json = try ServiceFeip.publishCarve(stdName: "DOCK@ME")
        XCTAssertTrue(json.hasPrefix(#"{"type":"FEIP","sn":"5","ver":"3","name":"Service","data":"#))
        XCTAssertEqual(ServiceFeip.sn, "5")
        XCTAssertEqual(ServiceFeip.ver, "3")
        XCTAssertEqual(ServiceFeip.protocolName, "Service")
    }

    /// The one field a port copies wrong: Protocol says `pid`, Code says
    /// `codeId`, Service says `sid`.
    func testTheRecordIsNamedBySidNotPidOrCodeId() throws {
        let update = try ServiceFeip.updateOp(sid: "sid0", stdName: "DOCK@ME")
        XCTAssertTrue(update.contains(#""sid":"sid0""#))
        XCTAssertFalse(update.contains(#""pid""#))
        XCTAssertFalse(update.contains(#""codeId""#))

        let stop = try ServiceFeip.stopOp(sids: ["a", "b"])
        XCTAssertTrue(stop.contains(#""sids":["a","b"]"#))
        XCTAssertFalse(stop.contains(#""pids""#))
        XCTAssertFalse(stop.contains(#""codeIds""#))
    }

    func testEmptyFieldsAreOmittedRatherThanSentBlank() throws {
        let op = try ServiceFeip.publishOp(
            stdName: "DOCK@ME", localNames: [:], desc: "   ", type: "",
            components: [], ver: nil, home: [:], waiters: [""],
            protocols: nil, codes: [], services: nil,
            pricing: .init(pricePerKB: "", currency: nil)
        )
        XCTAssertEqual(op, #"{"op":"publish","stdName":"DOCK@ME"}"#)
    }

    /// Android's `ProtocolOpData.rate` is a primitive `int`, so Gson
    /// writes `"rate":0` into every protocol op (**issue C20**).
    /// `ServiceOpData.rate` is a boxed `Integer` and does not. Pinned on
    /// the good copy, because the bug is one keyword away.
    func testNoOpCarriesAStrayRateField() throws {
        let ops = [
            try ServiceFeip.publishOp(stdName: "DOCK@ME"),
            try ServiceFeip.updateOp(sid: "s", stdName: "DOCK@ME"),
            try ServiceFeip.stopOp(sids: ["s"]),
            try ServiceFeip.recoverOp(sids: ["s"]),
            try ServiceFeip.closeOp(sids: ["s"], closeStatement: "done")
        ]
        for op in ops {
            XCTAssertFalse(op.contains(#""rate""#), "stray rate in \(op)")
        }
    }

    /// The prices go next to `stdName`, not inside a `params` object —
    /// Java moved them out of `params` and never moved them back, and
    /// `params` is now always null.
    func testPricingIsCarvedFlatAndParamsIsNeverSent() throws {
        let op = try ServiceFeip.publishOp(
            stdName: "DOCK@ME",
            pricing: .init(
                pricePerKB: "0.0001", currency: "FCH", maxDataSize: "262144"
            )
        )
        XCTAssertTrue(op.contains(#""pricePerKB":"0.0001""#))
        XCTAssertTrue(op.contains(#""currency":"FCH""#))
        XCTAssertTrue(op.contains(#""maxDataSize":"262144""#))
        XCTAssertFalse(op.contains(#""params""#))
        XCTAssertFalse(op.contains(#""pricing""#), "Pricing is a Swift grouping, not a wire key")
    }

    func testEveryPricingFieldReachesTheWire() throws {
        let all = ServiceFeip.Pricing(
            pricePerKB: "1", pricePerKBIn: "2", pricePerKBOut: "3", pricePerKBDay: "4",
            minPayment: "5", pricePerRequest: "6", sessionDays: "7",
            consumeViaShare: "8", orderViaShare: "9", currency: "FCH",
            minCredit: "11", maxDataSize: "12", dataExpiresInDays: "13"
        )
        XCTAssertEqual(all.wirePairs.count, 13, "thirteen fields, none dropped")
        let op = try ServiceFeip.publishOp(stdName: "DOCK@ME", pricing: all)
        for (key, value) in all.wirePairs {
            XCTAssertTrue(op.contains("\"\(key)\":\"\(value)\""), "missing \(key)")
        }
    }

    /// Android declares `minCredit` on the model and on the op data and
    /// then never collects it: no input in either activity writes it.
    func testMinCreditIsReachableHereUnlikeAndroid() throws {
        let op = try ServiceFeip.publishOp(
            stdName: "DOCK@ME", pricing: .init(minCredit: "10")
        )
        XCTAssertTrue(op.contains(#""minCredit":"10""#))
    }

    func testListEntriesAreTrimmedAndBlanksDropped() throws {
        let op = try ServiceFeip.publishOp(
            stdName: "  DOCK@ME  ",
            components: [" DOCK@No1_NrC7 ", "", "  ", "DISK@No1_NrC7"],
            codes: [" c1 "]
        )
        XCTAssertTrue(op.contains(#""stdName":"DOCK@ME""#))
        XCTAssertTrue(op.contains(#""components":["DOCK@No1_NrC7","DISK@No1_NrC7"]"#))
        XCTAssertTrue(op.contains(#""codes":["c1"]"#))
    }

    func testCloseCarriesItsStatementAndOmitsAnEmptyOne() throws {
        XCTAssertTrue(
            try ServiceFeip.closeOp(sids: ["s"], closeStatement: "moved to v4")
                .contains(#""closeStatement":"moved to v4""#)
        )
        XCTAssertFalse(
            try ServiceFeip.closeOp(sids: ["s"], closeStatement: "   ")
                .contains(#""closeStatement""#)
        )
    }

    func testAnEmptyIdListIsRefused() {
        XCTAssertThrowsError(try ServiceFeip.stopOp(sids: []))
        XCTAssertThrowsError(try ServiceFeip.recoverOp(sids: [""]))
        XCTAssertThrowsError(try ServiceFeip.closeOp(sids: []))
        XCTAssertThrowsError(try ServiceFeip.updateOp(sid: "", stdName: "X"))
    }

    func testAServiceNeedsAStandardName() {
        XCTAssertThrowsError(try ServiceFeip.publishCarve(stdName: "   "))
        XCTAssertThrowsError(try ServiceFeip.updateCarve(sid: "s", stdName: ""))
    }

    func testARatingIsOneToFive() {
        XCTAssertThrowsError(try ServiceFeip.rateOp(sid: "s", rate: 0))
        XCTAssertThrowsError(try ServiceFeip.rateOp(sid: "s", rate: 6))
        XCTAssertNoThrow(try ServiceFeip.rateOp(sid: "s", rate: 3))
    }

    // MARK: - the byte budget

    func testAnOversizeRegistrationIsRefusedNotTruncated() {
        XCTAssertThrowsError(
            try ServiceFeip.publishCarve(
                stdName: "DOCK@ME",
                desc: String(repeating: "x", count: ServiceFeip.maxOpReturnSize)
            )
        ) { error in
            guard case ServiceFeip.Failure.tooLarge = error else {
                return XCTFail("expected tooLarge, got \(error)")
            }
        }
    }

    func testTheBudgetCountsWhatTheEnvelopeActuallyCosts() {
        let empty = ServiceFeip.remainingDescBytes(stdName: "DOCK@ME", desc: "")
        XCTAssertLessThan(empty, ServiceFeip.maxOpReturnSize)
        let after10 = ServiceFeip.remainingDescBytes(
            stdName: "DOCK@ME", desc: String(repeating: "y", count: 10)
        )
        XCTAssertEqual(empty - after10, 10, "ten plain characters cost ten bytes")
    }

    /// Five id lists is what makes this record the tightest of the four
    /// — a code id is 64 hex characters and there is room for a handful,
    /// not a catalogue.
    func testTheIdListsEatTheBudgetFastest() {
        let bare = ServiceFeip.remainingDescBytes(stdName: "DOCK@ME", desc: "")
        let id = String(repeating: "a", count: 64)
        let loaded = ServiceFeip.remainingDescBytes(
            stdName: "DOCK@ME", desc: "",
            protocols: [id, id], codes: [id, id]
        )
        XCTAssertLessThan(loaded, bare - 4 * 64, "each id costs its full length, plus quoting")
    }

    /// The budget and the guard have to agree, or the form promises room
    /// the carve then refuses.
    func testTheBudgetAgreesWithTheGuard() throws {
        let stdName = "DOCK@No1_NrC7"
        let head = ServiceFeip.remainingDescBytes(stdName: stdName, desc: "")
        let exact = String(repeating: "z", count: head)
        XCTAssertNoThrow(try ServiceFeip.publishCarve(stdName: stdName, desc: exact))
        XCTAssertThrowsError(
            try ServiceFeip.publishCarve(stdName: stdName, desc: exact + "z")
        )
    }
}
