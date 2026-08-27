import XCTest
import FCCore
@testable import FCDomain

/// The `AppRecord` model and its FEIP builders — the fourth and last of
/// the Construct records.
final class AppRecordTests: XCTestCase {

    // MARK: - decoding

    func testDecodesTheWireRecordFieldForField() throws {
        let json = """
        {"stdName":"Freer","localNames":{"zh":"自由"},
         "types":["wallet","im"],"desc":"a freecash client","ver":"1.4.2",
         "home":{"site":"https://freer.cash"},
         "downloads":[{"os":"macos","link":"https://x/Freer.dmg","did":"abc"},
                      {"os":"android","link":"https://x/Freer.apk","did":"def"}],
         "waiters":["FIDW"],"protocols":["p1"],"codes":["c1"],"services":["s1"],
         "owner":"FIDO","birthTime":1700000000,"birthHeight":900000,
         "lastTxId":"tx1","lastTime":1700000100,"lastHeight":900001,
         "tCdd":4242,"tRate":4.5,"active":true,"closed":false,"id":"aid-1"}
        """
        let a = try JSONDecoder().decode(AppRecord.self, from: Data(json.utf8))
        XCTAssertEqual(a.stdName, "Freer")
        XCTAssertEqual(a.localNames?["zh"], "自由")
        XCTAssertEqual(a.types, ["wallet", "im"])
        XCTAssertEqual(a.desc, "a freecash client")
        XCTAssertEqual(a.ver, "1.4.2")
        XCTAssertEqual(a.home?["site"], "https://freer.cash")
        XCTAssertEqual(a.downloads?.count, 2)
        XCTAssertEqual(a.downloads?[0].os, "macos")
        XCTAssertEqual(a.downloads?[0].link, "https://x/Freer.dmg")
        XCTAssertEqual(a.downloads?[0].did, "abc")
        XCTAssertEqual(a.waiters, ["FIDW"])
        XCTAssertEqual(a.protocols, ["p1"])
        XCTAssertEqual(a.codes, ["c1"])
        XCTAssertEqual(a.services, ["s1"])
        XCTAssertEqual(a.owner, "FIDO")
        XCTAssertEqual(a.tCdd, 4242)
        XCTAssertEqual(a.tRate, 4.5)
        XCTAssertEqual(a.id, "aid-1")
    }

    /// A hand-rolled or half-migrated downloads list must not cost the
    /// row it arrived in — every other field is still worth showing.
    func testAMalformedDownloadsListDoesNotFailTheWholeRow() throws {
        let json = #"{"id":"a","stdName":"Freer","downloads":"not-a-list"}"#
        let a = try JSONDecoder().decode(AppRecord.self, from: Data(json.utf8))
        XCTAssertEqual(a.stdName, "Freer")
        XCTAssertNil(a.downloads)
    }

    func testAVersionThatArrivedUnquotedStillDecodes() throws {
        let a = try JSONDecoder().decode(AppRecord.self, from: Data(#"{"id":"a","ver":2}"#.utf8))
        XCTAssertEqual(a.ver, "2")
    }

    func testASingleEntryListFlattenedToAStringStillDecodes() throws {
        let json = #"{"id":"a","types":"wallet","codes":"c1"}"#
        let a = try JSONDecoder().decode(AppRecord.self, from: Data(json.utf8))
        XCTAssertEqual(a.types, ["wallet"])
        XCTAssertEqual(a.codes, ["c1"])
    }

    func testAMissingIdDecodesEmptyRatherThanThrowing() throws {
        let a = try JSONDecoder().decode(AppRecord.self, from: Data(#"{"stdName":"X"}"#.utf8))
        XCTAssertEqual(a.id, "")
        XCTAssertEqual(a.displayName, "X", "the name still labels it")
    }

    // MARK: - downloads

    func testADownloadRowNeedsMoreThanAnOsToBeWorthCarving() {
        XCTAssertNil(AppRecord.Download(os: "macos").pruned,
                     "a platform with no link and no digest offers nothing")
        XCTAssertNil(AppRecord.Download(os: "  ", link: "  ", did: nil).pruned)
        XCTAssertNotNil(AppRecord.Download(os: "macos", link: "https://x").pruned)
        XCTAssertNotNil(AppRecord.Download(did: "abc").pruned,
                        "a digest with no link is still a checkable claim")
    }

    func testADownloadIsTrimmedIntoItsWireObject() throws {
        let d = try XCTUnwrap(
            AppRecord.Download(os: " macos ", link: " https://x ", did: " abc ").pruned
        )
        XCTAssertEqual(d.wireObject, ["os": "macos", "link": "https://x", "did": "abc"])
    }

    func testTheRightDownloadIsFoundForAPlatform() {
        let a = AppRecord(
            id: "a",
            downloads: [
                .init(os: "macOS", link: "https://x/mac"),
                .init(os: "android", link: "https://x/apk")
            ]
        )
        XCTAssertEqual(a.download(forOS: "macos")?.link, "https://x/mac",
                       "the OS string is publisher-written, so matching is case-insensitive")
        XCTAssertNil(a.download(forOS: "windows"))
    }

    // MARK: - lifecycle

    func testStateRanksClosedAboveEverything() {
        XCTAssertEqual(AppRecord(id: "a", onChain: false).state, .draft)
        XCTAssertEqual(AppRecord(id: "a", onChain: nil).state, .broadcast)
        XCTAssertEqual(AppRecord(id: "a", active: true, onChain: true).state, .live)
        XCTAssertEqual(AppRecord(id: "a", active: false, onChain: true).state, .stopped)
        XCTAssertEqual(
            AppRecord(id: "a", active: true, closed: true, onChain: true).state, .closed,
            "closed outranks active"
        )
    }

    func testOnlyTheOwnerCarves() {
        let a = AppRecord(id: "a", owner: "ME", active: true, onChain: true)
        XCTAssertTrue(a.canUpdate(as: "ME"))
        XCTAssertTrue(a.canStop(as: "ME"))
        XCTAssertTrue(a.canClose(as: "ME"))
        for op in [a.canUpdate, a.canStop, a.canRecover, a.canClose] {
            XCTAssertFalse(op("YOU"))
        }
    }

    func testAClosedAppIsNeverRecoverable() {
        let a = AppRecord(id: "a", owner: "ME", active: false, closed: true, onChain: true)
        XCTAssertFalse(a.canRecover(as: "ME"), "close is the op recover does not undo")
        XCTAssertFalse(a.canStop(as: "ME"))
        XCTAssertFalse(a.canClose(as: "ME"))
        XCTAssertFalse(a.canUpdate(as: "ME"))
    }

    func testADraftDoesNotClaimToBeActive() {
        let draft = AppRecord.createLocal(stdName: "Freer", owner: "ME")
        XCTAssertNil(draft.active, "no indexer has seen it — Android writes true here")
        XCTAssertEqual(draft.state, .draft)
    }

    /// A download link is something a reader can see, so it should be
    /// findable among loaded rows even though the index cannot search
    /// it — see `AppService.Field.searchable`.
    func testMatchesReachesIntoTheDownloadsTheIndexCannotSearch() {
        let a = AppRecord(
            id: "aid-1", stdName: "Freer", types: ["wallet"],
            downloads: [.init(os: "macos", link: "https://dl.example/Freer.dmg", did: "abc")],
            owner: "FIDO"
        )
        for needle in ["freer", "wallet", "macos", "dl.example", "abc", "fido", "aid-1"] {
            XCTAssertTrue(a.matches(query: needle), "should match \(needle)")
        }
        XCTAssertFalse(a.matches(query: "nothing here"))
        XCTAssertFalse(a.matches(query: "  "), "a blank query matches nothing, not everything")
    }

    // MARK: - the local id

    func testTheLocalIdIsStableForAnUnchangedDraft() {
        let a = AppRecord.createLocal(stdName: "Freer", desc: "d", owner: "ME")
        let b = AppRecord.createLocal(stdName: "Freer", desc: "d", owner: "ME")
        XCTAssertEqual(a.id, b.id, "Android's currentTimeMillis id moves on every save")
        XCTAssertEqual(a.id.count, 64, "sha256x2, hex")
    }

    func testTheLocalIdMovesWhenAnyCarvedFieldMoves() {
        let base = AppRecord.createLocal(stdName: "Freer", owner: "ME")
        let others = [
            AppRecord.createLocal(stdName: "Freer2", owner: "ME"),
            AppRecord.createLocal(stdName: "Freer", types: ["wallet"], owner: "ME"),
            AppRecord.createLocal(stdName: "Freer", ver: "2", owner: "ME"),
            AppRecord.createLocal(stdName: "Freer", codes: ["c1"], owner: "ME")
        ]
        for other in others {
            XCTAssertNotEqual(base.id, other.id)
        }
    }

    /// A download is part of the payload, so it has to be part of the
    /// key — otherwise adding a build leaves the draft filed under the
    /// old digest and the pane shows two rows for one draft.
    func testTheLocalIdCoversTheDownloads() {
        let a = AppRecord.createLocal(stdName: "Freer", owner: "ME")
        let b = AppRecord.createLocal(
            stdName: "Freer",
            downloads: [.init(os: "macos", link: "https://x")],
            owner: "ME"
        )
        XCTAssertNotEqual(a.id, b.id)
    }

    func testCreateLocalPrunesEmptyEntries() {
        let draft = AppRecord.createLocal(
            stdName: "Freer",
            types: ["  ", ""],
            downloads: [.init(os: "macos"), .init(os: "linux", link: "https://x")],
            owner: "ME"
        )
        XCTAssertNil(draft.types, "a whitespace-only entry is not a type")
        XCTAssertEqual(draft.downloads?.count, 1,
                       "a download row with no link and no digest is dropped")
        XCTAssertEqual(draft.downloads?.first?.os, "linux")
    }

    // MARK: - the envelope

    /// The other three are `FeipProtocol`, `Code` and `Service` — title
    /// case — so `App` is exactly what a port writes here, and the
    /// indexer matches on `APP`.
    func testTheProtocolNameIsAppInCapitals() throws {
        let json = try AppFeip.publishCarve(stdName: "Freer")
        XCTAssertTrue(json.hasPrefix(#"{"type":"FEIP","sn":"15","ver":"1","name":"APP","data":"#))
        XCTAssertEqual(AppFeip.protocolName, "APP")
        XCTAssertNotEqual(AppFeip.protocolName, "App")
        XCTAssertEqual(AppFeip.sn, "15")
        XCTAssertEqual(AppFeip.ver, "1")
    }

    /// One subject field per record, four spellings: `pid`, `codeId`,
    /// `sid`, `aid`.
    func testTheRecordIsNamedByAid() throws {
        let update = try AppFeip.updateOp(aid: "aid0", stdName: "Freer")
        XCTAssertTrue(update.contains(#""aid":"aid0""#))
        for foreign in [#""pid""#, #""codeId""#, #""sid""#] {
            XCTAssertFalse(update.contains(foreign), "\(foreign) belongs to another record")
        }
        let stop = try AppFeip.stopOp(aids: ["a", "b"])
        XCTAssertTrue(stop.contains(#""aids":["a","b"]"#))
        XCTAssertFalse(stop.contains(#""sids""#))
    }

    func testEmptyFieldsAreOmittedRatherThanSentBlank() throws {
        let op = try AppFeip.publishOp(
            stdName: "Freer", localNames: [:], types: [], desc: "   ", ver: "",
            home: [:], downloads: [], waiters: [""], protocols: nil,
            codes: [], services: nil
        )
        XCTAssertEqual(op, #"{"op":"publish","stdName":"Freer"}"#)
    }

    /// `ProtocolOpData.rate` is a primitive `int`, so Gson writes
    /// `"rate":0` into every protocol op (**Android issue C20**).
    /// `AppOpData.rate` is a boxed `Integer` and does not.
    func testNoOpCarriesAStrayRateField() throws {
        let ops = [
            try AppFeip.publishOp(stdName: "Freer"),
            try AppFeip.updateOp(aid: "a", stdName: "Freer"),
            try AppFeip.stopOp(aids: ["a"]),
            try AppFeip.recoverOp(aids: ["a"]),
            try AppFeip.closeOp(aids: ["a"], closeStatement: "done")
        ]
        for op in ops {
            XCTAssertFalse(op.contains(#""rate""#), "stray rate in \(op)")
        }
    }

    /// The field Android hardcodes to null in both its activities. It
    /// carves here, as a list of objects — the only nested structure in
    /// the Construct family.
    func testDownloadsAreCarvedAsObjectsAndroidNeverSends() throws {
        let op = try AppFeip.publishOp(
            stdName: "Freer",
            downloads: [
                .init(os: "macos", link: "https://x/Freer.dmg", did: "abc"),
                .init(os: "android", link: "https://x/Freer.apk", did: "def")
            ]
        )
        XCTAssertTrue(op.contains(#""downloads":[{"did":"abc","link":"https://x/Freer.dmg","os":"macos"}"#))
        XCTAssertTrue(op.contains(#"{"did":"def","link":"https://x/Freer.apk","os":"android"}]"#))
    }

    /// An update that omitted the list would clear it on chain, which is
    /// exactly how Android loses downloads. Nothing here omits a list
    /// that has content — but an all-empty list is still dropped rather
    /// than sent as `[]`.
    func testAnAllEmptyDownloadListIsOmittedNotSentEmpty() throws {
        let op = try AppFeip.updateOp(
            aid: "a", stdName: "Freer",
            downloads: [.init(os: "macos"), .init(os: "  ")]
        )
        XCTAssertFalse(op.contains(#""downloads""#))
    }

    func testListEntriesAreTrimmedAndBlanksDropped() throws {
        let op = try AppFeip.publishOp(
            stdName: "  Freer  ", types: [" wallet ", "", "  ", "im"], codes: [" c1 "]
        )
        XCTAssertTrue(op.contains(#""stdName":"Freer""#))
        XCTAssertTrue(op.contains(#""types":["wallet","im"]"#))
        XCTAssertTrue(op.contains(#""codes":["c1"]"#))
    }

    func testCloseCarriesItsStatementAndOmitsAnEmptyOne() throws {
        XCTAssertTrue(
            try AppFeip.closeOp(aids: ["a"], closeStatement: "use Freer 2")
                .contains(#""closeStatement":"use Freer 2""#)
        )
        XCTAssertFalse(
            try AppFeip.closeOp(aids: ["a"], closeStatement: "   ")
                .contains(#""closeStatement""#)
        )
    }

    func testAnEmptyIdListIsRefused() {
        XCTAssertThrowsError(try AppFeip.stopOp(aids: []))
        XCTAssertThrowsError(try AppFeip.recoverOp(aids: [""]))
        XCTAssertThrowsError(try AppFeip.closeOp(aids: []))
        XCTAssertThrowsError(try AppFeip.updateOp(aid: "", stdName: "X"))
    }

    func testAnAppNeedsAStandardName() {
        XCTAssertThrowsError(try AppFeip.publishCarve(stdName: "   "))
        XCTAssertThrowsError(try AppFeip.updateCarve(aid: "a", stdName: ""))
    }

    func testARatingIsOneToFive() {
        XCTAssertThrowsError(try AppFeip.rateOp(aid: "a", rate: 0))
        XCTAssertThrowsError(try AppFeip.rateOp(aid: "a", rate: 6))
        XCTAssertNoThrow(try AppFeip.rateOp(aid: "a", rate: 3))
    }

    // MARK: - the byte budget

    func testAnOversizeRegistrationIsRefusedNotTruncated() {
        XCTAssertThrowsError(
            try AppFeip.publishCarve(
                stdName: "Freer",
                desc: String(repeating: "x", count: AppFeip.maxOpReturnSize)
            )
        ) { error in
            guard case AppFeip.Failure.tooLarge = error else {
                return XCTFail("expected tooLarge, got \(error)")
            }
        }
    }

    func testTheBudgetCountsWhatTheEnvelopeActuallyCosts() {
        let empty = AppFeip.remainingDescBytes(stdName: "Freer", desc: "")
        XCTAssertLessThan(empty, AppFeip.maxOpReturnSize)
        let after10 = AppFeip.remainingDescBytes(
            stdName: "Freer", desc: String(repeating: "y", count: 10)
        )
        XCTAssertEqual(empty - after10, 10, "ten plain characters cost ten bytes")
    }

    /// A download row is the most expensive thing on the form: a URL
    /// plus a 64-character digest, three times over for three
    /// platforms.
    func testEachDownloadRowCostsTheBudgetItsFullLength() {
        let bare = AppFeip.remainingDescBytes(stdName: "Freer", desc: "")
        let did = String(repeating: "a", count: 64)
        let loaded = AppFeip.remainingDescBytes(
            stdName: "Freer", desc: "",
            downloads: [
                .init(os: "macos", link: "https://dl.example/Freer.dmg", did: did),
                .init(os: "android", link: "https://dl.example/Freer.apk", did: did)
            ]
        )
        XCTAssertLessThan(loaded, bare - 2 * (64 + 28), "link and digest both cost their length")
    }

    /// The budget and the guard have to agree, or the form promises room
    /// the carve then refuses.
    func testTheBudgetAgreesWithTheGuard() throws {
        let head = AppFeip.remainingDescBytes(stdName: "Freer", desc: "")
        let exact = String(repeating: "z", count: head)
        XCTAssertNoThrow(try AppFeip.publishCarve(stdName: "Freer", desc: exact))
        XCTAssertThrowsError(try AppFeip.publishCarve(stdName: "Freer", desc: exact + "z"))
    }
}
