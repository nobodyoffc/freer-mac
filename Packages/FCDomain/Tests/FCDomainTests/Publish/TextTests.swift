import XCTest
import FCCore
@testable import FCDomain

/// The two Publish models and the two op builders — the layer with no
/// network under it.
///
/// Most of what is asserted here is *absence*: fields that must not be
/// sent, keys that must not appear, and an id the protocol forbids the
/// client to choose. A publish carve is permanent and uncompressed, so
/// a stray key is a byte cost that never comes back.
final class TextTests: XCTestCase {

    // MARK: - the envelope

    func testTheEnvelopeCarriesTheProtocolNumbers() throws {
        let text = TextFeip.envelope(opJson: #"{"op":"publish"}"#)
        XCTAssertTrue(text.contains(#""sn":"21""#))
        XCTAssertTrue(text.contains(#""ver":"1""#))
        XCTAssertTrue(text.contains(#""name":"Text""#))
        XCTAssertTrue(text.contains(#""type":"FEIP""#))

        let remark = RemarkFeip.envelope(opJson: #"{"op":"publish"}"#)
        XCTAssertTrue(remark.contains(#""sn":"22""#))
        XCTAssertTrue(remark.contains(#""name":"Remark""#))
    }

    /// The registry and the builders must agree; a protocol name no
    /// indexer matches produces a record that simply never appears.
    func testTheBuildersAgreeWithTheFeipRegistry() {
        XCTAssertEqual(TextFeip.sn, FeipProtocol.text.sn)
        XCTAssertEqual(TextFeip.ver, FeipProtocol.text.ver)
        XCTAssertEqual(RemarkFeip.sn, FeipProtocol.remark.sn)
        XCTAssertEqual(RemarkFeip.ver, FeipProtocol.remark.ver)
    }

    // MARK: - publish

    /// Rule 1 of FEIP21: the record's id is the carve's txid, so a
    /// publish op that named one would be claiming an id the chain is
    /// about to overrule.
    func testPublishNeverCarriesATextId() throws {
        let op = try TextFeip.publishOp(title: "Why Freecash", summary: "Short.")
        XCTAssertFalse(op.contains("textId"))
        XCTAssertTrue(op.contains(#""op":"publish""#))
    }

    /// Empty optionals are omitted rather than sent as `""` or `[]`:
    /// the parser copies only non-null values, so an empty key buys
    /// nothing and costs OP_RETURN budget.
    func testEmptyOptionalsAreOmitted() throws {
        let op = try TextFeip.publishOp(
            title: "t", type: "", did: nil, lang: "", authors: [], format: nil, summary: ""
        )
        XCTAssertFalse(op.contains("type"))
        XCTAssertFalse(op.contains("did"))
        XCTAssertFalse(op.contains("lang"))
        XCTAssertFalse(op.contains("authors"))
        XCTAssertFalse(op.contains("summary"))
    }

    func testPublishCarvesEveryFieldItWasGiven() throws {
        let json = try TextFeip.publishCarve(
            title: "Why Freecash", type: "essay", did: String(repeating: "ab", count: 32),
            lang: "en", authors: ["FIDA", "FIDB"], format: "markdown",
            summary: "Economic argument in short form."
        )
        XCTAssertTrue(json.contains(#""title":"Why Freecash""#))
        XCTAssertTrue(json.contains(#""type":"essay""#))
        XCTAssertTrue(json.contains(#""lang":"en""#))
        XCTAssertTrue(json.contains(#""authors":["FIDA","FIDB"]"#))
        XCTAssertTrue(json.contains(#""format":"markdown""#))
    }

    func testAPublishWithoutATitleIsRefused() {
        XCTAssertThrowsError(try TextFeip.publishCarve(title: "   "))
        XCTAssertThrowsError(try RemarkFeip.publishCarve(title: "", onDid: "abc"))
    }

    /// A remark about nothing is a text with extra steps, and the
    /// thread view has no way to place one.
    func testARemarkWithoutATargetIsRefused() {
        XCTAssertThrowsError(try RemarkFeip.publishCarve(title: "t", onDid: "  "))
    }

    /// The size guard is on the carve, not the op, so it runs before a
    /// caller can spend anything.
    func testAnOversizeCarveIsRefused() {
        XCTAssertThrowsError(
            try TextFeip.publishCarve(
                title: "t", summary: String(repeating: "x", count: TextFeip.maxOpReturnSize)
            )
        ) { error in
            guard case TextFeip.Failure.tooLarge = error else {
                return XCTFail("expected tooLarge, got \(error)")
            }
        }
    }

    /// The budget is measured on the encoded envelope, and it counts
    /// the `summary` key even when the summary is empty — otherwise the
    /// first keystroke would spend bytes the form said were free.
    func testTheSummaryBudgetShrinksByExactlyWhatIsTyped() {
        let empty = TextFeip.remainingSummaryBytes(title: "t", summary: "")
        let one = TextFeip.remainingSummaryBytes(title: "t", summary: "x")
        XCTAssertEqual(empty - one, 1)

        let full = TextFeip.remainingSummaryBytes(
            title: "t", summary: String(repeating: "x", count: TextFeip.maxOpReturnSize)
        )
        XCTAssertLessThan(full, 0, "over budget reads negative")
    }

    // MARK: - update

    /// The subject field is `textId` on Text and `remarkId` on Remark —
    /// one field, two spellings, and exactly what a port copies wrong.
    func testUpdateNamesItsSubjectAndNothingElses() throws {
        let text = try TextFeip.updateCarve(textId: "T1", title: "t")
        XCTAssertTrue(text.contains(#""textId":"T1""#))
        XCTAssertFalse(text.contains("remarkId"))

        let remark = try RemarkFeip.updateCarve(remarkId: "R1", title: "t", onDid: "T1")
        XCTAssertTrue(remark.contains(#""remarkId":"R1""#))
        XCTAssertFalse(remark.contains(#""textId""#))
    }

    /// The reference parser assigns nulls onto the entity, so an
    /// omitted field is a cleared field. The builder therefore has to
    /// be *able* to resend everything — this pins that it does.
    func testAnUpdateResendsEveryFieldRatherThanClearingThem() throws {
        let json = try TextFeip.updateCarve(
            textId: "T1", title: "Rev 2", type: "essay",
            did: "deadbeef", lang: "en", authors: ["FIDA"],
            format: "markdown", summary: "Expanded."
        )
        for fragment in [#""type":"essay""#, #""did":"deadbeef""#, #""lang":"en""#,
                         #""authors":["FIDA"]"#, #""format":"markdown""#, #""summary":"Expanded.""#] {
            XCTAssertTrue(json.contains(fragment), "missing \(fragment)")
        }
    }

    // MARK: - delete / recover / rate

    func testDeleteAndRecoverTakeListsAndRefuseEmptyOnes() throws {
        XCTAssertTrue(try TextFeip.deleteOp(textIds: ["a", "b"]).contains(#""textIds":["a","b"]"#))
        XCTAssertTrue(try TextFeip.recoverOp(textIds: ["a"]).contains(#""op":"recover""#))
        XCTAssertThrowsError(try TextFeip.deleteOp(textIds: []))
        XCTAssertThrowsError(try RemarkFeip.recoverOp(remarkIds: []))
        XCTAssertTrue(try RemarkFeip.deleteOp(remarkIds: ["r"]).contains(#""remarkIds":["r"]"#))
    }

    /// Built but not wired — the op has to be correct now so that
    /// 8.7.5 wires a builder it does not have to re-derive.
    func testRateCarriesAnIntegerRateAndTheSubjectId() throws {
        let op = try TextFeip.rateOp(textId: "T1", rate: 5)
        XCTAssertTrue(op.contains(#""rate":5"#))
        XCTAssertTrue(op.contains(#""textId":"T1""#))
        XCTAssertThrowsError(try TextFeip.rateOp(textId: "", rate: 5))
    }

    // MARK: - the models

    /// A draft's id is a digest of the op it will carve, so saving and
    /// reloading an unchanged draft leaves it in the same row.
    func testADraftIdIsStableAcrossIdenticalContent() {
        let a = TextRecord.createLocal(title: "t", summary: "s", publisher: "FID")
        let b = TextRecord.createLocal(title: "t", summary: "s", publisher: "FID")
        XCTAssertEqual(a.id, b.id)
        XCTAssertEqual(a.id.count, 64)

        let c = TextRecord.createLocal(title: "t", summary: "s2", publisher: "FID")
        XCTAssertNotEqual(a.id, c.id)
    }

    /// A draft has no edition: `ver` is the indexer's counter, and no
    /// indexer has seen this.
    func testADraftHasNoEditionAndIsNotOnChain() {
        let draft = TextRecord.createLocal(title: "t", publisher: "FID")
        XCTAssertNil(draft.ver)
        XCTAssertEqual(draft.onChain, false)
        XCTAssertEqual(draft.deleted, false)
    }

    /// `deleted != true` and `deleted == false` disagree exactly on the
    /// rows where the indexer omitted the flag, and a list that picks
    /// the wrong one shows a different set.
    func testAMissingDeletedFlagMeansNotDeleted() throws {
        let row = try JSONDecoder().decode(
            TextRecord.self, from: Data(#"{"id":"T1","title":"t"}"#.utf8)
        )
        XCTAssertFalse(row.isDeleted)
        XCTAssertNil(row.deleted)
    }

    /// Rows published before the reference parser was fixed carry
    /// `ver: null` forever; a reader that trusted the field would show
    /// nothing at all.
    func testAMissingVerIsToleratedAndReadsAsEditionOne() throws {
        let row = try JSONDecoder().decode(
            TextRecord.self, from: Data(#"{"id":"T1","title":"t","ver":null}"#.utf8)
        )
        XCTAssertNil(row.ver)
        XCTAssertEqual(row.edition, 1)

        let numeric = try JSONDecoder().decode(
            TextRecord.self, from: Data(#"{"id":"T1","ver":3}"#.utf8)
        )
        XCTAssertEqual(numeric.ver, "3")
        XCTAssertEqual(numeric.edition, 3)
    }

    /// Rule 13: the publisher cannot rate their own work, which is the
    /// only thing keeping the average from being self-issued.
    func testOnlySomebodyElseMayRate() {
        var row = TextRecord(id: "T1", publisher: "FIDA", onChain: true)
        XCTAssertFalse(row.canRate(as: "FIDA"))
        XCTAssertTrue(row.canRate(as: "FIDB"))

        row.deleted = true
        XCTAssertFalse(row.canRate(as: "FIDB"), "a retired record is not rateable")
        XCTAssertFalse(row.canUpdate(as: "FIDA"))
        XCTAssertTrue(row.canRecover(as: "FIDA"))
    }

    func testSearchMatchesTheFieldsTheIndexExposes() {
        let row = TextRecord(
            id: "T1", title: "Why Freecash", authors: ["FIDA"],
            type: "essay", summary: "Economics", publisher: "FIDB"
        )
        XCTAssertTrue(row.matches(query: "freecash"))
        XCTAssertTrue(row.matches(query: "ECONOM"))
        XCTAssertTrue(row.matches(query: "fida"))
        XCTAssertTrue(row.matches(query: "essay"))
        XCTAssertFalse(row.matches(query: "nothing here"))
        XCTAssertFalse(row.matches(query: "   "))
    }

    /// The remark model differs from the text model by exactly two
    /// fields, and a port that copies one file into the other is how
    /// they stop differing.
    func testARemarkHasOnDidAndNoType() throws {
        let json = #"{"id":"R1","title":"Errata","onDid":"T1","did":"abc","ver":"2"}"#
        let row = try JSONDecoder().decode(Remark.self, from: Data(json.utf8))
        XCTAssertEqual(row.onDid, "T1")
        XCTAssertEqual(row.did, "abc")
        XCTAssertEqual(row.edition, 2)

        let encoded = try JSONEncoder().encode(row)
        let text = String(data: encoded, encoding: .utf8) ?? ""
        XCTAssertFalse(text.contains(#""type""#))
    }
}
