import XCTest
import FCCore
@testable import FCDomain

/// FEIP24 `Image` — the model and the op builder.
///
/// Image is Text with one field removed and the subject renamed, which
/// makes it the exact shape of port that goes wrong silently: a record
/// that carries a `type` the mapping has no room for, or names a
/// `textId` on the `image` index. Most of what follows asserts the two
/// differences rather than the twenty similarities.
final class MediaTests: XCTestCase {

    func testTheEnvelopeCarriesImagesNumbers() {
        let json = MediaFeip.envelope(kind: .image, opJson: #"{"op":"publish"}"#)
        XCTAssertTrue(json.contains(#""sn":"24""#))
        XCTAssertTrue(json.contains(#""ver":"1""#))
        XCTAssertTrue(json.contains(#""name":"Image""#))
        XCTAssertEqual(MediaKind.image.sn, FeipProtocol.image.sn)
        XCTAssertEqual(MediaKind.image.ver, FeipProtocol.image.ver)
    }

    /// FEIP24 is FEIP21 minus `type`. The builder has no parameter for
    /// it, so the only way one could reach the wire is the envelope's
    /// own `"type":"FEIP"` — and exactly one of those is allowed.
    func testAnImageOpCarriesNoTypeOfItsOwn() throws {
        let json = try MediaFeip.publishCarve(
            kind: .image, title: "Cover", did: String(repeating: "ab", count: 32),
            lang: "en", authors: ["FIDA"], format: "image/png", summary: "The cover."
        )
        XCTAssertEqual(json.components(separatedBy: #""type""#).count, 2)
        XCTAssertTrue(json.contains(#""format":"image/png""#))
        XCTAssertTrue(json.contains(#""title":"Cover""#))
    }

    /// The subject field is `imageId` / `imageIds`. Four records, four
    /// spellings — the one thing a port copies wrong.
    func testTheSubjectFieldIsImageIdAndNeverTextId() throws {
        let update = try MediaFeip.updateCarve(kind: .image, imageId: "I1", title: "t")
        XCTAssertTrue(update.contains(#""imageId":"I1""#))
        XCTAssertFalse(update.contains("textId"))
        XCTAssertFalse(update.contains("remarkId"))

        let delete = try MediaFeip.deleteOp(kind: .image, imageIds: ["I1", "I2"])
        XCTAssertTrue(delete.contains(#""imageIds":["I1","I2"]"#))
        XCTAssertFalse(delete.contains("textIds"))
    }

    func testPublishNeverCarriesAnImageId() throws {
        let op = try MediaFeip.publishOp(kind: .image, title: "Cover")
        XCTAssertFalse(op.contains("imageId"))
    }

    func testEmptyOptionalsAreOmitted() throws {
        let op = try MediaFeip.publishOp(
            kind: .image, title: "t", did: nil, lang: "", authors: [], format: nil, summary: ""
        )
        XCTAssertFalse(op.contains("did"))
        XCTAssertFalse(op.contains("lang"))
        XCTAssertFalse(op.contains("authors"))
        XCTAssertFalse(op.contains("summary"))
    }

    func testAPublishWithoutATitleIsRefused() {
        XCTAssertThrowsError(try MediaFeip.publishCarve(kind: .image, title: "  "))
    }

    func testAnOversizeCarveIsRefused() {
        XCTAssertThrowsError(
            try MediaFeip.publishCarve(
                kind: .image, title: "t", summary: String(repeating: "x", count: MediaFeip.maxOpReturnSize)
            )
        ) { error in
            guard case MediaFeip.Failure.tooLarge = error else {
                return XCTFail("expected tooLarge, got \(error)")
            }
        }
    }

    func testTheSummaryBudgetShrinksByExactlyWhatIsTyped() {
        let empty = MediaFeip.remainingSummaryBytes(kind: .image, title: "t", summary: "")
        let one = MediaFeip.remainingSummaryBytes(kind: .image, title: "t", summary: "x")
        XCTAssertEqual(empty - one, 1)
    }

    /// The reference parser copies nulls onto the entity, so an update
    /// has to be able to resend everything.
    func testAnUpdateResendsEveryFieldRatherThanClearingThem() throws {
        let json = try MediaFeip.updateCarve(
            kind: .image, imageId: "I1", title: "Cover v2", did: "deadbeef",
            lang: "en", authors: ["FIDA"], format: "image/jpeg", summary: "Reshot."
        )
        for fragment in [#""did":"deadbeef""#, #""lang":"en""#, #""authors":["FIDA"]"#,
                         #""format":"image/jpeg""#, #""summary":"Reshot.""#] {
            XCTAssertTrue(json.contains(fragment), "missing \(fragment)")
        }
    }

    // MARK: - the model

    func testADraftIdIsStableAcrossIdenticalContent() {
        let a = MediaRecord.createLocal(kind: .image, title: "t", did: "abc", publisher: "FID")
        let b = MediaRecord.createLocal(kind: .image, title: "t", did: "abc", publisher: "FID")
        XCTAssertEqual(a.id, b.id)
        XCTAssertEqual(a.id.count, 64)
        XCTAssertNil(a.ver)
        XCTAssertEqual(a.onChain, false)
    }

    /// An image record and a text record with the same fields are
    /// different records, because the op they hash is different. Two
    /// drafts sharing a store key would be the failure here.
    func testAnImageDraftIdDiffersFromTheEquivalentTextDraftId() {
        let image = MediaRecord.createLocal(kind: .image, title: "t", did: "abc", publisher: "FID")
        let text = TextRecord.createLocal(title: "t", did: "abc", publisher: "FID")
        XCTAssertNotEqual(image.id, text.id)
    }

    func testAMissingVerIsToleratedAndAMissingDeletedFlagMeansNotDeleted() throws {
        let row = try JSONDecoder().decode(
            MediaRecord.self, from: Data(#"{"id":"I1","title":"t"}"#.utf8)
        )
        XCTAssertNil(row.ver)
        XCTAssertEqual(row.edition, 1)
        XCTAssertFalse(row.isDeleted)
    }

    /// Nothing on an image record decodes or encodes a `type`, so a
    /// row that arrives with one is ignored rather than round-tripped
    /// into an op the index would reject.
    func testATypeOnTheWireIsIgnored() throws {
        let row = try JSONDecoder().decode(
            MediaRecord.self, from: Data(#"{"id":"I1","title":"t","type":"photo"}"#.utf8)
        )
        let encoded = String(data: try JSONEncoder().encode(row), encoding: .utf8) ?? ""
        XCTAssertFalse(encoded.contains("photo"))
    }

    func testOnlySomebodyElseMayRate() {
        let row = MediaRecord(id: "I1", kind: .image, publisher: "FIDA", onChain: true)
        XCTAssertFalse(row.canRate(as: "FIDA"))
        XCTAssertTrue(row.canRate(as: "FIDB"))
        XCTAssertTrue(row.canUpdate(as: "FIDA"))
        XCTAssertFalse(row.canUpdate(as: "FIDB"))
    }

    func testSearchMatchesTheFieldsTheIndexExposes() {
        let row = MediaRecord(
            id: "I1", kind: .image, title: "Cover art", authors: ["FIDA"],
            summary: "A photograph", publisher: "FIDB"
        )
        XCTAssertTrue(row.matches(query: "cover"))
        XCTAssertTrue(row.matches(query: "PHOTOGRAPH"))
        XCTAssertTrue(row.matches(query: "fida"))
        XCTAssertFalse(row.matches(query: "nothing here"))
    }
}
