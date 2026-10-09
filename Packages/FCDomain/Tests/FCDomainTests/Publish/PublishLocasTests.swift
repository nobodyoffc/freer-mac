import XCTest
import FCCore
import FCTransport
@testable import FCDomain

/// `locas` on the Publish protocols (FEIP21–25): what the builders put
/// on the wire, what a record decodes, and how ``PublishBody`` uses a
/// record's list to find bytes no DISK of ours holds.
final class PublishLocasTests: XCTestCase {

    private var baseDir: URL!
    private var server: FakeDiskServer!

    private let ownSid = String(repeating: "1d", count: 32)
    private let diskA = "(sid)" + String(repeating: "aa", count: 32)
    private let diskB = "(sid)" + String(repeating: "bb", count: 32)

    override func setUpWithError() throws {
        baseDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("PublishLocasTests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: baseDir, withIntermediateDirectories: true)
        server = FakeDiskServer()
    }

    override func tearDownWithError() throws {
        if let baseDir { try? FileManager.default.removeItem(at: baseDir) }
    }

    private func makeBody(
        foreignDisk: PublishBody.DiskResolver? = nil,
        locaDisk: PublishBody.LocaResolver? = nil
    ) throws -> PublishBody {
        let mgr = try ConfigureManager(baseDirectory: baseDir.appendingPathComponent("vault"))
        let configure = try mgr.createConfigure(password: Data("pwd".utf8), kdfKind: .legacySha256)
        let info = try configure.addMain(privkey: Data(repeating: 0xB3, count: 32), label: "P")
        let session = try configure.unlockMain(fid: info.fid, fapi: server)
        let sync = HatSyncService(
            disk: DiskService(fapi: server), hats: session.hats,
            files: session.files, serviceSid: ownSid
        )
        return PublishBody(
            files: session.files, hats: session.hats, sync: sync,
            disk: DiskService(fapi: server),
            foreignDisk: foreignDisk, locaDisk: locaDisk
        )
    }

    // MARK: - builders

    func testTheBuildersCarveLocasAndOmitAnEmptyList() throws {
        let with = try TextFeip.publishCarve(title: "t", did: "d", locas: [diskA, "https://x.org/a"])
        XCTAssertTrue(with.contains(#""locas":["\#(diskA)","https://x.org/a"]"#), with)

        for json in [try TextFeip.publishCarve(title: "t", locas: []),
                     try TextFeip.publishCarve(title: "t")] {
            XCTAssertFalse(json.contains("locas"), json)
        }

        XCTAssertTrue(try TextFeip.updateCarve(textId: "T", title: "t", locas: [diskA]).contains("locas"))
        XCTAssertTrue(try RemarkFeip.publishCarve(title: "t", onDid: "o", locas: [diskA]).contains("locas"))
        XCTAssertTrue(try MediaFeip.publishCarve(kind: .video, title: "t", locas: [diskA]).contains("locas"))
    }

    /// The summary budget a form draws counts the `locas` it will carve.
    func testTheSummaryBudgetCountsTheLocas() {
        let without = TextFeip.remainingSummaryBytes(title: "t", summary: "")
        let with = TextFeip.remainingSummaryBytes(title: "t", summary: "", locas: [diskA])
        XCTAssertGreaterThan(without - with, diskA.utf8.count)
    }

    func testARecordDecodesLocasFromTheIndex() throws {
        let json = #"{"id":"T1","title":"t","did":"d","locas":["\#(diskA)"]}"#
        XCTAssertEqual(try JSONDecoder().decode(TextRecord.self, from: Data(json.utf8)).locas, [diskA])
        XCTAssertEqual(try JSONDecoder().decode(Remark.self, from: Data(json.utf8)).locas, [diskA])
        let old = #"{"id":"T1","title":"t"}"#
        XCTAssertNil(try JSONDecoder().decode(TextRecord.self, from: Data(old.utf8)).locas)
    }

    // MARK: - choosing what to carve

    /// Storing a body uploads it to our DISK, and the HAT remembers
    /// where — which is exactly what the carve should say.
    func testCarvedLocasNameTheDiskTheBodyWentTo() async throws {
        let body = try makeBody()
        let did = try await body.store("an essay")
        XCTAssertEqual(body.carvedLocas(did: did), ["(sid)" + ownSid])
        XCTAssertNil(body.carvedLocas(did: nil))
        XCTAssertNil(body.carvedLocas(did: String(repeating: "ee", count: 32)), "never uploaded")
    }

    func testCarvedLocasKeepTheOldListOnlyForTheSameBodyAndCapAtThree() async throws {
        let body = try makeBody()
        let did = try await body.store("an essay")
        let own = "(sid)" + ownSid

        XCTAssertEqual(body.carvedLocas(did: did, keeping: [diskA], previousDid: did), [diskA, own])
        XCTAssertEqual(body.carvedLocas(did: did, keeping: [diskA], previousDid: "other"), [own])
        XCTAssertEqual(body.carvedLocas(did: did, keeping: [own], previousDid: did), [own], "no duplicates")

        let many = [diskA, diskB, "https://x.org/a", "https://y.org/b"]
        XCTAssertEqual(
            body.carvedLocas(did: did, keeping: many, previousDid: did)?.count,
            PublishBody.maxCarvedLocas
        )
    }

    func testLocasSplitIntoWhatTheAppFetchesAndWhatTheUserOpens() {
        let locas = [diskA, "fudp://1.2.3.4:8500", "https://x.org/a", "local:///tmp/x", "ftp://y"]
        XCTAssertEqual(PublishBody.diskLocas(locas), [diskA, "fudp://1.2.3.4:8500"])
        XCTAssertEqual(PublishBody.webLocas(locas).map(\.absoluteString), ["https://x.org/a"])
    }

    // MARK: - reading

    /// A body only the listed DISK holds is fetched from it, verified,
    /// and kept — and the publisher's home is not looked up at all,
    /// because the record already said where to go.
    func testABodyIsFetchedFromTheRecordsListedDisk() async throws {
        let theirs = FakeDiskServer()
        let text = "held only by the listed DISK"
        let did = theirs.seed(Data(text.utf8))
        let asked = Captured()
        let body = try makeBody(
            foreignDisk: { _ in asked.value = true; return nil },
            locaDisk: { [diskA] loca in loca == diskA ? DiskService(fapi: theirs) : nil }
        )

        let got = try await body.read(did: did, publisher: "THEM", locas: [diskA])
        XCTAssertEqual(got, text)
        XCTAssertNil(asked.value, "the publisher's home is the fallback, not the first resort")
        XCTAssertTrue(body.isLocal(did: did))
    }

    /// A listed DISK is a hint: when it serves the wrong bytes, the
    /// fetch moves on rather than believing it.
    func testAListedDiskServingTheWrongBytesIsPassedOver() async throws {
        let liar = FakeDiskServer()
        let honest = FakeDiskServer()
        let text = "the real essay"
        let did = honest.seed(Data(text.utf8))
        _ = liar.seed(Data(text.utf8))
        liar.substituteOnGet = Data("something else".utf8)
        let body = try makeBody(locaDisk: { [diskA, diskB] loca in
            switch loca {
            case diskA: return DiskService(fapi: liar)
            case diskB: return DiskService(fapi: honest)
            default: return nil
            }
        })

        let got = try await body.read(did: did, locas: [diskA, diskB])
        XCTAssertEqual(got, text)
    }

    /// `https://` entries are never fetched by the app, and an
    /// unresolvable DISK entry is named in the failure.
    func testWebEntriesAreNotFetchedAndFailuresNameEachLoca() async throws {
        let asked = Captured()
        let body = try makeBody(locaDisk: { loca in
            if loca.hasPrefix("https") { asked.value = true }
            return nil
        })
        do {
            _ = try await body.read(did: String(repeating: "ee", count: 32), locas: [diskA, "https://x.org/a"])
            XCTFail("expected a throw")
        } catch {
            XCTAssertTrue("\(error)".contains("=unresolved"), "\(error)")
        }
        XCTAssertNil(asked.value)
    }
}

private final class Captured: @unchecked Sendable {
    var value: Bool?
}
