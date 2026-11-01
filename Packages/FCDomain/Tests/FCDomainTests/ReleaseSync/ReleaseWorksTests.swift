import XCTest
import FCCore
@testable import FCDomain

final class ReleaseWorksTests: XCTestCase {
    let owner = "FOwner"
    var dir: URL!

    override func setUpWithError() throws {
        dir = FileManager.default.temporaryDirectory.appendingPathComponent("rw-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    }

    override func tearDown() {
        try? FileManager.default.removeItem(at: dir)
    }

    func entry(_ kind: WorkKind = .video, id: String? = nil, title: String = "U1-01 Hello", asset: String = "U1-01.mp4",
               summary: String? = nil, mirrors: [String]? = nil, disk: Bool? = nil) -> ReleaseManifest.WorkEntry {
        .init(kind: kind, id: id, title: title, asset: asset, lang: "zh", format: "video/mp4",
              summary: summary, mirrors: mirrors, disk: disk)
    }

    func local(_ e: ReleaseManifest.WorkEntry, did: String = "d1") -> LocalWork {
        let (locas, _) = LocalWork.locas(link: "https://github.com/o/School/releases/download/v1/\(e.source)",
                                         entry: e, tag: "v1", fileName: e.source)
        return LocalWork(entry: e, tag: "v1", fileName: e.source, fileURL: dir.appendingPathComponent(e.source),
                         did: did, size: 1, locas: locas)
    }

    func scan(_ works: [LocalWork], owner manifestOwner: String? = nil) throws -> RepoScan {
        let manifest = ReleaseManifest(github: "o/School", owner: manifestOwner, works: works.map(\.entry))
        try writeManifest(manifest)
        return RepoScan(root: dir, manifest: manifest, tag: "v1", branch: "main", works: works)
    }

    func writeManifest(_ m: ReleaseManifest) throws {
        try JSONEncoder().encode(m).write(to: dir.appendingPathComponent(ReleaseManifest.fileName))
    }

    func record(_ id: String, title: String = "U1-01 Hello", did: String = "d1", locas: [String]? = nil,
                deleted: Bool = false) -> WorkRecord {
        WorkRecord(id: id, kind: .video, title: title, did: did, lang: "zh", format: "video/mp4",
                   locas: locas ?? ["https://github.com/o/School/releases/download/v1/U1-01.mp4"], deleted: deleted)
    }

    func testValidation() {
        XCTAssertNoThrow(try ReleaseManifest(github: "o/r", works: [entry()]).validate())
        var both = entry(); both.path = "a.md"
        XCTAssertThrowsError(try ReleaseManifest(github: "o/r", works: [both]).validate())
        XCTAssertThrowsError(try ReleaseManifest(github: "o/r", works: [entry(), entry(title: "Other")]).validate(), "same asset twice")
        var typed = entry(); typed.type = "article"
        XCTAssertThrowsError(try ReleaseManifest(github: "o/r", works: [typed]).validate(), "only a text has a type")
        XCTAssertThrowsError(try ReleaseManifest(github: "o/r", works: [entry(id: "abc")]).validate())
        XCTAssertThrowsError(try ReleaseManifest(github: "o/r", works: [entry(mirrors: ["http://x/{name}"])]).validate())
        XCTAssertThrowsError(try ReleaseManifest(github: "o/r", works: [.init(kind: .text, title: "T", path: "../x.md")]).validate())
    }

    func testMirrorsAreExpandedAndCappedBesideDisk() {
        let e = entry(mirrors: ["https://a/{tag}/{name}", "https://b/{name}", "https://c/{name}"], disk: true)
        let (locas, dropped) = LocalWork.locas(link: "https://gh/U1-01.mp4", entry: e, tag: "v1", fileName: "U1-01.mp4")
        XCTAssertEqual(locas, ["https://gh/U1-01.mp4", "https://a/v1/U1-01.mp4"])
        XCTAssertEqual(dropped, ["https://b/U1-01.mp4", "https://c/U1-01.mp4"])
    }

    func testMatchByTitleThenUnchanged() throws {
        let w = local(entry())
        var plan = ReleasePlanner.plan(scans: [try scan([w])], chain: ReleaseChainState(), owner: owner)
        XCTAssertEqual(plan.works[0].action, .publish)
        XCTAssertEqual(plan.carveCount, 1)

        plan = ReleasePlanner.plan(scans: [try scan([w])], chain: ReleaseChainState(works: [record("v1id")]), owner: owner)
        XCTAssertEqual(plan.works[0].action, .unchanged(id: "v1id"))

        // A new file, a new summary or a new mirror is an update.
        for changed in [record("v1id", did: "d0"), record("v1id", locas: ["https://old"])] {
            plan = ReleasePlanner.plan(scans: [try scan([w])], chain: ReleaseChainState(works: [changed]), owner: owner)
            XCTAssertEqual(plan.works[0].action, .update(id: "v1id"))
        }
        plan = ReleasePlanner.plan(scans: [try scan([local(entry(summary: "new"))])],
                                   chain: ReleaseChainState(works: [record("v1id")]), owner: owner)
        XCTAssertEqual(plan.works[0].action, .update(id: "v1id"))

        // Other kinds and titles are not matched; two of the same need a choice.
        let image = WorkRecord(id: "img", kind: .image, title: "U1-01 Hello")
        plan = ReleasePlanner.plan(scans: [try scan([w])], chain: ReleaseChainState(works: [image, record("x", title: "Else")]), owner: owner)
        XCTAssertEqual(plan.works[0].action, .publish)
        plan = ReleasePlanner.plan(scans: [try scan([w])], chain: ReleaseChainState(works: [record("a"), record("b")]), owner: owner)
        XCTAssertEqual(plan.works[0].action, .ambiguous(ids: ["a", "b"]))
        plan = ReleasePlanner.plan(scans: [try scan([w])], chain: ReleaseChainState(works: [record("a"), record("b", did: "d0")]),
                                   owner: owner, choices: [plan.works[0].key: "b"])
        XCTAssertEqual(plan.works[0].action, .update(id: "b"))
    }

    func testTheIdWinsOverTheTitle() throws {
        let id = String(repeating: "ab", count: 32)
        let w = local(entry(id: id, title: "Renamed"))
        var plan = ReleasePlanner.plan(scans: [try scan([w])], chain: ReleaseChainState(works: [record(id), record("other", title: "Renamed")]), owner: owner)
        XCTAssertEqual(plan.works[0].action, .update(id: id), "title changed on the same record")

        plan = ReleasePlanner.plan(scans: [try scan([w])], chain: ReleaseChainState(), owner: owner)
        guard case .invalid = plan.works[0].action else { return XCTFail("an id that is not on chain") }

        var log = ReleaseRunLog()
        log.entries[plan.works[0].key] = .init(kind: .video, id: id, txid: id, did: "d1", at: Date())
        plan = ReleasePlanner.plan(scans: [try scan([w])], chain: ReleaseChainState(), owner: owner, log: log)
        guard case .pending = plan.works[0].action else { return XCTFail("just published, not indexed yet") }
    }

    func testADeletedRecordIsBlocked() throws {
        let plan = ReleasePlanner.plan(scans: [try scan([local(entry())])],
                                       chain: ReleaseChainState(works: [record("v1id", did: "d0", deleted: true)]), owner: owner)
        guard case .blocked = plan.works[0].action else { return XCTFail() }
    }

    func testARepoSignedBySomeoneElseIsNotCarved() throws {
        let plan = ReleasePlanner.plan(scans: [try scan([local(entry())], owner: "FTeacher")], chain: ReleaseChainState(), owner: owner)
        guard case .invalid(let why) = plan.works[0].action else { return XCTFail() }
        XCTAssertTrue(why.contains("FTeacher"))
        XCTAssertEqual(ReleasePlanner.plan(scans: [try scan([local(entry())], owner: owner)], chain: ReleaseChainState(),
                                           owner: owner).works[0].action, .publish)
    }

    func testCarvesFitAndNameTheirKind() throws {
        let item = ReleasePlanner.plan(scans: [try scan([local(entry(summary: String(repeating: "很长的介绍 ", count: 400), disk: true))])],
                                       chain: ReleaseChainState(), owner: owner).works[0]
        let carve = try ReleaseCarves.workCarve(item)
        XCTAssertTrue(carve.summary!.hasSuffix("…"))
        let json = try carve.json()
        XCTAssertTrue(json.contains("\"sn\":\"25\""))
        XCTAssertTrue(json.contains("(sid)"), "room is kept for the DISK entry")
        XCTAssertFalse(json.contains("videoId"))
        let text = WorkCarve(kind: .text, targetId: "t1", title: "T", type: "article", did: "d")
        XCTAssertTrue(try text.json().contains("\"textId\":\"t1\""))
    }

    func testTheRunCarvesImagesFirstStoresOnDiskAndWritesTheIdBack() async throws {
        let video = local(entry(disk: true))
        let cover = local(.init(kind: .image, title: "Cover", asset: "cover.png"), did: "c1")
        let plan = ReleasePlanner.plan(scans: [try scan([video, cover])], chain: ReleaseChainState(), owner: owner)
        let fake = FakeBackend()
        let log = dir.appendingPathComponent("log.json")
        try await ReleaseRunner(backend: fake, logURL: log).run(plan, selected: Set(plan.works.map(\.key))) { _ in }
        XCTAssertEqual(fake.calls, [
            "W image Cover publish locas=[\"https://github.com/o/School/releases/download/v1/cover.png\"]",
            "disk U1-01.mp4",
            "W video U1-01 Hello publish locas=[\"(sid)disk\", \"https://github.com/o/School/releases/download/v1/U1-01.mp4\"]",
        ])
        let written = try ReleaseManifest.load(repo: dir)
        XCTAssertEqual(written.works?.first(where: { $0.source == "U1-01.mp4" })?.id, String(format: "%064d", 2))
        XCTAssertEqual(written.works?.first(where: { $0.source == "cover.png" })?.id, String(format: "%064d", 1))

        // Run again: the log holds both, nothing is carved twice.
        let again = FakeBackend()
        try await ReleaseRunner(backend: again, logURL: log).run(plan, selected: Set(plan.works.map(\.key))) { _ in }
        XCTAssertEqual(again.calls, [])
    }

    // MARK: cover

    func testCoverValidation() {
        let image = ReleaseManifest.WorkEntry(kind: .image, title: "C", asset: "c.png")
        var video = entry(); video.cover = "c.png"
        XCTAssertNoThrow(try ReleaseManifest(github: "o/r", works: [image, video]).validate())
        video.cover = String(repeating: "ab", count: 32)
        XCTAssertNoThrow(try ReleaseManifest(github: "o/r", works: [video]).validate())
        video.cover = "missing.png"
        XCTAssertThrowsError(try ReleaseManifest(github: "o/r", works: [image, video]).validate())
        var other = entry(title: "Other", asset: "U1-02.mp4"); other.cover = "U1-01.mp4"
        XCTAssertThrowsError(try ReleaseManifest(github: "o/r", works: [entry(), other]).validate(), "a cover must be an image")
        var coveredImage = image; coveredImage.cover = String(repeating: "ab", count: 32)
        XCTAssertThrowsError(try ReleaseManifest(github: "o/r", works: [coveredImage]).validate())
    }

    func testAnImageDoesNotCarryACover() throws {
        let json = try MediaFeip.publishCarve(kind: .image, title: "C", cover: "x")
        XCTAssertFalse(json.contains("cover"))
        XCTAssertTrue(try MediaFeip.publishCarve(kind: .video, title: "V", cover: "x").contains("\"cover\":\"x\""))
        XCTAssertTrue(try TextFeip.updateCarve(textId: "t", title: "T", cover: "x").contains("\"cover\":\"x\""))
    }

    func testTheCoverFollowsTheImageCarvedInTheRun() async throws {
        var e = entry(); e.cover = "cover.png"
        let video = local(e)
        let cover = local(.init(kind: .image, title: "Cover", asset: "cover.png"), did: "c1")
        let plan = ReleasePlanner.plan(scans: [try scan([video, cover])], chain: ReleaseChainState(), owner: owner)
        let item = plan.works.first { $0.local.entry.kind == .video }!
        XCTAssertEqual(item.cover, .workInRun(plan.works.first { $0.local.entry.kind == .image }!.key))
        XCTAssertTrue(try ReleaseCarves.workCarve(item).json().contains(ReleaseCarves.placeholderId), "sized with a placeholder")

        final class Covers: @unchecked Sendable { var seen: [String?] = [] }
        let covers = Covers()
        let reviewer = Reviewer { draft in
            if case .work(let c) = draft { covers.seen.append(c.cover) }
            return draft
        }
        var runner = ReleaseRunner(backend: FakeBackend(), logURL: dir.appendingPathComponent("log.json"))
        runner.reviewer = reviewer
        try await runner.run(plan, selected: Set(plan.works.map(\.key))) { _ in }
        XCTAssertEqual(covers.seen, [nil, String(format: "%064d", 1)], "the image's txid becomes the video's cover")
    }

    func testACoverChangeIsAnUpdate() throws {
        let imageId = String(repeating: "ab", count: 32)
        var e = entry(); e.cover = imageId
        var rec = record("v1id")
        var plan = ReleasePlanner.plan(scans: [try scan([local(e)])], chain: ReleaseChainState(works: [rec]), owner: owner)
        XCTAssertEqual(plan.works[0].action, .update(id: "v1id"), "no cover on chain yet")
        rec.cover = imageId
        plan = ReleasePlanner.plan(scans: [try scan([local(e)])], chain: ReleaseChainState(works: [rec]), owner: owner)
        XCTAssertEqual(plan.works[0].action, .unchanged(id: "v1id"))
        plan = ReleasePlanner.plan(scans: [try scan([local(entry())])], chain: ReleaseChainState(works: [rec]), owner: owner)
        XCTAssertEqual(plan.works[0].action, .update(id: "v1id"), "the manifest dropped the cover")
        // An image already on chain resolves to its id.
        let image = WorkRecord(id: "img1", kind: .image, title: "Cover",
                               locas: ["https://github.com/o/School/releases/download/v1/cover.png"])
        var withRef = entry(); withRef.cover = "cover.png"
        plan = ReleasePlanner.plan(scans: [try scan([local(withRef), local(.init(kind: .image, title: "Cover", asset: "cover.png"), did: "c1")])],
                                   chain: ReleaseChainState(works: [rec, WorkRecord(id: "img1", kind: .image, title: "Cover", did: "c1", locas: image.locas)]),
                                   owner: owner)
        XCTAssertEqual(plan.works.first { $0.local.entry.kind == .video }!.cover, .known("img1"))
    }

    func testAFailingConfirmationCheckIsReportedNotSwallowed() async throws {
        let works = [local(entry()), local(entry(title: "Two", asset: "U1-02.mp4"), did: "d2")]
        let plan = ReleasePlanner.plan(scans: [try scan(works)], chain: ReleaseChainState(), owner: owner)
        let fake = FakeBackend()
        fake.failConfirmChecks = 1
        var runner = ReleaseRunner(backend: fake, logURL: dir.appendingPathComponent("log.json"))
        runner.maxUnconfirmed = 1
        runner.pollInterval = .milliseconds(1)
        let events = EventBox()
        try await runner.run(plan, selected: Set(plan.works.map(\.key))) { events.add($0) }
        XCTAssertEqual(fake.calls.filter { $0.hasPrefix("W ") }.count, 2, "the run goes on once lookups work again")
        XCTAssertTrue(events.all.contains { if case .confirmCheckFailed = $0 { return true }; return false })
    }
}
