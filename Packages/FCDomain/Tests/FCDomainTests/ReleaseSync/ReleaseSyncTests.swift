import XCTest
import FCCore
@testable import FCDomain

final class ProtocolDocTests: XCTestCase {

    static func markdown(type: String = "FEIP", sn: String = "1", ver: String = "7", pid: String = "",
                         title: String = "Protocol", abstract: String = "The **on-chain** `registry`, see [FEIP0](FEIP0V1_FEIP.md).\n\nSecond   line.") -> String {
        """
        # \(type)\(sn)V\(ver)_\(title)
        ## Contents
        [Summary](#summary)
        ---
        ## Summary
        |Field|Content|
        |---|---|
        |Title|\(title)|
        |Type|\(type)|
        |SN|\(sn)|
        |Version|\(ver)|
        |Status|Active|
        |PID|\(pid)|

        ## Abstract
        \(abstract)
        ```
        code is dropped
        ```
        ### sub heading dropped
        ## Motivation
        |PID|not this one|
        """
    }

    func doc(_ md: String, file: String = "FEIP1V7_Protocol.md") throws -> ProtocolDoc {
        try ProtocolDoc.parse(data: Data(md.utf8), url: URL(fileURLWithPath: "/r/Protocols/\(file)"),
                              relativePath: "Protocols/\(file)")
    }

    func testFileNames() {
        XCTAssertEqual(ProtocolDoc.parseFileName("FEIP1V7_Protocol.md")?.type, "FEIP")
        XCTAssertEqual(ProtocolDoc.parseFileName("FTSP027V1_X.md")?.sn, "27")
        XCTAssertNil(ProtocolDoc.parseFileName("FEIP1_Protocol.md"))
        XCTAssertNil(ProtocolDoc.parseFileName("README.md"))
        XCTAssertNil(ProtocolDoc.parseFileName("FEIP1V7Protocol.md"))
    }

    func testFieldsFromTheSummaryAndAbstract() throws {
        let d = try doc(Self.markdown())
        XCTAssertEqual(d.ref, ProtocolRef(type: "FEIP", sn: "1"))
        XCTAssertEqual(d.ver, "7")
        XCTAssertEqual(d.name, "Protocol")
        XCTAssertEqual(d.lang, "en")
        XCTAssertNil(d.pid)
        XCTAssertEqual(d.desc, "The on-chain registry, see FEIP0. Second line.")
        XCTAssertEqual(d.did, Hex.encode(Hash.doubleSha256(Data(Self.markdown().utf8))).lowercased())
    }

    func testATxidInThePidRowIsRead() throws {
        let pid = String(repeating: "ab", count: 32)
        XCTAssertEqual(try doc(Self.markdown(pid: pid)).pid, pid)
    }

    func testAChangeProposalIsNotTheNextVersion() {
        XCTAssertThrowsError(try doc(Self.markdown(type: "FIMP (change proposal)", sn: "0", ver: "3"),
                                     file: "FIMP0V3_Signing_Proposal.md"))
        XCTAssertThrowsError(try doc(Self.markdown(ver: "6")), "table and file name disagree")
    }

    func testFillingThePidTouchesOnlyTheSummaryRow() throws {
        let pid = String(repeating: "cd", count: 32)
        let filled = String(decoding: try ProtocolDoc.fillingPid(pid, in: Data(Self.markdown().utf8)), as: UTF8.self)
        XCTAssertEqual(filled, Self.markdown(pid: pid))
        XCTAssertTrue(filled.contains("|PID|not this one|"))
    }

    /// FAPI3, FIMP1-4 and FUDP3 keep the table at the top, before Contents.
    func testATableAboveTheContentsIsTheSummary() throws {
        let md = "# FAPI3V1_Components\n\n|Field|Content|\n|---|---|\n|Title|Components|\n|Type|FAPI|\n|SN|3|\n|Version|1|\n|PID||\n\n## Contents\n\n## Abstract\nA.\n\n## Summary\nProse, no table.\n"
        let d = try ProtocolDoc.parse(data: Data(md.utf8), url: URL(fileURLWithPath: "/FAPI3V1_Components.md"), relativePath: "FAPI3V1_Components.md")
        XCTAssertEqual(d.name, "Components")
        let pid = String(repeating: "9", count: 64)
        let filled = String(decoding: try ProtocolDoc.fillingPid(pid, in: Data(md.utf8)), as: UTF8.self)
        XCTAssertEqual(filled, md.replacingOccurrences(of: "|PID||", with: "|PID|\(pid)|"))
    }

    func testFillingAppendsARowWhenThereIsNone() throws {
        let md = Self.markdown().replacingOccurrences(of: "|PID||\n", with: "")
        let pid = String(repeating: "ef", count: 32)
        let filled = String(decoding: try ProtocolDoc.fillingPid(pid, in: Data(md.utf8)), as: UTF8.self)
        XCTAssertTrue(filled.contains("|Status|Active|\n|PID|\(pid)|\n\n## Abstract"))
    }
}

final class ReleaseManifestTests: XCTestCase {

    func testAssetPatterns() {
        XCTAssertTrue(ReleaseManifest.assetMatches(pattern: "FapiServer.jar", name: "FapiServer.jar"))
        XCTAssertFalse(ReleaseManifest.assetMatches(pattern: "FapiServer.jar", name: "FapiClient.jar"))
        XCTAssertTrue(ReleaseManifest.assetMatches(pattern: "Freer-*.dmg", name: "Freer-0.4.1.dmg"))
        XCTAssertFalse(ReleaseManifest.assetMatches(pattern: "Freer-*.dmg", name: "Freer-0.4.1.zip"))
        XCTAssertTrue(ReleaseManifest.assetMatches(pattern: "*-release-*.apk", name: "freer-release-3.3.0.apk"))
    }

    func testProtocolRefs() {
        XCTAssertEqual(ProtocolRef("FEIP1"), ProtocolRef(type: "FEIP", sn: "1"))
        XCTAssertEqual(ProtocolRef("FTSP07"), ProtocolRef(type: "FTSP", sn: "7"))
        XCTAssertNil(ProtocolRef("FEIP"))
        XCTAssertNil(ProtocolRef("1"))
    }

    func testRawIdsAreAcceptedAsReferences() throws {
        let pid = String(repeating: "a", count: 64)
        XCTAssertNoThrow(try ReleaseManifest(github: "a/b", codes: [.init(name: "X", path: ".", protocols: [pid])]).validate())
    }

    func testValidation() {
        XCTAssertThrowsError(try ReleaseManifest(github: "Freeverse").validate())
        XCTAssertThrowsError(try ReleaseManifest(github: "a/b", codes: [.init(name: "X", path: "x"), .init(name: "X", path: "y")]).validate())
        XCTAssertThrowsError(try ReleaseManifest(github: "a/b", codes: [.init(name: "X", path: "../x")]).validate())
        XCTAssertThrowsError(try ReleaseManifest(github: "a/b", codes: [.init(name: "X", path: "x", protocols: ["feip"])]).validate())
        XCTAssertNoThrow(try ReleaseManifest(github: "a/b", codes: [.init(name: "X", path: ".", protocols: ["FEIP1"])]).validate())
    }

    func testAssetDidComesFromGitHubsDigest() {
        let bytes = Data("jar bytes".utf8)
        let asset = GitHubReleases.Asset(name: "a.jar", size: 9, url: "u",
                                         digest: "sha256:" + Hex.encode(Hash.sha256(bytes)).lowercased())
        XCTAssertEqual(asset.did, Hex.encode(Hash.doubleSha256(bytes)).lowercased())
        XCTAssertNil(GitHubReleases.Asset(name: "a", size: 0, url: "u", digest: nil).did)
    }
}

final class DeterministicZipTests: XCTestCase {

    func entries() -> [DeterministicZip.Entry] {
        [.init(path: "M/b.txt", data: Data(String(repeating: "hello ", count: 200).utf8)),
         .init(path: "M/a/run.sh", data: Data("#!/bin/sh\necho hi\n".utf8), executable: true),
         .init(path: "M/empty", data: Data())]
    }

    func testSameFilesSameBytesWhateverTheOrder() {
        XCTAssertEqual(DeterministicZip.archive(entries()), DeterministicZip.archive(entries().reversed()))
    }

    func testUnzipAcceptsItAndRestoresTheFiles() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("dz-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let zip = dir.appendingPathComponent("t.zip")
        try DeterministicZip.archive(entries()).write(to: zip)
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/unzip")
        p.arguments = ["-q", zip.path, "-d", dir.appendingPathComponent("out").path]
        try p.run(); p.waitUntilExit()
        XCTAssertEqual(p.terminationStatus, 0)
        for e in entries() {
            XCTAssertEqual(try Data(contentsOf: dir.appendingPathComponent("out/\(e.path)")), e.data)
        }
        let attrs = try FileManager.default.attributesOfItem(atPath: dir.appendingPathComponent("out/M/a/run.sh").path)
        XCTAssertNotEqual(((attrs[.posixPermissions] as? NSNumber)?.intValue ?? 0) & 0o100, 0, "the executable bit survives")
    }

    /// Pins the encoder: if a macOS update changed Compression's output,
    /// every code's DID would change at once, and this says so first.
    func testTheBytesArePinned() {
        let did = Hex.encode(Hash.doubleSha256(DeterministicZip.archive(entries()))).lowercased()
        XCTAssertEqual(did, Self.pinnedDid, "archive bytes changed; every code DID will change")
    }
    static let pinnedDid = "13d23ee9d4ecaf5746ed39dcd18d3c25b09a9d957ddddffbf50d9e7e6b335f62"

    func testCrc() {
        XCTAssertEqual(CRC32.checksum(Data("123456789".utf8)), 0xCBF4_3926)
    }
}

// MARK: - planner

final class ReleasePlannerTests: XCTestCase {
    let owner = "FOwner"
    var dir: URL!

    override func setUpWithError() throws {
        dir = FileManager.default.temporaryDirectory.appendingPathComponent("rp-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir.appendingPathComponent("Protocols"), withIntermediateDirectories: true)
    }

    override func tearDown() {
        try? FileManager.default.removeItem(at: dir)
    }

    func writeDoc(sn: String, ver: String = "1", pid: String = "", body: String = "x") throws -> ProtocolDoc {
        let file = "FEIP\(sn)V\(ver)_P\(sn).md"
        let url = dir.appendingPathComponent("Protocols/\(file)")
        try Data(ProtocolDocTests.markdown(sn: sn, ver: ver, pid: pid, title: "P\(sn)", abstract: body).utf8).write(to: url)
        return try ProtocolDoc.load(url: url, relativePath: "Protocols/\(file)")
    }

    func spec(_ id: String, sn: String, did: String?, active: Bool = true, closed: Bool = false) -> ProtocolSpec {
        var s = ProtocolSpec(id: id, type: "FEIP", sn: sn, ver: "1", did: did, name: "P\(sn)", owner: owner)
        s.active = active
        s.closed = closed
        return s
    }

    func scan(_ docs: [ProtocolDoc], codes: [LocalCode] = [], apps: [LocalApp] = []) -> RepoScan {
        RepoScan(root: dir, manifest: ReleaseManifest(github: "o/R"), tag: "v1", branch: "main",
                 protocols: docs, codes: codes, apps: apps)
    }

    func code(_ name: String, did: String, protocols: [String]) -> LocalCode {
        LocalCode(entry: .init(name: name, path: name, langs: ["Java"], protocols: protocols), tag: "v1",
                  zipURL: dir.appendingPathComponent("\(name).zip"), assetName: "\(name)-v1.zip",
                  did: did, fileCount: 1, byteCount: 1)
    }

    func testProtocolActions() throws {
        let same = try writeDoc(sn: "1")
        let changed = try writeDoc(sn: "2")
        let new = try writeDoc(sn: "3")
        let closed = try writeDoc(sn: "4")
        let stopped = try writeDoc(sn: "5")
        let chain = ReleaseChainState(protocols: [
            spec("p1", sn: "1", did: same.did),
            spec("p2", sn: "2", did: "old"),
            spec("p4", sn: "4", did: "old", active: false, closed: true),
            spec("p5", sn: "5", did: "old", active: false),
            spec("p8", sn: "8", did: "x", active: false, closed: true),
            spec("p9", sn: "9", did: "x"),
        ])
        let plan = ReleasePlanner.plan(scans: [scan([same, changed, new, closed, stopped])], chain: chain, owner: owner)
        let byRef = Dictionary(uniqueKeysWithValues: plan.protocols.map { ($0.doc.sn, $0) })
        XCTAssertEqual(byRef["1"]?.action, .unchanged(id: "p1"))
        XCTAssertEqual(byRef["2"]?.action, .update(id: "p2"))
        XCTAssertEqual(byRef["3"]?.action, .publish)
        XCTAssertEqual(byRef["4"]?.action, .publish)
        XCTAssertEqual(byRef["5"]?.action, .blocked(id: "p5", reason: "stopped on chain; recover it first"))
        XCTAssertEqual(plan.orphanProtocols.map(\.id), ["p9"])
        XCTAssertEqual(plan.carveCount, 3)

        // An update is carved with the PID filled in; a publish as-is.
        XCTAssertEqual(byRef["2"]?.carveDid, try ReleaseSyncFiles.didWithPid("p2", doc: changed))
        XCTAssertNotEqual(byRef["2"]?.carveDid, changed.did)
        XCTAssertEqual(byRef["3"]?.carveDid, new.did)
        XCTAssertEqual(byRef["2"]?.home?["src"], "https://github.com/o/R/blob/main/Protocols/FEIP2V1_P2.md")
    }

    func testADocumentWhoseOnlyDifferenceIsItsPidIsUnchanged() throws {
        let pid = String(repeating: "1", count: 64)
        let doc = try writeDoc(sn: "1")
        let carved = try ReleaseSyncFiles.didWithPid(pid, doc: doc)
        let plan = ReleasePlanner.plan(scans: [scan([doc])], chain: ReleaseChainState(protocols: [spec(pid, sn: "1", did: carved)]), owner: owner)
        XCTAssertEqual(plan.protocols[0].action, .unchanged(id: pid))
    }

    func testThePidInTheDocumentWinsOverTypeAndSn() throws {
        let pid = String(repeating: "2", count: 64)
        let doc = try writeDoc(sn: "1", pid: pid)
        let chain = ReleaseChainState(protocols: [spec("other", sn: "1", did: "a"), spec(pid, sn: "1", did: "b")])
        let plan = ReleasePlanner.plan(scans: [scan([doc])], chain: chain, owner: owner)
        XCTAssertEqual(plan.protocols[0].action, .update(id: pid))
        XCTAssertEqual(plan.protocols[0].carveDid, doc.did, "the PID is already there")
        XCTAssertTrue(plan.orphanProtocols.isEmpty, "both records share the key, so neither is an orphan")

        let foreign = try writeDoc(sn: "2", pid: String(repeating: "3", count: 64))
        let plan2 = ReleasePlanner.plan(scans: [scan([foreign])], chain: ReleaseChainState(), owner: owner)
        guard case .invalid = plan2.protocols[0].action else { return XCTFail("a PID the owner lacks is invalid") }
    }

    func testDuplicatesNeedAChoice() throws {
        let doc = try writeDoc(sn: "15")
        let chain = ReleaseChainState(protocols: [spec("a", sn: "15", did: "x"), spec("b", sn: "15", did: "y")])
        XCTAssertEqual(ReleasePlanner.plan(scans: [scan([doc])], chain: chain, owner: owner).protocols[0].action,
                       .ambiguous(ids: ["a", "b"]))
        let chosen = ReleasePlanner.plan(scans: [scan([doc])], chain: chain, owner: owner,
                                         choices: [ReleasePlanner.choiceKey(protocol: doc.ref): "b"])
        XCTAssertEqual(chosen.protocols[0].action, .update(id: "b"))
    }

    func testCodesLinkToProtocolsOnChainOrInTheRun() throws {
        let new = try writeDoc(sn: "3")
        let same = try writeDoc(sn: "1")
        let chain = ReleaseChainState(protocols: [spec("p1", sn: "1", did: same.did)],
                                      codes: [Code(id: "c1", name: "Lib", ver: "v0", did: "zip0", langs: ["Java"], protocols: ["p1"], owner: owner)])
        let plan = ReleasePlanner.plan(
            scans: [scan([new, same], codes: [code("Lib", did: "zip0", protocols: ["FEIP1"]),
                                              code("Two", did: "z2", protocols: ["FEIP1", "FEIP3", "FEIP8"])])],
            chain: chain, owner: owner)
        XCTAssertEqual(plan.codes[0].action, .unchanged(id: "c1"), "same archive, same links")
        XCTAssertEqual(plan.codes[1].action, .publish)
        XCTAssertEqual(plan.codes[1].protocols, [.known("p1"), .protocolInRun(ProtocolRef(type: "FEIP", sn: "3")), .unresolved("FEIP8")])
        XCTAssertTrue(plan.problems.contains { $0.contains("FEIP8") })
        XCTAssertEqual(plan.codes[1].home["zip"], "https://github.com/o/R/releases/download/v1/Two-v1.zip")
        XCTAssertEqual(plan.codes[1].home["src"], "https://github.com/o/R/tree/v1/Two")
    }

    func logged(_ key: String, _ kind: ReleaseEntityKind, id: String, txid: String, did: String, at: Date) -> ReleaseRunLog {
        var log = ReleaseRunLog()
        log.entries[key] = .init(kind: kind, id: id, txid: txid, did: did, at: at)
        return log
    }

    func testACarveNotOnChainYetIsPending() throws {
        let doc = try writeDoc(sn: "3")
        let now = Date()
        let log = logged("protocol:FEIP3", .protocol, id: "tx3", txid: "tx3", did: doc.did, at: now.addingTimeInterval(-600))
        let plan = ReleasePlanner.plan(scans: [scan([doc], codes: [code("Lib", did: "z", protocols: ["FEIP3"])])],
                                       chain: ReleaseChainState(), owner: owner, log: log, now: now)
        XCTAssertEqual(plan.protocols[0].action, .pending(id: "tx3", txid: "tx3", since: now.addingTimeInterval(-600), stale: false))
        XCTAssertFalse(plan.protocols[0].action.carves, "not offered again")
        XCTAssertEqual(plan.codes[0].protocols, [.known("tx3")], "its id is already known")
        XCTAssertEqual(plan.carveCount, 1, "only the code")
    }

    func testAPendingCarveGoesStaleAfterTwoHours() throws {
        let doc = try writeDoc(sn: "3")
        let now = Date()
        let at = now.addingTimeInterval(-ReleasePlanner.pendingExpiry - 1)
        let plan = ReleasePlanner.plan(scans: [scan([doc])], chain: ReleaseChainState(), owner: owner,
                                       log: logged("protocol:FEIP3", .protocol, id: "tx3", txid: "tx3", did: doc.did, at: at), now: now)
        XCTAssertEqual(plan.protocols[0].action, .pending(id: "tx3", txid: "tx3", since: at, stale: true))

        // Carve Again forgets it, and it is offered again.
        let url = dir.appendingPathComponent("log.json")
        try logged("protocol:FEIP3", .protocol, id: "tx3", txid: "tx3", did: doc.did, at: at).save(url)
        try ReleaseRunLog.forget("protocol:FEIP3", at: url)
        let again = ReleasePlanner.plan(scans: [scan([doc])], chain: ReleaseChainState(), owner: owner,
                                        log: ReleaseRunLog.load(url), now: now)
        XCTAssertEqual(again.protocols[0].action, .publish)
    }

    func testOnceOnChainItIsUnchangedAndAPendingPublishIsNeverRepeated() throws {
        let doc = try writeDoc(sn: "3")
        let log = logged("protocol:FEIP3", .protocol, id: "tx3", txid: "tx3", did: doc.did, at: Date())
        let confirmed = ReleasePlanner.plan(scans: [scan([doc])], chain: ReleaseChainState(protocols: [spec("tx3", sn: "3", did: doc.did)]),
                                            owner: owner, log: log)
        XCTAssertEqual(confirmed.protocols[0].action, .unchanged(id: "tx3"))

        // Edited while its publish is unconfirmed: still pending, never a second publish.
        let edited = try writeDoc(sn: "3", body: "edited after the carve")
        let plan = ReleasePlanner.plan(scans: [scan([edited])], chain: ReleaseChainState(), owner: owner, log: log)
        guard case .pending(id: "tx3", _, _, _) = plan.protocols[0].action else {
            return XCTFail("a pending publish must not be offered again: \(plan.protocols[0].action)")
        }

        // An update with a new DID on top of a pending update is offered.
        let updateLog = logged("protocol:FEIP3", .protocol, id: "p3", txid: "tx9", did: "old-update", at: Date())
        let onChain = ReleaseChainState(protocols: [spec("p3", sn: "3", did: "older")])
        XCTAssertEqual(ReleasePlanner.plan(scans: [scan([edited])], chain: onChain, owner: owner, log: updateLog).protocols[0].action,
                       .update(id: "p3"))
    }

    func testAppsChangeWithTheirAsset() throws {
        let app = LocalApp(entry: .init(stdName: "Srv", asset: "Srv.jar", os: "java", codes: ["Lib"]), tag: "v2",
                           asset: .init(name: "Srv.jar", size: 1, url: "https://x/Srv.jar", digest: nil), did: "d2")
        var record = AppRecord(id: "a1", stdName: "Srv", ver: "v1", owner: owner)
        record.codes = ["c1"]
        record.downloads = [.init(os: "java", link: "https://x/old.jar", did: "d1")]
        let chain = ReleaseChainState(codes: [Code(id: "c1", name: "Lib", owner: owner)], apps: [record])
        let plan = ReleasePlanner.plan(scans: [scan([], apps: [app])], chain: chain, owner: owner)
        XCTAssertEqual(plan.apps[0].action, .update(id: "a1"))
        XCTAssertEqual(plan.apps[0].codes, [.known("c1")])

        record.downloads = [.init(os: "java", link: "https://x/Srv.jar", did: "d2")]
        let plan2 = ReleasePlanner.plan(scans: [scan([], apps: [app])], chain: ReleaseChainState(codes: chain.codes, apps: [record]), owner: owner)
        XCTAssertEqual(plan2.apps[0].action, .unchanged(id: "a1"))
    }
}

// MARK: - carves and runner

final class ReleaseCarvesTests: XCTestCase {

    func testALongDescriptionIsClippedToFit() throws {
        let long = String(repeating: "word ", count: 2000)
        let desc = try ReleaseCarves.fitDesc(long) { d in
            try ProtocolFeip.publishCarve(sn: "1", name: "P", type: "FEIP", ver: "1", did: String(repeating: "a", count: 64), desc: d)
        }
        XCTAssertNotNil(desc)
        XCTAssertTrue(desc!.hasSuffix("…"))
        XCTAssertNoThrow(try ProtocolFeip.publishCarve(sn: "1", name: "P", type: "FEIP", ver: "1", did: String(repeating: "a", count: 64), desc: desc))
        XCTAssertThrowsError(try ProtocolFeip.publishCarve(sn: "1", name: "P", type: "FEIP", ver: "1", did: String(repeating: "a", count: 64),
                                                            desc: String(desc!.dropLast()) + "wordy …"))
        XCTAssertEqual(try ReleaseCarves.fitDesc("short") { d in try ProtocolFeip.publishCarve(name: "P", desc: d) }, "short")
    }
}

final class FakeBackend: ReleaseSyncBackend, @unchecked Sendable {
    let lock = NSLock()
    var calls: [String] = []
    var confirmed = Set<String>()
    var counter = 0
    var failCodeCarve = false

    func note(_ s: String) { lock.withLock { calls.append(s) } }
    func nextTxid() -> String { lock.withLock { counter += 1; return String(format: "%064d", counter) } }

    func storeOnDisk(_ file: URL, name: String) async throws { note("disk \(name)") }
    func uploadAsset(_ file: URL, repo: String, tag: String) async throws { note("gh \(file.lastPathComponent)") }
    func carveProtocol(_ c: ProtocolCarve) async throws -> String {
        let t = nextTxid(); note("P \(c.type)\(c.sn) \(c.targetId == nil ? "publish" : "update") \(t.suffix(2))"); return t
    }
    func carveCode(_ c: CodeCarve) async throws -> String {
        if failCodeCarve { throw URLError(.timedOut) }
        let t = nextTxid(); note("C \(c.name) protocols=\((c.protocols ?? []).map { String($0.suffix(2)) })"); return t
    }
    func carveApp(_ c: AppCarve) async throws -> String {
        let t = nextTxid(); note("A \(c.stdName) codes=\((c.codes ?? []).map { String($0.suffix(2)) })"); return t
    }
    func isConfirmed(kind: ReleaseEntityKind, id: String, txid: String) async throws -> Bool {
        lock.withLock { confirmed.insert(txid); return true }
    }
}

final class ReleaseRunnerTests: XCTestCase {
    var t: ReleasePlannerTests!

    override func setUpWithError() throws {
        t = ReleasePlannerTests()
        try t.setUpWithError()
    }

    override func tearDown() { t.tearDown() }

    func makePlan() throws -> ReleasePlan {
        let a = try t.writeDoc(sn: "1"), b = try t.writeDoc(sn: "2")
        let chain = ReleaseChainState(protocols: [t.spec("p2", sn: "2", did: "old")])
        let app = LocalApp(entry: .init(stdName: "Srv", asset: "Srv.jar", codes: ["Lib"], protocols: ["FEIP1"]), tag: "v1",
                           asset: .init(name: "Srv.jar", size: 1, url: "https://x/Srv.jar", digest: nil), did: "d")
        return ReleasePlanner.plan(scans: [t.scan([a, b], codes: [t.code("Lib", did: "z", protocols: ["FEIP1", "FEIP2"])], apps: [app])],
                                   chain: chain, owner: t.owner)
    }

    func allKeys(_ plan: ReleasePlan) -> Set<String> {
        Set(plan.protocols.map { ReleasePlanner.choiceKey(protocol: $0.doc.ref) }
            + plan.codes.map { ReleasePlanner.choiceKey(code: $0.local.entry.name) }
            + plan.apps.map { ReleasePlanner.choiceKey(app: $0.local.entry.stdName) })
    }

    func testOrderIdsAndPidFill() async throws {
        let plan = try makePlan()
        let fake = FakeBackend()
        let log = t.dir.appendingPathComponent("log.json")
        let events = EventBox()
        try await ReleaseRunner(backend: fake, logURL: log).run(plan, selected: allKeys(plan)) { events.add($0) }
        XCTAssertEqual(fake.calls, [
            "disk FEIP1V1_P1.md", "P FEIP1 publish 01",
            "disk FEIP2V1_P2.md", "P FEIP2 update 02",
            "disk Lib-v1.zip", "gh Lib.zip", "C Lib protocols=[\"01\", \"p2\"]",
            "A Srv codes=[\"03\"]",
        ])
        // The update wrote its PID into the document; the publish did not.
        let p2 = try String(contentsOf: t.dir.appendingPathComponent("Protocols/FEIP2V1_P2.md"))
        XCTAssertTrue(p2.contains("|PID|p2|"))
        let p1 = try String(contentsOf: t.dir.appendingPathComponent("Protocols/FEIP1V1_P1.md"))
        XCTAssertTrue(p1.contains("|PID||"))
        XCTAssertTrue(events.all.contains(.pidWritten(file: "Protocols/FEIP2V1_P2.md")))

        // A second run of the same plan carves nothing again.
        let again = FakeBackend()
        let plan2 = ReleasePlanner.plan(scans: [t.scan([try ProtocolDoc.load(url: t.dir.appendingPathComponent("Protocols/FEIP1V1_P1.md"), relativePath: "Protocols/FEIP1V1_P1.md"),
                                                       try ProtocolDoc.load(url: t.dir.appendingPathComponent("Protocols/FEIP2V1_P2.md"), relativePath: "Protocols/FEIP2V1_P2.md")],
                                                      codes: plan.codes.map(\.local), apps: plan.apps.map(\.local))],
                                        chain: ReleaseChainState(protocols: [t.spec("p2", sn: "2", did: "old")]), owner: t.owner)
        try await ReleaseRunner(backend: again, logURL: log).run(plan2, selected: allKeys(plan2)) { _ in }
        XCTAssertEqual(again.calls, [])
    }

    func testAFailedCodeLeavesItsAppUncarved() async throws {
        let plan = try makePlan()
        let fake = FakeBackend()
        fake.failCodeCarve = true
        let events = EventBox()
        try await ReleaseRunner(backend: fake, logURL: t.dir.appendingPathComponent("log.json"))
            .run(plan, selected: allKeys(plan)) { events.add($0) }
        XCTAssertFalse(fake.calls.contains { $0.hasPrefix("A ") })
        XCTAssertTrue(events.all.contains { if case .failed(key: "app:Srv", _) = $0 { return true }; return false })
    }

    func testTheRunPausesAtTheUnconfirmedLimit() async throws {
        let plan = try makePlan()
        let fake = FakeBackend()
        var runner = ReleaseRunner(backend: fake, logURL: t.dir.appendingPathComponent("log.json"))
        runner.maxUnconfirmed = 2
        runner.pollInterval = .milliseconds(1)
        let events = EventBox()
        try await runner.run(plan, selected: allKeys(plan)) { events.add($0) }
        XCTAssertTrue(events.all.contains(.waiting(unconfirmed: 2)))
        XCTAssertEqual(fake.calls.filter { $0.hasPrefix("P ") || $0.hasPrefix("C ") || $0.hasPrefix("A ") }.count, 4)
    }

    /// The code went out in an earlier run and is not parsed yet, so the
    /// plan still says publish; an app carved alone must reference it.
    func testAnAppReferencesACodeCarvedInAnEarlierRun() async throws {
        let plan = try makePlan()
        let log = t.dir.appendingPathComponent("log.json")
        let first = FakeBackend()
        try await ReleaseRunner(backend: first, logURL: log)
            .run(plan, selected: ["protocol:FEIP1", "code:Lib"]) { _ in }
        XCTAssertEqual(first.calls.last, "C Lib protocols=[\"01\", \"p2\"]")

        let second = FakeBackend()
        second.counter = 10
        let events = EventBox()
        try await ReleaseRunner(backend: second, logURL: log).run(plan, selected: ["app:Srv"]) { events.add($0) }
        XCTAssertEqual(second.calls, ["A Srv codes=[\"02\"]"], "the logged codeId, not a failure")
    }

    /// A manifest on disk for the plan's repo, so write-back has a file.
    func writeManifest() throws {
        let m = ReleaseManifest(github: "o/R", codes: [.init(name: "Lib", path: "Lib", langs: ["Java"], desc: "lib", protocols: ["FEIP1", "FEIP2"])],
                                apps: [.init(stdName: "Srv", asset: "Srv.jar", desc: "server", codes: ["Lib"], protocols: ["FEIP1"])])
        try JSONEncoder().encode(m).write(to: t.dir.appendingPathComponent(ReleaseManifest.fileName))
    }

    func makeReviewedPlan() throws -> ReleasePlan {
        try writeManifest()
        let a = try t.writeDoc(sn: "1"), b = try t.writeDoc(sn: "2")
        let manifest = try ReleaseManifest.load(repo: t.dir)
        let code = LocalCode(entry: manifest.codes![0], tag: "v1", zipURL: t.dir.appendingPathComponent("Lib.zip"),
                             assetName: "Lib-v1.zip", did: "z", fileCount: 1, byteCount: 1)
        let app = LocalApp(entry: manifest.apps![0], tag: "v1",
                           asset: .init(name: "Srv.jar", size: 1, url: "https://x/Srv.jar", digest: nil), did: "d")
        let scan = RepoScan(root: t.dir, manifest: manifest, tag: "v1", branch: "main", protocols: [a, b], codes: [code], apps: [app])
        return ReleasePlanner.plan(scans: [scan], chain: ReleaseChainState(protocols: [t.spec("p2", sn: "2", did: "old")]), owner: t.owner)
    }

    func testReviewSkipsBeforeAnythingIsWrittenOrUploaded() async throws {
        let plan = try makeReviewedPlan()
        let fake = FakeBackend()
        var runner = ReleaseRunner(backend: fake, logURL: t.dir.appendingPathComponent("log.json"))
        runner.reviewer = Reviewer { draft in
            if case .protocol(let p) = draft, p.sn == "2" { return nil }   // skip the update
            return draft
        }
        let events = EventBox()
        try await runner.run(plan, selected: allKeys(plan)) { events.add($0) }
        XCTAssertFalse(fake.calls.contains("disk FEIP2V1_P2.md"), "nothing stored for a skipped record")
        XCTAssertFalse(fake.calls.contains { $0.hasPrefix("P FEIP2") })
        let p2 = try String(contentsOf: t.dir.appendingPathComponent("Protocols/FEIP2V1_P2.md"))
        XCTAssertTrue(p2.contains("|PID||"), "no PID written for a skipped update")
        XCTAssertTrue(events.all.contains(.skipped(key: "protocol:FEIP2", "skipped in review")))
        // Skipping an update leaves the record as it was, so the code still links its pid.
        XCTAssertTrue(fake.calls.contains("C Lib protocols=[\"01\", \"p2\"]"), "\(fake.calls)")
    }

    func testReviewEditsAreCarvedAndWrittenBackToTheManifest() async throws {
        let plan = try makeReviewedPlan()
        let fake = FakeBackend()
        var runner = ReleaseRunner(backend: fake, logURL: t.dir.appendingPathComponent("log.json"))
        let extra = String(repeating: "e", count: 64)
        runner.reviewer = Reviewer { draft in
            switch draft {
            case .code(var c):
                c.desc = "edited lib"
                c.protocols = (c.protocols ?? []) + [extra]
                return .code(c)
            case .app(var a):
                a.types = ["server", "tool"]
                return .app(a)
            default:
                return draft
            }
        }
        let events = EventBox()
        try await runner.run(plan, selected: allKeys(plan)) { events.add($0) }
        XCTAssertTrue(fake.calls.contains { $0.hasPrefix("C Lib") && $0.contains("\"ee\"") }, "\(fake.calls)")

        let m = try ReleaseManifest.load(repo: t.dir)
        XCTAssertEqual(m.codes?[0].desc, "edited lib")
        XCTAssertEqual(m.codes?[0].protocols, ["FEIP1", "FEIP2", extra], "offered links keep their names; the new one is raw")
        XCTAssertEqual(m.codes?[0].langs, ["Java"], "untouched fields stay")
        XCTAssertEqual(m.apps?[0].types, ["server", "tool"])
        XCTAssertEqual(m.apps?[0].desc, "server")
        XCTAssertEqual(events.all.filter { if case .manifestUpdated = $0 { return true }; return false }.count, 2)
    }

    func testStoppingInReviewStopsTheRun() async throws {
        let plan = try makeReviewedPlan()
        let fake = FakeBackend()
        var runner = ReleaseRunner(backend: fake, logURL: t.dir.appendingPathComponent("log.json"))
        runner.reviewer = Reviewer { _ in throw CancellationError() }
        do {
            try await runner.run(plan, selected: allKeys(plan)) { _ in }
            XCTFail("expected the run to stop")
        } catch is CancellationError {}
        XCTAssertEqual(fake.calls, [])
    }

    func testUnselectedItemsAreLeftAlone() async throws {
        let plan = try makePlan()
        let fake = FakeBackend()
        try await ReleaseRunner(backend: fake, logURL: t.dir.appendingPathComponent("log.json"))
            .run(plan, selected: ["protocol:FEIP2"]) { _ in }
        XCTAssertEqual(fake.calls, ["disk FEIP2V1_P2.md", "P FEIP2 update 01"])
    }
}

struct Reviewer: ReleaseReviewer {
    let decide: @Sendable (ReleaseDraft) async throws -> ReleaseDraft?
    func review(_ draft: ReleaseDraft) async throws -> ReleaseDraft? { try await decide(draft) }
}

final class EventBox: @unchecked Sendable {
    private let lock = NSLock()
    private var events: [ReleaseRunEvent] = []
    func add(_ e: ReleaseRunEvent) { lock.withLock { events.append(e) } }
    var all: [ReleaseRunEvent] { lock.withLock { events } }
}

