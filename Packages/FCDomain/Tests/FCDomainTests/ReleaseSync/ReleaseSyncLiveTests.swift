import XCTest
import FCCore
import FCTransport
@testable import FCDomain

/// Reads a FID's registry records from a real FAPI server. Runs only when
/// RELEASE_SYNC_FAPI names a server, e.g.
/// `RELEASE_SYNC_FAPI=fudp://fapi.cid.cash:8500 RELEASE_SYNC_OWNER=FEk41…`.
final class ReleaseSyncLiveTests: XCTestCase {

    private func connect(_ url: String) async throws -> (FudpClient, FapiClient) {
        guard let endpoint = FudpUrl.hostPort(url) else { throw URLError(.badURL) }
        let peer = try await FudpDiscovery.discoverPubkey(host: endpoint.host, port: endpoint.port)
        var priv = Data(count: 32)
        for i in 0..<32 { priv[i] = UInt8.random(in: 1...255) }
        let fudp = try await FudpClient(host: endpoint.host, port: endpoint.port, peerPubkey: peer, localPrivkey: priv)
        return (fudp, FapiClient(fudp: fudp))
    }

    /// `RELEASE_SYNC_IDS=pid1,pid2` prints who owns those protocols.
    func testLookUpProtocolIds() async throws {
        let env = ProcessInfo.processInfo.environment
        guard let url = env["RELEASE_SYNC_FAPI"], let ids = env["RELEASE_SYNC_IDS"] else {
            throw XCTSkip("set RELEASE_SYNC_FAPI and RELEASE_SYNC_IDS to run")
        }
        let (fudp, fapi) = try await connect(url)
        defer { fudp.close() }
        let found = try await ProtocolService(fapi: fapi).fetchProtocolsByIds(ids.split(separator: ",").map(String.init))
        for (id, p) in found { print("ID", id, p.owner ?? "-", p.type ?? "-", p.sn ?? "-", p.ver ?? "-", p.name ?? "-") }
    }

    func testDumpOwnedRecords() async throws {
        let env = ProcessInfo.processInfo.environment
        guard let url = env["RELEASE_SYNC_FAPI"], let owner = env["RELEASE_SYNC_OWNER"] else {
            throw XCTSkip("set RELEASE_SYNC_FAPI and RELEASE_SYNC_OWNER to run")
        }
        let (fudp, fapi) = try await connect(url)
        defer { fudp.close() }

        let chain = try await ReleaseChainState.fetch(owner: owner, fapi: fapi)
        for p in chain.protocols.sorted(by: { ($0.type ?? "", Int($0.sn ?? "") ?? 0) < ($1.type ?? "", Int($1.sn ?? "") ?? 0) }) {
            print(["P", p.id, p.type ?? "-", p.sn ?? "-", p.ver ?? "-", p.name ?? "-", p.did ?? "-",
                   p.active == false ? "stopped" : "", p.closed == true ? "closed" : ""].joined(separator: "|"))
        }
        for c in chain.codes { print(["C", c.id, c.name ?? "-", c.ver ?? "-", c.did ?? "-"].joined(separator: "|")) }
        for a in chain.apps {
            let downloads = (a.downloads ?? []).map { "\($0.os ?? "-")=\($0.link ?? "-")" }.joined(separator: ",")
            print(["A", a.id, a.stdName ?? "-", a.ver ?? "-", downloads].joined(separator: "|"))
        }
    }

    /// Parity with the retired Java tool: for every document whose DID
    /// is on chain unchanged, the fields this port extracts must equal
    /// what was carved. `RELEASE_SYNC_REPO` is a Freeverse clone.
    func testParsingMatchesWhatWasCarved() async throws {
        let env = ProcessInfo.processInfo.environment
        guard let url = env["RELEASE_SYNC_FAPI"], let owner = env["RELEASE_SYNC_OWNER"],
              let repo = env["RELEASE_SYNC_REPO"] else {
            throw XCTSkip("set RELEASE_SYNC_FAPI, RELEASE_SYNC_OWNER and RELEASE_SYNC_REPO to run")
        }
        let (fudp, fapi) = try await connect(url)
        defer { fudp.close() }
        let chain = try await ReleaseChainState.fetch(owner: owner, fapi: fapi)
        let byDid = Dictionary(chain.protocols.compactMap { p in p.did.map { ($0, p) } }, uniquingKeysWith: { a, _ in a })
        let (docs, problems) = ReleaseScanner.protocolDocs(root: URL(fileURLWithPath: repo), dirs: ["Protocols"])
        problems.forEach { print("PROBLEM", $0) }
        var compared = 0
        var descDiffers: [String] = []
        for doc in docs {
            guard let p = byDid[doc.did] else { continue }
            compared += 1
            XCTAssertEqual(doc.name, p.name, doc.relativePath)
            XCTAssertEqual(doc.type, p.type, doc.relativePath)
            XCTAssertEqual(doc.sn, p.sn, doc.relativePath)
            XCTAssertEqual(doc.ver, p.ver, doc.relativePath)
            // Some descriptions were edited by hand at carve time (the
            // FTSP crypto profiles); report them rather than fail.
            if doc.desc != p.desc { descDiffers.append(doc.relativePath) }
            XCTAssertEqual(doc.lang, p.lang ?? "en", doc.relativePath)
        }
        print("compared \(compared) of \(docs.count) documents; desc differs for \(descDiffers.sorted())")
        XCTAssertGreaterThan(compared, 0)
    }

    /// Scans real repos and plans against the chain; carves nothing.
    /// `RELEASE_SYNC_REPOS=/path/a=v1,/path/b=v2`.
    func testDryRunPlan() async throws {
        let env = ProcessInfo.processInfo.environment
        guard let url = env["RELEASE_SYNC_FAPI"], let owner = env["RELEASE_SYNC_OWNER"],
              let repos = env["RELEASE_SYNC_REPOS"] else {
            throw XCTSkip("set RELEASE_SYNC_FAPI, RELEASE_SYNC_OWNER and RELEASE_SYNC_REPOS to run")
        }
        let (fudp, fapi) = try await connect(url)
        defer { fudp.close() }
        let chain = try await ReleaseChainState.fetch(owner: owner, fapi: fapi)
        let work = FileManager.default.temporaryDirectory.appendingPathComponent("rs-dry")
        let scanner = ReleaseScanner(workDir: work)
        var scans: [RepoScan] = []
        for pair in repos.split(separator: ",") {
            let parts = pair.split(separator: "=", maxSplits: 1).map(String.init)
            scans.append(try await scanner.scan(root: URL(fileURLWithPath: parts[0]), tag: parts.count > 1 ? parts[1] : nil))
        }
        let plan = ReleasePlanner.plan(scans: scans, chain: chain, owner: owner)
        func line(_ kind: String, _ key: String, _ action: ReleaseAction, _ json: () throws -> String) {
            var size = ""
            if action.carves {
                do { size = "\(try json().utf8.count)B" } catch { size = "ERROR \(error)" }
            }
            print("PLAN", kind, key, action, size)
        }
        for p in plan.protocols { line("protocol", "\(p.doc.ref)V\(p.doc.ver)", p.action) { try ReleaseCarves.protocolCarve(p).json() } }
        for c in plan.codes {
            print("CODE", c.local.entry.name, c.local.fileCount, "files", c.local.byteCount, "bytes", c.local.did.prefix(12))
            line("code", c.local.entry.name, c.action) { try ReleaseCarves.codeCarve(c, ids: nil).json() }
        }
        for a in plan.apps { line("app", a.local.entry.stdName, a.action) { try ReleaseCarves.appCarve(a, ids: nil).json() } }
        plan.problems.forEach { print("PROBLEM", $0) }
        print("ORPHANS", plan.orphanProtocols.count, plan.orphanCodes.count, plan.orphanApps.map { $0.stdName ?? "" })
        print("CARVES", plan.carveCount)
    }
}
