import XCTest
import FCCore
import FCTransport
import FCStorage
@testable import FCDomain

/// ``SshServersStore`` and the session accessors beside it.
final class SshServersStoreTests: XCTestCase {

    private var baseDir: URL!
    private var manager: ConfigureManager!
    private var configure: ConfigureSession!
    private var session: ActiveSession!

    private let alice = Data(repeating: 0xA1, count: 32)

    override func setUpWithError() throws {
        baseDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("SshServersStoreTests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: baseDir, withIntermediateDirectories: true)

        manager = try ConfigureManager(baseDirectory: baseDir)
        configure = try manager.createConfigure(password: Data("pwd".utf8), kdfKind: .legacySha256)
        let info = try configure.addMain(privkey: alice, label: "A")
        session = try configure.unlockMain(fid: info.fid, fapi: MockFapiClient())
    }

    override func tearDownWithError() throws {
        session = nil
        configure = nil
        manager = nil
        try? FileManager.default.removeItem(at: baseDir)
    }

    private func makeServer(label: String = "", host: String = "vps01.example.com", user: String = "root", port: Int = 22) -> SshServer {
        SshServer(label: label, host: host, port: port, user: user)
    }

    // MARK: - Round trip

    func testUpsertAndGet() throws {
        let store = session.sshServers
        let server = makeServer(label: "vps01")
        try store.upsert(server)

        let loaded = try XCTUnwrap(try store.get(id: server.id))
        XCTAssertEqual(loaded.host, "vps01.example.com")
        XCTAssertEqual(loaded.user, "root")
        XCTAssertEqual(loaded.port, 22)
        XCTAssertEqual(loaded.label, "vps01")
    }

    func testRemove() throws {
        let store = session.sshServers
        let server = makeServer()
        try store.upsert(server)
        XCTAssertTrue(try store.remove(id: server.id))
        XCTAssertNil(try store.get(id: server.id))
        XCTAssertFalse(try store.remove(id: server.id), "removing twice is not an error")
    }

    /// The reason the key is a UUID: the same machine, twice, on
    /// purpose.
    func testTwoEntriesMayShareOneMachine() throws {
        let store = session.sshServers
        try store.upsert(makeServer(label: "as root", user: "root"))
        try store.upsert(makeServer(label: "as deploy", user: "deploy"))
        XCTAssertEqual(try store.all().count, 2)
    }

    // MARK: - Validation

    func testBlankHostAndUserAreRejected() {
        let store = session.sshServers
        XCTAssertThrowsError(try store.upsert(makeServer(host: "   "))) {
            guard case SshServersStore.Failure.emptyHost = $0 else { return XCTFail("got \($0)") }
        }
        XCTAssertThrowsError(try store.upsert(makeServer(user: ""))) {
            guard case SshServersStore.Failure.emptyUser = $0 else { return XCTFail("got \($0)") }
        }
    }

    func testPortRangeIsEnforced() {
        let store = session.sshServers
        for bad in [0, -1, 65536, 99999] {
            XCTAssertThrowsError(try store.upsert(makeServer(port: bad)), "port \(bad) should be rejected") {
                guard case SshServersStore.Failure.badPort = $0 else { return XCTFail("got \($0)") }
            }
        }
        XCTAssertNoThrow(try store.upsert(makeServer(port: 1)))
        XCTAssertNoThrow(try store.upsert(makeServer(port: 65535)))
    }

    func testSurroundingWhitespaceIsTrimmed() throws {
        let store = session.sshServers
        let server = SshServer(label: "  box  ", host: "  h.example.com ", user: " root ")
        try store.upsert(server)
        let loaded = try XCTUnwrap(try store.get(id: server.id))
        XCTAssertEqual(loaded.host, "h.example.com")
        XCTAssertEqual(loaded.user, "root")
        XCTAssertEqual(loaded.label, "box")
    }

    // MARK: - Sorting

    func testAllSortsPinnedThenRecentThenName() throws {
        let store = session.sshServers
        let never = makeServer(label: "aaa-never")
        let older = makeServer(label: "bbb-older")
        let newer = makeServer(label: "ccc-newer")
        let pinned = makeServer(label: "zzz-pinned")
        for s in [never, older, newer, pinned] { try store.upsert(s) }

        try store.touchLastUsed(id: older.id)
        try store.touchLastUsed(id: newer.id)   // later than older
        _ = try store.togglePin(id: pinned.id)

        let order = try store.all().map(\.label)
        XCTAssertEqual(order, ["zzz-pinned", "ccc-newer", "bbb-older", "aaa-never"])
    }

    func testTouchLastUsedOnAMissingIdIsANoOp() throws {
        XCTAssertNoThrow(try session.sshServers.touchLastUsed(id: "nope"))
    }

    // MARK: - Naming

    func testNameFallsBackToTargetAndPortIsElidedWhenDefault() {
        XCTAssertEqual(makeServer().name, "root@vps01.example.com")
        XCTAssertEqual(makeServer(port: 2222).name, "root@vps01.example.com:2222")
        XCTAssertEqual(makeServer(label: "prod").name, "prod")
    }

    // MARK: - The session accessor

    /// The SSH key follows the main FID, so it must not change when the
    /// live identity does — that is what lets the pane stay open for a
    /// watch-only identity.
    func testSshIdentityIsStableAcrossLiveIdentitySwitches() throws {
        let before = try session.sshIdentity().authorizedKeysLine()

        let watched = try FchAddress(publicKey: Secp256k1.publicKey(fromPrivateKey: Data(repeating: 0xB2, count: 32))).fid
        try session.addWatchedFid(watched, label: "watch")
        try session.switchLive(fid: watched)
        XCTAssertFalse(session.canSign, "the live identity is watch-only")

        XCTAssertEqual(try session.sshIdentity().authorizedKeysLine(), before)
    }

    func testSshIdentityMatchesDerivingFromTheMainKeyDirectly() throws {
        let direct = try SshEd25519Key(mainPrikey: alice, mainFid: session.mainFid)
        XCTAssertEqual(try session.sshIdentity().publicKeyBlob, direct.publicKeyBlob)
    }
}
