import XCTest
import Darwin
import FCCore
@testable import FCDomain

/// ``SshAgentServer`` against the only client whose opinion matters:
/// OpenSSH's own `ssh-add`.
///
/// The protocol tests next door assert our bytes are what the RFC says.
/// These assert that a real OpenSSH build agrees — which is a different
/// claim, and the one that decides whether the feature works.
final class SshAgentServerTests: XCTestCase {

    private var key: SshEd25519Key!
    private var agent: SshAgentServer!
    private let comment = "freer:FEk41Kqjar45fLDriztUDTUkdki7mmcjWK"

    override func setUpWithError() throws {
        key = try SshEd25519Key(
            mainPrikey: Data(repeating: 0x42, count: 32),
            mainFid: "FEk41Kqjar45fLDriztUDTUkdki7mmcjWK"
        )
        agent = try SshAgentServer(key: key, comment: comment)
    }

    override func tearDown() {
        agent?.stop()
        agent = nil
    }

    // MARK: - Paths

    /// `sun_path` is 104 bytes on Darwin. The margin is the whole
    /// reason the socket does not live in Application Support.
    func testSocketPathFitsSunPathWithRoomToSpare() {
        XCTAssertLessThan(agent.socketPath.utf8.count, 104)
        XCTAssertFalse(agent.socketPath.contains(" "), "a space would need quoting through -o IdentityAgent=")
    }

    // MARK: - Lifecycle

    func testStartCreatesAPrivateDirectoryAndA0600Socket() throws {
        try agent.start()
        XCTAssertTrue(agent.isRunning)

        var dir = stat()
        XCTAssertEqual(stat(agent.runtimeDirectory, &dir), 0)
        XCTAssertEqual(dir.st_mode & 0o777, 0o700, "the parent directory is the real boundary")
        XCTAssertEqual(dir.st_uid, getuid())

        var sock = stat()
        XCTAssertEqual(stat(agent.socketPath, &sock), 0)
        XCTAssertEqual(sock.st_mode & 0o777, 0o600)

        // The public key is on disk; the private key is not, anywhere.
        let pub = try String(contentsOfFile: agent.publicKeyPath, encoding: .utf8)
        XCTAssertEqual(pub, key.publicKeyFileContents(comment: comment))
        XCTAssertTrue(pub.hasSuffix("\n"), "ssh-keygen expects a trailing newline")
    }

    func testStartIsIdempotent() throws {
        try agent.start()
        XCTAssertNoThrow(try agent.start())
        XCTAssertTrue(agent.isRunning)
    }

    /// Vault lock calls this, so it is the security boundary: after it
    /// returns, nothing can ask the key for a signature.
    func testStopRemovesEverythingAndRefusesRestart() throws {
        try agent.start()
        let socketPath = agent.socketPath
        let dir = agent.runtimeDirectory

        agent.stop()
        XCTAssertFalse(agent.isRunning)

        var st = stat()
        XCTAssertNotEqual(stat(socketPath, &st), 0, "the socket must be unlinked")
        XCTAssertNotEqual(stat(dir, &st), 0, "the runtime directory must be gone")
        XCTAssertFalse(connectSucceeds(to: socketPath), "nothing may connect after stop")

        XCTAssertThrowsError(try agent.start()) {
            guard case SshAgentServer.Failure.alreadyStopped = $0 else {
                return XCTFail("expected .alreadyStopped, got \($0)")
            }
        }
    }

    func testStopIsIdempotent() throws {
        try agent.start()
        agent.stop()
        agent.stop()
    }

    // MARK: - Against real OpenSSH

    /// The cross-check: `ssh-add -l` speaks the agent protocol and
    /// prints the fingerprint it was told about. If this passes, our
    /// framing, our identities answer and our key blob are all correct
    /// by OpenSSH's own reckoning.
    func testSshAddListsOurKeyWithTheRightFingerprint() throws {
        try XCTSkipUnless(FileManager.default.isExecutableFile(atPath: "/usr/bin/ssh-add"))
        try agent.start()

        let (status, output) = run("/usr/bin/ssh-add", ["-l"], socket: agent.socketPath)
        XCTAssertEqual(status, 0, "ssh-add could not talk to the agent: \(output)")
        XCTAssertTrue(output.contains(key.fingerprint), "expected \(key.fingerprint) in: \(output)")
        XCTAssertTrue(output.contains(comment), "expected the comment in: \(output)")
        XCTAssertTrue(output.contains("ED25519"), "expected the key type in: \(output)")
    }

    /// `ssh-add -L` prints the full `authorized_keys` line — the same
    /// text the pane offers to copy. This proves the two agree.
    func testSshAddPrintsTheSameAuthorizedKeysLineThePaneShows() throws {
        try XCTSkipUnless(FileManager.default.isExecutableFile(atPath: "/usr/bin/ssh-add"))
        try agent.start()

        let (status, output) = run("/usr/bin/ssh-add", ["-L"], socket: agent.socketPath)
        XCTAssertEqual(status, 0, output)
        XCTAssertEqual(output.trimmingCharacters(in: .whitespacesAndNewlines), key.authorizedKeysLine())
    }

    /// The agent must refuse to forget its key. `ssh-add -D` asks it to.
    func testSshAddCannotDeleteTheKey() throws {
        try XCTSkipUnless(FileManager.default.isExecutableFile(atPath: "/usr/bin/ssh-add"))
        try agent.start()

        let (status, _) = run("/usr/bin/ssh-add", ["-D"], socket: agent.socketPath)
        XCTAssertNotEqual(status, 0, "REMOVE_ALL_IDENTITIES must be refused")

        let (after, output) = run("/usr/bin/ssh-add", ["-l"], socket: agent.socketPath)
        XCTAssertEqual(after, 0)
        XCTAssertTrue(output.contains(key.fingerprint), "the key must survive the attempt")
    }

    /// Several `ssh` processes share one agent; one must not disturb
    /// another, and the connection cap must not deadlock.
    func testConcurrentClientsAllGetAnswers() throws {
        try XCTSkipUnless(FileManager.default.isExecutableFile(atPath: "/usr/bin/ssh-add"))
        try agent.start()

        let group = DispatchGroup()
        let lock = NSLock()
        var failures: [String] = []
        for _ in 0 ..< 12 {
            group.enter()
            DispatchQueue.global().async {
                defer { group.leave() }
                let (status, output) = self.run("/usr/bin/ssh-add", ["-l"], socket: self.agent.socketPath)
                if status != 0 || !output.contains(self.key.fingerprint) {
                    lock.lock(); failures.append("status \(status): \(output)"); lock.unlock()
                }
            }
        }
        XCTAssertEqual(group.wait(timeout: .now() + 60), .success, "clients did not finish")
        XCTAssertEqual(failures, [])
    }

    // MARK: - Helpers

    private func run(_ path: String, _ args: [String], socket: String) -> (Int32, String) {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: path)
        process.arguments = args
        var env = ProcessInfo.processInfo.environment
        env["SSH_AUTH_SOCK"] = socket
        // Keep ssh-add from trying to prompt for anything.
        env.removeValue(forKey: "DISPLAY")
        env.removeValue(forKey: "SSH_ASKPASS")
        process.environment = env

        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        do { try process.run() } catch { return (-1, "could not run \(path): \(error)") }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        return (process.terminationStatus, String(data: data, encoding: .utf8) ?? "")
    }

    private func connectSucceeds(to path: String) -> Bool {
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { return false }
        defer { close(fd) }

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        addr.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        let bytes = Array(path.utf8)
        guard bytes.count < MemoryLayout.size(ofValue: addr.sun_path) else { return false }
        withUnsafeMutableBytes(of: &addr.sun_path) { raw in
            raw.copyBytes(from: bytes)
            raw[bytes.count] = 0
        }
        let size = socklen_t(MemoryLayout<sockaddr_un>.size)
        return withUnsafePointer(to: &addr) { p in
            p.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(fd, $0, size) } == 0
        }
    }
}

/// The agent must clean up after itself even when nobody calls
/// `stop()`. A cancel handler that captured `self` would be a retain
/// cycle through the dispatch source, `deinit` would never run, and the
/// socket plus its directory would be left behind for the life of the
/// process.
final class SshAgentServerDeinitTests: XCTestCase {

    func testDroppingTheAgentWithoutStoppingItStillUnlinksEverything() throws {
        let key = try SshEd25519Key(
            mainPrikey: Data(repeating: 0x42, count: 32),
            mainFid: "FEk41Kqjar45fLDriztUDTUkdki7mmcjWK"
        )

        var paths: (dir: String, sock: String) = ("", "")
        try autoreleasepool {
            let agent = try SshAgentServer(key: key, comment: "freer:deinit")
            try agent.start()
            paths = (agent.runtimeDirectory, agent.socketPath)

            var st = stat()
            XCTAssertEqual(stat(paths.sock, &st), 0, "precondition: the socket exists")
            // No stop() — just let the last reference go.
        }

        var st = stat()
        XCTAssertNotEqual(stat(paths.sock, &st), 0, "deinit must unlink the socket")
        XCTAssertNotEqual(stat(paths.dir, &st), 0, "deinit must remove the runtime directory")
    }
}
