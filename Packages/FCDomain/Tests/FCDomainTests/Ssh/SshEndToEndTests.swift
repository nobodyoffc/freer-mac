import XCTest
import Darwin
import FCCore
@testable import FCDomain

/// The whole path, against a real `sshd`: derive the key, publish it in
/// an `authorized_keys` file, run the real `/usr/bin/ssh` with the real
/// argument vector, and log in with nothing on disk but a `.pub`.
///
/// **Opt-in.** Set `FREER_SSH_E2E=1` to run it. It binds a port, spawns
/// `sshd`, and takes a second or two — none of which belongs in the
/// default suite — but it is the only test that proves the feature
/// rather than its parts. The unit tests next door check that our bytes
/// match the RFC and that `ssh-add` accepts them; this one checks that
/// `ssh` itself authenticates.
final class SshEndToEndTests: XCTestCase {

    private var dir: URL!
    private var sshd: Process?

    override func setUpWithError() throws {
        try XCTSkipUnless(
            ProcessInfo.processInfo.environment["FREER_SSH_E2E"] == "1",
            "set FREER_SSH_E2E=1 to run the end-to-end ssh test"
        )
        try XCTSkipUnless(FileManager.default.isExecutableFile(atPath: "/usr/sbin/sshd"))
        try XCTSkipUnless(FileManager.default.isExecutableFile(atPath: "/usr/bin/ssh-keygen"))

        dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("fc-ssh-e2e-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    }

    override func tearDown() {
        sshd?.terminate()
        sshd?.waitUntilExit()
        sshd = nil
        if let dir { try? FileManager.default.removeItem(at: dir) }
    }

    func testRealSshAuthenticatesThroughOurAgentWithNoPrivateKeyOnDisk() throws {
        let key = try SshEd25519Key(
            mainPrikey: Data(repeating: 0x42, count: 32),
            mainFid: "FEk41Kqjar45fLDriztUDTUkdki7mmcjWK"
        )

        // The server trusts exactly the line the pane offers to copy.
        let authorized = dir.appendingPathComponent("authorized_keys")
        try key.publicKeyFileContents().write(to: authorized, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: authorized.path)

        let port = try freePort()
        try startSshd(port: port, authorizedKeys: authorized)

        let agent = try SshAgentServer(key: key, comment: "freer:e2e")
        defer { agent.stop() }
        try agent.start()

        let server = SshServer(host: "127.0.0.1", port: port, user: NSUserName())
        let credential = SshLaunch.Credential.freerAgent(
            publicKeyPath: agent.publicKeyPath,
            socketPath: agent.socketPath
        )
        var args = SshLaunch.arguments(for: server, credential: credential)
        // Test-only: there is no known_hosts to consult and no TTY to
        // answer the fingerprint prompt on. The app deliberately leaves
        // both at their defaults.
        args.insert(contentsOf: [
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "StrictHostKeyChecking=no",
            "-o", "BatchMode=yes"
        ], at: 0)
        args.append("echo FREER_SSH_OK")

        let (status, output) = run(
            "/usr/bin/ssh",
            args,
            environment: SshLaunch.environment(credential: credential)
        )

        XCTAssertEqual(status, 0, "ssh failed:\n\(output)\n\nsshd log:\n\(sshdLog())")
        XCTAssertTrue(output.contains("FREER_SSH_OK"), "expected the remote command's output, got:\n\(output)")

        // The promise: the only key material on disk is public.
        let pub = try String(contentsOfFile: agent.publicKeyPath, encoding: .utf8)
        XCTAssertEqual(pub, key.publicKeyFileContents(comment: "freer:e2e"))
        let contents = try FileManager.default.contentsOfDirectory(atPath: agent.runtimeDirectory)
        XCTAssertEqual(Set(contents), ["agent.sock", "id_ed25519.pub"], "nothing else may be written")
    }

    /// The negative control. Without the agent there is no private key
    /// anywhere, so the same command must fail — otherwise the test
    /// above could be passing on some other credential entirely.
    func testWithoutTheAgentTheSameCommandIsRejected() throws {
        let key = try SshEd25519Key(
            mainPrikey: Data(repeating: 0x42, count: 32),
            mainFid: "FEk41Kqjar45fLDriztUDTUkdki7mmcjWK"
        )
        let authorized = dir.appendingPathComponent("authorized_keys")
        try key.publicKeyFileContents().write(to: authorized, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: authorized.path)

        let port = try freePort()
        try startSshd(port: port, authorizedKeys: authorized)

        let agent = try SshAgentServer(key: key, comment: "freer:e2e")
        try agent.start()
        let pubPath = agent.publicKeyPath
        let sockPath = agent.socketPath
        // Keep the .pub, take the agent away — exactly what vault lock
        // does to a session that has not reconnected yet.
        let pubCopy = dir.appendingPathComponent("id_ed25519.pub")
        try FileManager.default.copyItem(atPath: pubPath, toPath: pubCopy.path)
        agent.stop()

        let server = SshServer(host: "127.0.0.1", port: port, user: NSUserName())
        let credential = SshLaunch.Credential.freerAgent(publicKeyPath: pubCopy.path, socketPath: sockPath)
        var args = SshLaunch.arguments(for: server, credential: credential)
        args.insert(contentsOf: [
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "StrictHostKeyChecking=no",
            "-o", "BatchMode=yes"
        ], at: 0)
        args.append("echo FREER_SSH_OK")

        let (status, output) = run(
            "/usr/bin/ssh",
            args,
            environment: SshLaunch.environment(credential: credential)
        )
        XCTAssertNotEqual(status, 0, "authentication must fail once the agent is gone")
        XCTAssertFalse(output.contains("FREER_SSH_OK"))
    }

    // MARK: - scp, sftp and tunnels

    /// Test-only: no known_hosts to consult and no TTY for the
    /// fingerprint prompt. `scp` and `sftp` take `-o` like `ssh` does.
    private let testOnlyOptions = [
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "StrictHostKeyChecking=no",
        "-o", "BatchMode=yes"
    ]

    private struct Rig {
        let server: SshServer
        let credential: SshLaunch.Credential
        let agent: SshAgentServer
        /// Where the SFTP subsystem starts, so an upload to the "home
        /// directory" lands in the scratch dir and never in the real one.
        let landing: URL
    }

    private func startRig() throws -> Rig {
        let key = try SshEd25519Key(
            mainPrikey: Data(repeating: 0x42, count: 32),
            mainFid: "FEk41Kqjar45fLDriztUDTUkdki7mmcjWK"
        )
        let authorized = dir.appendingPathComponent("authorized_keys")
        try key.publicKeyFileContents().write(to: authorized, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: authorized.path)

        let landing = dir.appendingPathComponent("landing")
        try FileManager.default.createDirectory(at: landing, withIntermediateDirectories: true)

        let port = try freePort()
        try startSshd(port: port, authorizedKeys: authorized, sftpStartDirectory: landing)

        let agent = try SshAgentServer(key: key, comment: "freer:e2e")
        try agent.start()
        return Rig(
            server: SshServer(host: "127.0.0.1", port: port, user: NSUserName()),
            credential: .freerAgent(publicKeyPath: agent.publicKeyPath, socketPath: agent.socketPath),
            agent: agent,
            landing: landing
        )
    }

    /// The app's own `scp` vector — `-P`, `-r`, `--`, the empty remote
    /// path — through the agent, with a file whose name has a space and
    /// a folder with something in it.
    func testUploadThroughTheAgentLandsInTheRemoteHome() throws {
        let rig = try startRig()
        defer { rig.agent.stop() }

        let tag = UUID().uuidString.prefix(8)
        let file = dir.appendingPathComponent("fc e2e \(tag).txt")
        try "one".write(to: file, atomically: true, encoding: .utf8)
        let folder = dir.appendingPathComponent("fc-e2e-folder-\(tag)")
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        try "two".write(to: folder.appendingPathComponent("inner.txt"), atomically: true, encoding: .utf8)

        let inv = try SshLaunch.invocation(
            .upload(localPaths: [file.path, folder.path]),
            server: rig.server,
            credential: rig.credential
        )
        let (status, output) = run(inv.executable, testOnlyOptions + inv.arguments,
                                   environment: SshLaunch.environment(credential: rig.credential))

        XCTAssertEqual(status, 0, "scp failed:\n\(output)\n\nsshd log:\n\(sshdLog())")
        XCTAssertEqual(try? String(contentsOf: rig.landing.appendingPathComponent(file.lastPathComponent), encoding: .utf8), "one")
        XCTAssertEqual(
            try? String(contentsOf: rig.landing.appendingPathComponent("\(folder.lastPathComponent)/inner.txt"), encoding: .utf8),
            "two"
        )
    }

    /// A chosen folder: into it when it exists, with a space in its
    /// name — and a failure, not a file renamed to the folder's name,
    /// when it does not.
    func testUploadIntoAChosenFolder() throws {
        let rig = try startRig()
        defer { rig.agent.stop() }

        let file = dir.appendingPathComponent("fc-e2e-\(UUID().uuidString.prefix(8)).txt")
        try "three".write(to: file, atomically: true, encoding: .utf8)
        let sub = rig.landing.appendingPathComponent("sub dir")
        try FileManager.default.createDirectory(at: sub, withIntermediateDirectories: true)
        let env = SshLaunch.environment(credential: rig.credential)

        let into = try SshLaunch.invocation(
            .upload(localPaths: [file.path], remoteDirectory: "sub dir"),
            server: rig.server,
            credential: rig.credential
        )
        let (status, output) = run(into.executable, testOnlyOptions + into.arguments, environment: env)
        XCTAssertEqual(status, 0, "scp failed:\n\(output)\n\nsshd log:\n\(sshdLog())")
        XCTAssertEqual(try? String(contentsOf: sub.appendingPathComponent(file.lastPathComponent), encoding: .utf8), "three")

        let missing = try SshLaunch.invocation(
            .upload(localPaths: [file.path], remoteDirectory: "nosuch"),
            server: rig.server,
            credential: rig.credential
        )
        let (missingStatus, missingOutput) = run(missing.executable, testOnlyOptions + missing.arguments, environment: env)
        XCTAssertNotEqual(missingStatus, 0, "a folder that is not there must fail:\n\(missingOutput)")
        XCTAssertFalse(
            FileManager.default.fileExists(atPath: rig.landing.appendingPathComponent("nosuch").path),
            "the file must not be written under the folder's name"
        )
    }

    func testSftpThroughTheAgentWithTheAppsArguments() throws {
        let rig = try startRig()
        defer { rig.agent.stop() }

        let batch = dir.appendingPathComponent("batch")
        try "mkdir fc-sftp-ok\n".write(to: batch, atomically: true, encoding: .utf8)
        let inv = try SshLaunch.invocation(.sftp, server: rig.server, credential: rig.credential)
        let (status, output) = run(inv.executable, ["-b", batch.path] + testOnlyOptions + inv.arguments,
                                   environment: SshLaunch.environment(credential: rig.credential))

        XCTAssertEqual(status, 0, "sftp failed:\n\(output)\n\nsshd log:\n\(sshdLog())")
        var isDir: ObjCBool = false
        XCTAssertTrue(FileManager.default.fileExists(atPath: rig.landing.appendingPathComponent("fc-sftp-ok").path, isDirectory: &isDir))
        XCTAssertTrue(isDir.boolValue)
    }

    /// A service only the "server" can reach, a local port forwarded to
    /// it through the app's tunnel vector, and bytes coming back.
    func testTunnelCarriesALocalPortThroughTheServer() throws {
        let rig = try startRig()
        defer { rig.agent.stop() }

        let service = try startGreetingService("FREER_TUNNEL_OK")
        defer { close(service.fd) }

        let localPort = try freePort()
        let inv = try SshLaunch.invocation(
            .tunnel([SshPortForward(localPort: localPort, remoteHost: "127.0.0.1", remotePort: service.port)]),
            server: rig.server,
            credential: rig.credential
        )

        let log = dir.appendingPathComponent("tunnel.log")
        FileManager.default.createFile(atPath: log.path, contents: nil)
        let process = Process()
        process.executableURL = URL(fileURLWithPath: inv.executable)
        process.arguments = testOnlyOptions + inv.arguments
        process.environment = environmentDictionary(SshLaunch.environment(credential: rig.credential))
        process.standardOutput = try FileHandle(forWritingTo: log)
        process.standardError = try FileHandle(forWritingTo: log)
        try process.run()
        defer { process.terminate(); process.waitUntilExit() }

        var greeting = ""
        let deadline = Date().addingTimeInterval(10)
        while Date() < deadline, process.isRunning {
            greeting = readAll(port: localPort)
            if greeting.contains("FREER_TUNNEL_OK") { break }
            usleep(100_000)
        }
        let tunnelLog = (try? String(contentsOf: log, encoding: .utf8)) ?? ""
        XCTAssertTrue(process.isRunning, "ssh -N exited:\n\(tunnelLog)\n\nsshd log:\n\(sshdLog())")
        XCTAssertEqual(greeting, "FREER_TUNNEL_OK", "tunnel log:\n\(tunnelLog)")
    }

    // MARK: - Helpers

    /// Accepts until its descriptor is closed and writes `message` to
    /// every connection — the readiness poll above connects too.
    private func startGreetingService(_ message: String) throws -> (fd: Int32, port: Int) {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = 0
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")
        var size = socklen_t(MemoryLayout<sockaddr_in>.size)
        let bound = withUnsafePointer(to: &addr) { p in
            p.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.bind(fd, $0, size) }
        }
        guard bound == 0, listen(fd, 8) == 0 else {
            close(fd)
            throw XCTSkip("could not start the local service")
        }
        var out = sockaddr_in()
        _ = withUnsafeMutablePointer(to: &out) { p in
            p.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.getsockname(fd, $0, &size) }
        }
        Thread.detachNewThread {
            while true {
                let client = accept(fd, nil, nil)
                if client < 0 { return }
                _ = message.withCString { write(client, $0, strlen($0)) }
                close(client)
            }
        }
        return (fd, Int(UInt16(bigEndian: out.sin_port)))
    }

    /// Connect, read to EOF (or a two-second timeout), return what came.
    private func readAll(port: Int) -> String {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { return "" }
        defer { close(fd) }
        var timeout = timeval(tv_sec: 2, tv_usec: 0)
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = UInt16(port).bigEndian
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")
        let size = socklen_t(MemoryLayout<sockaddr_in>.size)
        let connected = withUnsafePointer(to: &addr) { p in
            p.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.connect(fd, $0, size) }
        }
        guard connected == 0 else { return "" }
        var data = Data()
        var buffer = [UInt8](repeating: 0, count: 256)
        while true {
            let n = read(fd, &buffer, buffer.count)
            if n <= 0 { break }
            data.append(buffer, count: n)
        }
        return String(data: data, encoding: .utf8) ?? ""
    }

    private func freePort() throws -> Int {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        defer { close(fd) }
        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = 0
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")
        let size = socklen_t(MemoryLayout<sockaddr_in>.size)
        let bound = withUnsafePointer(to: &addr) { p in
            p.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.bind(fd, $0, size) }
        }
        guard bound == 0 else { throw XCTSkip("could not bind a local port") }
        var out = sockaddr_in()
        var outLen = size
        _ = withUnsafeMutablePointer(to: &out) { p in
            p.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.getsockname(fd, $0, &outLen) }
        }
        return Int(UInt16(bigEndian: out.sin_port))
    }

    private func startSshd(port: Int, authorizedKeys: URL, sftpStartDirectory: URL? = nil) throws {
        let hostKey = dir.appendingPathComponent("host_ed25519")
        let (kgStatus, kgOut) = run("/usr/bin/ssh-keygen",
                                    ["-q", "-t", "ed25519", "-f", hostKey.path, "-N", ""],
                                    environment: nil)
        guard kgStatus == 0 else { throw XCTSkip("ssh-keygen failed: \(kgOut)") }

        var config = """
        Port \(port)
        ListenAddress 127.0.0.1
        HostKey \(hostKey.path)
        AuthorizedKeysFile \(authorizedKeys.path)
        StrictModes no
        UsePAM no
        PasswordAuthentication no
        KbdInteractiveAuthentication no
        PubkeyAuthentication yes
        LogLevel DEBUG1
        """
        if let sftpStartDirectory {
            // `-d` starts the SFTP server there, and both `sftp` and
            // scp's SFTP mode resolve the empty remote path against it.
            config += "\nSubsystem sftp internal-sftp -d \(sftpStartDirectory.path)"
        }
        let configPath = dir.appendingPathComponent("sshd_config")
        try config.write(to: configPath, atomically: true, encoding: .utf8)

        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/sbin/sshd")
        // -D keeps it in the foreground so terminating the Process
        // actually kills the listener rather than orphaning a daemon.
        process.arguments = ["-D", "-f", configPath.path, "-E", dir.appendingPathComponent("sshd.log").path]
        try process.run()
        sshd = process

        // Wait for the listener rather than sleeping a fixed amount.
        let deadline = Date().addingTimeInterval(10)
        while Date() < deadline {
            if canConnect(port: port) { return }
            usleep(50_000)
        }
        throw XCTSkip("sshd did not come up on \(port):\n\(sshdLog())")
    }

    private func canConnect(port: Int) -> Bool {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { return false }
        defer { close(fd) }
        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = UInt16(port).bigEndian
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")
        let size = socklen_t(MemoryLayout<sockaddr_in>.size)
        return withUnsafePointer(to: &addr) { p in
            p.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.connect(fd, $0, size) } == 0
        }
    }

    private func sshdLog() -> String {
        (try? String(contentsOf: dir.appendingPathComponent("sshd.log"), encoding: .utf8)) ?? "(no log)"
    }

    private func run(_ path: String, _ args: [String], environment: [String]?) -> (Int32, String) {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: path)
        process.arguments = args
        if let environment {
            process.environment = environmentDictionary(environment)
        }
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        do { try process.run() } catch { return (-1, "could not run \(path): \(error)") }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        return (process.terminationStatus, String(data: data, encoding: .utf8) ?? "")
    }

    private func environmentDictionary(_ environment: [String]) -> [String: String] {
        var dict: [String: String] = [:]
        for entry in environment {
            guard let i = entry.firstIndex(of: "=") else { continue }
            dict[String(entry[entry.startIndex ..< i])] = String(entry[entry.index(after: i)...])
        }
        return dict
    }
}
