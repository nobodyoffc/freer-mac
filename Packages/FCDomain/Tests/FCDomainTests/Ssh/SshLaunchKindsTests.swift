import XCTest
@testable import FCDomain

/// ``SshLaunch/Kind`` beyond the shell: installing the key, `sftp`,
/// `scp` uploads and tunnels. Like the tests next door, each assertion
/// here stands in for a failure that `ssh` would not report — a wrong
/// port flag, a forward bound to every interface, a key glued onto the
/// end of somebody else's.
final class SshLaunchKindsTests: XCTestCase {

    private let server = SshServer(label: "vps", host: "vps01.example.com", user: "root")
    private let pub = "/tmp/fc.freer.ssh.1/id_ed25519.pub"
    private let sock = "/tmp/fc.freer.ssh.1/agent.sock"
    private let line = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH0dTXVr3ZBn9FRX8u6pyCTDdwD5ZC6gA0p6tQKpjWuB freer:FEk41Kqjar45fLDriztUDTUkdki7mmcjWK"

    private var freer: SshLaunch.Credential {
        .freerAgent(publicKeyPath: pub, socketPath: sock)
    }

    private func invocation(_ kind: SshLaunch.Kind, _ s: SshServer? = nil) throws -> SshLaunch.Invocation {
        try SshLaunch.invocation(kind, server: s ?? server, credential: freer)
    }

    private func value(after flag: String, in args: [String]) -> String? {
        guard let i = args.firstIndex(of: flag), i + 1 < args.count else { return nil }
        return args[i + 1]
    }

    // MARK: - Shell

    /// The shell kind is the old argument vector, unchanged.
    func testShellKindIsTheExistingArgumentVector() throws {
        let inv = try invocation(.shell)
        XCTAssertEqual(inv.executable, "/usr/bin/ssh")
        XCTAssertEqual(inv.execName, "ssh")
        XCTAssertEqual(inv.arguments, SshLaunch.arguments(for: server, credential: freer))
    }

    // MARK: - Port flag

    /// `ssh -p`, `scp -P`, `sftp -P`. To scp, `-p` is "preserve times":
    /// the wrong flag uploads to port 22 and says nothing.
    func testEachProgramGetsItsOwnPortFlag() throws {
        var s = server
        s.port = 2222
        let ssh = try invocation(.shell, s).arguments
        let sftp = try invocation(.sftp, s).arguments
        let scp = try invocation(.upload(localPaths: ["/tmp/a"]), s).arguments
        let tunnel = try invocation(.tunnel([SshPortForward(localPort: 8080, remotePort: 80)]), s).arguments

        XCTAssertEqual(value(after: "-p", in: ssh), "2222")
        XCTAssertEqual(value(after: "-p", in: tunnel), "2222")
        XCTAssertEqual(value(after: "-P", in: sftp), "2222")
        XCTAssertEqual(value(after: "-P", in: scp), "2222")
        XCTAssertFalse(scp.contains("-p"), "scp -p is preserve-times, not the port")
        XCTAssertFalse(sftp.contains("-p"))
    }

    /// The agent has to be authoritative for the file tools too, or an
    /// upload quietly authenticates as some other key.
    func testFileToolsCarryTheSameCredentialOptions() throws {
        for kind in [SshLaunch.Kind.sftp, .upload(localPaths: ["/tmp/a"])] {
            let args = try invocation(kind).arguments
            XCTAssertEqual(value(after: "-i", in: args), pub)
            XCTAssertTrue(args.contains("IdentitiesOnly=yes"))
            XCTAssertTrue(args.contains("IdentityAgent=\(sock)"))
        }
    }

    // MARK: - sftp and scp

    func testSftpStartsInDownloads() throws {
        let inv = try invocation(.sftp)
        XCTAssertEqual(inv.executable, "/usr/bin/sftp")
        XCTAssertEqual(inv.arguments.last, "root@vps01.example.com")
        let downloads = FileManager.default.urls(for: .downloadsDirectory, in: .userDomainMask).first!.path
        let expected = FileManager.default.fileExists(atPath: downloads) ? downloads : NSHomeDirectory()
        XCTAssertEqual(inv.currentDirectory, expected, "a get with no local path writes to the cwd")
    }

    func testUploadCopiesRecursivelyIntoTheRemoteHome() throws {
        let inv = try invocation(.upload(localPaths: ["/Users/me/a b.txt", "/Users/me/folder"]))
        XCTAssertEqual(inv.executable, "/usr/bin/scp")
        XCTAssertTrue(inv.arguments.contains("-r"))
        XCTAssertTrue(inv.arguments.contains("-s"), "over the legacy protocol the remote path goes through a shell")
        XCTAssertEqual(
            Array(inv.arguments.suffix(4)),
            ["--", "/Users/me/a b.txt", "/Users/me/folder", "root@vps01.example.com:"],
            "an empty remote path is the home directory in both scp modes"
        )
    }

    /// scp reads `a:b` as host `a`, and `-x` as an option. An absolute
    /// path can be neither.
    func testUploadRefusesRelativePathsAndEmptyLists() {
        XCTAssertThrowsError(try invocation(.upload(localPaths: ["notes:today.txt"]))) { error in
            XCTAssertEqual(error as? SshLaunch.Failure, .relativeUploadPath("notes:today.txt"))
        }
        XCTAssertThrowsError(try invocation(.upload(localPaths: []))) { error in
            XCTAssertEqual(error as? SshLaunch.Failure, .nothingToUpload)
        }
    }

    /// The field's text becomes a directory path: a trailing slash so a
    /// missing folder is an error rather than a rename, and `~` as the
    /// empty path so it means home on every server.
    func testUploadGoesIntoTheChosenFolder() throws {
        func target(_ directory: String) throws -> String? {
            try invocation(.upload(localPaths: ["/tmp/a"], remoteDirectory: directory)).arguments.last
        }
        XCTAssertEqual(try target("/var/www"), "root@vps01.example.com:/var/www/")
        XCTAssertEqual(try target("backups/"), "root@vps01.example.com:backups/")
        XCTAssertEqual(try target("~/my site"), "root@vps01.example.com:~/my site/",
                       "one argv entry, and over SFTP a space needs no quoting")
        for home in ["", "~", "~/", "  ~  "] {
            XCTAssertEqual(try target(home), "root@vps01.example.com:", "\"\(home)\" is home")
        }
    }

    func testUploadRefusesAFolderWithControlCharacters() {
        XCTAssertThrowsError(try invocation(.upload(localPaths: ["/tmp/a"], remoteDirectory: "www\nrm"))) { error in
            XCTAssertEqual(error as? SshLaunch.Failure, .badRemoteDirectory)
        }
    }

    func testOSC7ReportsBecomePlainPaths() {
        XCTAssertEqual(SshLaunch.reportedDirectory("file://build/var/www"), "/var/www")
        XCTAssertEqual(SshLaunch.reportedDirectory("file://build.example.com/home/liu/my%20site"), "/home/liu/my site")
        XCTAssertEqual(SshLaunch.reportedDirectory("file:///tmp"), "/tmp")
        XCTAssertEqual(SshLaunch.reportedDirectory("/srv"), "/srv")
        XCTAssertNil(SshLaunch.reportedDirectory("relative/dir"))
        XCTAssertNil(SshLaunch.reportedDirectory("file://hostonly"))
        XCTAssertNil(SshLaunch.reportedDirectory("file://h/a%0Ab"), "remote text decoding to a newline is dropped")
    }

    /// scp and sftp split `host:path` on the colon; ssh does not.
    func testIPv6LiteralsAreBracketedForTheFileToolsOnly() throws {
        let v6 = SshServer(host: "2001:db8::7", user: "ops")
        XCTAssertEqual(try invocation(.upload(localPaths: ["/tmp/a"]), v6).arguments.last, "ops@[2001:db8::7]:")
        XCTAssertEqual(try invocation(.sftp, v6).arguments.last, "ops@[2001:db8::7]")
        XCTAssertEqual(try invocation(.shell, v6).arguments.last, "ops@2001:db8::7")
    }

    // MARK: - Tunnel

    func testTunnelHoldsForwardsOpenAndNothingElse() throws {
        let forwards = [
            SshPortForward(localPort: 8080, remotePort: 80),
            SshPortForward(localPort: 15432, remoteHost: "db.internal", remotePort: 5432)
        ]
        let args = try invocation(.tunnel(forwards)).arguments
        XCTAssertTrue(args.contains("-N"), "a tunnel must not open a shell")
        XCTAssertTrue(args.contains("ExitOnForwardFailure=yes"), "a port in use must end the session, not scroll past")
        let specs = args.indices.filter { args[$0] == "-L" }.map { args[$0 + 1] }
        XCTAssertEqual(specs, ["127.0.0.1:8080:localhost:80", "127.0.0.1:15432:db.internal:5432"])
        XCTAssertEqual(args.last, "root@vps01.example.com")
    }

    /// Every forward names its bind address, so `GatewayPorts yes` in
    /// someone's config cannot publish it to the LAN.
    func testForwardsAlwaysBindLoopback() {
        XCTAssertTrue(SshPortForward(localPort: 1, remotePort: 2).specification.hasPrefix("127.0.0.1:"))
        XCTAssertEqual(
            SshPortForward(localPort: 8443, remoteHost: "::1", remotePort: 443).specification,
            "127.0.0.1:8443:[::1]:443"
        )
    }

    func testTunnelRefusesNoForwardsAndBadOnes() {
        XCTAssertThrowsError(try invocation(.tunnel([])))
        XCTAssertThrowsError(try invocation(.tunnel([SshPortForward(localPort: 0, remotePort: 80)])))
        XCTAssertThrowsError(try invocation(.tunnel([
            SshPortForward(localPort: 8080, remotePort: 80),
            SshPortForward(localPort: 8080, remotePort: 81)
        ])), "two forwards on one local port kill the tunnel at the second bind")
        XCTAssertThrowsError(try invocation(.tunnel([
            SshPortForward(localPort: 8080, remoteHost: "local host", remotePort: 80)
        ])))
    }

    func testAServerStoredWithoutForwardsDecodesWithNone() throws {
        let legacy = "{\"id\":\"abc\",\"label\":\"old\",\"host\":\"h\",\"port\":22,\"user\":\"root\",\"addedAt\":0,\"updatedAt\":0}"
        let decoded = try JSONDecoder().decode(SshServer.self, from: Data(legacy.utf8))
        XCTAssertNil(decoded.forwards)
        XCTAssertEqual(decoded.portForwards, [])
        XCTAssertNil(decoded.portForwardsError)
    }

    // MARK: - Install key: the argument vector

    func testInstallKeyIsOneSshWithTheScriptAsTheRemoteCommand() throws {
        let inv = try invocation(.installKey(authorizedKeysLine: line))
        XCTAssertEqual(inv.executable, "/usr/bin/ssh")
        let command = try XCTUnwrap(inv.arguments.last)
        XCTAssertTrue(command.hasPrefix("exec sh -c '"), "the login shell may be fish or tcsh")
        XCTAssertEqual(inv.arguments[inv.arguments.count - 2], "root@vps01.example.com")
        XCTAssertFalse(inv.arguments.contains("-t"))
        XCTAssertFalse(inv.arguments.contains("BatchMode=yes"), "the password fallback is the point")
    }

    /// Anything that could close the single quotes, or mean something
    /// to a shell inside double quotes, never reaches the script.
    func testKeyScriptsRefuseLinesThatCouldEscapeTheQuoting() {
        for bad in [
            "ssh-ed25519 AAAA x'; rm -rf ~; '",
            "ssh-ed25519 AAAA $(id)",
            "ssh-ed25519 AAAA `id`",
            "ssh-ed25519 AAAA \"x\"",
            "ssh-ed25519 AAAA a\\b",
            "ssh-ed25519 AAAA\nssh-rsa BBBB",
            "ssh-ed25519",
            "ssh-ed25519  AAAA"
        ] {
            for kind in [SshLaunch.Kind.installKey(authorizedKeysLine: bad), .removeKey(authorizedKeysLine: bad)] {
                XCTAssertThrowsError(try invocation(kind), bad) { error in
                    XCTAssertEqual(error as? SshLaunch.Failure, .unsafeAuthorizedKeysLine)
                }
            }
        }
    }

    /// One pair of single quotes around the whole script and none in
    /// it — the fixed text is ours, and a stray apostrophe in a message
    /// would cut the script in half on every shell.
    func testNeitherScriptBreaksItsOwnQuoting() throws {
        for command in [
            try SshLaunch.installKeyRemoteCommand(authorizedKeysLine: line),
            try SshLaunch.removeKeyRemoteCommand(authorizedKeysLine: line)
        ] {
            XCTAssertEqual(command.filter { $0 == "'" }.count, 2, command)
            XCTAssertFalse(command.contains("\\"), command)
            XCTAssertFalse(command.contains("\n"), command)
            XCTAssertFalse(command.contains("!"), "csh history expansion: \(command)")
        }
    }

    /// The tooltip and the dimmed line in the scrollback are meant to
    /// be pasteable; the install command is the one a naive join breaks.
    func testCommandLineIsQuotedSoItRunsAsShown() throws {
        XCTAssertEqual(SshLaunch.shellQuoted("root@vps01.example.com"), "root@vps01.example.com")
        XCTAssertEqual(SshLaunch.shellQuoted("a b"), "'a b'")
        XCTAssertEqual(SshLaunch.shellQuoted("it's"), "'it'\\''s'")
        XCTAssertEqual(SshLaunch.shellQuoted(""), "''")

        let inv = try invocation(.upload(localPaths: ["/tmp/a b"]))
        let (status, output) = run("/bin/sh", ["-c", "printf '%s\\n' " + inv.commandLine], env: [:])
        XCTAssertEqual(status, 0)
        XCTAssertEqual(output.split(separator: "\n").map(String.init), [inv.execName] + inv.arguments)
    }

    // MARK: - Install key: the script, run for real

    /// The command as the remote login shell would receive it, run by
    /// every shell this Mac has. `HOME` is a scratch directory, so the
    /// script's `cd` lands there and not in the real one.
    private func runInstall(shell: String, home: URL, line: String? = nil) throws -> (Int32, String) {
        let command = try SshLaunch.installKeyRemoteCommand(authorizedKeysLine: line ?? self.line)
        return run(shell, ["-c", command], env: ["HOME": home.path, "PATH": "/usr/bin:/bin:/usr/sbin:/sbin"])
    }

    private var shells: [String] {
        ["/bin/sh", "/bin/bash", "/bin/zsh", "/bin/csh", "/bin/tcsh", "/opt/homebrew/bin/fish", "/usr/local/bin/fish"]
            .filter { FileManager.default.isExecutableFile(atPath: $0) }
    }

    private func scratchHome() throws -> URL {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("fc-ssh-install-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        addTeardownBlock { try? FileManager.default.removeItem(at: dir) }
        return dir
    }

    private func authorizedKeys(in home: URL) throws -> String {
        try String(contentsOf: home.appendingPathComponent(".ssh/authorized_keys"), encoding: .utf8)
    }

    func testInstallCreatesTheFileWithStrictModesPermissions() throws {
        XCTAssertGreaterThanOrEqual(shells.count, 3)
        for shell in shells {
            let home = try scratchHome()
            let (status, output) = try runInstall(shell: shell, home: home)
            XCTAssertEqual(status, 0, "\(shell): \(output)")
            XCTAssertTrue(output.contains("Key added"), "\(shell): \(output)")
            XCTAssertEqual(try authorizedKeys(in: home), line + "\n", shell)

            let fm = FileManager.default
            let dirMode = try fm.attributesOfItem(atPath: home.appendingPathComponent(".ssh").path)[.posixPermissions] as? Int
            let fileMode = try fm.attributesOfItem(atPath: home.appendingPathComponent(".ssh/authorized_keys").path)[.posixPermissions] as? Int
            XCTAssertEqual(dirMode, 0o700, shell)
            XCTAssertEqual(fileMode, 0o600, shell)
        }
    }

    func testInstallTwiceAddsTheKeyOnce() throws {
        for shell in shells {
            let home = try scratchHome()
            _ = try runInstall(shell: shell, home: home)
            let (status, output) = try runInstall(shell: shell, home: home)
            XCTAssertEqual(status, 0, shell)
            XCTAssertTrue(output.contains("already"), "\(shell): \(output)")
            XCTAssertEqual(try authorizedKeys(in: home), line + "\n", shell)
        }
    }

    /// The same key under another comment, or behind an options prefix,
    /// is the same key.
    func testTheKeyIsRecognisedWhateverItsCommentOrOptions() throws {
        let home = try scratchHome()
        let ssh = home.appendingPathComponent(".ssh")
        try FileManager.default.createDirectory(at: ssh, withIntermediateDirectories: true)
        let blob = line.split(separator: " ")[1]
        let existing = "from=\"10.0.0.0/8\" ssh-ed25519 \(blob) renamed-by-hand\n"
        try existing.write(to: ssh.appendingPathComponent("authorized_keys"), atomically: true, encoding: .utf8)

        let (status, output) = try runInstall(shell: "/bin/zsh", home: home)
        XCTAssertEqual(status, 0)
        XCTAssertTrue(output.contains("already"), output)
        XCTAssertEqual(try authorizedKeys(in: home), existing)
    }

    /// A last line with no newline must not have our key glued to it.
    func testInstallStartsANewLineWhenTheFileDoesNotEndInOne() throws {
        let home = try scratchHome()
        let ssh = home.appendingPathComponent(".ssh")
        try FileManager.default.createDirectory(at: ssh, withIntermediateDirectories: true)
        let other = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ someone@laptop"
        try other.write(to: ssh.appendingPathComponent("authorized_keys"), atomically: true, encoding: .utf8)

        let (status, _) = try runInstall(shell: "/bin/bash", home: home)
        XCTAssertEqual(status, 0)
        XCTAssertEqual(try authorizedKeys(in: home), other + "\n" + line + "\n")

        // …and does not add a blank line when it already ends in one.
        let home2 = try scratchHome()
        let ssh2 = home2.appendingPathComponent(".ssh")
        try FileManager.default.createDirectory(at: ssh2, withIntermediateDirectories: true)
        try (other + "\n").write(to: ssh2.appendingPathComponent("authorized_keys"), atomically: true, encoding: .utf8)
        _ = try runInstall(shell: "/bin/bash", home: home2)
        XCTAssertEqual(try authorizedKeys(in: home2), other + "\n" + line + "\n")
    }

    /// A home the script cannot write to is a non-zero exit, which the
    /// tab reports as a failure — not a success with nothing installed.
    func testInstallFailsLoudlyWhenItCannotWrite() throws {
        let home = try scratchHome()
        let ssh = home.appendingPathComponent(".ssh")
        try FileManager.default.createDirectory(at: ssh, withIntermediateDirectories: true)
        try FileManager.default.setAttributes([.posixPermissions: 0o500], ofItemAtPath: ssh.path)
        addTeardownBlock { try? FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: ssh.path) }

        let (status, _) = try runInstall(shell: "/bin/sh", home: home)
        XCTAssertNotEqual(status, 0)
        XCTAssertEqual(
            SshLaunch.exitDescription(rawStatus: status << 8, kind: .installKey(authorizedKeysLine: line)),
            "Could not install the key (exit \(status))."
        )
    }

    // MARK: - Remove key

    func testRemoveKeyIsOneSshWithTheScriptAsTheRemoteCommand() throws {
        let inv = try invocation(.removeKey(authorizedKeysLine: line))
        XCTAssertEqual(inv.executable, "/usr/bin/ssh")
        let command = try XCTUnwrap(inv.arguments.last)
        XCTAssertTrue(command.hasPrefix("exec sh -c '"), "the login shell may be fish or tcsh")
        XCTAssertEqual(inv.arguments[inv.arguments.count - 2], "root@vps01.example.com")
        XCTAssertFalse(inv.arguments.contains("-t"))
    }

    private func runRemove(shell: String, home: URL) throws -> (Int32, String) {
        let command = try SshLaunch.removeKeyRemoteCommand(authorizedKeysLine: line)
        return run(shell, ["-c", command], env: ["HOME": home.path, "PATH": "/usr/bin:/bin:/usr/sbin:/sbin"])
    }

    /// `~/.ssh/authorized_keys` holding exactly `contents`, with the
    /// modes `sshd` wants.
    private func seedAuthorizedKeys(_ contents: String, in home: URL) throws -> URL {
        let ssh = home.appendingPathComponent(".ssh")
        try FileManager.default.createDirectory(at: ssh, withIntermediateDirectories: true)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: ssh.path)
        let file = ssh.appendingPathComponent("authorized_keys")
        try contents.write(to: file, atomically: false, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path)
        return file
    }

    private func attribute(_ key: FileAttributeKey, of url: URL) throws -> Int? {
        try FileManager.default.attributesOfItem(atPath: url.path)[key] as? Int
    }

    private func sshDirectoryListing(_ home: URL) throws -> [String] {
        try FileManager.default.contentsOfDirectory(atPath: home.appendingPathComponent(".ssh").path).sorted()
    }

    private let laptopKey = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ someone@laptop"

    /// Every line holding the key goes — under its own comment, another
    /// one, or behind options — and every other line stays, in order,
    /// in the same file.
    func testRemoveTakesOutEveryCopyOfTheKeyAndNothingElse() throws {
        XCTAssertGreaterThanOrEqual(shells.count, 3)
        let blob = line.split(separator: " ")[1]
        let ci = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGq9yVdYc1s0q3n8rZ9m0CwGxXg3k6bR7oJmS2dFh4Tp ci@build"
        for shell in shells {
            let home = try scratchHome()
            let file = try seedAuthorizedKeys([
                "# team keys",
                laptopKey,
                line,
                "from=\"10.0.0.0/8\" ssh-ed25519 \(blob) renamed-by-hand",
                ci
            ].joined(separator: "\n") + "\n", in: home)
            let inode = try attribute(.systemFileNumber, of: file)

            let (status, output) = try runRemove(shell: shell, home: home)
            XCTAssertEqual(status, 0, "\(shell): \(output)")
            XCTAssertTrue(output.contains("Key removed"), "\(shell): \(output)")
            XCTAssertEqual(try authorizedKeys(in: home), "# team keys\n\(laptopKey)\n\(ci)\n", shell)
            XCTAssertEqual(try attribute(.systemFileNumber, of: file), inode, "\(shell): rewritten in place, not renamed over")
            XCTAssertEqual(try attribute(.posixPermissions, of: file), 0o600, shell)
            XCTAssertEqual(try sshDirectoryListing(home), ["authorized_keys"], "\(shell): no temp file left behind")
        }
    }

    /// Ours the only key: `grep -v` prints nothing and exits 1, which is
    /// success, and the file is emptied rather than deleted.
    func testRemovingTheOnlyKeyLeavesAnEmptyFile() throws {
        for shell in shells {
            let home = try scratchHome()
            _ = try seedAuthorizedKeys(line + "\n", in: home)
            let (status, output) = try runRemove(shell: shell, home: home)
            XCTAssertEqual(status, 0, "\(shell): \(output)")
            XCTAssertEqual(try authorizedKeys(in: home), "", shell)
        }
    }

    func testRemoveWhenTheKeyIsNotThereChangesNothingAndSucceeds() throws {
        let home = try scratchHome()
        _ = try seedAuthorizedKeys(laptopKey, in: home)
        let (status, output) = try runRemove(shell: "/bin/zsh", home: home)
        XCTAssertEqual(status, 0, output)
        XCTAssertTrue(output.contains("was not in"), output)
        XCTAssertEqual(try authorizedKeys(in: home), laptopKey, "not even a newline added")

        let bare = try scratchHome()
        let (bareStatus, bareOutput) = try runRemove(shell: "/bin/sh", home: bare)
        XCTAssertEqual(bareStatus, 0, bareOutput)
        XCTAssertTrue(bareOutput.contains("There is no"), bareOutput)
        XCTAssertFalse(FileManager.default.fileExists(atPath: bare.appendingPathComponent(".ssh").path),
                       "removing a key must not create ~/.ssh")
    }

    /// Config management often links `authorized_keys` to a managed
    /// file. A rename would replace the link with a plain file and
    /// leave the managed one still holding the key.
    func testRemoveWritesThroughASymlinkedFile() throws {
        let home = try scratchHome()
        let managed = home.appendingPathComponent("managed_keys")
        try (laptopKey + "\n" + line + "\n").write(to: managed, atomically: false, encoding: .utf8)
        let ssh = home.appendingPathComponent(".ssh")
        try FileManager.default.createDirectory(at: ssh, withIntermediateDirectories: true)
        let link = ssh.appendingPathComponent("authorized_keys")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: managed)

        let (status, output) = try runRemove(shell: "/bin/bash", home: home)
        XCTAssertEqual(status, 0, output)
        XCTAssertEqual(try FileManager.default.destinationOfSymbolicLink(atPath: link.path), managed.path)
        XCTAssertEqual(try String(contentsOf: managed, encoding: .utf8), laptopKey + "\n")
    }

    /// A file it may not write, or a folder it cannot put the filtered
    /// copy in, is a failure with the file untouched — never "removed"
    /// with the key still there, and never a half-written file.
    func testRemoveFailsLoudlyAndChangesNothingWhenItCannotWrite() throws {
        let contents = laptopKey + "\n" + line + "\n"

        let home = try scratchHome()
        let file = try seedAuthorizedKeys(contents, in: home)
        try FileManager.default.setAttributes([.posixPermissions: 0o400], ofItemAtPath: file.path)
        addTeardownBlock { try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path) }
        let (status, output) = try runRemove(shell: "/bin/sh", home: home)
        XCTAssertNotEqual(status, 0, output)
        XCTAssertEqual(try authorizedKeys(in: home), contents)
        XCTAssertEqual(try sshDirectoryListing(home), ["authorized_keys"])
        XCTAssertEqual(
            SshLaunch.exitDescription(rawStatus: status << 8, kind: .removeKey(authorizedKeysLine: line)),
            "Could not remove the key (exit \(status))."
        )

        let home2 = try scratchHome()
        let file2 = try seedAuthorizedKeys(contents, in: home2)
        let ssh2 = file2.deletingLastPathComponent()
        try FileManager.default.setAttributes([.posixPermissions: 0o500], ofItemAtPath: ssh2.path)
        addTeardownBlock { try? FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: ssh2.path) }
        let (status2, output2) = try runRemove(shell: "/bin/bash", home: home2)
        XCTAssertNotEqual(status2, 0, output2)
        XCTAssertEqual(try authorizedKeys(in: home2), contents)
    }

    /// The by-hand form, in the shell it is pasted into: the same
    /// removal, and the shell is still there afterwards to run the
    /// next command.
    func testThePastedRemovalLeavesTheShellRunning() throws {
        let paste = try SshLaunch.removeKeyCommand(authorizedKeysLine: line)
        XCTAssertEqual(try SshLaunch.removeKeyRemoteCommand(authorizedKeysLine: line), "exec " + paste)

        let home = try scratchHome()
        _ = try runInstall(shell: "/bin/zsh", home: home)
        let (status, output) = run(
            "/bin/zsh",
            ["-c", paste + "; echo still-here"],
            env: ["HOME": home.path, "PATH": "/usr/bin:/bin:/usr/sbin:/sbin"]
        )
        XCTAssertEqual(status, 0, output)
        XCTAssertTrue(output.contains("Key removed"), output)
        XCTAssertTrue(output.contains("still-here"), output)
        XCTAssertEqual(try authorizedKeys(in: home), "")
    }

    // MARK: - Exit status

    func testExitDescriptionsSpeakForTheKind() {
        let upload = SshLaunch.Kind.upload(localPaths: ["/a"])
        let tunnel = SshLaunch.Kind.tunnel([SshPortForward(localPort: 1, remotePort: 2)])
        XCTAssertEqual(SshLaunch.exitDescription(rawStatus: 0), "Session ended.")
        XCTAssertTrue(SshLaunch.exitDescription(rawStatus: 0, kind: upload).hasPrefix("Upload finished"))
        XCTAssertEqual(SshLaunch.exitDescription(rawStatus: 1 << 8, kind: upload), "Upload failed (exit 1).")
        let intoFolder = SshLaunch.Kind.upload(localPaths: ["/a"], remoteDirectory: "/srv/www")
        XCTAssertEqual(SshLaunch.exitDescription(rawStatus: 0, kind: intoFolder),
                       "Upload finished — the files are in /srv/www on the server.")
        XCTAssertTrue(SshLaunch.exitDescription(rawStatus: 1 << 8, kind: intoFolder).contains("check that /srv/www exists"))
        XCTAssertTrue(SshLaunch.exitDescription(rawStatus: 255 << 8, kind: tunnel).contains("local port"))
        XCTAssertEqual(SshLaunch.exitDescription(rawStatus: 15, kind: tunnel), "Session killed by signal 15.")
        let remove = SshLaunch.Kind.removeKey(authorizedKeysLine: line)
        XCTAssertEqual(SshLaunch.exitDescription(rawStatus: 0, kind: remove),
                       "The Freer key is not in the server's authorized_keys.")
        XCTAssertEqual(SshLaunch.exitDescription(rawStatus: 255 << 8, kind: remove), "ssh could not log in (exit 255).")
    }

    // MARK: - Helpers

    private func run(_ path: String, _ args: [String], env: [String: String]) -> (Int32, String) {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: path)
        process.arguments = args
        process.environment = env
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        do { try process.run() } catch { return (-1, "could not run \(path): \(error)") }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        return (process.terminationStatus, String(data: data, encoding: .utf8) ?? "")
    }
}
