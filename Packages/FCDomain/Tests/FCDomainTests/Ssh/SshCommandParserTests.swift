import XCTest
@testable import FCDomain

/// ``SshCommandParser``. The parser exists so a port is never retyped;
/// every case here is a line somebody really does paste, and a wrong
/// answer is a server entry that looks right and cannot connect.
final class SshCommandParserTests: XCTestCase {

    private func parse(_ line: String) throws -> SshCommandParser.Parsed {
        try SshCommandParser.parse(line)
    }

    /// The line this feature was asked for.
    func testTheWholeLine() throws {
        let p = try parse("ssh -p 50227 -i ~/.ssh/contabo-154-38-169-146-nerve armx@154.38.169.146")
        XCTAssertEqual(p.host, "154.38.169.146")
        XCTAssertEqual(p.user, "armx")
        XCTAssertEqual(p.port, 50227)
        XCTAssertEqual(p.identityFile, "~/.ssh/contabo-154-38-169-146-nerve")
        XCTAssertTrue(p.ignored.isEmpty)
    }

    func testBareTarget() throws {
        let p = try parse("ssh root@vps01.example.com")
        XCTAssertEqual(p.host, "vps01.example.com")
        XCTAssertEqual(p.user, "root")
        XCTAssertNil(p.port, "a line with no port must leave the field alone")
        XCTAssertNil(p.identityFile)
    }

    /// A host alias from `~/.ssh/config` is a legitimate paste, and
    /// carries no user at all.
    func testHostAloneKeepsUserNil() throws {
        let p = try parse("ssh prod")
        XCTAssertEqual(p.host, "prod")
        XCTAssertNil(p.user)
    }

    func testDashLUser() throws {
        let p = try parse("ssh -l deploy box.example.com")
        XCTAssertEqual(p.user, "deploy")
        XCTAssertEqual(p.host, "box.example.com")
    }

    /// `ssh` resolves the target last, so alice connects, not bob.
    func testTargetUserBeatsDashL() throws {
        XCTAssertEqual(try parse("ssh -l bob alice@host").user, "alice")
    }

    func testAttachedValue() throws {
        let p = try parse("ssh -p2222 me@host")
        XCTAssertEqual(p.port, 2222)
    }

    /// `-tt` and `-vvv` bundle; `-o` before the target must not eat it.
    func testBundledFlagsAndOptionValues() throws {
        let p = try parse("ssh -vvv -tt -o StrictHostKeyChecking=no -p 2200 me@host")
        XCTAssertEqual(p.host, "host")
        XCTAssertEqual(p.port, 2200)
        XCTAssertEqual(p.ignored, ["-o StrictHostKeyChecking=no"])
    }

    func testForwards() throws {
        let p = try parse("ssh -L 8080:localhost:80 -L 5432:db:5432 me@host")
        XCTAssertEqual(p.forwards.map(\.summary), ["localhost:8080 → localhost:80", "localhost:5432 → db:5432"])
        XCTAssertTrue(p.ignored.isEmpty)
    }

    /// The four-field form is accepted and its bind address is not:
    /// the tunnel binds loopback on purpose, and a silently obeyed
    /// `0.0.0.0` would serve the database to the café's Wi-Fi.
    func testForwardBindAddressIsNarrowedAndReported() throws {
        let p = try parse("ssh -L 0.0.0.0:8080:localhost:80 me@host")
        XCTAssertEqual(p.forwards.first?.localPort, 8080)
        XCTAssertEqual(p.forwards.first?.remoteHost, "localhost")
        XCTAssertEqual(p.ignored.count, 1)
        XCTAssertTrue(p.ignored[0].contains("0.0.0.0"))
    }

    func testForwardOnLoopbackBindAddressIsSilent() throws {
        XCTAssertTrue(try parse("ssh -L 127.0.0.1:8080:localhost:80 me@host").ignored.isEmpty)
    }

    /// A jump host cannot be stored, and dropping it quietly would
    /// leave an entry that can never reach its box.
    func testJumpHostIsReported() throws {
        let p = try parse("ssh -J bastion me@host")
        XCTAssertEqual(p.ignored, ["jump host -J bastion"])
    }

    func testRemoteCommandIsReportedWhole() throws {
        let p = try parse("ssh me@host sudo systemctl restart nginx")
        XCTAssertEqual(p.host, "host")
        XCTAssertEqual(p.ignored, ["remote command sudo systemctl restart nginx"])
    }

    /// The wrapper strip takes the first ssh word, so a remote command
    /// that is itself an ssh does not become the server.
    func testRemoteCommandThatIsItselfSsh() throws {
        let p = try parse("ssh gateway ssh inner")
        XCTAssertEqual(p.host, "gateway")
        XCTAssertEqual(p.ignored, ["remote command ssh inner"])
    }

    /// A key path with a space in it is quoted in the line, and
    /// splitting on whitespace alone would hand `-i` half of it.
    func testQuotedPath() throws {
        let p = try parse("ssh -i \"~/my keys/id_ed25519\" me@host")
        XCTAssertEqual(p.identityFile, "~/my keys/id_ed25519")
        let escaped = try parse("ssh -i ~/my\\ keys/id_ed25519 me@host")
        XCTAssertEqual(escaped.identityFile, "~/my keys/id_ed25519")
    }

    /// Pasted with its prompt, its wrapper, or across two lines.
    func testWrappersAndPrompts() throws {
        XCTAssertEqual(try parse("$ ssh me@host").host, "host")
        XCTAssertEqual(try parse("sudo ssh -p 2222 me@host").port, 2222)
        XCTAssertEqual(try parse("/usr/bin/ssh me@host").host, "host")
        XCTAssertEqual(try parse("ssh -p 2222 \\\n  me@host").host, "host")
    }

    /// The `ssh` word is a convenience, not a requirement — the fields
    /// alone are a perfectly clear paste.
    func testArgumentsWithoutTheSshWord() throws {
        let p = try parse("-p 2222 me@host")
        XCTAssertEqual(p.port, 2222)
        XCTAssertEqual(p.host, "host")
    }

    func testUrlForm() throws {
        let p = try parse("ssh ssh://armx@154.38.169.146:50227")
        XCTAssertEqual(p.host, "154.38.169.146")
        XCTAssertEqual(p.user, "armx")
        XCTAssertEqual(p.port, 50227)
    }

    func testIpv6Literal() throws {
        let p = try parse("ssh me@[2001:db8::1]")
        XCTAssertEqual(p.host, "2001:db8::1")
        XCTAssertNil(p.port)
        let ported = try parse("ssh ssh://me@[2001:db8::1]:2222")
        XCTAssertEqual(ported.host, "2001:db8::1")
        XCTAssertEqual(ported.port, 2222)
    }

    func testDoubleDashEndsOptions() throws {
        XCTAssertEqual(try parse("ssh -- me@host").host, "host")
    }

    // MARK: - Failures

    func testEmpty() {
        XCTAssertThrowsError(try parse("   ")) {
            XCTAssertEqual($0 as? SshCommandParser.Failure, .empty)
        }
    }

    func testNoHost() {
        XCTAssertThrowsError(try parse("ssh -p 2222")) {
            XCTAssertEqual($0 as? SshCommandParser.Failure, .noHost)
        }
    }

    /// `ssh` parses options again after the target, so a line written
    /// this way round means the same thing.
    func testOptionsAfterTheHost() throws {
        let p = try parse("ssh 154.38.169.146 -p 50227 -l armx")
        XCTAssertEqual(p.host, "154.38.169.146")
        XCTAssertEqual(p.port, 50227)
        XCTAssertEqual(p.user, "armx")
        XCTAssertTrue(p.ignored.isEmpty)
    }

    func testMissingValue() {
        XCTAssertThrowsError(try parse("ssh -p")) {
            XCTAssertEqual($0 as? SshCommandParser.Failure, .missingValue("-p"))
        }
    }

    func testBadPort() {
        for line in ["ssh -p 0 me@host", "ssh -p 70000 me@host", "ssh -p http me@host"] {
            XCTAssertThrowsError(try parse(line), line)
        }
    }

    func testUnbalancedQuote() {
        XCTAssertThrowsError(try parse("ssh -i \"~/.ssh/key me@host")) {
            XCTAssertEqual($0 as? SshCommandParser.Failure, .unbalancedQuote)
        }
    }

    /// Two forwards on one local port kill the whole tunnel, so the
    /// paste is refused rather than saved.
    func testDuplicateLocalPortIsRefused() {
        XCTAssertThrowsError(try parse("ssh -L 8080:a:80 -L 8080:b:80 me@host"))
    }

    func testUnstorableForward() {
        XCTAssertThrowsError(try parse("ssh -L /tmp/sock:localhost:80 me@host"))
    }

    /// The parsed fields have to survive the trip back out as the
    /// command they came from, or the pane is filling the form with
    /// something that connects elsewhere.
    func testRoundTripThroughSshLaunch() throws {
        let p = try parse("ssh -p 50227 armx@154.38.169.146")
        let server = SshServer(host: p.host, port: p.port ?? 22, user: p.user ?? "")
        let args = SshLaunch.arguments(for: server, credential: .systemDefaults)
        XCTAssertEqual(args, ["-p", "50227", "armx@154.38.169.146"])
    }
}
