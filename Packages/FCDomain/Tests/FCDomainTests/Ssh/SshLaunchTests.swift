import XCTest
@testable import FCDomain

/// ``SshLaunch``. Every assertion here stands in for a failure that is
/// silent in the field: get an option wrong and `ssh` does not error,
/// it just quietly authenticates some other way.
final class SshLaunchTests: XCTestCase {

    private let server = SshServer(label: "vps", host: "vps01.example.com", user: "root")
    private let pub = "/tmp/fc.freer.ssh.1/id_ed25519.pub"
    private let sock = "/tmp/fc.freer.ssh.1/agent.sock"

    private var freer: SshLaunch.Credential {
        .freerAgent(publicKeyPath: pub, socketPath: sock)
    }

    private func args(_ s: SshServer) -> [String] {
        SshLaunch.arguments(for: s, credential: freer)
    }

    func testTargetIsLastAndPortIsElidedWhenDefault() {
        let a = args(server)
        XCTAssertEqual(a.last, "root@vps01.example.com")
        XCTAssertFalse(a.contains("-p"), "port 22 must be left to ~/.ssh/config")
    }

    func testNonDefaultPortIsPassed() {
        var s = server
        s.port = 2222
        let a = args(s)
        let i = try? XCTUnwrap(a.firstIndex(of: "-p"))
        XCTAssertEqual(a[(i ?? 0) + 1], "2222")
    }

    /// Only the public key is ever named. If this ever becomes a path
    /// to a private key, the feature's central promise is broken.
    func testOnlyThePublicKeyIsPassedToDashI() {
        let a = args(server)
        let i = a.firstIndex(of: "-i")
        XCTAssertNotNil(i)
        XCTAssertEqual(a[i! + 1], pub)
        XCTAssertTrue(pub.hasSuffix(".pub"))
    }

    /// `IdentityAgent` is the one that looks redundant with
    /// `SSH_AUTH_SOCK` and is not: a user with 1Password or gpg-agent
    /// in `~/.ssh/config` would otherwise never consult our agent.
    func testTheFourOptionsThatMakeTheAgentAuthoritative() {
        let a = args(server)
        XCTAssertTrue(a.contains("IdentitiesOnly=yes"))
        XCTAssertTrue(a.contains("AddKeysToAgent=no"))
        XCTAssertTrue(a.contains("IdentityAgent=\(sock)"))
    }

    /// Stock behaviour is deliberate: the fingerprint prompt and the
    /// password fallback are both answered in the PTY, and both are
    /// required for the first connection to a new box.
    func testHostKeyCheckingAndPasswordFallbackAreLeftAlone() {
        let joined = args(server).joined(separator: " ")
        XCTAssertFalse(joined.contains("StrictHostKeyChecking"))
        XCTAssertFalse(joined.contains("PreferredAuthentications"))
        XCTAssertFalse(joined.contains("BatchMode"))
    }

    // MARK: - Environment

    func testEnvironmentCarriesWhatSshNeeds() {
        let env = SshLaunch.environment(credential: freer)
        func value(_ key: String) -> String? {
            env.first { $0.hasPrefix("\(key)=") }.map { String($0.dropFirst(key.count + 1)) }
        }
        XCTAssertEqual(value("TERM"), "xterm-256color")
        XCTAssertEqual(value("SSH_AUTH_SOCK"), sock)
        XCTAssertEqual(value("HOME"), NSHomeDirectory())
        XCTAssertNotNil(value("PATH"), "SwiftTerm's default env omits PATH; ProxyCommand needs it")
        XCTAssertTrue(value("LANG")?.uppercased().contains("UTF-8") ?? false)
    }

    /// With these set, `ssh` may pop a GUI password panel instead of
    /// prompting on the terminal we handed it.
    func testAskpassVariablesAreNotForwarded() {
        let env = SshLaunch.environment(credential: freer)
        XCTAssertFalse(env.contains { $0.hasPrefix("DISPLAY=") })
        XCTAssertFalse(env.contains { $0.hasPrefix("SSH_ASKPASS=") })
    }

    // MARK: - Exit status

    /// SwiftTerm hands the delegate a raw `waitpid` status, so 255
    /// arrives as 255 << 8. Printing it raw is how "weird number"
    /// reports happen.
    func testWaitpidStatusIsDecodedNotPrintedRaw() {
        XCTAssertEqual(SshLaunch.exitDescription(rawStatus: 0), "Session ended.")
        XCTAssertEqual(SshLaunch.exitDescription(rawStatus: 1 << 8), "Session ended with exit code 1.")
        XCTAssertEqual(SshLaunch.exitDescription(rawStatus: 255 << 8), "ssh could not connect (exit 255).")
        XCTAssertEqual(SshLaunch.exitDescription(rawStatus: 9), "Session killed by signal 9.")
        XCTAssertEqual(SshLaunch.exitDescription(rawStatus: nil), "Disconnected.")
    }

    func testSshIsPresentOnThisMachine() {
        XCTAssertTrue(SshLaunch.sshIsAvailable, "/usr/bin/ssh is expected on macOS")
    }

    // MARK: - Your own keys

    /// A key file is read by `ssh` itself, so `-i` points at the
    /// *private* key and our agent is not involved at all.
    func testKeyFileUsesTheFileAndNeverOurAgent() {
        let path = "/Users/someone/.ssh/p2pool_ovh"
        let a = SshLaunch.arguments(for: server, credential: .keyFile(path: path))
        let i = a.firstIndex(of: "-i")
        XCTAssertNotNil(i)
        XCTAssertEqual(a[i! + 1], path)
        XCTAssertTrue(a.contains("IdentitiesOnly=yes"))
        XCTAssertFalse(a.joined().contains("IdentityAgent"),
                       "overriding IdentityAgent would break the user's own agent for ProxyJump")
        XCTAssertEqual(a.last, "root@vps01.example.com")
    }

    /// The user's own agent must be handed through untouched — these
    /// two modes exist precisely for setups that depend on it.
    func testKeyFileAndSystemDefaultsNeverPointAtOurAgent() {
        for credential in [SshLaunch.Credential.keyFile(path: "/k"), .systemDefaults] {
            let env = SshLaunch.environment(credential: credential)
            XCTAssertFalse(env.contains("SSH_AUTH_SOCK=\(sock)"),
                           "must not point ssh at Freer's agent for \(credential)")
        }
    }

    /// "Behave as ssh would from a shell" has to mean *no* options,
    /// otherwise it is just a differently-broken mode.
    func testSystemDefaultsAddsNothingButThePortAndTarget() {
        var s = server
        s.port = 50409
        XCTAssertEqual(
            SshLaunch.arguments(for: s, credential: .systemDefaults),
            ["-p", "50409", "root@vps01.example.com"]
        )
        XCTAssertEqual(
            SshLaunch.arguments(for: server, credential: .systemDefaults),
            ["root@vps01.example.com"]
        )
    }

    /// The exact shape of a hand-written invocation, so the mapping
    /// from "what I type in a shell" to "what the pane stores" is
    /// pinned rather than assumed.
    func testReproducesAHandWrittenSshInvocation() {
        let key = "/Users/liuchangyong/.ssh/p2pool_ovh@15-235-207-132_ubuntu"
        let s = SshServer(host: "15.235.207.132", port: 50409, user: "ubuntu",
                          identity: .keyFile(path: key))
        XCTAssertEqual(
            SshLaunch.arguments(for: s, credential: .keyFile(path: key)),
            ["-i", key,
             "-o", "IdentitiesOnly=yes",
             "-o", "AddKeysToAgent=no",
             "-p", "50409",
             "ubuntu@15.235.207.132"]
        )
    }

    // MARK: - Stored default

    /// Rows written before the field existed must keep decoding, and
    /// must mean "the Freer key" — the behaviour they had. A
    /// non-optional field here would have emptied the server list.
    func testAServerStoredWithoutAnIdentityDecodesAsFreer() throws {
        let legacy = "{\"id\":\"abc\",\"label\":\"old\",\"host\":\"h\",\"port\":22,\"user\":\"root\",\"addedAt\":0,\"updatedAt\":0}"
        let decoded = try JSONDecoder().decode(SshServer.self, from: Data(legacy.utf8))
        XCTAssertNil(decoded.identity)
        XCTAssertEqual(decoded.credentialKind, .freer)
    }

    func testIdentityRoundTripsThroughCodable() throws {
        for identity: SshServer.Identity in [.freer, .keyFile(path: "/k"), .systemDefaults] {
            let s = SshServer(host: "h", user: "u", identity: identity)
            let data = try JSONEncoder().encode(s)
            let back = try JSONDecoder().decode(SshServer.self, from: data)
            XCTAssertEqual(back.credentialKind, identity)
        }
    }
}
