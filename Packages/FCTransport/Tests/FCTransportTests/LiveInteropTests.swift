import XCTest
import Network
import FCCore
@testable import FCTransport

/// Live interop test against a running FC-JDK FUDP node on
/// `localhost:9000` with public key
/// `03cd1496eb365c66cfaeaa9a4aa3accd2d5bfd23d4820c2b2384df087c535cbe07`.
///
/// Skips automatically if the port isn't reachable. Spawn the Linux
/// node, then run with `swift test --filter LiveInteropTests` to
/// exercise the full encode → encrypt → send → recv → decrypt → decode
/// pipeline against real bytes on the wire.
final class LiveInteropTests: XCTestCase {

    private let serverHost = "127.0.0.1"
    private let serverPort: UInt16 = 9000
    private let serverPubkeyHex = "03cd1496eb365c66cfaeaa9a4aa3accd2d5bfd23d4820c2b2384df087c535cbe07"

    /// A throwaway client identity. Real wallets supply their own
    /// privkey; for test traffic any valid scalar works.
    private let clientPrivkey = Data(repeating: 0x42, count: 32)

    func testPingExpectsPong() async throws {
        try await skipIfUnreachable()

        let client = try await FudpClient(
            host: serverHost,
            port: serverPort,
            peerPubkey: Data(fromHex: serverPubkeyHex),
            localPrivkey: clientPrivkey
        )
        client.debugLogging = true
        defer { client.close() }

        let pong = try await client.ping(timeoutMs: 5_000)
        // We don't assert exact echo timestamp values (the server will
        // also set one), but the pong should be parseable and have a
        // sane timestamp pair.
        XCTAssertGreaterThan(pong.echoTimestamp, 1_700_000_000_000,
                             "echo timestamp looks plausible (post-2023)")
        XCTAssertGreaterThanOrEqual(pong.replyTimestamp, pong.echoTimestamp,
                                    "reply timestamp should be ≥ echo timestamp")
    }

    // MARK: - reachability

    private func skipIfUnreachable() async throws {
        // UDP doesn't have a connect handshake, so we approximate
        // reachability by binding any-port and sending a probe; if the
        // server is listening at all we expect SecRandom + send to
        // succeed locally regardless. Skip purely on errors that show
        // the test environment doesn't have UDP available.
        let probe = FudpSocket()
        defer { probe.close() }
        do {
            _ = try await probe.bind()
        } catch {
            throw XCTSkip("FudpSocket.bind failed: \(error)")
        }
        // We've bound — if the server isn't running, ping() will time
        // out and the assertion will fail. We don't pre-skip on
        // connectivity since "no PONG within 5s" is itself an
        // interesting test result.
    }
}
