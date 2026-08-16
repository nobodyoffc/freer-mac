import XCTest
import FCCore
@testable import FCTransport

/// Datagram pipe that can be killed the way a real socket dies over a
/// sleep/wake cycle: the stream ends and the pipe stops being viable,
/// without anyone calling `close()` on the client above it.
private final class KillableTransport: DatagramTransport, @unchecked Sendable {
    let datagrams: AsyncStream<FudpConnection.Datagram>
    private let continuation: AsyncStream<FudpConnection.Datagram>.Continuation
    private let lock = NSLock()
    private var _viable = true
    private(set) var sentCount = 0

    var isViable: Bool {
        lock.lock(); defer { lock.unlock() }
        return _viable
    }

    init() {
        var captured: AsyncStream<FudpConnection.Datagram>.Continuation!
        self.datagrams = AsyncStream { captured = $0 }
        self.continuation = captured
    }

    /// Socket death, as the OS delivers it: no more datagrams, ever.
    func kill() {
        lock.lock()
        _viable = false
        lock.unlock()
        continuation.finish()
    }

    func send(_ data: Data) async throws {
        lock.lock(); sentCount += 1; lock.unlock()
    }

    func close() { kill() }
}

final class ReconnectTests: XCTestCase {

    private let clientPriv = Data(repeating: 0x33, count: 32)
    private let serverPriv = Data(repeating: 0x44, count: 32)

    private func makeClient(_ transport: KillableTransport) throws -> FudpClient {
        try FudpClient(
            transport: transport,
            host: "127.0.0.1",
            port: 1,
            peerPubkey: Secp256k1.publicKey(fromPrivateKey: serverPriv),
            localPrivkey: clientPriv
        )
    }

    // MARK: - liveness

    func testClientIsAliveUntilTransportDies() throws {
        let transport = KillableTransport()
        let client = try makeClient(transport)
        defer { client.close() }

        XCTAssertTrue(client.isAlive)
        transport.kill()
        XCTAssertFalse(client.isAlive)
    }

    func testClosedClientIsNotAlive() throws {
        let client = try makeClient(KillableTransport())
        client.close()
        XCTAssertFalse(client.isAlive)
    }

    /// The bug this whole change exists for: once the pump's stream
    /// ended, the mailbox was finished, so every later `receive`
    /// returned nil *immediately* and got reported as a timeout — which
    /// reads as "the server is slow" when it actually means "this socket
    /// is dead, rebuild it".
    func testDeadTransportReportsConnectionLostNotTimeout() async throws {
        let transport = KillableTransport()
        let client = try makeClient(transport)
        defer { client.close() }

        transport.kill()
        // Let the pump observe the stream ending.
        try await Task.sleep(nanoseconds: 50_000_000)

        do {
            _ = try await client.receive(matching: 42, timeoutMs: 500)
            XCTFail("expected a failure from a dead transport")
        } catch let failure as FudpClient.Failure {
            guard case .transportClosed = failure else {
                return XCTFail("expected .transportClosed, got \(failure)")
            }
        }
    }

    // MARK: - reconnecting client

    /// Factory over `KillableTransport`s, counting builds and keeping
    /// each transport so a test can kill it.
    private final class FactorySpy: @unchecked Sendable {
        private let lock = NSLock()
        private(set) var transports: [KillableTransport] = []
        private let build: (KillableTransport) throws -> FudpClient

        var buildCount: Int {
            lock.lock(); defer { lock.unlock() }
            return transports.count
        }

        var newest: KillableTransport? {
            lock.lock(); defer { lock.unlock() }
            return transports.last
        }

        init(build: @escaping (KillableTransport) throws -> FudpClient) {
            self.build = build
        }

        func make() throws -> FudpClient {
            let transport = KillableTransport()
            lock.lock(); transports.append(transport); lock.unlock()
            return try build(transport)
        }
    }

    private func makeSpy() -> FactorySpy {
        FactorySpy { [self] transport in try makeClient(transport) }
    }

    /// Every call fails (nothing answers the fake socket) — the point
    /// is which transport it failed on, not that it succeeded.
    @discardableResult
    private func attemptCall(_ client: ReconnectingFapiClient) async -> Error? {
        do {
            _ = try await client.call(
                api: "base.ping", params: nil, fcdsl: nil, binary: nil,
                sid: nil, via: nil, maxCost: nil, timeoutMs: 150
            )
            return nil
        } catch {
            return error
        }
    }

    func testHealthyTransportIsReusedAcrossCalls() async throws {
        let spy = makeSpy()
        let client = ReconnectingFapiClient(factory: { try spy.make() })
        defer { client.close() }

        await attemptCall(client)
        await attemptCall(client)

        XCTAssertEqual(spy.buildCount, 1, "a healthy transport must not be rebuilt")
    }

    func testInitialTransportIsUsedWithoutBuilding() async throws {
        let spy = makeSpy()
        let initial = try makeClient(KillableTransport())
        let client = ReconnectingFapiClient(factory: { try spy.make() }, initial: initial)
        defer { client.close() }

        await attemptCall(client)

        XCTAssertEqual(spy.buildCount, 0, "the supplied transport should be used as-is")
    }

    func testDeadTransportIsRebuiltOnNextCall() async throws {
        let spy = makeSpy()
        let client = ReconnectingFapiClient(factory: { try spy.make() })
        defer { client.close() }

        await attemptCall(client)
        XCTAssertEqual(spy.buildCount, 1)

        spy.newest?.kill()   // sleep/wake: the socket is gone
        await attemptCall(client)

        XCTAssertEqual(spy.buildCount, 2, "a dead transport must be replaced")
    }

    /// The wake path: the OS can leave a UDP socket looking perfectly
    /// healthy while the flow is already dead on the far side, so a
    /// stale mark has to force the rebuild on its own.
    func testMarkStaleForcesRebuildEvenWhenTransportLooksHealthy() async throws {
        let spy = makeSpy()
        let client = ReconnectingFapiClient(factory: { try spy.make() })
        defer { client.close() }

        await attemptCall(client)
        XCTAssertEqual(spy.buildCount, 1)
        XCTAssertEqual(spy.newest?.isViable, true)

        client.markStale()
        await attemptCall(client)

        XCTAssertEqual(spy.buildCount, 2, "a stale mark must force a fresh socket")
    }

    func testConcurrentCallersShareOneRebuild() async throws {
        let spy = makeSpy()
        let client = ReconnectingFapiClient(factory: { try spy.make() })
        defer { client.close() }

        await withTaskGroup(of: Void.self) { group in
            for _ in 0..<8 {
                group.addTask { await self.attemptCall(client) }
            }
        }

        XCTAssertEqual(spy.buildCount, 1, "concurrent callers must not each open a socket")
    }

    func testClosedClientRefusesCalls() async throws {
        let spy = makeSpy()
        let client = ReconnectingFapiClient(factory: { try spy.make() })

        await attemptCall(client)
        client.close()

        // Refusal is synchronous — the call right after `close()`
        // must already be rejected.
        let error = await attemptCall(client)
        guard case .closed? = error as? ReconnectingFapiClient.Failure else {
            return XCTFail("expected .closed, got \(String(describing: error))")
        }
        XCTAssertEqual(spy.buildCount, 1, "a closed client must not open new sockets")
    }
}
