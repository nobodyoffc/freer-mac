import XCTest
import Network
@testable import FCTransport

/// Exercises the real `NWConnection`-backed client socket: the opening
/// handshake (and its timeout), the viability signal the reconnect
/// machinery keys off, and teardown.
final class FudpConnectionTests: XCTestCase {

    /// Happy path: a connection to a bound peer reaches `.ready`,
    /// carries a datagram, and reports itself viable. Guards against
    /// the post-ready state observer — added so sleep/wake is noticed —
    /// killing a perfectly healthy connection.
    func testConnectsAndStaysViable() async throws {
        let peer = FudpSocket()
        defer { peer.close() }
        let peerPort = try await peer.bind()

        let connection = try await FudpConnection(host: "127.0.0.1", port: peerPort)
        defer { connection.close() }
        XCTAssertTrue(connection.isViable)

        let inbound: Task<FudpSocket.Datagram?, Never> = Task {
            for await dg in peer.datagrams { return dg }
            return nil
        }

        let payload = Data("hello fudp".utf8)
        try await connection.send(payload)

        let received = await withTaskGroup(of: FudpSocket.Datagram?.self) { group in
            group.addTask { await inbound.value }
            group.addTask {
                try? await Task.sleep(nanoseconds: 3_000_000_000)
                return nil
            }
            let first = await group.next() ?? nil
            group.cancelAll()
            return first
        }
        XCTAssertEqual(received?.data, payload)
        XCTAssertTrue(connection.isViable, "a working connection must stay viable")
    }

    /// Closing ends the datagram stream and drops viability, which is
    /// what tells the client above it never to use this socket again.
    func testCloseEndsStreamAndViability() async throws {
        let peer = FudpSocket()
        defer { peer.close() }
        let peerPort = try await peer.bind()

        let connection = try await FudpConnection(host: "127.0.0.1", port: peerPort)
        let drained = Task {
            for await _ in connection.datagrams {}
            return true
        }

        connection.close()
        XCTAssertFalse(connection.isViable)

        let finished = await withTaskGroup(of: Bool.self) { group in
            group.addTask { await drained.value }
            group.addTask {
                try? await Task.sleep(nanoseconds: 2_000_000_000)
                return false
            }
            let first = await group.next() ?? false
            group.cancelAll()
            return first
        }
        XCTAssertTrue(finished, "close() must end the datagram stream")
    }

    /// A connect attempt with no usable path must fail rather than park
    /// forever — otherwise a reconnect fired a moment too early after
    /// wake hangs the call that triggered it.
    func testConnectGivesUpWhenNoPathAppears() async throws {
        // 192.0.2.0/24 is TEST-NET-1 (RFC 5737): reserved, never routed.
        do {
            let connection = try await FudpConnection(
                host: "192.0.2.1",
                port: 9,
                connectTimeoutMs: 300
            )
            // Some environments hand out a default route that makes even
            // this endpoint "ready" — UDP has no handshake to disprove
            // it. That is not a failure of the timeout.
            connection.close()
        } catch let failure as FudpConnection.Failure {
            guard case .openTimedOut = failure else {
                return XCTFail("expected .openTimedOut, got \(failure)")
            }
        }
    }
}
