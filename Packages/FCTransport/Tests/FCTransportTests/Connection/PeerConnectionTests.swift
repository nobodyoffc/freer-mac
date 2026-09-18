import XCTest
import Network
@testable import FCTransport

final class PeerConnectionTests: XCTestCase {

    private let now0: Int64 = 1_700_000_000_000

    private let pubkey33 = Data(repeating: 0x02, count: 33)
    private let address: NWEndpoint = .hostPort(host: "127.0.0.1", port: 12345)

    private func makeConnection(
        connectionId: Int64 = 1,
        fid: String? = "FEsamplekey"
    ) throws -> PeerConnection {
        try PeerConnection(
            connectionId: connectionId,
            peerPubkey: pubkey33,
            peerAddress: address,
            peerFid: fid,
            nowMs: now0
        )
    }

    // MARK: - construction

    func testInitialState() throws {
        let conn = try makeConnection()
        XCTAssertEqual(conn.state, .idle)
        XCTAssertEqual(conn.nextPacketNumberPreview, 0)
        XCTAssertEqual(conn.largestSentPacketNumber, -1)
        XCTAssertEqual(conn.largestAckedPacketNumber, -1)
        XCTAssertEqual(conn.peerSessionEpoch, 0)
        XCTAssertFalse(conn.ourEpochConfirmed)
        XCTAssertTrue(conn.isOpen)
        XCTAssertEqual(conn.lastActivityMs, now0)
    }

    func testRejectsBadPubkeyLength() {
        XCTAssertThrowsError(
            try PeerConnection(
                connectionId: 1,
                peerPubkey: Data(repeating: 0x02, count: 32),
                peerAddress: address
            )
        )
    }

    // MARK: - state machine

    func testValidTransitions() throws {
        let conn = try makeConnection()
        try conn.transition(to: .establishing)
        XCTAssertEqual(conn.state, .establishing)
        try conn.transition(to: .established)
        XCTAssertEqual(conn.state, .established)
        try conn.transition(to: .closing)
        XCTAssertEqual(conn.state, .closing)
        try conn.transition(to: .closed)
        XCTAssertEqual(conn.state, .closed)
        XCTAssertFalse(conn.isOpen)
    }

    func testIdleCanGoStraightToClosed() throws {
        let conn = try makeConnection()
        try conn.transition(to: .closed)
        XCTAssertFalse(conn.isOpen)
    }

    func testInvalidTransitionsRejected() throws {
        let conn = try makeConnection()
        // idle → established (must go through establishing)
        XCTAssertThrowsError(try conn.transition(to: .established))
        // closed is terminal
        try conn.transition(to: .closed)
        XCTAssertThrowsError(try conn.transition(to: .establishing))
        XCTAssertThrowsError(try conn.transition(to: .established))
    }

    func testNoSelfLoops() throws {
        let conn = try makeConnection()
        try conn.transition(to: .establishing)
        XCTAssertThrowsError(try conn.transition(to: .establishing))
    }

    // MARK: - packet numbers

    func testNextPacketNumberIncrements() throws {
        let conn = try makeConnection()
        XCTAssertEqual(conn.nextPacketNumber(), 0)
        XCTAssertEqual(conn.nextPacketNumber(), 1)
        XCTAssertEqual(conn.nextPacketNumber(), 2)
        XCTAssertEqual(conn.nextPacketNumberPreview, 3)
        XCTAssertEqual(conn.largestSentPacketNumber, 2)
    }

    func testRecordPeerAckMonotonic() throws {
        let conn = try makeConnection()
        conn.recordPeerAck(largestAcked: 5)
        XCTAssertEqual(conn.largestAckedPacketNumber, 5)
        // Stale ack must not roll back.
        conn.recordPeerAck(largestAcked: 3)
        XCTAssertEqual(conn.largestAckedPacketNumber, 5)
        conn.recordPeerAck(largestAcked: 10)
        XCTAssertEqual(conn.largestAckedPacketNumber, 10)
    }

    // MARK: - session epoch

    /// **The epoch is drawn at random, so it is set once and not
    /// updated.** FUDP4V1 makes it a random 64-bit value the peer picks
    /// at startup, which means a second, different epoch is not "newer"
    /// — it is either a restart, which the replay window detects and
    /// handles, or a delayed packet carrying the old one. Taking every
    /// epoch as it came let the second case overwrite the first.
    ///
    /// Both reference implementations store it only from zero:
    /// `if (incomingEpoch != 0 && conn.getSessionEpoch() == 0)`.
    func testThePeerEpochIsRecordedOnceAndNotOverwritten() throws {
        let conn = try makeConnection()
        XCTAssertEqual(conn.observePeerEpoch(0xAAAA), 0)
        XCTAssertEqual(conn.peerSessionEpoch, 0xAAAA)

        // A later packet carrying a different epoch still reports what
        // we held, but does not replace it.
        XCTAssertEqual(conn.observePeerEpoch(0xBBBB), 0xAAAA)
        XCTAssertEqual(
            conn.peerSessionEpoch, 0xAAAA,
            "a delayed packet's epoch must not displace the established one"
        )

        // Zero is the wire's "unknown or omitted" and is never stored.
        XCTAssertEqual(conn.observePeerEpoch(0), 0xAAAA)
        XCTAssertEqual(conn.peerSessionEpoch, 0xAAAA)

        // A handled restart clears it, and the next packet establishes
        // the new one.
        conn.clearPeerEpoch()
        XCTAssertEqual(conn.peerSessionEpoch, 0)
        XCTAssertEqual(conn.observePeerEpoch(0xBBBB), 0)
        XCTAssertEqual(conn.peerSessionEpoch, 0xBBBB)
    }

    /// The peer's connection ID is the primary routing key (FUDP1V1),
    /// and a *change* means the peer rebuilt its connection — a reason
    /// to reset our receive state, never to reject the packet.
    func testAChangedRemoteConnectionIdIsReported() throws {
        let conn = try makeConnection()
        XCTAssertNil(conn.remoteConnectionId)
        XCTAssertFalse(conn.observeRemoteConnectionId(77), "the first binding is not a change")
        XCTAssertEqual(conn.remoteConnectionId, 77)
        XCTAssertFalse(conn.observeRemoteConnectionId(77), "the same id is not a change")
        XCTAssertTrue(conn.observeRemoteConnectionId(78), "a different id is the peer rebuilding")
        XCTAssertEqual(conn.remoteConnectionId, 78)
    }

    func testEpochConfirmationFlag() throws {
        let conn = try makeConnection()
        XCTAssertFalse(conn.ourEpochConfirmed)
        conn.markOurEpochConfirmed()
        XCTAssertTrue(conn.ourEpochConfirmed)
    }

    // MARK: - activity

    func testTouchUpdatesLastActivity() throws {
        let conn = try makeConnection()
        conn.touch(nowMs: now0 + 5_000)
        XCTAssertEqual(conn.lastActivityMs, now0 + 5_000)
    }

    func testNextPacketNumberAlsoTouches() throws {
        let conn = try makeConnection()
        _ = conn.nextPacketNumber(nowMs: now0 + 1_000)
        XCTAssertEqual(conn.lastActivityMs, now0 + 1_000)
    }
}
