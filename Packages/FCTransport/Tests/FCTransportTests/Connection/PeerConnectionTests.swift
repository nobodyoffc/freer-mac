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

    func testObservePeerEpochReturnsPrevious() throws {
        let conn = try makeConnection()
        XCTAssertEqual(conn.observePeerEpoch(0xAAAA), 0)
        XCTAssertEqual(conn.peerSessionEpoch, 0xAAAA)
        XCTAssertEqual(conn.observePeerEpoch(0xBBBB), 0xAAAA)
        XCTAssertEqual(conn.peerSessionEpoch, 0xBBBB)
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
