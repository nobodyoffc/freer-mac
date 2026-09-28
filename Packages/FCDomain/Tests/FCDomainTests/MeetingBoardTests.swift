import XCTest
import FCCore
@testable import FCDomain

final class MeetingBoardTests: XCTestCase {

    private let id = MeetingSignal.idPrefix + String(repeating: "ab", count: 12)
    private let relay = CallSignal.Relay(url: "fudp://relay.example:8500")

    private func start(epoch: Int64, authPub: String) -> MeetingSignal {
        MeetingSignal(op: .MEETING_START, meetingId: id, relay: relay, nonce: String(repeating: "11", count: 32),
                      symkeyVersion: UInt64(1 + epoch), authPub: authPub, keyEpoch: epoch, title: "t", started: 1000)
    }

    func testStartThenRekeyThenEnd() {
        var saved: Data?
        let board = MeetingBoard(load: { nil }, save: { saved = $0 })
        XCTAssertEqual(board.onStart(entityId: "room1", entityType: "ROOM", senderFid: "host", start(epoch: 0, authPub: "02aa")), .new)
        XCTAssertEqual(board.onStart(entityId: "room1", entityType: "ROOM", senderFid: "host", start(epoch: 0, authPub: "02aa")), .unchanged)
        // The same id in another entity is not this meeting.
        XCTAssertEqual(board.onStart(entityId: "room2", entityType: "ROOM", senderFid: "x", start(epoch: 1, authPub: "02bb")), .unchanged)
        XCTAssertEqual(board.onStart(entityId: "room1", entityType: "ROOM", senderFid: "member", start(epoch: 1, authPub: "02bb")), .updated)
        XCTAssertEqual(board.get(id)?.newestKeys?.keyEpoch, 1)
        XCTAssertEqual(board.get(id)?.hostFid, "host")
        XCTAssertEqual(board.open(entityId: "room1").count, 1)

        // Only the host's end counts at once; anyone else's is checked with the relay.
        XCTAssertEqual(board.onEnd(entityId: "room1", senderFid: "member", .end(meetingId: id, durationMs: 5)), .confirm)
        XCTAssertEqual(board.onEnd(entityId: "room1", senderFid: "host", .end(meetingId: id, durationMs: 5)), .updated)
        XCTAssertTrue(board.isEnded(id))
        XCTAssertEqual(board.open(entityId: "room1").count, 0)

        // It persists.
        let again = MeetingBoard(load: { saved }, save: { _ in })
        XCTAssertEqual(again.get(id)?.duration, 5)
        XCTAssertEqual(again.get(id)?.keys.count, 2)
    }

    func testInviteKeysByTheMeetingId() {
        let board = MeetingBoard(load: { nil }, save: { _ in })
        let invite = MeetingSignal.invite(meetingId: id, entityId: "team1", entityType: "TEAM", relay: relay,
                                          nonce: Data(repeating: 1, count: 32), authPub: Data(repeating: 2, count: 33),
                                          key: Data(repeating: 3, count: 32), title: nil, startedMs: 9)
        XCTAssertEqual(board.onInvite(hostFid: "host", invite), .new)
        XCTAssertEqual(board.onInvite(hostFid: "host", invite), .unchanged)
        let m = board.get(id)
        XCTAssertEqual(m?.invited, true)
        XCTAssertEqual(m?.keyEntity, id)
        XCTAssertEqual(m?.newestKeys?.symkeyVersion, MeetingSignal.invitedVersion)
    }

    func testSecretPicksTheKeyWhoseAuthPubMatches() throws {
        let nonce = Data(repeating: 7, count: 32)
        let right = Data(repeating: 5, count: 32), wrong = Data(repeating: 6, count: 32)
        let secret = try CallKeys.meetingSecret(symkey: right, nonce: nonce, entityId: "room1", symkeyVersion: 3, meetingId: id)
        let authPub = Hex.encode(try CallKeys.authPub(authPriv: CallKeys.authPriv(callSecret: secret)))
        XCTAssertEqual(MeetingKeys.secret(symkeys: [wrong, right], nonce: nonce, entityId: "room1", version: 3,
                                          meetingId: id, authPubHex: authPub), secret)
        XCTAssertNil(MeetingKeys.secret(symkeys: [wrong], nonce: nonce, entityId: "room1", version: 3,
                                        meetingId: id, authPubHex: authPub))
    }

    /// What Android's Gson writes for a card: nulls left out, the relay as a record.
    func testAndroidCardDecodes() {
        let json = #"{"op":"MEETING_START","meetingId":"mtg_269aa5e16822807257977aee","relay":{"url":"fudp://1.2.3.4:8500","pubkey":"02\#(String(repeating: "ab", count: 32))","sid":"s1"},"nonce":"\#(String(repeating: "11", count: 32))","symkeyVersion":2,"authPub":"03\#(String(repeating: "cd", count: 32))","keyEpoch":0,"started":1759044690000}"#
        let s = MeetingSignal.fromJson(json)
        XCTAssertEqual(s?.op, .MEETING_START)
        XCTAssertEqual(s?.relay?.sid, "s1")
        XCTAssertEqual(s?.symkeyVersion, 2)
    }
}
