import XCTest
import FCCore
@testable import FCDomain

/// VOICE_SPEC §3.2–§3.3: the signals parse what Android sends and send what it parses.
final class CallSignalsTests: XCTestCase {

    static let callId = "00112233445566778899aabbccddeeff"
    static let delegationJson = """
    {"fid":"FUc4YfApTPiCC2dRLNDLvUPB4RhYq2Ffar","fidPub":"02778a1f5cb30074fde9f69be4b208ab1d93149acdc2152b4ed27f6738cd56f12b",\
    "tPub":"031a5ef517babfd12c61a6f56117d5d1c59ee4a5b3d4192bb643c0dce805fd9dc2","expiresSec":1790003600,\
    "sig":"629e307b3dc92dcbf08c4d5ac1fc0601f5c870b5077936472912a8baa9d7717e2c4cab9ae01833899076fee1f45f0289ab5cd1cac9b68236ecfe2c18485e2690"}
    """

    func testAnAndroidInviteParses() throws {
        // As Gson writes it: nulls left out, the delegation an object.
        let json = """
        {"op":"INVITE","callId":"\(Self.callId)","transportPub":"031a5ef517babfd12c61a6f56117d5d1c59ee4a5b3d4192bb643c0dce805fd9dc2",\
        "delegation":\(Self.delegationJson),"relay":{"url":"fudp://191.223.41.70:19950","pubkey":"02ab","sid":"s1"},\
        "expires":1790000045000,"codecs":["opus"]}
        """
        let s = try XCTUnwrap(CallSignal.fromJson(json))
        XCTAssertEqual(s.op, .INVITE)
        XCTAssertEqual(s.relay?.sid, "s1")
        XCTAssertEqual(s.delegation?.verify(callOrMeetingId: Self.callId, nowSec: 1790003600 - 60), .ok)
        XCTAssertEqual(CallSignal.fromJson(s.toJson()), s, "and it round-trips")
    }

    func testMalformedCallSignalsAreRefused() {
        XCTAssertNil(CallSignal.fromJson("{\"op\":\"INVITE\",\"callId\":\"\(Self.callId)\"}"), "an INVITE needs its keys")
        XCTAssertNil(CallSignal.fromJson("{\"op\":\"HANGUP\",\"callId\":\"short\"}"))
        XCTAssertNil(CallSignal.fromJson("{\"op\":\"MEETING_START\",\"callId\":\"\(Self.callId)\"}"), "not a 1:1 op")
        XCTAssertNotNil(CallSignal.fromJson("{\"op\":\"HANGUP\",\"callId\":\"\(Self.callId)\",\"duration\":5}"))
        XCTAssertNil(CallSignal.fromJson("{\"op\":\"REJECT\",\"callId\":\"\(Self.callId)\"}"), "a reject says why")
    }

    func testMeetingSignals() throws {
        let id = "mtg_00112233445566778899aabb"
        let start = MeetingSignal.start(meetingId: id, relay: .init(url: "fudp://r:1"), nonce: Data(repeating: 7, count: 32),
                                        symkeyVersion: 1_790_000_000, authPub: Data([2] + [UInt8](repeating: 1, count: 32)),
                                        keyEpoch: 0, title: "Weekly", startedMs: 42)
        XCTAssertEqual(MeetingSignal.fromJson(start.toJson()), start)
        let inv = MeetingSignal.invite(meetingId: id, entityId: "room_x", entityType: "ROOM", relay: .init(url: "fudp://r:1"),
                                       nonce: Data(repeating: 7, count: 32), authPub: Data([2] + [UInt8](repeating: 1, count: 32)),
                                       key: Data(repeating: 9, count: 32), title: nil, startedMs: 42)
        let back = try XCTUnwrap(MeetingSignal.fromJson(inv.toJson()))
        XCTAssertEqual(back.keyBytes, Data(repeating: 9, count: 32))
        XCTAssertEqual(back.symkeyVersion, MeetingSignal.invitedVersion)
        XCTAssertNil(back.withoutKey.key, "a card never holds the key")
        XCTAssertNil(MeetingSignal.fromJson(inv.toJson().replacingOccurrences(of: "\"ROOM\"", with: "\"SQUARE\"")))
        XCTAssertNil(MeetingSignal.fromJson(MeetingSignal.end(meetingId: "mtg_short", durationMs: 1).toJson()))
        // Android's MEETING_END: only these fields.
        XCTAssertNotNil(MeetingSignal.fromJson("{\"op\":\"MEETING_END\",\"meetingId\":\"\(id)\",\"duration\":65000}"))
    }
}
