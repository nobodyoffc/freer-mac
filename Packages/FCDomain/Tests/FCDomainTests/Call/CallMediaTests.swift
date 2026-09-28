import XCTest
import FCCore
@testable import FCDomain

/// CallMedia (VOICE_SPEC §5, §5.1), ported from Android's CallMediaTest:
/// sealing, opening, and catching audio passed off as someone else's.
final class CallMediaTests: XCTestCase {

    static let callId = "00112233445566778899aabbccddeeff"

    final class Party {
        let fid: String
        let tPriv = CallMediaTests.key()
        let tPub: Data
        let ssrc = UInt32.random(in: 0...UInt32.max)
        var media: CallMedia!
        init(_ fid: String) {
            self.fid = fid
            tPub = try! Secp256k1.publicKey(fromPrivateKey: tPriv)
        }
    }

    final class Events: CallMedia.Listener {
        var unverified: [String] = []
        var paused: [String] = []
        func unverified(fid: String, ssrc: UInt32) { unverified.append(fid) }
        func paused(fid: String, ssrc: UInt32, on: Bool) { paused.append(fid + (on ? " paused" : " resumed")) }
    }

    static func key() -> Data { Data((0..<32).map { _ in UInt8.random(in: 0...255) }) }

    var now: Int64 = 1_000_000
    var secret = key()
    var alice = Party("FAlice"), bob = Party("FBob"), carol = Party("FCarol")
    let events = Events()

    override func setUp() {
        for p in [alice, bob, carol] {
            p.media = CallMedia(callId: Self.callId, callSecret: secret, myFid: p.fid, mySsrc: p.ssrc, tPriv: p.tPriv)
            p.media.setRouteId(p.ssrc ^ 0x5A5A_5A5A)
        }
        bob.media.listener = events
        for p in [alice, bob, carol] { for q in [alice, bob, carol] where p !== q { p.media.addPeer(fid: q.fid, ssrc: q.ssrc, tPub: q.tPub) } }
    }

    func frame(_ p: Party, _ seq: UInt64) throws -> Data {
        try p.media.seal(seq: seq, timestamp: UInt32(seq * 960), level: 30, voiceActive: true, afterDtx: false,
                         opus: Data([UInt8(truncatingIfNeeded: seq), 1, 2]), nowMs: now)
    }

    func testFramesOpenOnlyForTheRightPeerAndOnlyOnce() throws {
        let wire = try frame(alice, 0)
        XCTAssertEqual(bob.media.open(wire, nowMs: now)?.opus, Data([0, 1, 2]))
        XCTAssertNil(bob.media.open(wire, nowMs: now), "a replay")
        let stranger = CallMedia(callId: Self.callId, callSecret: secret, myFid: "FDave", mySsrc: 1, tPriv: Self.key())
        XCTAssertNil(stranger.open(try frame(alice, 1), nowMs: now), "an ssrc not in the roster")
    }

    func testHonestAudioIsVouchedForAndKeepsPlaying() throws {
        for seq in UInt64(0)..<25 { XCTAssertNotNil(bob.media.open(try frame(alice, seq), nowMs: now)); now += 40 }
        let att = alice.media.takeAttestations(nowMs: now)
        XCTAssertEqual(att.count, 1)
        bob.media.onAttestation(att[0], nowMs: now)
        now += 5_000
        bob.media.tick(nowMs: now)
        XCTAssertTrue(events.unverified.isEmpty && events.paused.isEmpty)
    }

    func testAMemberPassingOffAudioAsAnothersIsCaught() throws {
        let aliceKey = CallKeys.senderKey(callSecret: secret, fid: alice.fid, ssrc: alice.ssrc, keyEpoch: 0)
        let forged = try MediaFrame.seal(senderKey: aliceKey, header: .init(flags: MediaFrame.flagVad,
            routeId: alice.ssrc ^ 0x5A5A_5A5A, ssrc: alice.ssrc, seq: 3, timestamp: 3 * 960, level: 20, keyEpoch: 0),
                                         payload: Data([9, 9, 9]))
        for seq in UInt64(0)..<3 { _ = bob.media.open(try frame(alice, seq), nowMs: now) }
        XCTAssertNotNil(bob.media.open(forged, nowMs: now), "it plays at first")
        _ = try frame(alice, 3) // Alice's real frame 3
        now += 1_000
        for a in alice.media.takeAttestations(nowMs: now) { bob.media.onAttestation(a, nowMs: now) }
        XCTAssertEqual(events.unverified, [alice.fid])
        XCTAssertNil(bob.media.open(try frame(alice, 4), nowMs: now), "silent for the rest of the join")
    }

    func testALateAttestationPausesAndAMatchingOneResumes() throws {
        XCTAssertNotNil(bob.media.open(try frame(alice, 0), nowMs: now))
        now += CallMedia.attestDeadlineMs
        bob.media.tick(nowMs: now)
        XCTAssertEqual(events.paused, ["FAlice paused"])
        XCTAssertNil(bob.media.open(try frame(alice, 1), nowMs: now), "held, not played")
        now += 5_000
        bob.media.tick(nowMs: now)
        for a in alice.media.finish(nowMs: now) { bob.media.onAttestation(a, nowMs: now) }
        XCTAssertEqual(events.paused, ["FAlice paused", "FAlice resumed"])
        XCTAssertNotNil(bob.media.open(try frame(alice, 2), nowMs: now))
    }

    func testInAOneToOneCallALateAttestationSilencesNoOne() throws {
        bob.media.setOneToOne(true)
        for seq in UInt64(0)..<25 { _ = bob.media.open(try frame(alice, seq), nowMs: now) }
        bob.media.tick(nowMs: now + 10_000)
        XCTAssertFalse(bob.media.isPaused(ssrc: alice.ssrc) || bob.media.isUnverified(ssrc: alice.ssrc))
    }

    func testFramesOnTheDirectConnectionNeedNoAttestation() throws {
        for seq in UInt64(0)..<25 { XCTAssertNotNil(bob.media.open(try frame(alice, seq), nowMs: now, fromPeerConnection: true)) }
        bob.media.tick(nowMs: now + 10_000)
        XCTAssertFalse(bob.media.isPaused(ssrc: alice.ssrc))
    }

    func testARekeyWaitsForEveryoneThenTheOldEpochLapses() throws {
        let next = Self.key()
        alice.media.rekey(secret: next, keyEpoch: 1, nowMs: now)
        bob.media.rekey(secret: next, keyEpoch: 1, nowMs: now)
        let behind = CallMedia(callId: Self.callId, callSecret: secret, myFid: "FDave", mySsrc: 77, tPriv: Self.key())
        behind.addPeer(fid: alice.fid, ssrc: alice.ssrc, tPub: alice.tPub)
        let held = try frame(alice, 0)
        XCTAssertEqual(MediaFrame.Header.parse(held)?.keyEpoch, 0, "not sent under the new key yet")
        XCTAssertNotNil(behind.open(held, nowMs: now))
        alice.media.switchSending(nowMs: now)
        let fresh = try frame(alice, 1)
        XCTAssertEqual(MediaFrame.Header.parse(fresh)?.keyEpoch, 1)
        XCTAssertNotNil(bob.media.open(fresh, nowMs: now))
        XCTAssertNil(behind.open(fresh, nowMs: now))
    }

    func testDtxGapsAttestWithZeroDigestsAndLongSilenceStartsANewWindow() throws {
        for seq: UInt64 in [0, 1, 5] { _ = try frame(alice, seq) }
        _ = try frame(alice, 500) // 20 s of DTX later
        now += 1_000
        let att = alice.media.takeAttestations(nowMs: now).compactMap(Attestation.parse)
        XCTAssertEqual(att.count, 2)
        XCTAssertEqual(att[0].lastSeq, 5)
        XCTAssertEqual(att[0].digests[2], Data(count: 8), "seq 2 was not sent")
        XCTAssertEqual(att[1].firstSeq, 500)
    }
}
