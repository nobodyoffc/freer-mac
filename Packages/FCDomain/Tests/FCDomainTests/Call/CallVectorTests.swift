import XCTest
import FCCore
@testable import FCDomain

/// VOICE_SPEC §4–§5 against `callVectors.json`, generated from FC-AJDK's
/// reference by tools/vector-gen: every value must reproduce exactly.
final class CallVectorTests: XCTestCase {

    private func vectors() throws -> [String: Any] {
        let url = try XCTUnwrap(Bundle.module.url(forResource: "callVectors", withExtension: "json"))
        return try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any])
    }

    private func h(_ o: [String: Any], _ k: String) throws -> Data {
        try XCTUnwrap(Hex.decodeOrNil(try XCTUnwrap(o[k] as? String)), k)
    }

    func testEveryVectorReproduces() throws {
        let v = try vectors()
        let keys = try XCTUnwrap(v["keys"] as? [String: Any])
        let fidPrivA = try h(keys, "fid_priv_a"), tPrivA = try h(keys, "t_priv_a"), tPrivB = try h(keys, "t_priv_b")
        let tPubA = try h(keys, "t_pub_a"), tPubB = try h(keys, "t_pub_b")
        let fidA = keys["fid_a"] as! String, fidB = keys["fid_b"] as! String, callId = keys["call_id"] as! String
        XCTAssertEqual(try Secp256k1.publicKey(fromPrivateKey: tPrivA), tPubA)

        let del = try XCTUnwrap(v["delegation"] as? [String: Any])
        let expires = (del["expires_sec"] as! NSNumber).int64Value
        let d = try Delegation.sign(fidPriv: fidPrivA, callOrMeetingId: callId, tPub: tPubA, expiresSec: expires)
        XCTAssertEqual(d.fid, fidA)
        XCTAssertEqual(d.toJson(), del["json"] as? String, "delegation JSON")
        XCTAssertEqual(Delegation.fromJson(del["json"] as! String)?.verify(callOrMeetingId: callId, nowSec: expires - 60), .ok)
        XCTAssertEqual(d.verify(callOrMeetingId: "another call", nowSec: expires - 60), .badSignature)

        let p2p = try CallKeys.p2pSecret(tPrivSelf: tPrivA, tPubPeer: tPubB, callIdHex: callId, fidA: fidA, fidB: fidB)
        XCTAssertEqual(Hex.encode(p2p), v["p2p_secret"] as? String)
        XCTAssertEqual(Hex.encode(try CallKeys.p2pSecret(tPrivSelf: tPrivB, tPubPeer: tPubA, callIdHex: callId,
                                                          fidA: fidB, fidB: fidA)), v["p2p_secret"] as? String)

        let m = try XCTUnwrap(v["meeting"] as? [String: Any])
        XCTAssertEqual(Hex.encode(try CallKeys.meetingSecret(symkey: try h(m, "symkey"), nonce: try h(m, "nonce"),
                                                             entityId: m["entity_id"] as! String,
                                                             symkeyVersion: (m["symkey_version"] as! NSNumber).uint64Value,
                                                             meetingId: m["meeting_id"] as! String)),
                       m["secret"] as? String)

        let sk = try XCTUnwrap(v["sender_key"] as? [String: Any])
        let ssrc = UInt32(sk["ssrc"] as! String)!
        XCTAssertEqual(Hex.encode(CallKeys.senderKey(callSecret: p2p, fid: fidA, ssrc: ssrc, keyEpoch: 0)), sk["epoch0"] as? String)
        XCTAssertEqual(Hex.encode(CallKeys.senderKey(callSecret: p2p, fid: fidA, ssrc: ssrc, keyEpoch: 1)), sk["epoch1"] as? String)
        XCTAssertEqual(Hex.encode(CallKeys.frameNonce(ssrc: ssrc, seq: 258)), sk["nonce_seq_258"] as? String)

        let ad = try XCTUnwrap(v["admission"] as? [String: Any])
        let authPriv = CallKeys.authPriv(callSecret: p2p)
        XCTAssertEqual(Hex.encode(authPriv), ad["auth_priv"] as? String)
        XCTAssertEqual(Hex.encode(try CallKeys.authPub(authPriv: authPriv)), ad["auth_pub"] as? String)
        let ts = (ad["ts_ms"] as! NSNumber).uint64Value
        XCTAssertEqual(Hex.encode(try CallKeys.admitSig(authPriv: authPriv, meetingId: callId, tPub: tPubB, ssrc: ssrc, tsMs: ts)),
                       ad["admit_sig"] as? String)
        XCTAssertTrue(CallKeys.verifyAdmit(authPub: try h(ad, "auth_pub"), meetingId: callId, tPub: tPubB, ssrc: ssrc, tsMs: ts,
                                           signature: try h(ad, "admit_sig")))

        let senderKey = CallKeys.senderKey(callSecret: p2p, fid: fidA, ssrc: ssrc, keyEpoch: 0)
        let mf = try XCTUnwrap(v["media_frame"] as? [String: Any])
        let header = try XCTUnwrap(MediaFrame.Header.parse(try h(mf, "frame")))
        XCTAssertEqual(Hex.encode(header.bytes), mf["header"] as? String)
        XCTAssertEqual(Hex.encode(try MediaFrame.seal(senderKey: senderKey, header: header, payload: try h(mf, "payload"))),
                       mf["frame"] as? String)
        XCTAssertEqual(MediaFrame.open(senderKey: senderKey, frame: try h(mf, "frame")), try h(mf, "payload"))
        var tampered = try h(mf, "frame")
        tampered[22] ^= 1 // the level byte: part of the AAD
        XCTAssertNil(MediaFrame.open(senderKey: senderKey, frame: tampered))

        let at = try XCTUnwrap(v["attestation"] as? [String: Any])
        let frames = (at["frames"] as! [String]).map { Hex.decodeOrNil($0)! }
        let a = try Attestation.sign(tPriv: tPrivA, callOrMeetingId: callId, routeId: 0x01020304, ssrc: ssrc, firstSeq: 258,
                                     frames: frames)
        XCTAssertEqual(Hex.encode(a.bytes), at["attestation"] as? String)
        let parsed = try XCTUnwrap(Attestation.parse(try h(at, "attestation")))
        XCTAssertTrue(parsed.verify(tPub: tPubA, callOrMeetingId: callId))
        XCTAssertFalse(parsed.verify(tPub: tPubB, callOrMeetingId: callId))
        for (i, f) in frames.enumerated() { XCTAssertEqual(parsed.digests[i], Attestation.digest(f)) }
    }

    func testTheReplayWindow() {
        var w = ReplayWindow()
        XCTAssertTrue(w.accept(5))
        XCTAssertFalse(w.accept(5), "a replay")
        XCTAssertTrue(w.accept(3), "late but new")
        XCTAssertTrue(w.accept(2000))
        XCTAssertFalse(w.accept(900), "older than the window")
        XCTAssertTrue(w.accept(1500))
    }
}
