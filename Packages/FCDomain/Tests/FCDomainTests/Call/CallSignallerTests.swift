import XCTest
import FCCore
@testable import FCDomain

/// CallSignaller (VOICE_SPEC §3.2), ported from Android's CallSignallerTest:
/// devices of several FIDs wired together by an in-memory wire, where every
/// device of a FID receives what is sent to it.
final class CallSignallerTests: XCTestCase {

    var now: Int64 = 1_790_000_000_000
    var wire: [() -> Void] = []
    var devices: [String: [Device]] = [:]
    var nextId = 1

    final class Device: CallSignaller.Listener {
        let fid: String
        var signaller: CallSignaller!
        var records: [CallSignaller.CallRecord] = []
        var rang: [CallSignaller.Call] = []
        var ended: [CallSignaller.End] = []
        var answered: [CallSignaller.Call] = []

        init(_ t: CallSignallerTests, fidPriv: Data = CallMediaTests.key()) {
            fid = NobodyRegistry.fid(ofPubkeyHex: Hex.encode(try! Secp256k1.publicKey(fromPrivateKey: fidPriv)))!
            signaller = CallSignaller(myFid: fid, fidPriv: fidPriv, outbox: { [unowned t, fid] peer, s in
                let json = s.toJson()
                let id = String(t.nextId)
                t.nextId += 1
                t.wire.append { for d in t.devices[peer] ?? [] { d.signaller.onSignal(from: fid, messageId: id, CallSignal.fromJson(json)!) } }
            }, records: { [unowned self] _, r in self.records.append(r) }, clock: { [unowned t] in t.now })
            signaller.listener = self
            t.devices[fid, default: []].append(self)
        }

        func incoming(_ call: CallSignaller.Call) { rang.append(call) }
        func answered(_ call: CallSignaller.Call) { answered.append(call) }
        func ended(_ call: CallSignaller.Call, _ reason: CallSignaller.End) { ended.append(reason) }
    }

    func flush() {
        while !wire.isEmpty { wire.removeFirst()() }
    }

    func place(_ a: Device, _ b: Device) throws -> CallSignaller.Call {
        let c = try a.signaller.prepare(peerFid: b.fid, relayUrl: "fudp://relay:1")
        a.signaller.ring(callId: c.callId, relay: .init(url: "fudp://relay:1"))
        flush()
        return c
    }

    func testAnAnsweredCallGivesBothSidesTheSameKey() throws {
        let a = Device(self), b = Device(self)
        let c = try place(a, b)
        XCTAssertEqual(b.rang.count, 1)
        b.signaller.accept(callId: c.callId)
        flush()
        XCTAssertEqual(a.answered.count, 1)
        let ka = try XCTUnwrap(a.signaller.callSecret(callId: c.callId))
        XCTAssertEqual(ka, b.signaller.callSecret(callId: c.callId))
    }

    func testHangingUpEndsBothSidesWithTheDurationAndWipesTheKey() throws {
        let a = Device(self), b = Device(self)
        let c = try place(a, b)
        b.signaller.accept(callId: c.callId)
        flush()
        now += 65_000
        a.signaller.hangup(callId: c.callId)
        flush()
        XCTAssertEqual(a.ended, [.localHangup])
        XCTAssertEqual(b.ended, [.hungUp])
        XCTAssertEqual(a.records.last?.kind, .ENDED)
        XCTAssertEqual(a.records.last?.durationMs, 65_000)
        XCTAssertEqual(c.transportPriv, Data(count: 32), "§4.1: wiped")
    }

    func testDeclinedCancelledAndUnansweredCalls() throws {
        let a = Device(self), b = Device(self)
        var c = try place(a, b)
        b.signaller.reject(callId: c.callId)
        flush()
        XCTAssertEqual(a.ended.last, .declined)
        c = try place(a, b)
        a.signaller.cancel(callId: c.callId)
        flush()
        XCTAssertEqual(b.ended.last, .missed)
        c = try place(a, b)
        now += CallSignal.ringMs
        a.signaller.tick()
        flush()
        XCTAssertEqual(a.ended.last, .noAnswer)
        XCTAssertEqual(b.ended.last, .missed)
    }

    func testAnExpiredInviteIsAMissedCallAndABusyCalleeRejects() throws {
        let a = Device(self), b = Device(self), c = Device(self)
        let call = try a.signaller.prepare(peerFid: b.fid, relayUrl: nil)
        a.signaller.ring(callId: call.callId, relay: nil)
        now += CallSignal.ringMs + 1
        flush()
        XCTAssertTrue(b.rang.isEmpty)
        XCTAssertEqual(b.records.last?.kind, .MISSED)
        now -= CallSignal.ringMs + 1
        _ = try place(c, b)
        XCTAssertEqual(b.rang.count, 1)
        let d = Device(self) // A still rings out its own expired call, so another caller
        _ = try place(d, b)
        XCTAssertEqual(d.ended.last, .busy, "one call at a time")
    }

    func testTheSameSignalByThreeChannelsRingsOnceAndOtherDevicesStop() throws {
        let a = Device(self)
        let bKey = CallMediaTests.key()
        let b1 = Device(self, fidPriv: bKey), b2 = Device(self, fidPriv: bKey)
        let c = try a.signaller.prepare(peerFid: b1.fid, relayUrl: nil)
        a.signaller.ring(callId: c.callId, relay: nil)
        let invite = wire[0]
        invite(); invite()
        flush()
        XCTAssertEqual(b1.rang.count, 1)
        XCTAssertEqual(b2.rang.count, 1)
        b1.signaller.accept(callId: c.callId)
        flush()
        XCTAssertEqual(b2.ended, [.answeredElsewhere])
        XCTAssertTrue(b1.ended.isEmpty, "the device that answered ignores it")
    }

    func testAnInviteWithSomeoneElsesDelegationDoesNotRing() throws {
        let a = Device(self), b = Device(self), mallory = Device(self)
        let c = try a.signaller.prepare(peerFid: b.fid, relayUrl: nil)
        let forged = CallSignal.invite(callId: c.callId, tPub: c.tPub, delegation: c.myDelegation, relay: nil, nowMs: now)
        b.signaller.onSignal(from: mallory.fid, messageId: "x", forged)
        XCTAssertTrue(b.rang.isEmpty)
    }

    func testAKnockAnswersWhenTheAcceptIsSlow() throws {
        let a = Device(self), b = Device(self)
        let c = try place(a, b)
        b.signaller.accept(callId: c.callId)
        let bCall = try XCTUnwrap(b.signaller.call(c.callId))
        wire.removeAll() // the ACCEPT is lost on the way
        a.signaller.onKnock(callId: c.callId, delegation: bCall.myDelegation)
        XCTAssertEqual(a.answered.count, 1)
        XCTAssertEqual(a.signaller.callSecret(callId: c.callId), b.signaller.callSecret(callId: c.callId))
    }
}
