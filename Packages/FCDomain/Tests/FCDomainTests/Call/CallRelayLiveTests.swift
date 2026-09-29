import XCTest
import FCCore
import FCTransport
@testable import FCDomain

/// A meeting's network path against a real CALL relay, as the Mac runs it:
/// CallRelayLink and CallMedia, minus audio devices and IM. Runs only when
/// CALL_RELAY names a relay, e.g. `CALL_RELAY=fudp://191.223.41.70:19950`.
final class CallRelayLiveTests: XCTestCase {

    final class Member: CallRelayLink.Events {
        let fidPriv = CallMediaTests.key(), tPriv = CallMediaTests.key()
        let tPub: Data
        let fid: String
        let ssrc = UInt32.random(in: 0...UInt32.max)
        var link: CallRelayLink!
        var media: CallMedia!
        let lock = NSLock()
        var frames: [Data] = []
        var opened = 0
        var notices: [[String: Any]] = []

        init() {
            tPub = try! Secp256k1.publicKey(fromPrivateKey: tPriv)
            fid = NobodyRegistry.fid(ofPubkeyHex: Hex.encode(try! Secp256k1.publicKey(fromPrivateKey: fidPriv)))!
        }

        /// Opened on arrival, as the app does, so an attestation finds its frames already played.
        func frame(_ datagram: Data) {
            let ok = media?.open(datagram, nowMs: Int64(Date().timeIntervalSince1970 * 1000)) != nil
            lock.withLock {
                frames.append(datagram)
                if ok { opened += 1 }
            }
        }
        func attestation(_ bytes: Data) { media?.onAttestation(bytes, nowMs: Int64(Date().timeIntervalSince1970 * 1000)) }
        func notice(_ notice: [String: Any]) { lock.withLock { notices.append(notice) } }
    }

    func testAMeetingThroughTheRelay() async throws {
        guard let relay = ProcessInfo.processInfo.environment["CALL_RELAY"] else {
            throw XCTSkip("set CALL_RELAY=fudp://host:port to run")
        }
        let meetingId = "mtg_" + Hex.encode(Data((0..<12).map { _ in UInt8.random(in: 0...255) }))
        let symkey = CallMediaTests.key(), nonce = CallMediaTests.key()
        let secret = try CallKeys.meetingSecret(symkey: symkey, nonce: nonce, entityId: "FTeamLive", symkeyVersion: 1,
                                                meetingId: meetingId)
        let authPriv = CallKeys.authPriv(callSecret: secret)
        let host = Member(), bob = Member()
        for m in [host, bob] {
            let d = try Delegation.sign(fidPriv: m.fidPriv, callOrMeetingId: meetingId, tPub: m.tPub,
                                        expiresSec: Int64(Date().timeIntervalSince1970) + 3600)
            m.link = CallRelayLink(tPriv: m.tPriv, callId: meetingId, delegation: d, events: m)
            try await m.link.connect(url: relay, pubkeyHex: nil, sid: nil)
            XCTAssertEqual(m.link.overTcp, CallRelayLink.udpBlockedForTesting, "UDP when it answers, TCP when it does not")
        }
        try await host.link.createMeeting(authPub: try CallKeys.authPub(authPriv: authPriv))
        var last: [String: Any] = [:]
        for m in [host, bob] {
            last = try await m.link.join(ssrc: m.ssrc, authPriv: authPriv)
            XCTAssertEqual(last["host"] as? String, host.fid, "the join names the host")
            m.media = CallMedia(callId: meetingId, callSecret: secret, myFid: m.fid, mySsrc: m.ssrc, tPriv: m.tPriv)
            m.media.setRouteId(UInt32((last["routeId"] as! NSNumber).uint32Value))
        }
        for m in [host, bob] {
            for e in CallRelayLink.roster(last) {
                guard let json = e["delegation"] as? String, let d = Delegation.fromJson(json),
                      d.verify(callOrMeetingId: meetingId, nowSec: Int64(Date().timeIntervalSince1970)) == .ok,
                      let ssrc = (e["ssrc"] as? NSNumber)?.uint32Value, ssrc != m.ssrc else { continue }
                m.media.addPeer(fid: d.fid, ssrc: ssrc, tPub: d.tPubBytes!)
            }
        }

        // The host speaks for a second and a half, attesting as it goes.
        for seq in UInt64(0)..<40 {
            let now = Int64(Date().timeIntervalSince1970 * 1000)
            let f = try host.media.seal(seq: seq, timestamp: UInt32(seq * 1920), level: 30, voiceActive: true,
                                        afterDtx: false, opus: Data([UInt8(truncatingIfNeeded: seq), 7]), nowMs: now)
            await host.link.sendFrame(f)
            for a in host.media.takeAttestations(nowMs: now) { await host.link.sendAttestation(a) }
            try await Task.sleep(nanoseconds: 40_000_000)
        }
        for a in host.media.finish(nowMs: Int64(Date().timeIntervalSince1970 * 1000)) { await host.link.sendAttestation(a) }
        try await Task.sleep(nanoseconds: 1_500_000_000)
        let opened = bob.lock.withLock { bob.opened }
        XCTAssertGreaterThanOrEqual(opened, 35, "Bob hears the host: \(opened) of 40")
        try await Task.sleep(nanoseconds: 2_000_000_000)
        bob.media.tick(nowMs: Int64(Date().timeIntervalSince1970 * 1000) + CallMedia.attestDeadlineMs)
        XCTAssertFalse(bob.media.isPaused(ssrc: host.ssrc), "the attestations came, by NOTIFY, and vouched for them")

        try await bob.link.hand(raised: true)
        try await Task.sleep(nanoseconds: 1_000_000_000)
        let handShown = host.lock.withLock { host.notices }.contains { n in
            n["type"] as? String == "roster" && CallRelayLink.roster(n).contains { $0["fid"] as? String == bob.fid && $0["hand"] as? Bool == true }
        }
        XCTAssertTrue(handShown, "the host's roster shows Bob's hand")

        try await host.link.control(action: "end", target: nil)
        try await Task.sleep(nanoseconds: 1_000_000_000)
        XCTAssertTrue(bob.lock.withLock { bob.notices }.contains { $0["type"] as? String == "ended" })
        for m in [host, bob] { m.link.close() }
    }

    private final class DirectEar: CallDirectPath.Listener, @unchecked Sendable {
        let up: XCTestExpectation
        init(_ up: XCTestExpectation) { self.up = up }
        func directUp() { up.fulfill() }
        func directDown() {}
        func directFrame(_ datagram: Data) {}
        func directAttestation(_ bytes: Data) {}
        func directLog(_ what: String) { print("direct:", what) }
    }

    /// A 1:1 call joined with candidates (§6.1, §6.2 steps 6-8): the relay
    /// passes each side's candidates to the other in the roster, and the two
    /// direct paths, on the same ports as the relay connections, come up.
    func testACallGoesDirectBesideTheRelay() async throws {
        guard let relay = ProcessInfo.processInfo.environment["CALL_RELAY"] else {
            throw XCTSkip("set CALL_RELAY=fudp://host:port to run")
        }
        let callId = Hex.encode(Data((0..<16).map { _ in UInt8.random(in: 0...255) }))
        let authPriv = CallKeys.authPriv(callSecret: CallMediaTests.key())
        let caller = Member(), callee = Member()
        var ports: [SharedUdpPort] = []
        defer { ports.forEach { $0.close() } }
        for m in [caller, callee] {
            let d = try Delegation.sign(fidPriv: m.fidPriv, callOrMeetingId: callId, tPub: m.tPub,
                                        expiresSec: Int64(Date().timeIntervalSince1970) + 3600)
            m.link = CallRelayLink(tPriv: m.tPriv, callId: callId, delegation: d, events: m)
            let port = try SharedUdpPort()
            ports.append(port)
            try await m.link.connect(url: relay, pubkeyHex: nil, sid: nil, over: port)
        }
        try await caller.link.create()
        _ = try await caller.link.join(ssrc: caller.ssrc, authPriv: nil, share: true)
        try await caller.link.register(authPub: try CallKeys.authPub(authPriv: authPriv))
        let joined = try await callee.link.join(ssrc: callee.ssrc, authPriv: authPriv, share: true)

        func candidates(of m: Member, in roster: [String: Any]) -> [CallDirectPath.Candidate] {
            let entry = CallRelayLink.roster(roster).first { ($0["ssrc"] as? NSNumber)?.uint32Value == m.ssrc }
            return (entry?["candidates"] as? [[String: Any]] ?? []).compactMap(CallDirectPath.Candidate.parse)
        }
        let ofCaller = candidates(of: caller, in: joined)
        XCTAssertFalse(ofCaller.isEmpty, "the callee's join result carries the caller's candidates")
        XCTAssertTrue(ofCaller.contains { $0.t == "map" }, "including the address the relay sees: \(ofCaller)")
        try await Task.sleep(nanoseconds: 500_000_000)
        let rosterAtCaller = caller.lock.withLock { caller.notices }.last { $0["type"] as? String == "roster" } ?? [:]
        let ofCallee = candidates(of: callee, in: rosterAtCaller)
        XCTAssertFalse(ofCallee.isEmpty, "the caller's roster notice carries the callee's candidates")

        let upA = expectation(description: "caller's path up"), upB = expectation(description: "callee's path up")
        let earA = DirectEar(upA), earB = DirectEar(upB)
        let callerFirst = caller.fid < callee.fid
        let a = try CallDirectPath(port: ports[0], tPriv: caller.tPriv, peerTPub: callee.tPub, initiator: callerFirst,
                                   candidates: ofCallee, listener: earA)
        let b = try CallDirectPath(port: ports[1], tPriv: callee.tPriv, peerTPub: caller.tPub, initiator: !callerFirst,
                                   candidates: ofCaller, listener: earB)
        a.start()
        b.start()
        await fulfillment(of: [upA, upB], timeout: 8)
        a.stop()
        b.stop()
        for m in [caller, callee] {
            await m.link.leave()
            m.link.close()
        }
    }

    /// On a network that drops every UDP reply (§11.1), the links fall back to
    /// FUDP over TCP, and a meeting runs over it as it does over UDP.
    func testAMeetingOverTcpWhenUdpGetsNoAnswer() async throws {
        guard ProcessInfo.processInfo.environment["CALL_RELAY"] != nil else {
            throw XCTSkip("set CALL_RELAY=fudp://host:port to run")
        }
        CallRelayLink.udpBlockedForTesting = true
        defer { CallRelayLink.udpBlockedForTesting = false }
        try await testAMeetingThroughTheRelay()
    }
}
