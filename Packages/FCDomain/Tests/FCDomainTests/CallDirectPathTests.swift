import XCTest
import FCCore
import FCTransport
@testable import FCDomain

/// Two direct paths finding each other over loopback (VOICE_SPEC §6.2 steps
/// 6-8): punching, the lower FID opening, probes passing both ways, then a
/// frame and an attestation crossing.
final class CallDirectPathTests: XCTestCase {

    private final class Ear: CallDirectPath.Listener, @unchecked Sendable {
        let up: XCTestExpectation
        let frame: XCTestExpectation?
        let attestation: XCTestExpectation?
        init(up: XCTestExpectation, frame: XCTestExpectation? = nil, attestation: XCTestExpectation? = nil) {
            self.up = up
            self.frame = frame
            self.attestation = attestation
        }
        func directUp() { up.fulfill() }
        func directDown() {}
        func directFrame(_ datagram: Data) { if datagram == Data([0x01, 9, 9]) { frame?.fulfill() } }
        func directAttestation(_ bytes: Data) { if bytes == Data([0x02, 7]) { attestation?.fulfill() } }
        func directLog(_ what: String) { print("direct:", what) }
    }

    private func key() -> Data { Data((0..<32).map { _ in UInt8.random(in: 1...255) }) }

    func testTwoPathsPunchProbeAndCarryMedia() async throws {
        let pa = try SharedUdpPort(), pb = try SharedUdpPort()
        defer { pa.close(); pb.close() }
        let aPriv = key(), bPriv = key()
        let aPub = try Secp256k1.publicKey(fromPrivateKey: aPriv), bPub = try Secp256k1.publicKey(fromPrivateKey: bPriv)
        let aUp = expectation(description: "A up"), bUp = expectation(description: "B up")
        let bFrame = expectation(description: "B hears A's frame"), aAtt = expectation(description: "A gets B's attestation")
        let earA = Ear(up: aUp, attestation: aAtt), earB = Ear(up: bUp, frame: bFrame)
        let a = try CallDirectPath(port: pa, tPriv: aPriv, peerTPub: bPub, initiator: true,
                                   candidates: [.init(t: "lan", address: .init(host: "127.0.0.1", port: pb.localPort))],
                                   listener: earA)
        let b = try CallDirectPath(port: pb, tPriv: bPriv, peerTPub: aPub, initiator: false,
                                   candidates: [.init(t: "lan", address: .init(host: "127.0.0.1", port: pa.localPort))],
                                   listener: earB)
        a.start()
        b.start()
        await fulfillment(of: [aUp, bUp], timeout: 5)
        XCTAssertTrue(a.isUp && b.isUp)
        let sent = await a.send(Data([0x01, 9, 9]))
        XCTAssertTrue(sent)
        await b.sendAttestation(Data([0x02, 7]))
        await fulfillment(of: [bFrame, aAtt], timeout: 3)
        a.stop()
        b.stop()
    }

    func testCandidatesParseAndOnlyPrivateAddressesAreOffered() {
        XCTAssertEqual(CallDirectPath.Candidate.parse(["t": "map", "a": "1.2.3.4:5000"])?.address,
                       .init(host: "1.2.3.4", port: 5000))
        XCTAssertEqual(CallDirectPath.Candidate.parse(["t": "lan", "a": "[fd00::1]:7"])?.address.host, "fd00::1")
        XCTAssertNil(CallDirectPath.Candidate.parse(["t": "lan", "a": "nope"]))
        XCTAssertTrue(CallDirectPath.isPrivate("192.168.1.9"))
        XCTAssertTrue(CallDirectPath.isPrivate("172.20.0.1"))
        XCTAssertFalse(CallDirectPath.isPrivate("172.32.0.1"))
        XCTAssertFalse(CallDirectPath.isPrivate("8.8.8.8"))
        XCTAssertTrue(CallDirectPath.isPrivate("fd12::3"))
        XCTAssertFalse(CallDirectPath.isPrivate("2001:db8::1"))
    }
}
