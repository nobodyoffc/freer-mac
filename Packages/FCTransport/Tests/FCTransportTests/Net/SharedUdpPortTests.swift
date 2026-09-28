import XCTest
import FCCore
@testable import FCTransport

/// Two FUDP clients meeting over loopback on shared ports, one opening the
/// connection and one taking it from its first packet: the shape of a
/// call's direct path (VOICE_SPEC §6.2 steps 6-7).
final class SharedUdpPortTests: XCTestCase {

    private func key() -> Data { Data((0..<32).map { _ in UInt8.random(in: 1...255) }) }

    func testRoutesBySourceAndHandsTheRestToUnclaimed() throws {
        let a = try SharedUdpPort(), b = try SharedUdpPort()
        defer { a.close(); b.close() }
        let got = expectation(description: "unclaimed")
        b.unclaimed = { data, from in
            if data == Data([1, 2, 3]) && from.port == a.localPort { got.fulfill() }
        }
        try a.send(Data([1, 2, 3]), to: .init(host: "127.0.0.1", port: b.localPort))
        wait(for: [got], timeout: 2)
    }

    func testAnOpenerAndATakerExchangeDatagramsAndNotifies() async throws {
        let a = try SharedUdpPort(), b = try SharedUdpPort()
        defer { a.close(); b.close() }
        let aPriv = key(), bPriv = key()
        let aPub = try Secp256k1.publicKey(fromPrivateKey: aPriv), bPub = try Secp256k1.publicKey(fromPrivateKey: bPriv)

        // B takes the connection from the first packet that names A's key.
        let taken = LockedBox<FudpClient?>(nil)
        let bGot = expectation(description: "B hears a datagram")
        b.unclaimed = { data, from in
            guard taken.value == nil, AsyTwoWay.senderPubkey(inBundle: Data(data.dropFirst(PacketHeader.size))) == aPub else { return }
            let ch = b.channel(to: from)
            guard let client = try? FudpClient(over: ch, host: from.host, port: from.port, peerPubkey: aPub, localPrivkey: bPriv) else { return }
            client.enableDatagrams()
            client.setDatagramHandler { _, _, d in if d == Data("hi b".utf8) { bGot.fulfill() } }
            taken.value = client
            ch.inject(data)
        }

        let bAddr = SharedUdpPort.Address(host: "127.0.0.1", port: b.localPort)
        let opener = try FudpClient(over: a.channel(to: bAddr), host: bAddr.host, port: bAddr.port,
                                    peerPubkey: bPub, localPrivkey: aPriv)
        opener.enableDatagrams()
        let aGot = expectation(description: "A hears a datagram")
        let aNotified = expectation(description: "A gets a notify")
        opener.setDatagramHandler { _, _, d in if d == Data("hi a".utf8) { aGot.fulfill() } }
        opener.setNotifyHandler { type, d in if type == 0 && d == Data("att".utf8) { aNotified.fulfill() } }

        _ = await opener.sendDatagram(Data("hi b".utf8))
        await fulfillment(of: [bGot], timeout: 3)
        let taker = try XCTUnwrap(taken.value)
        _ = await taker.sendDatagram(Data("hi a".utf8))
        try await taker.sendNotify(Data("att".utf8), dataType: 0)
        await fulfillment(of: [aGot, aNotified], timeout: 3)
        opener.close()
        taker.close()
    }
}

final class LockedBox<T>: @unchecked Sendable {
    private let lock = NSLock()
    private var _value: T
    init(_ value: T) { _value = value }
    var value: T {
        get { lock.withLock { _value } }
        set { lock.withLock { _value = newValue } }
    }
}
