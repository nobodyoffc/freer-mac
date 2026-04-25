import XCTest
import Network
@testable import FCTransport

final class FudpSocketTests: XCTestCase {

    /// Two FudpSockets bound to ephemeral localhost ports exchange a
    /// datagram. Validates the full Network.framework path:
    ///   bind → listen → outbound NWConnection → send → inbound
    ///   newConnectionHandler → receiveMessage → AsyncStream yield.
    func testLoopbackRoundTrip() async throws {
        let receiver = FudpSocket()
        let sender = FudpSocket()
        defer {
            receiver.close()
            sender.close()
        }

        let receiverPort = try await receiver.bind()
        _ = try await sender.bind()
        XCTAssertGreaterThan(receiverPort, 0)

        // Drain one datagram off the receiver in a background task.
        let received: Task<FudpSocket.Datagram?, Never> = Task {
            for await dg in receiver.datagrams {
                return dg
            }
            return nil
        }

        // Send.
        let dest = NWEndpoint.hostPort(
            host: NWEndpoint.Host("127.0.0.1"),
            port: NWEndpoint.Port(rawValue: receiverPort)!
        )
        let payload = Data("hello fudp".utf8)
        try await sender.send(payload, to: dest)

        // Wait for receipt with a timeout.
        let dg = try await withThrowingTaskGroup(of: FudpSocket.Datagram?.self) { group in
            group.addTask { await received.value }
            group.addTask {
                try await Task.sleep(nanoseconds: 3_000_000_000)
                return nil
            }
            let first = try await group.next() ?? nil
            group.cancelAll()
            return first
        }

        XCTAssertNotNil(dg, "no datagram received within 3 s")
        XCTAssertEqual(dg?.data, payload)
    }

    /// Multiple datagrams from the same sender flow through the *same*
    /// inbound NWConnection (UDP semantics in Network.framework: one
    /// connection per remote endpoint).
    func testReceivesMultipleDatagramsFromSameSender() async throws {
        let receiver = FudpSocket()
        let sender = FudpSocket()
        defer {
            receiver.close()
            sender.close()
        }
        let port = try await receiver.bind()
        _ = try await sender.bind()

        let dest = NWEndpoint.hostPort(
            host: NWEndpoint.Host("127.0.0.1"),
            port: NWEndpoint.Port(rawValue: port)!
        )

        let collector: Task<[Data], Never> = Task {
            var collected: [Data] = []
            for await dg in receiver.datagrams {
                collected.append(dg.data)
                if collected.count == 3 { break }
            }
            return collected
        }

        try await sender.send(Data("one".utf8), to: dest)
        try await sender.send(Data("two".utf8), to: dest)
        try await sender.send(Data("three".utf8), to: dest)

        let collected = try await withThrowingTaskGroup(of: [Data]?.self) { group in
            group.addTask { await collector.value }
            group.addTask {
                try await Task.sleep(nanoseconds: 3_000_000_000)
                return nil
            }
            let first = try await group.next() ?? nil
            group.cancelAll()
            return first
        }

        guard let collected else {
            XCTFail("did not receive 3 datagrams within 3 s"); return
        }
        XCTAssertEqual(collected.count, 3)
        XCTAssertEqual(collected.map { String(data: $0, encoding: .utf8) },
                       ["one", "two", "three"])
    }

    func testSendBeforeBindThrows() async throws {
        let socket = FudpSocket()
        defer { socket.close() }
        let dest = NWEndpoint.hostPort(host: "127.0.0.1", port: 9999)
        do {
            try await socket.send(Data("x".utf8), to: dest)
            XCTFail("expected notBound")
        } catch FudpSocket.Failure.notBound {
            // expected
        } catch {
            XCTFail("wrong error: \(error)")
        }
    }

    func testDoubleBindThrows() async throws {
        let socket = FudpSocket()
        defer { socket.close() }
        _ = try await socket.bind()
        do {
            _ = try await socket.bind()
            XCTFail("expected alreadyBound")
        } catch FudpSocket.Failure.alreadyBound {
            // expected
        } catch {
            XCTFail("wrong error: \(error)")
        }
    }

    func testBindToSpecificPortReturnsThatPort() async throws {
        let socket = FudpSocket()
        defer { socket.close() }
        // Pick something likely-unused; if the port is in use we'd see
        // bindFailed. Re-running the suite is fine.
        let requested: UInt16 = 56789
        do {
            let actual = try await socket.bind(localPort: requested)
            XCTAssertEqual(actual, requested)
        } catch FudpSocket.Failure.bindFailed {
            // skip — port already in use; test environment limitation.
            throw XCTSkip("port \(requested) already in use")
        }
    }
}
