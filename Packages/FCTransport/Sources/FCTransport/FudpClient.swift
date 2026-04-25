import Foundation
import Network
import FCCore

/// Minimal end-to-end FUDP client. Wires together every primitive in
/// FCTransport: socket → packet encode → AsyTwoWay seal → send;
/// receive → decode header → AsyTwoWay open → parse frames → emit
/// AppMessage. Handles a one-shot DDoS challenge if the server
/// demands it.
///
/// Designed for the simple "talk to one server" use case the Mac
/// client needs day one. Multi-peer routing, ACK-based retransmit,
/// and CUBIC congestion control are deferred — sending a request and
/// waiting for the matching response is enough for the FAPI flows
/// we need now.
public final class FudpClient: @unchecked Sendable {

    public struct ReceivedMessage: Sendable {
        public let envelope: AppMessageEnvelope
        public let senderPubkey: Data
    }

    public enum Failure: Error, CustomStringConvertible {
        case challengeFailed(underlying: Error)
        case timeout
        case unexpectedSenderPubkey(got: Data, expected: Data)
        case underlying(Error)

        public var description: String {
            switch self {
            case .challengeFailed(let e):                return "FudpClient: challenge failed — \(e)"
            case .timeout:                               return "FudpClient: timeout"
            case let .unexpectedSenderPubkey(got, exp):  return "FudpClient: peer pubkey mismatch (\(got.prefix(4).hex)…  vs \(exp.prefix(4).hex)…)"
            case .underlying(let e):                     return "FudpClient: \(e)"
            }
        }
    }

    public let connection: PeerConnection
    public let localPubkey: Data
    public let sessionEpoch: Int64

    /// When true, decode failures and unrecognised inbound packets are
    /// printed to stderr. Off by default; tests can flip it on for
    /// triage when interop fails.
    public var debugLogging: Bool = false

    private let transport: FudpConnection
    private let localPrivkey: Data
    private let challengeHandler: ChallengeHandler

    public init(
        host: String,
        port: UInt16,
        peerPubkey: Data,
        peerFid: String? = nil,
        localPrivkey: Data,
        connectionId: Int64 = Int64.random(in: 1...Int64.max),
        sessionEpoch: Int64 = Int64.random(in: 1...Int64.max),
        challengeHandler: ChallengeHandler = ChallengeHandler()
    ) async throws {
        self.localPrivkey = localPrivkey
        self.localPubkey = try Secp256k1.publicKey(fromPrivateKey: localPrivkey)
        let peerAddress: NWEndpoint = .hostPort(
            host: NWEndpoint.Host(host),
            port: NWEndpoint.Port(rawValue: port)!
        )
        self.connection = try PeerConnection(
            connectionId: connectionId,
            peerPubkey: peerPubkey,
            peerAddress: peerAddress,
            peerFid: peerFid
        )
        self.sessionEpoch = sessionEpoch
        self.challengeHandler = challengeHandler
        self.transport = try await FudpConnection(host: host, port: port)
    }

    @inline(__always)
    private func log(_ message: @autoclosure () -> String) {
        if debugLogging {
            FileHandle.standardError.write(Data(("[FudpClient] " + message() + "\n").utf8))
        }
    }

    // MARK: - send

    /// Encrypt and send a single AppMessage to the peer. Returns when the
    /// UDP write completes; the response (if any) is read separately via
    /// `nextReceived(timeoutMs:)`.
    public func send(_ envelope: AppMessageEnvelope) async throws {
        let messageBytes = AppMessageCodec.encode(envelope)
        let frame = StreamFrame(streamId: 0, offset: 0, data: messageBytes, fin: true)
        try await sendDataPacket(frames: [frame.encode()])
    }

    /// One-shot ping: builds + encrypts + sends a PING with a fresh
    /// `messageId`, then waits for a PONG matching that id. Returns the
    /// PONG. Throws `.timeout` if no matching PONG arrives in
    /// `timeoutMs`.
    @discardableResult
    public func ping(timeoutMs: Int = 3_000) async throws -> PongMessage {
        let messageId = Int64.random(in: 1...Int64.max)
        let pingTs = ReplayProtection.currentTimeMillis()
        try await send(AppMessageEnvelope(
            type: .ping,
            messageId: messageId,
            payload: PingMessage(timestamp: pingTs).payload()
        ))
        log("sent PING messageId=\(messageId) ts=\(pingTs)")

        let envelope = try await receive(
            matching: { $0.type == .pong && $0.messageId == messageId },
            timeoutMs: timeoutMs
        )
        return try PongMessage.parse(payload: envelope.payload)
    }

    /// Wait for the next inbound `AppMessageEnvelope` whose
    /// `messageId` equals `id`. Throws ``Failure/timeout`` if nothing
    /// matches in `timeoutMs`. Datagrams that fail to decode, that come
    /// from the wrong sender, or that don't match the predicate are
    /// dropped (logged when ``debugLogging`` is on).
    ///
    /// **Concurrency:** the underlying datagram stream is a single
    /// consumer source. Don't issue overlapping `receive` calls — they
    /// will race for arrivals. Phase 5 callers serialize at the
    /// FapiClient layer; multi-call multiplexing comes later if needed.
    public func receive(
        matching messageId: Int64,
        timeoutMs: Int = 3_000
    ) async throws -> AppMessageEnvelope {
        try await receive(matching: { $0.messageId == messageId }, timeoutMs: timeoutMs)
    }

    public func receive(
        matching predicate: @escaping @Sendable (AppMessageEnvelope) -> Bool,
        timeoutMs: Int = 3_000
    ) async throws -> AppMessageEnvelope {
        return try await withThrowingTaskGroup(of: AppMessageEnvelope.self) { group in
            group.addTask { [self] in
                for await datagram in self.transport.datagrams {
                    if Task.isCancelled { throw Failure.timeout }
                    self.log("rx datagram \(datagram.data.count) B")
                    let received: ReceivedMessage?
                    do {
                        received = try self.processDatagram(datagram.data)
                    } catch {
                        self.log("processDatagram threw: \(error)")
                        continue
                    }
                    guard let received else { continue }
                    self.log("got envelope type=\(received.envelope.type) id=\(received.envelope.messageId)")
                    if predicate(received.envelope) {
                        return received.envelope
                    }
                }
                throw Failure.timeout
            }
            group.addTask {
                try await Task.sleep(nanoseconds: UInt64(timeoutMs) * 1_000_000)
                throw Failure.timeout
            }
            defer { group.cancelAll() }
            return try await group.next()!
        }
    }

    private func processDatagram(_ data: Data) throws -> ReceivedMessage? {
        guard data.count >= PacketHeader.size else {
            log("datagram too short for header (\(data.count) B)")
            return nil
        }
        let header: PacketHeader
        do {
            header = try PacketHeader.decode(data)
        } catch {
            log("PacketHeader.decode failed: \(error)")
            return nil
        }
        log("hdr type=\(header.packetType) flags=0x\(String(header.flags.rawValue, radix: 16)) connId=\(header.connectionId) pktNum=\(header.packetNumber)")

        let body = Data(data.dropFirst(PacketHeader.size))

        switch header.packetType {
        case .control:
            try handleControlPacket(body: body)
            return nil
        case .data, .ack:
            return try handleEncryptedPacket(header: header, body: body)
        case .error:
            log("ERROR packet (ignored)")
            return nil
        }
    }

    private func handleControlPacket(body: Data) throws {
        // CHALLENGE control packet: type byte 0x03 at offset 0 of body.
        guard body.count >= ChallengePayload.length, body.first == ChallengePayload.typeByte else {
            return
        }
        let outcome: ChallengeHandler.Outcome
        do {
            outcome = try challengeHandler.handle(challengePayload: body)
        } catch {
            throw Failure.challengeFailed(underlying: error)
        }
        // Reply with a CONTROL packet wrapping the response payload.
        try sendControlPacket(payload: outcome.responsePayload)
    }

    private func handleEncryptedPacket(header: PacketHeader, body: Data) throws -> ReceivedMessage? {
        let aad = header.encode()
        let opened: (senderPubkey: Data, plaintext: Data)
        do {
            opened = try AsyTwoWay.open(bundle: body, aad: aad, localPrivkey: localPrivkey)
        } catch {
            log("AsyTwoWay.open failed: \(error)")
            return nil
        }
        log("decrypted \(opened.plaintext.count) B from sender pubkey=\(opened.senderPubkey.prefix(4).hex)…")

        guard opened.senderPubkey == connection.peerPubkey else {
            log("sender pubkey mismatch (got \(opened.senderPubkey.prefix(4).hex)… expected \(connection.peerPubkey.prefix(4).hex)…)")
            return nil
        }

        let parsed: ParsedPayload
        do {
            parsed = try FudpPayload.parse(
                opened.plaintext,
                hasTimestamp: header.flags.contains(.hasTimestamp),
                hasEpoch: header.flags.contains(.hasEpoch)
            )
        } catch {
            log("FudpPayload.parse failed: \(error)")
            return nil
        }
        log("payload ts=\(parsed.timestamp ?? -1) epoch=\(parsed.sessionEpoch ?? -1) frames=\(parsed.frames.count)")

        if let epoch = parsed.sessionEpoch {
            connection.observePeerEpoch(epoch)
        }

        for frame in parsed.frames {
            if case .stream(let sf) = frame {
                log("stream frame streamId=\(sf.streamId) data=\(sf.data.count) B")
                do {
                    let envelope = try AppMessageCodec.decode(sf.data)
                    return ReceivedMessage(envelope: envelope, senderPubkey: opened.senderPubkey)
                } catch {
                    log("AppMessageCodec.decode failed: \(error)")
                    return nil
                }
            } else {
                log("non-stream frame: \(frame)")
            }
        }
        return nil
    }

    public func close() {
        transport.close()
    }

    // MARK: - private send helpers

    private func sendDataPacket(frames: [Data]) async throws {
        let pktNum = connection.nextPacketNumber()
        var flags: PacketHeader.Flags = [.hasTimestamp]
        if !connection.ourEpochConfirmed { flags.insert(.hasEpoch) }
        let header = PacketHeader(
            packetType: .data,
            flags: flags,
            connectionId: connection.connectionId,
            packetNumber: pktNum
        )
        let plaintext = FudpPayload.assemble(
            includeTimestamp: true,
            timestamp: ReplayProtection.currentTimeMillis(),
            includeEpoch: !connection.ourEpochConfirmed,
            sessionEpoch: sessionEpoch,
            frameBytes: frames
        )
        let iv = try randomBytes(count: AsyTwoWay.ivLength)
        let aad = header.encode()
        let bundle = try AsyTwoWay.seal(
            plaintext: plaintext,
            aad: aad,
            peerPubkey: connection.peerPubkey,
            localPrivkey: localPrivkey,
            localPubkey: localPubkey,
            iv: iv
        )
        var packet = aad
        packet.append(bundle)
        try await transport.send(packet)
    }

    private func sendControlPacket(payload: Data) throws {
        let pktNum = connection.nextPacketNumber()
        let header = PacketHeader(
            packetType: .control,
            flags: [],
            connectionId: connection.connectionId,
            packetNumber: pktNum
        )
        var packet = header.encode()
        packet.append(payload)
        Task { [weak self] in
            try? await self?.transport.send(packet)
        }
    }

    private func randomBytes(count: Int) throws -> Data {
        var data = Data(count: count)
        let status = data.withUnsafeMutableBytes { ptr -> Int32 in
            guard let base = ptr.baseAddress else { return -1 }
            return SecRandomCopyBytes(kSecRandomDefault, count, base)
        }
        guard status == errSecSuccess else { throw Failure.underlying(NSError(domain: "SecRandom", code: Int(status))) }
        return data
    }
}

// MARK: - hex display helper for debug strings

private extension Data {
    var hex: String { map { String(format: "%02x", $0) }.joined() }
}

import Security
