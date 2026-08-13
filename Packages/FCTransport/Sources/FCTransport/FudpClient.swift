import Foundation
import Network
import FCCore

/// End-to-end FUDP client. Wires together every primitive in
/// FCTransport: socket → packet encode → AsyTwoWay seal → send;
/// receive → decode header → AsyTwoWay open → parse frames → emit
/// AppMessage. Handles a one-shot DDoS challenge if the server
/// demands it.
///
/// Since Phase 8.4.1 the client carries the full reliability
/// machinery mirroring the Java `Protocol`/`PeerConnection` pair:
///
/// - a background **receive pump** owns the datagram stream, processes
///   inbound ACK frames (congestion window, RTT, loss bookkeeping),
///   generates ACKs for received data packets, and reassembles stream
///   chunks (spilling large responses to a temp file so a big download
///   never sits fully in RAM);
/// - **outbound fragmentation**: any message larger than one MTU-safe
///   chunk is split across STREAM frames sharing a streamId, gated on
///   the CUBIC congestion window and rate-paced (QUIC-style leaky
///   bucket) — `sendMessageStreaming` additionally streams a file
///   straight from disk;
/// - a **retransmit loop** re-sends gap- or timeout-detected lost
///   packets with per-packet exponential backoff, signalling
///   congestion only on gap-detected (real) loss.
public final class FudpClient: @unchecked Sendable {

    public struct ReceivedMessage: Sendable {
        public let envelope: AppMessageEnvelope
        public let senderPubkey: Data
    }

    public enum Failure: Error, CustomStringConvertible {
        case challengeFailed(underlying: Error)
        case timeout
        case sendStalled(String)
        case unexpectedSenderPubkey(got: Data, expected: Data)
        case underlying(Error)

        public var description: String {
            switch self {
            case .challengeFailed(let e):                return "FudpClient: challenge failed — \(e)"
            case .timeout:                               return "FudpClient: timeout"
            case .sendStalled(let why):                  return "FudpClient: send stalled — \(why)"
            case let .unexpectedSenderPubkey(got, exp):  return "FudpClient: peer pubkey mismatch (\(got.prefix(4).hex)…  vs \(exp.prefix(4).hex)…)"
            case .underlying(let e):                     return "FudpClient: \(e)"
            }
        }
    }

    // MARK: - sizing (mirrors the Java Protocol constants)

    /// UDP datagram budget. 1350 keeps every packet under the usual
    /// 1500-byte path MTU with headroom for IP/UDP headers.
    public static let defaultMaxPacketSize = 1350
    /// Header + AsyTwoWay bundle overhead subtracted from the packet
    /// budget to get the plaintext payload budget.
    static let packetOverhead = PacketHeader.size + AsyTwoWay.headerOverhead
    /// Conservative per-frame framing overhead (type + streamId +
    /// offset + length varints).
    static let frameOverheadEstimate = 30
    /// Estimated full-packet overhead added on top of a stream chunk
    /// when reserving congestion-window space.
    static let cwndPacketOverhead = 128
    /// Abort a bulk send if the congestion window stays closed this
    /// long (no ACKs at all — the link is dead).
    static let appSendStallAbortMs: Int64 = 30_000

    static let retransmitIntervalMs: UInt64 = 50
    static let maxRetransmitsBeforeAbandon = 60
    static let maxRetransmitPerCycle = 50

    public let connection: PeerConnection
    public let localPubkey: Data
    public let sessionEpoch: Int64
    /// Reliability machinery (RTT, CUBIC window, packet tracking, ACK
    /// generation, pacing) for this connection.
    public let transfer: TransferMachinery

    /// When true, decode failures and unrecognised inbound packets are
    /// printed to stderr. Off by default; tests can flip it on for
    /// triage when interop fails.
    public var debugLogging: Bool = false

    private let transport: any DatagramTransport
    private let localPrivkey: Data
    private let challengeHandler: ChallengeHandler
    private let maxPacketSize: Int

    private let stateLock = NSLock()
    private var pumpTask: Task<Void, Never>?
    private var retransmitTask: Task<Void, Never>?
    private var closed = false
    private var _inboundProgress: (@Sendable (Int) -> Void)?

    /// Completed inbound AppMessages, fed by the pump, drained by
    /// `receive(matching:)`. A mailbox (not an AsyncStream) so a
    /// timed-out or cancelled wait cannot terminate the channel — see
    /// ``InboundMailbox``.
    private let inboundMailbox = InboundMailbox<ReceivedMessage>()

    /// Per-streamId reassembly buffers (pump-task-confined).
    private var streamBuffers: [UInt64: InboundStreamBuffer] = [:]
    /// Streams whose message was already delivered. Late retransmitted
    /// frames for them are dropped — re-creating the buffer would
    /// deliver the whole message twice. Bounded FIFO.
    private var retiredStreams: Set<UInt64> = []
    private var retiredOrder: [UInt64] = []
    private static let retiredStreamCap = 512

    // MARK: - init

    public convenience init(
        host: String,
        port: UInt16,
        peerPubkey: Data,
        peerFid: String? = nil,
        localPrivkey: Data,
        connectionId: Int64 = Int64.random(in: 1...Int64.max),
        sessionEpoch: Int64 = Int64.random(in: 1...Int64.max),
        challengeHandler: ChallengeHandler = ChallengeHandler()
    ) async throws {
        let transport = try await FudpConnection(host: host, port: port)
        try self.init(
            transport: transport,
            host: host,
            port: port,
            peerPubkey: peerPubkey,
            peerFid: peerFid,
            localPrivkey: localPrivkey,
            connectionId: connectionId,
            sessionEpoch: sessionEpoch,
            challengeHandler: challengeHandler
        )
    }

    /// Designated initializer with an injectable transport (tests use
    /// an in-process fake to exercise ACK/retransmit behaviour).
    init(
        transport: any DatagramTransport,
        host: String,
        port: UInt16,
        peerPubkey: Data,
        peerFid: String? = nil,
        localPrivkey: Data,
        connectionId: Int64 = Int64.random(in: 1...Int64.max),
        sessionEpoch: Int64 = Int64.random(in: 1...Int64.max),
        challengeHandler: ChallengeHandler = ChallengeHandler(),
        maxPacketSize: Int = FudpClient.defaultMaxPacketSize
    ) throws {
        self.localPrivkey = localPrivkey
        self.localPubkey = try Secp256k1.publicKey(fromPrivateKey: localPrivkey)
        let peerAddress: NWEndpoint = .hostPort(
            host: NWEndpoint.Host(host),
            port: NWEndpoint.Port(rawValue: port) ?? .any
        )
        let resolvedPeerFid = try peerFid ?? FchAddress(publicKey: peerPubkey).fid
        self.connection = try PeerConnection(
            connectionId: connectionId,
            peerPubkey: peerPubkey,
            peerAddress: peerAddress,
            peerFid: resolvedPeerFid
        )
        // Disjoint stream-id spaces per endpoint, mirroring the server's
        // `Protocol.connect` / `handleIncomingPacket`: the lower FID gets
        // even ids, the higher FID gets odd. Without this both sides
        // would allocate 0, 4, 8, ... and every id after the first
        // request would collide with one the server already retired —
        // silently dropped, surfacing as a client-side timeout.
        let localFid = try FchAddress(publicKey: self.localPubkey).fid
        self.connection.initLocalStreamParity(localFid < resolvedPeerFid ? 0 : 1)
        self.sessionEpoch = sessionEpoch
        self.challengeHandler = challengeHandler
        self.transport = transport
        self.maxPacketSize = maxPacketSize
        self.transfer = TransferMachinery()

        startPump()
        startRetransmitLoop()
    }

    deinit {
        pumpTask?.cancel()
        retransmitTask?.cancel()
    }

    // MARK: - sizing helpers

    var maxPayloadSize: Int { maxPacketSize - FudpClient.packetOverhead }
    /// Largest stream-chunk the send paths will put in one packet.
    var maxStreamChunk: Int { max(100, maxPayloadSize - FudpClient.frameOverheadEstimate) }

    @inline(__always)
    private func log(_ message: @autoclosure () -> String) {
        if debugLogging {
            FileHandle.standardError.write(Data(("[FudpClient] " + message() + "\n").utf8))
        }
    }

    /// Progress hook for inbound stream reassembly: called from the
    /// pump with the count of NEW bytes each stream chunk contributed.
    /// Set by FapiClient around a download call; pass nil to clear.
    public func setInboundProgressHandler(_ handler: (@Sendable (Int) -> Void)?) {
        stateLock.lock(); defer { stateLock.unlock() }
        _inboundProgress = handler
    }

    private var inboundProgress: (@Sendable (Int) -> Void)? {
        stateLock.lock(); defer { stateLock.unlock() }
        return _inboundProgress
    }

    // MARK: - send

    /// Encrypt and send a single AppMessage to the peer. Messages that
    /// fit one MTU-safe chunk go out as a single fin STREAM frame (the
    /// pre-8.4.1 fast path); larger messages are fragmented across
    /// multiple packets sharing a streamId, congestion-gated and paced.
    public func send(_ envelope: AppMessageEnvelope) async throws {
        let messageBytes = AppMessageCodec.encode(envelope)
        let streamId = connection.nextStreamId()

        if messageBytes.count <= maxStreamChunk {
            let frame = StreamFrame(streamId: streamId, offset: 0, data: messageBytes, fin: true)
            try await sendDataPacket(streamFrames: [frame])
            return
        }

        var cursor = messageBytes.startIndex
        try await sendChunkedStream(
            streamId: streamId,
            totalLength: Int64(messageBytes.count),
            next: { maxLen in
                guard cursor < messageBytes.endIndex else { return nil }
                let end = messageBytes.index(cursor, offsetBy: maxLen,
                                             limitedBy: messageBytes.endIndex) ?? messageBytes.endIndex
                let chunk = messageBytes[cursor..<end]
                cursor = end
                return Data(chunk)
            },
            progress: nil
        )
    }

    /// Stream a large AppMessage whose payload is `payloadPrefix`
    /// followed by `fileLength` bytes read from `fileHandle` — the
    /// upload path. The file is read in MTU-safe chunks and never
    /// materialised in memory. `progress` receives cumulative payload
    /// bytes handed to the network (prefix + file).
    public func sendMessageStreaming(
        type: MessageType,
        messageId: Int64,
        flags: AppMessageEnvelope.Flags = [],
        payloadPrefix: Data,
        fileHandle: FileHandle,
        fileLength: Int64,
        progress: (@Sendable (Int64) -> Void)? = nil
    ) async throws {
        // Envelope header with the payload length declared up front —
        // same wire bytes as AppMessageCodec.encode would emit, minus
        // the payload itself.
        var header = Data()
        header.append(type.rawValue)
        var idBE = UInt64(bitPattern: messageId).bigEndian
        header.append(Data(bytes: &idBE, count: 8))
        header.append(flags.rawValue)
        header.append(FudpVarint.encode(UInt64(payloadPrefix.count) + UInt64(fileLength)))

        var pending: [Data] = [header, payloadPrefix]
        var fileRemaining = fileLength
        let totalLength = Int64(header.count + payloadPrefix.count) + fileLength

        try await sendChunkedStream(
            streamId: connection.nextStreamId(),
            totalLength: totalLength,
            next: { maxLen in
                // Serve buffered prefix data first, then the file.
                while let first = pending.first {
                    if first.isEmpty { pending.removeFirst(); continue }
                    let take = min(maxLen, first.count)
                    let chunk = first.prefix(take)
                    if take == first.count {
                        pending.removeFirst()
                    } else {
                        pending[0] = Data(first.dropFirst(take))
                    }
                    return Data(chunk)
                }
                guard fileRemaining > 0 else { return nil }
                let want = min(Int64(maxLen), fileRemaining)
                guard let chunk = try fileHandle.read(upToCount: Int(want)), !chunk.isEmpty else {
                    throw Failure.sendStalled("file ended \(fileRemaining) bytes early")
                }
                fileRemaining -= Int64(chunk.count)
                return chunk
            },
            progress: progress
        )
    }

    /// Shared bulk-send loop: pulls chunks from `next`, gates each on
    /// the congestion window (the ACK clock is the true pacing for slow
    /// WAN links), spreads packets at ~cwnd/sRTT, and sets `fin` on the
    /// final chunk. Mirrors `Protocol.sendAndCloseFromInputStream`.
    private func sendChunkedStream(
        streamId: UInt64,
        totalLength: Int64,
        next: (Int) throws -> Data?,
        progress: (@Sendable (Int64) -> Void)?
    ) async throws {
        var offset: UInt64 = 0
        var sent: Int64 = 0

        while true {
            let chunk: Data?
            do {
                chunk = try next(maxStreamChunk)
            } catch let e as Failure {
                throw e
            } catch {
                throw Failure.underlying(error)
            }
            guard let chunk, !chunk.isEmpty else { break }

            sent += Int64(chunk.count)
            let isLast = sent >= totalLength

            // Congestion gate: only push what the ACK clock confirms
            // the path carries.
            let reserve = chunk.count + FudpClient.cwndPacketOverhead
            guard await awaitCongestionWindow(bytes: reserve) else {
                throw Failure.sendStalled(
                    "congestion window closed for \(FudpClient.appSendStallAbortMs) ms (no ACKs from peer)")
            }
            // Rate pacing: no line-rate bursts (skip before the last
            // chunk so short tails aren't delayed).
            if !isLast {
                let delay = transfer.reservePacingDelayNanos(bytes: reserve)
                if delay > 0 {
                    await QuietClock.sleep(nanoseconds: UInt64(delay))
                }
            }

            let frame = StreamFrame(streamId: streamId, offset: offset, data: chunk, fin: isLast)
            offset += UInt64(chunk.count)
            try await sendDataPacket(streamFrames: [frame])
            progress?(sent)

            if isLast { return }
        }
        // The source ran dry before `totalLength`, so no frame ever
        // carried `fin`: the peer would wait out its idle timeout on a
        // stream that can never complete. Fail loudly instead.
        throw Failure.sendStalled(
            "stream \(streamId) ended at \(sent)/\(totalLength) bytes without a fin frame")
    }

    /// Block (cooperatively) until the congestion window has room, or
    /// the stall budget elapses. The window only opens as ACKs come
    /// back, so waiting here paces the sender to the delivered rate.
    private func awaitCongestionWindow(bytes: Int) async -> Bool {
        if transfer.congestion.canSend(bytes) { return true }
        let deadline = PeerConnection.currentTimeMillis() + FudpClient.appSendStallAbortMs
        while PeerConnection.currentTimeMillis() < deadline {
            if Task.isCancelled { return false }
            await QuietClock.sleep(nanoseconds: 1_000_000) // ~1 ms
            if transfer.congestion.canSend(bytes) { return true }
        }
        return false
    }

    /// One-shot ping: builds + encrypts + sends a PING with a fresh
    /// `messageId`, then waits for a PONG matching that id.
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

    // MARK: - receive

    /// Wait for the next inbound `AppMessageEnvelope` whose `messageId`
    /// equals `id`. Throws ``Failure/timeout`` if nothing matches in
    /// `timeoutMs`.
    ///
    /// **Concurrency:** single consumer — don't issue overlapping
    /// `receive` calls; they would race for arrivals. FapiClient
    /// serializes calls.
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
        let deadlineMs = PeerConnection.currentTimeMillis() + Int64(timeoutMs)
        while true {
            let remaining = deadlineMs - PeerConnection.currentTimeMillis()
            guard remaining > 0 else { throw Failure.timeout }
            guard let received = await inboundMailbox.next(timeoutMs: Int(remaining)) else {
                throw Failure.timeout
            }
            if predicate(received.envelope) {
                return received.envelope
            }
            log("dropping non-matching envelope type=\(received.envelope.type) id=\(received.envelope.messageId)")
        }
    }

    // MARK: - receive pump

    private func startPump() {
        pumpTask = Task { [weak self] in
            guard let stream = self?.transport.datagrams else { return }
            for await datagram in stream {
                guard let self else { return }
                if Task.isCancelled { break }
                await self.handleDatagram(datagram.data)
            }
            self?.inboundMailbox.finish()
        }
    }

    private func handleDatagram(_ data: Data) async {
        guard data.count >= PacketHeader.size else {
            log("datagram too short for header (\(data.count) B)")
            return
        }
        let header: PacketHeader
        do {
            header = try PacketHeader.decode(data)
        } catch {
            log("PacketHeader.decode failed: \(error)")
            return
        }
        log("hdr type=\(header.packetType) flags=0x\(String(header.flags.rawValue, radix: 16)) connId=\(header.connectionId) pktNum=\(header.packetNumber)")

        let body = Data(data.dropFirst(PacketHeader.size))

        switch header.packetType {
        case .control:
            handleControlPacket(body: body)
        case .data, .ack:
            await handleEncryptedPacket(header: header, body: body)
        case .error:
            log("ERROR packet (ignored)")
        }
    }

    private func handleControlPacket(body: Data) {
        // CHALLENGE control packet: type byte 0x03 at offset 0 of body.
        guard body.count >= ChallengePayload.length, body.first == ChallengePayload.typeByte else {
            return
        }
        let outcome: ChallengeHandler.Outcome
        do {
            outcome = try challengeHandler.handle(challengePayload: body)
        } catch {
            log("challenge handling failed: \(error)")
            return
        }
        // Reply with a CONTROL packet wrapping the response payload.
        sendControlPacket(payload: outcome.responsePayload)
    }

    private func handleEncryptedPacket(header: PacketHeader, body: Data) async {
        let aad = header.encode()
        let opened: (senderPubkey: Data, plaintext: Data)
        do {
            opened = try AsyTwoWay.open(bundle: body, aad: aad, localPrivkey: localPrivkey)
        } catch {
            log("AsyTwoWay.open failed: \(error)")
            return
        }

        guard opened.senderPubkey == connection.peerPubkey else {
            log("sender pubkey mismatch (got \(opened.senderPubkey.prefix(4).hex)… expected \(connection.peerPubkey.prefix(4).hex)…)")
            return
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
            return
        }
        log("payload ts=\(parsed.timestamp ?? -1) epoch=\(parsed.sessionEpoch ?? -1) frames=\(parsed.frames.count)")

        connection.touch()
        if let epoch = parsed.sessionEpoch {
            connection.observePeerEpoch(epoch)
        }

        var ackEliciting = false
        for frame in parsed.frames {
            switch frame {
            case .ack(let ack):
                // The peer has responded → it has seen our epoch.
                connection.markOurEpochConfirmed()
                connection.recordPeerAck(largestAcked: Int64(ack.largestAcknowledged))
                transfer.processAckFrame(ack)
            case .stream(let sf):
                ackEliciting = true
                handleStreamFrame(sf)
            case .padding:
                break
            case .unknown(let typeByte, _):
                // Unmodelled frame (MAX_DATA etc.). ACK the packet —
                // "received" is true even if we can't act on it, and a
                // missing ACK would make the server retransmit forever.
                ackEliciting = true
                log("unknown frame type 0x\(String(typeByte, radix: 16)) (acked, ignored)")
            }
        }

        if ackEliciting {
            transfer.ackGenerator.onPacketReceived(header.packetNumber)
            // ACK_THRESHOLD = 1: immediate ACK per ack-eliciting packet.
            await sendAckOnly()
        }
    }

    private func handleStreamFrame(_ sf: StreamFrame) {
        if retiredStreams.contains(sf.streamId) {
            // Late/retransmitted frame for a completed stream. The
            // packet is still ACKed (caller), which stops the
            // retransmissions; re-assembling would deliver twice.
            log("dropping frame for retired stream \(sf.streamId)")
            return
        }
        log("stream frame streamId=\(sf.streamId) offset=\(sf.offset) data=\(sf.data.count) B fin=\(sf.fin)")

        // Dictionary ops are locked (close() may race); the buffer
        // object itself is pump-task-confined.
        let buffer: InboundStreamBuffer = {
            stateLock.lock(); defer { stateLock.unlock() }
            if let existing = streamBuffers[sf.streamId] { return existing }
            let fresh = InboundStreamBuffer()
            streamBuffers[sf.streamId] = fresh
            return fresh
        }()

        let newBytes: Int
        do {
            newBytes = try buffer.append(offset: sf.offset, data: sf.data, fin: sf.fin)
        } catch {
            log("stream \(sf.streamId) buffer append failed: \(error)")
            buffer.cleanup()
            removeStreamBuffer(sf.streamId)
            return
        }
        if newBytes > 0 {
            inboundProgress?(newBytes)
        }

        let complete: Data?
        do {
            complete = try buffer.assembleIfComplete()
        } catch {
            log("stream \(sf.streamId) assembly failed: \(error)")
            buffer.cleanup()
            removeStreamBuffer(sf.streamId)
            return
        }
        guard let complete else { return }

        removeStreamBuffer(sf.streamId)
        retireStream(sf.streamId)
        log("stream \(sf.streamId) reassembled \(complete.count) B")

        do {
            let envelope = try AppMessageCodec.decode(complete)
            inboundMailbox.put(ReceivedMessage(envelope: envelope, senderPubkey: connection.peerPubkey))
        } catch {
            log("AppMessageCodec.decode failed: \(error)")
        }
    }

    private func removeStreamBuffer(_ streamId: UInt64) {
        stateLock.lock(); defer { stateLock.unlock() }
        streamBuffers.removeValue(forKey: streamId)
    }

    private func retireStream(_ streamId: UInt64) {
        retiredStreams.insert(streamId)
        retiredOrder.append(streamId)
        if retiredOrder.count > FudpClient.retiredStreamCap {
            let oldest = retiredOrder.removeFirst()
            retiredStreams.remove(oldest)
        }
    }

    // MARK: - retransmit loop

    private func startRetransmitLoop() {
        retransmitTask = Task { [weak self] in
            while !Task.isCancelled {
                await QuietClock.sleep(nanoseconds: FudpClient.retransmitIntervalMs * 1_000_000)
                guard let self, !Task.isCancelled else { return }
                await self.retransmitCycle()
            }
        }
    }

    private func retransmitCycle() async {
        let detection = transfer.detectLostPackets()
        guard !detection.packets.isEmpty else { return }

        // Rate-limit retransmission (packets AND bytes): a back-to-back
        // burst of retransmits is exactly the line-rate burst that
        // shallow bottleneck buffers clip, turning one loss into a
        // self-sustaining storm.
        let byteBudget = max(8 * 1024, transfer.pacingBudgetBytes(intervalMs: Int64(FudpClient.retransmitIntervalMs)))
        var retransmittedBytes: Int64 = 0
        var retransmitted = 0
        var abandoned = 0

        for record in detection.packets {
            if record.retransmitCount >= FudpClient.maxRetransmitsBeforeAbandon {
                // Abandon the undeliverable packet but keep the
                // connection alive. The receiver's stream now has a
                // permanent gap — loud, so stalls are diagnosable.
                if let removed = transfer.sentPackets.removeForRetransmit(record.packetNumber) {
                    transfer.congestion.onRetransmitRemove(removed.size)
                    abandoned += 1
                }
                continue
            }

            if retransmitted >= FudpClient.maxRetransmitPerCycle || retransmittedBytes >= byteBudget {
                break // leave the rest for the next cycle
            }

            guard !record.frames.isEmpty else {
                // Nothing retransmittable (shouldn't happen — only
                // stream frames are tracked); drop the entry.
                if let removed = transfer.sentPackets.removeForRetransmit(record.packetNumber) {
                    transfer.congestion.onRetransmitRemove(removed.size)
                }
                continue
            }

            guard let removed = transfer.sentPackets.removeForRetransmit(record.packetNumber) else {
                continue // an ACK raced us — nothing to do
            }
            transfer.congestion.onRetransmitRemove(removed.size)

            // Retransmits ALWAYS proceed regardless of the congestion
            // window (loss recovery, not new data — QUIC RFC 9002).
            do {
                try await sendDataPacket(
                    streamFrames: removed.frames,
                    retransmitCount: removed.retransmitCount + 1
                )
                transfer.sentPackets.recordRetransmit()
                retransmitted += 1
                retransmittedBytes += Int64(removed.size)
            } catch {
                log("retransmit of packet \(record.packetNumber) failed: \(error)")
            }
        }

        if abandoned > 0 {
            log("abandoned \(abandoned) packet(s) after \(FudpClient.maxRetransmitsBeforeAbandon) failed retransmits — a stream has a permanent gap")
        }

        // Congestion signal ONLY for gap-detected loss (real drop
        // evidence). Timeout-detected loss retransmits without
        // shrinking the window (spurious under RTT spikes).
        if retransmitted > 0 && detection.gapLoss {
            transfer.trySignalLoss()
        }
    }

    public func close() {
        stateLock.lock()
        let alreadyClosed = closed
        closed = true
        let orphaned = Array(streamBuffers.values)
        streamBuffers.removeAll()
        stateLock.unlock()
        guard !alreadyClosed else { return }

        pumpTask?.cancel()
        retransmitTask?.cancel()
        for buffer in orphaned { buffer.cleanup() }
        transport.close()
        inboundMailbox.finish()
    }

    // MARK: - private send helpers

    /// Encrypt and send one DATA packet carrying `streamFrames` (plus
    /// any pending ACK piggybacked in front). Ack-eliciting packets are
    /// recorded for loss detection BEFORE the socket write — on
    /// localhost the ACK can beat a post-write record.
    private func sendDataPacket(streamFrames: [StreamFrame], retransmitCount: Int = 0) async throws {
        var frameBytes: [Data] = []
        if transfer.ackGenerator.hasPendingAcks,
           let ack = transfer.ackGenerator.generateAckFrame() {
            frameBytes.append(ack.encode())
        }
        for frame in streamFrames {
            frameBytes.append(frame.encode())
        }
        let ackEliciting = !streamFrames.isEmpty

        let packet = try sealPacket(frameBytes: frameBytes, includeTimestamp: ackEliciting)

        if ackEliciting {
            transfer.sentPackets.recordSent(
                packetNumber: packet.number,
                frames: streamFrames,
                size: packet.bytes.count,
                retransmitCount: retransmitCount
            )
            transfer.congestion.onSend(packet.bytes.count)
        }

        try await transport.send(packet.bytes)
    }

    /// Send an ACK-only packet (not ack-eliciting, no timestamp — E1).
    private func sendAckOnly() async {
        guard let ack = transfer.ackGenerator.generateAckFrame() else { return }
        do {
            let packet = try sealPacket(frameBytes: [ack.encode()], includeTimestamp: false)
            try await transport.send(packet.bytes)
        } catch {
            log("failed to send ACK: \(error)")
        }
    }

    private func sealPacket(
        frameBytes: [Data],
        includeTimestamp: Bool
    ) throws -> (number: Int64, bytes: Data) {
        let pktNum = connection.nextPacketNumber()
        var flags: PacketHeader.Flags = []
        if includeTimestamp { flags.insert(.hasTimestamp) }
        let includeEpoch = !connection.ourEpochConfirmed
        if includeEpoch { flags.insert(.hasEpoch) }
        let header = PacketHeader(
            packetType: .data,
            flags: flags,
            connectionId: connection.connectionId,
            packetNumber: pktNum
        )
        let plaintext = FudpPayload.assemble(
            includeTimestamp: includeTimestamp,
            timestamp: ReplayProtection.currentTimeMillis(),
            includeEpoch: includeEpoch,
            sessionEpoch: sessionEpoch,
            frameBytes: frameBytes
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
        return (pktNum, packet)
    }

    private func sendControlPacket(payload: Data) {
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
