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
        /// The socket underneath died (sleep/wake, Wi-Fi change, peer
        /// gone). Distinct from ``timeout`` because no amount of
        /// waiting fixes it — the transport has to be rebuilt.
        case transportClosed
        case sendStalled(String)
        case unexpectedSenderPubkey(got: Data, expected: Data)
        case underlying(Error)

        public var description: String {
            switch self {
            case .challengeFailed(let e):                return "FudpClient: challenge failed — \(e)"
            case .timeout:                               return "FudpClient: timeout"
            case .transportClosed:                       return "FudpClient: connection lost (network changed or server unreachable)"
            case .sendStalled(let why):                  return "FudpClient: send stalled — \(why)"
            case let .unexpectedSenderPubkey(got, exp):  return "FudpClient: peer pubkey mismatch (\(got.prefix(4).hex)…  vs \(exp.prefix(4).hex)…)"
            case .underlying(let e):                     return "FudpClient: \(e)"
            }
        }
    }

    // MARK: - sizing (mirrors the Java Protocol constants)

    /// UDP datagram budget. 1350 keeps every packet under the usual
    /// 1500-byte path MTU with headroom for IP/UDP headers.
    ///
    /// **A hard limit** (FUDP1 §Packet Size Budget): a packet over the
    /// path MTU is split into IP fragments, and losing either fragment
    /// loses the packet.
    public static let defaultMaxPacketSize = 1350
    /// Size of the AsyTwoWay bundle around the plaintext: algorithm (6)
    /// + type (1) + sender pubkey (33) + IV (12) + GCM tag (16). This was
    /// budgeted as 52, leaving out the tag.
    static let packetCryptoOverhead = AsyTwoWay.minBundleSize
    /// Plaintext before the first frame, worst case: timestamp (8) +
    /// session epoch (8).
    static let packetPrefix = 16
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
    /// Set when the transport's datagram stream ends — the socket is
    /// gone, so nothing will ever arrive again on this client.
    private var transportEnded = false
    private var _inboundProgress: (@Sendable (Int) -> Void)?

    /// Completed inbound AppMessages, fed by the pump, drained by
    /// `receive(matching:)`. A mailbox (not an AsyncStream) so a
    /// timed-out or cancelled wait cannot terminate the channel — see
    /// ``InboundMailbox``.
    private let inboundMailbox = InboundMailbox<ReceivedMessage>()
    /// Serialises request/response exchanges — see ``exchanging(_:)``.
    private let exchangeGate = ExchangeGate()

    /// Per-streamId reassembly buffers (pump-task-confined).
    private var streamBuffers: [UInt64: InboundStreamBuffer] = [:]
    /// Streams whose message was already delivered. Late retransmitted
    /// frames for them are dropped — re-creating the buffer would
    /// deliver the whole message twice. Bounded FIFO.
    private var retiredStreams: Set<UInt64> = []
    private var retiredOrder: [UInt64] = []
    /// Matches `StreamManager.MAX_RETIRED_STREAMS` in both reference
    /// implementations. FUDP2V1 endorses bounding the set — old
    /// tombstones are safe to evict because retransmission of a long-
    /// finished stream is bounded by the Max Retransmit Count — but a
    /// cap eight times smaller than the peers' drops tombstones they
    /// still consider live.
    private static let retiredStreamCap = 4096

    /// Replay window for this connection. FUDP4V1 requires the check;
    /// without it a captured packet verifies exactly as well the second
    /// time as the first.
    private let replay = ReplayProtection.withDefaults()

    /// `Max Remote Streams` from FUDP2V1's flow-control table.
    private static let maxConcurrentInboundStreams = 100

    /// Send budget for DATAGRAM frames on this connection (FUDP7).
    public let datagramBudget = DatagramBudget()
    // DATAGRAM frames are off until the application learns the peer
    // supports them: an older peer loses every packet carrying one.
    private var _datagramsEnabled = false
    private var _datagramHandler: (@Sendable (_ peerId: String, _ connectionId: Int64, _ data: Data) -> Void)?

    // Counters (under `stateLock`).
    private var _datagramsSent: Int64 = 0
    private var _datagramsReceived: Int64 = 0
    private var _datagramDrops: [DatagramResult: Int64] = [:]
    private var _oversizePacketCount: Int64 = 0
    private var _frameParseFailCount: Int64 = 0
    private var _decryptFailCount: Int64 = 0

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

    // MARK: - liveness

    /// True while this client can still carry a request/response pair.
    /// Goes false when it is closed, when the transport's datagram
    /// stream ends, or when the socket reports its path is gone — the
    /// three ways a laptop's connection dies over a sleep/wake cycle.
    ///
    /// A dead client never recovers: the AsyTwoWay session, the
    /// connection id and the peer's NAT mapping all belong to the old
    /// socket. Callers rebuild — see ``ReconnectingFapiClient``.
    public var isAlive: Bool {
        stateLock.lock()
        let dead = closed || transportEnded
        stateLock.unlock()
        return !dead && transport.isViable
    }

    /// Run `body` with `stateLock` held. `lock()`/`unlock()` written out
    /// inside an `async` function are an error in the Swift 6 language
    /// mode, since a suspension between the two would strand the lock; a
    /// scoped, non-async helper cannot suspend.
    private func withStateLock<T>(_ body: () -> T) -> T {
        stateLock.lock()
        defer { stateLock.unlock() }
        return body()
    }

    // MARK: - request/response exclusion

    /// Run one request/response exchange with exclusive use of the
    /// inbound mailbox.
    ///
    /// **Why this has to exist.** ``receive(matching:timeoutMs:)`` is a
    /// single-consumer queue that *discards* envelopes it was not
    /// waiting for. With two exchanges in flight, whichever `receive`
    /// wakes first takes the next arrival, drops it if it belongs to the
    /// other, and the rightful owner then waits out its full timeout for
    /// a reply that has already been thrown away. Both calls are
    /// well-formed; one simply eats the other's answer.
    ///
    /// That never surfaced while the app made one call at a time. A
    /// background poller makes several — a balance lookup, a
    /// `dock.fetch` and an outbox drain can now overlap on one socket —
    /// and the symptom is a `FudpClient: timeout` on whichever call was
    /// unlucky, on a connection that is working perfectly.
    ///
    /// The gate lives here, on the object that owns the mailbox, rather
    /// than in ``FapiClient``: a `FapiClient` is created per call (it
    /// holds no state but its `fudp`), so exclusion kept there would
    /// guard nothing. Serialising rather than demultiplexing costs
    /// pipelining, which this protocol never had — the mailbox has
    /// always been single-consumer, and the calls were merely never
    /// concurrent enough to prove it.
    public func exchanging<T>(_ body: () async throws -> T) async throws -> T {
        await exchangeGate.acquire()
        do {
            let value = try await body()
            await exchangeGate.release()
            return value
        } catch {
            await exchangeGate.release()
            throw error
        }
    }

    // MARK: - datagrams (FUDP7)

    /// Allow DATAGRAM frames on this connection, with a send budget of
    /// `rateBps` bits per second of datagram payload. Call only once the
    /// peer has shown it supports them: an older peer loses every packet
    /// carrying one. Datagrams turn off again if the peer restarts.
    public func enableDatagrams(rateBps: Int64 = DatagramBudget.defaultRateBps) {
        datagramBudget.setRate(rateBps)
        stateLock.lock(); defer { stateLock.unlock() }
        _datagramsEnabled = true
    }

    public var datagramsEnabled: Bool {
        stateLock.lock(); defer { stateLock.unlock() }
        return _datagramsEnabled
    }

    /// Override the DATAGRAM send budget, in bits per second of payload.
    public func setDatagramRate(bitsPerSecond: Int64) {
        datagramBudget.setRate(bitsPerSecond)
    }

    /// Receive datagrams: called once per DATAGRAM frame, in arrival
    /// order, with the peer's FID and this connection's id.
    ///
    /// Datagrams are unreliable: no retransmission, no ordering, and no
    /// deduplication beyond the packet replay window. The handler runs
    /// on the receive pump, so it must return quickly — anything slow
    /// here delays every packet on the connection. Pass nil to clear.
    public func setDatagramHandler(
        _ handler: (@Sendable (_ peerId: String, _ connectionId: Int64, _ data: Data) -> Void)?
    ) {
        stateLock.lock(); defer { stateLock.unlock() }
        _datagramHandler = handler
    }

    /// Send one unreliable datagram. It never waits behind stream data —
    /// congestion window and pacer are skipped — and is never
    /// retransmitted; any result other than ``DatagramResult/sent``
    /// means it was dropped.
    public func sendDatagram(_ data: Data) async -> DatagramResult {
        await sendDatagrams([data])[0]
    }

    /// Send several datagrams, packed into as few packets as they fit
    /// (for frames that fall due together). Each is budgeted and may be
    /// dropped on its own. Returns the outcome for each, in order.
    public func sendDatagrams(_ datagrams: [Data]) async -> [DatagramResult] {
        guard isAlive, connection.isOpen else {
            return datagrams.map { _ in countDrop(.noConnection) }
        }
        guard datagramsEnabled else {
            return datagrams.map { _ in countDrop(.notEnabled) }
        }

        var results = [DatagramResult](repeating: .sent, count: datagrams.count)
        let room = maxFrameBytes
        let maxSize = maxDatagramSize
        var frames: [Data] = []
        var packed: [Int] = []
        var used = 0
        for (i, data) in datagrams.enumerated() {
            if data.count > maxSize {
                results[i] = countDrop(.tooLarge)
                continue
            }
            if !datagramBudget.tryConsume(data.count) {
                results[i] = countDrop(.overBudget)
                continue
            }
            let frame = DatagramFrame(data: data).encode()
            if used + frame.count > room {
                await flushDatagramPacket(frames, packed: packed, into: &results)
                frames.removeAll()
                packed.removeAll()
                used = 0
            }
            frames.append(frame)
            packed.append(i)
            used += frame.count
        }
        await flushDatagramPacket(frames, packed: packed, into: &results)
        return results
    }

    private func flushDatagramPacket(_ frames: [Data], packed: [Int], into results: inout [DatagramResult]) async {
        guard !frames.isEmpty else { return }
        var outcome = DatagramResult.sent
        do {
            try await sendPacket(frameBytes: await withPendingAck(frames), trackedFrames: [], hasDatagram: true)
        } catch {
            log("datagram packet not sent: \(error)")
            outcome = .bufferFull
        }
        for i in packed {
            results[i] = outcome == .sent ? .sent : countDrop(outcome)
        }
        if outcome == .sent {
            withStateLock { _datagramsSent += Int64(packed.count) }
        }
    }

    private func countDrop(_ reason: DatagramResult) -> DatagramResult {
        stateLock.lock(); defer { stateLock.unlock() }
        _datagramDrops[reason, default: 0] += 1
        return reason
    }

    /// Cap the rate of stream (reliable) data on this connection, in
    /// bits per second; 0 removes it. DATAGRAM frames are exempt.
    ///
    /// Datagrams go out ahead of stream data at the sender, but a bulk
    /// transfer still fills any queue further along the path, and audio
    /// then waits behind it. A call layer should cap bulk transfers below
    /// the path rate for the duration of a call, or pause them (VOICE_SPEC
    /// §9.5).
    public func setStreamRateCap(bitsPerSecond: Int64) {
        transfer.setStreamRateCap(bitsPerSecond: bitsPerSecond)
    }

    /// DATAGRAM frames handed to the socket.
    public var datagramsSent: Int64 {
        stateLock.lock(); defer { stateLock.unlock() }
        return _datagramsSent
    }

    /// DATAGRAM frames received and delivered.
    public var datagramsReceived: Int64 {
        stateLock.lock(); defer { stateLock.unlock() }
        return _datagramsReceived
    }

    /// DATAGRAM frames dropped at this sender for `reason`.
    public func datagramsDropped(_ reason: DatagramResult) -> Int64 {
        stateLock.lock(); defer { stateLock.unlock() }
        return _datagramDrops[reason, default: 0]
    }

    /// Packets sent larger than `maxPacketSize`; nonzero means a
    /// size-budget bug.
    public var oversizePacketCount: Int64 {
        stateLock.lock(); defer { stateLock.unlock() }
        return _oversizePacketCount
    }

    /// Packets that authenticated but whose frames could not be parsed.
    public var frameParseFailCount: Int64 {
        stateLock.lock(); defer { stateLock.unlock() }
        return _frameParseFailCount
    }

    /// Packets that claimed to be from the peer but did not decrypt.
    public var decryptFailCount: Int64 {
        stateLock.lock(); defer { stateLock.unlock() }
        return _decryptFailCount
    }

    // MARK: - sizing helpers

    /// Bytes of frames that fit in one packet of `maxPacketSize`.
    var maxFrameBytes: Int {
        maxPacketSize - PacketHeader.size - FudpClient.packetCryptoOverhead - FudpClient.packetPrefix
    }
    /// Largest stream-chunk the send paths will put in one packet, sized
    /// for the worst-case STREAM header. A pending ACK that does not fit
    /// beside it goes in a packet of its own.
    var maxStreamChunk: Int { max(100, maxFrameBytes - StreamFrame.maxHeaderSize) }

    /// Largest DATAGRAM payload that fits in one packet. Larger ones are
    /// refused (``DatagramResult/tooLarge``); datagrams are never
    /// fragmented. The budget includes the session epoch even once it is
    /// confirmed, so the limit stays the same for the life of a
    /// connection.
    public var maxDatagramSize: Int { FudpClient.maxDatagramSize(maxPacketSize: maxPacketSize) }

    /// ``maxDatagramSize`` for a given packet size: 1242 at the default
    /// 1350, 1292 at 1400 (checked against `fudpVectors.json`).
    public static func maxDatagramSize(maxPacketSize: Int) -> Int {
        let room = maxPacketSize - PacketHeader.size - packetCryptoOverhead - packetPrefix
        var size = room - 2 // type and a 1-byte length; shrink as the length varint grows
        while size > 0 && DatagramFrame.encodedSize(dataLength: size) > room { size -= 1 }
        return max(0, size)
    }

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
        // A length is a caller-supplied `Int64` — a file size, a
        // `Data.count` — and a negative one makes every comparison
        // below nonsense before any byte is read.
        guard totalLength >= 0 else {
            throw Failure.sendStalled("stream \(streamId) was given a negative length \(totalLength)")
        }

        var offset: UInt64 = 0
        var sent: Int64 = 0

        // **An empty payload is a payload.** Nothing to chunk means the
        // loop below breaks on its first turn and falls through to the
        // "ended without a fin frame" error, so sending a zero-byte
        // file failed as if the source had died. One empty frame with
        // `fin` is the whole stream.
        if totalLength == 0 {
            guard await awaitCongestionWindow(bytes: FudpClient.cwndPacketOverhead) else {
                throw Failure.sendStalled(
                    "congestion window closed for \(FudpClient.appSendStallAbortMs) ms (no ACKs from peer)")
            }
            try await sendDataPacket(streamFrames: [
                StreamFrame(streamId: streamId, offset: 0, data: Data(), fin: true)
            ])
            progress?(0)
            return
        }

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

            // **The declared length is the contract.** `sent >=
            // totalLength` made the overshooting chunk the terminating
            // one, so a source that handed back more than it promised
            // shipped the excess inside the frame carrying `fin` — a
            // stream whose real length silently disagreed with the one
            // the request announced.
            guard sent + Int64(chunk.count) <= totalLength else {
                throw Failure.sendStalled(
                    "stream \(streamId) source produced more than the \(totalLength) bytes it declared")
            }

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
        // A ping is an exchange like any other, and a connection test
        // fired while a fetch is in flight must not eat its reply.
        let envelope = try await exchanging {
            try await send(AppMessageEnvelope(
                type: .ping,
                messageId: messageId,
                payload: PingMessage(timestamp: pingTs).payload()
            ))
            log("sent PING messageId=\(messageId) ts=\(pingTs)")

            return try await receive(
                matching: { $0.type == .pong && $0.messageId == messageId },
                timeoutMs: timeoutMs
            )
        }
        return try PongMessage.parse(payload: envelope.payload)
    }

    // MARK: - receive

    /// Wait for the next inbound `AppMessageEnvelope` whose `messageId`
    /// equals `id`. Throws ``Failure/timeout`` if nothing matches in
    /// `timeoutMs`.
    ///
    /// **Concurrency:** single consumer — overlapping `receive` calls
    /// race for arrivals, and the loser's reply is *discarded* by the
    /// winner rather than put back. Callers must hold
    /// ``exchanging(_:)`` for the whole send-then-receive, which is
    /// what every path in `FapiClient` does. (This note used to claim
    /// `FapiClient` serialized calls on its own; it never did, and a
    /// `FapiClient` is built per call, so it could not.)
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
                // A finished mailbox returns nil immediately, so a
                // dead socket looks exactly like a wait that expired.
                // Tell them apart — only one of the two is fixable by
                // reconnecting.
                throw isAlive ? Failure.timeout : Failure.transportClosed
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
            // The stream only ends when the socket is gone (or we
            // closed it). Record that so `receive` can say "connection
            // lost" instead of the misleading "timeout" a finished
            // mailbox would otherwise produce.
            self?.markTransportEnded()
            self?.inboundMailbox.finish()
        }
    }

    private func markTransportEnded() {
        stateLock.lock()
        transportEnded = true
        stateLock.unlock()
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
            // **Refuse an unknown wire version before touching crypto.**
            // Both reference implementations gate the data path on
            // `isSupportedDataVersion` and name its absence as the F1
            // vulnerability: without it a packet claiming a future
            // version is parsed by today's rules, so a later format's
            // field layout is reinterpreted under this one. Control
            // packets stay version-agnostic — they are plaintext and
            // are how versions get negotiated in the first place.
            guard header.version == PacketHeader.currentVersion else {
                log("dropping data packet with unsupported version \(header.version)")
                return
            }
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
        // **Check who it claims to be from before doing the ECDH.**
        // The sender's pubkey sits in the clear at a fixed offset of
        // the bundle, and this client talks to exactly one peer, so a
        // 33-byte comparison decides the question that `AsyTwoWay.open`
        // used to answer only *after* deriving a shared secret. Doing
        // the derivation first handed anyone who could reach the socket
        // an asymmetric cost: a packet with a fresh random pubkey costs
        // them nothing to make and costs us a full ECDH, missing the
        // shared-secret cache every time by construction. The servers
        // defend this with a per-source rate limiter; a client with one
        // known peer can simply refuse to start.
        guard let claimed = AsyTwoWay.senderPubkey(inBundle: body) else {
            log("bundle too short to carry a sender pubkey")
            return
        }
        guard claimed == connection.peerPubkey else {
            log("sender pubkey mismatch (got \(claimed.prefix(4).hex)… expected \(connection.peerPubkey.prefix(4).hex)…)")
            return
        }

        let aad = header.encode()
        let opened: (senderPubkey: Data, plaintext: Data)
        do {
            opened = try AsyTwoWay.open(bundle: body, aad: aad, localPrivkey: localPrivkey)
        } catch {
            withStateLock { _decryptFailCount += 1 }
            log("AsyTwoWay.open failed: \(error)")
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
            // Authentic packet, unreadable frames (e.g. a frame type
            // newer than ours). Lose this packet only, and do not count
            // it as a decrypt failure: its sender is genuine (FUDP1
            // §Versioning, FUDP4 §7). Its reliable frames come back by
            // retransmission.
            withStateLock { _frameParseFailCount += 1 }
            log("dropping packet \(header.packetNumber) with unparseable frames: \(error)")
            return
        }
        log("payload ts=\(parsed.timestamp ?? -1) epoch=\(parsed.sessionEpoch ?? -1) frames=\(parsed.frames.count)")

        connection.touch()

        // **The peer's connection id is a routing key, not a gate.**
        // FUDP1V1 makes it primary for resolving a packet to a
        // connection and requires that a *changed* id be read as the
        // peer having rebuilt its connection — fresh packet numbers,
        // fresh stream ids — and so as a reason to reset our receive
        // state. Rejecting the packet instead is what the path-migration
        // revision was written to stop: it turned a mid-transfer NAT
        // rebind into every subsequent request timing out.
        if connection.observeRemoteConnectionId(header.connectionId) {
            log("peer rebuilt its connection (remote connId now \(header.connectionId)) — resetting connection state")
            resetStateForPeerRestart()
        }

        // FUDP4V1: the epoch rides in the plaintext only until the peer
        // has seen it acknowledged, after which the flag is cleared to
        // save eight bytes a packet. A packet without it is not a peer
        // claiming epoch zero — zero is the wire's "unknown" — so the
        // established value stands in. Feeding the replay window a
        // literal zero would read as an epoch change and reset the
        // window on every packet after the flag goes away, which is the
        // `incomingEpoch = conn.getSessionEpoch()` fallback in both
        // reference implementations.
        var incomingEpoch = parsed.sessionEpoch ?? 0
        if incomingEpoch == 0 { incomingEpoch = connection.peerSessionEpoch }
        if let epoch = parsed.sessionEpoch { connection.observePeerEpoch(epoch) }

        switch replay.checkAndRecord(
            connectionId: connection.connectionId,
            packetNumber: header.packetNumber,
            timestamp: parsed.timestamp ?? ReplayProtection.currentTimeMillis(),
            sessionEpoch: incomingEpoch
        ) {
        case .ok:
            break
        case .peerRestart:
            // The window has already reset itself; ours has to follow,
            // or the restarted peer's stream ids are dropped by
            // tombstones its previous life left behind (FUDP2V1
            // §Stream Retirement).
            log("peer restart detected (epoch \(incomingEpoch)) — resetting connection state")
            resetStateForPeerRestart()
            if let epoch = parsed.sessionEpoch { connection.observePeerEpoch(epoch) }
        case .invalidTimestamp:
            // **Drop it; do not tear the connection down.** Both
            // reference implementations answer this with a
            // CONNECTION_CLOSE, and that hands anyone who can capture
            // one genuine packet a connection reset they can replay at
            // will: the packet authenticates because it is real, and
            // sixty seconds later its timestamp is out of tolerance by
            // arithmetic. FUDP4V1 allows the quieter reading — "other
            // implementations MAY drop silently" — and a packet we will
            // not act on is not grounds for ending a working session.
            log("dropping packet with out-of-tolerance timestamp \(parsed.timestamp ?? -1)")
            return
        case .duplicate:
            // **Drop it silently, and do not ACK it.** FUDP4V1 is
            // explicit ("SHOULD NOT send any response to duplicate
            // packets") and the reason holds on inspection: a packet
            // number is allocated fresh on every send in all three
            // implementations, retransmissions included, so a repeated
            // number is never the peer retrying — it is a duplicated
            // datagram or a replay. Answering it feeds an attacker-
            // chosen packet number back into the ACK generator, whose
            // retention prune assumes receive times ascend with packet
            // numbers.
            log("dropping replayed packet \(header.packetNumber)")
            return
        }

        // Datagrams first: they are the latency-sensitive traffic.
        let datagrams = parsed.frames.compactMap { frame -> Data? in
            if case .datagram(let df) = frame { return df.data }
            return nil
        }
        if !datagrams.isEmpty {
            let handler = withStateLock { () -> (@Sendable (String, Int64, Data) -> Void)? in
                _datagramsReceived += Int64(datagrams.count)
                return _datagramHandler
            }
            if let handler {
                let peerId = connection.peerFid ?? ""
                for data in datagrams {
                    handler(peerId, connection.connectionId, data)
                }
            }
        }

        let ackEliciting = parsed.frames.contains { $0.isAckEliciting }
        for frame in parsed.frames {
            switch frame {
            case .ack(let ack):
                // The peer has responded → it has seen our epoch.
                connection.markOurEpochConfirmed()
                // The field is a 64-bit unsigned on the wire and a
                // signed packet number here; a peer naming anything
                // above Int64.max used to trap on the conversion. We
                // never sent such a number, so it acknowledges nothing.
                if let largest = Int64(exactly: ack.largestAcknowledged) {
                    connection.recordPeerAck(largestAcked: largest)
                } else {
                    log("ignoring ACK for out-of-range packet number \(ack.largestAcknowledged)")
                }
                transfer.processAckFrame(ack)
            case .stream(let sf):
                handleStreamFrame(sf)
            case .connectionClose(let code, let reason):
                // Acknowledged like any other frame; the transport's
                // liveness, not this frame, decides when we rebuild.
                log("peer sent CONNECTION_CLOSE code=\(code) reason=\(reason)")
            case .padding, .datagram, .maxData, .maxStreamData, .maxStreams:
                // Flow-control frames are acknowledged but not acted on:
                // this client never sends enough to reach the limits.
                break
            }
        }

        if ackEliciting {
            transfer.ackGenerator.onPacketReceived(header.packetNumber)
            // ACK_THRESHOLD = 1: immediate ACK per ack-eliciting packet.
            await sendAckOnly()
        } else {
            // ACK-only / DATAGRAM-only: listed in later ACKs so the
            // ranges have holes only where packets were lost; elicits none.
            transfer.ackGenerator.onNonElicitingPacketReceived(header.packetNumber)
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
        // FUDP2V1 puts a ceiling of 100 concurrent remote streams on a
        // connection and has the receiver drop frames that would exceed
        // it. Without one, a peer opening a fresh stream id per packet
        // mints a reassembly buffer per packet, each with its own
        // interval list and possible spill file.
        let buffer: InboundStreamBuffer? = {
            stateLock.lock(); defer { stateLock.unlock() }
            if let existing = streamBuffers[sf.streamId] { return existing }
            guard streamBuffers.count < FudpClient.maxConcurrentInboundStreams else { return nil }
            let fresh = InboundStreamBuffer()
            streamBuffers[sf.streamId] = fresh
            return fresh
        }()
        guard let buffer else {
            log("refusing stream \(sf.streamId): \(FudpClient.maxConcurrentInboundStreams) already open")
            return
        }

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

    /// Drop everything whose meaning depended on the peer's previous
    /// connection: half-assembled streams and the tombstones that would
    /// otherwise reject the stream ids it is about to reuse.
    ///
    /// FUDP2V1 §Stream Retirement is explicit that the retired set MUST
    /// be cleared on peer restart — "the restarted peer's stream IDs
    /// begin again at the lowest value, and stale tombstones would
    /// wrongly drop its new streams." Keeping them is the failure where
    /// a request is answered and the answer silently discarded.
    private func resetStateForPeerRestart() {
        stateLock.lock()
        let orphaned = Array(streamBuffers.values)
        streamBuffers.removeAll()
        retiredStreams.removeAll()
        retiredOrder.removeAll()
        stateLock.unlock()
        for buffer in orphaned { buffer.cleanup() }
        replay.removeConnection(connection.connectionId)

        // **The send side has to forget too.** A restarted peer counts
        // its packets from zero again, and an ACK generator still
        // advertising the previous session's numbers tells it we
        // received packets it never sent — which its own loss detection
        // reads as an enormous gap. `TransferMachinery.resetForRestart`
        // existed for this and nothing called it; the reference clears
        // sentPackets, the ack manager and largestAcked together.
        transfer.resetForRestart()
        connection.clearPeerEpoch()

        // The restarted peer may run different software; datagram
        // capability must be re-established by the application.
        stateLock.lock()
        _datagramsEnabled = false
        stateLock.unlock()
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
        // A stream rate cap (set during a call) is honoured exactly; the
        // 8 KB floor would otherwise let retransmits alone exceed a low cap.
        let pacingBudget = transfer.pacingBudgetBytes(intervalMs: Int64(FudpClient.retransmitIntervalMs))
        let byteBudget = transfer.streamRateCapBps > 0 ? max(1, pacingBudget) : max(8 * 1024, pacingBudget)
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
    /// any pending ACK piggybacked in front, if it fits).
    private func sendDataPacket(streamFrames: [StreamFrame], retransmitCount: Int = 0) async throws {
        try await sendPacket(
            frameBytes: await withPendingAck(streamFrames.map { $0.encode() }),
            trackedFrames: streamFrames,
            hasDatagram: false,
            retransmitCount: retransmitCount
        )
    }

    /// The frames for one packet: `frameBytes`, plus the pending ACK in
    /// front if it fits beside them within `maxPacketSize`. An ACK that
    /// does not fit is sent in a packet of its own first — never
    /// truncated to fit, since every ACK frame's full ranges are what
    /// protect against earlier ACKs being lost (FUDP3 §2.1).
    private func withPendingAck(_ frameBytes: [Data]) async -> [Data] {
        guard transfer.ackGenerator.hasPendingAcks,
              let ack = transfer.ackGenerator.generateAckFrame(maxBytes: maxFrameBytes)
        else { return frameBytes }
        let ackBytes = ack.encode()
        let used = frameBytes.reduce(0) { $0 + $1.count }
        if used + ackBytes.count <= maxFrameBytes {
            return [ackBytes] + frameBytes
        }
        do {
            try await sendPacket(frameBytes: [ackBytes], trackedFrames: [], hasDatagram: false)
        } catch {
            log("failed to send ACK: \(error)")
        }
        return frameBytes
    }

    /// Seal and send one packet. Ack-eliciting packets (those carrying
    /// `trackedFrames`) are recorded for loss detection BEFORE the socket
    /// write — on localhost the ACK can beat a post-write record. ACK-only
    /// and DATAGRAM-only packets are not tracked and not in bytes in flight.
    private func sendPacket(
        frameBytes: [Data],
        trackedFrames: [StreamFrame],
        hasDatagram: Bool,
        retransmitCount: Int = 0
    ) async throws {
        let ackEliciting = !trackedFrames.isEmpty
        // E1: ACK-only packets skip the timestamp. DATAGRAM packets carry
        // application data, so they keep it (replay protection).
        let packet = try sealPacket(frameBytes: frameBytes, includeTimestamp: ackEliciting || hasDatagram)

        if packet.bytes.count > maxPacketSize {
            // Every sender budgets to maxFrameBytes, so this is a bug in
            // the budget, not a condition to handle: count it loudly and
            // send anyway.
            let n = withStateLock { () -> Int64 in
                _oversizePacketCount += 1
                return _oversizePacketCount
            }
            if n <= 5 || n % 1000 == 0 {
                FileHandle.standardError.write(Data(
                    "[FudpClient] sent a \(packet.bytes.count)-byte packet over maxPacketSize \(maxPacketSize) (count=\(n))\n".utf8))
            }
        }

        if ackEliciting {
            transfer.sentPackets.recordSent(
                packetNumber: packet.number,
                frames: trackedFrames,
                size: packet.bytes.count,
                retransmitCount: retransmitCount
            )
            transfer.congestion.onSend(packet.bytes.count)
        }

        try await transport.send(packet.bytes)
    }

    /// Send an ACK-only packet (not ack-eliciting, no timestamp — E1).
    private func sendAckOnly() async {
        guard let ack = transfer.ackGenerator.generateAckFrame(maxBytes: maxFrameBytes) else { return }
        do {
            try await sendPacket(frameBytes: [ack.encode()], trackedFrames: [], hasDatagram: false)
        } catch {
            log("failed to send ACK: \(error)")
        }
    }

    /// Test hook: send arbitrary frame bytes in one packet, bypassing
    /// every check — used to put frames an older peer cannot parse on
    /// the wire. Stamped like a datagram packet, so only the frames can
    /// make the receiver drop it.
    func sendFramesForTest(_ frameBytes: [Data]) async throws {
        try await sendPacket(frameBytes: frameBytes, trackedFrames: [], hasDatagram: true)
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

/// One-at-a-time admission, FIFO.
///
/// Deliberately not a lock: holding one across the `await` that a
/// request/response exchange *is* would block a thread for the whole
/// round trip. Waiters queue in arrival order, so a burst of calls is
/// served in the order it was made rather than by whoever the scheduler
/// happens to wake.
private actor ExchangeGate {
    private var busy = false
    private var waiting: [CheckedContinuation<Void, Never>] = []

    func acquire() async {
        guard busy else {
            busy = true
            return
        }
        await withCheckedContinuation { waiting.append($0) }
    }

    /// Hands the slot straight to the next waiter rather than clearing
    /// `busy`: releasing it first would let a call that arrived later
    /// overtake the queue.
    func release() {
        if waiting.isEmpty {
            busy = false
        } else {
            waiting.removeFirst().resume()
        }
    }
}

private extension Data {
    var hex: String { map { String(format: "%02x", $0) }.joined() }
}

import Security
