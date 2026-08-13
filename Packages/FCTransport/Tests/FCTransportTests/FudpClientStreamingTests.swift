import XCTest
import Security
import FCCore
@testable import FCTransport

/// In-process datagram pipe standing in for the UDP socket.
/// `send` hands the datagram to the test server; the server injects
/// its packets back through the stream continuation.
private final class FakeTransport: DatagramTransport, @unchecked Sendable {
    let datagrams: AsyncStream<FudpConnection.Datagram>
    private let continuation: AsyncStream<FudpConnection.Datagram>.Continuation
    private let lock = NSLock()
    private var handler: ((Data) -> Void)?

    init() {
        var captured: AsyncStream<FudpConnection.Datagram>.Continuation!
        self.datagrams = AsyncStream { captured = $0 }
        self.continuation = captured
    }

    func setHandler(_ handler: @escaping (Data) -> Void) {
        lock.lock(); defer { lock.unlock() }
        self.handler = handler
    }

    private func currentHandler() -> ((Data) -> Void)? {
        lock.lock(); defer { lock.unlock() }
        return handler
    }

    func send(_ data: Data) async throws {
        currentHandler()?(data)
    }

    func inject(_ data: Data) {
        continuation.yield(FudpConnection.Datagram(data: data))
    }

    func close() {
        continuation.finish()
    }
}

/// Minimal FUDP peer for loopback tests: decrypts client packets,
/// ACKs every ack-eliciting one (mirroring the Java server's
/// ACK_THRESHOLD=1), reassembles request streams, and answers each
/// complete REQUEST via `makeResponse`, chunking large responses
/// across stream frames exactly like the real server.
private final class LoopbackServer: @unchecked Sendable {
    let privkey: Data
    let pubkey: Data
    let clientPubkey: Data
    let transport: FakeTransport

    /// Drop every Nth inbound DATA packet before processing (0 = no loss).
    var dropEveryNth: Int = 0
    /// Only the first N inbound packets are subject to dropping, so
    /// retransmissions (which arrive later) always get through — keeps
    /// the loss test deterministic and fast (pure gap-detected loss).
    var dropWindow: Int = 60
    var makeResponse: ((AppMessageEnvelope) -> AppMessageEnvelope?)?

    private let lock = NSLock()
    private var packetNumber: Int64 = 0
    private var inboundCount = 0
    private let ackGenerator = AckGenerator()
    private var streams: [UInt64: InboundStreamBuffer] = [:]
    private var completedStreams: Set<UInt64> = []
    private(set) var receivedDataPackets = 0
    private(set) var droppedPackets = 0

    private let maxChunk = 1247   // mirrors FudpClient.maxStreamChunk at 1350 MTU
    private var nextStreamId: UInt64 = 1  // odd parity — disjoint from the client's

    init(privkey: Data, clientPubkey: Data, transport: FakeTransport) throws {
        self.privkey = privkey
        self.pubkey = try Secp256k1.publicKey(fromPrivateKey: privkey)
        self.clientPubkey = clientPubkey
        self.transport = transport
    }

    func handle(_ datagram: Data) {
        lock.lock(); defer { lock.unlock() }
        guard datagram.count > PacketHeader.size else { return }
        guard let header = try? PacketHeader.decode(datagram) else { return }
        guard header.packetType == .data || header.packetType == .ack else { return }

        receivedDataPackets += 1
        if dropEveryNth > 0 {
            inboundCount += 1
            if inboundCount <= dropWindow && inboundCount % dropEveryNth == 0 {
                droppedPackets += 1
                return  // simulated network loss: no ACK, no processing
            }
        }

        let aad = header.encode()
        let body = Data(datagram.dropFirst(PacketHeader.size))
        guard let opened = try? AsyTwoWay.open(bundle: body, aad: aad, localPrivkey: privkey),
              opened.senderPubkey == clientPubkey,
              let payload = try? FudpPayload.parse(
                  opened.plaintext,
                  hasTimestamp: header.flags.contains(.hasTimestamp),
                  hasEpoch: header.flags.contains(.hasEpoch)
              )
        else { return }

        var ackEliciting = false
        for frame in payload.frames {
            switch frame {
            case .stream(let sf):
                ackEliciting = true
                handleStream(sf)
            case .ack, .padding, .unknown:
                break
            }
        }

        if ackEliciting {
            ackGenerator.onPacketReceived(header.packetNumber)
            if let ack = ackGenerator.generateAckFrame() {
                sendPacket(frameBytes: [ack.encode()])
            }
        }
    }

    private func handleStream(_ sf: StreamFrame) {
        guard !completedStreams.contains(sf.streamId) else { return }
        let buffer = streams[sf.streamId] ?? InboundStreamBuffer()
        streams[sf.streamId] = buffer
        guard (try? buffer.append(offset: sf.offset, data: sf.data, fin: sf.fin)) != nil else { return }
        // `try?` flattens the Data?? to Data? — nil covers both "threw"
        // and "not complete yet".
        guard let complete = try? buffer.assembleIfComplete() else { return }

        streams.removeValue(forKey: sf.streamId)
        completedStreams.insert(sf.streamId)

        guard let envelope = try? AppMessageCodec.decode(complete),
              envelope.type == .request,
              let response = makeResponse?(envelope)
        else { return }
        sendMessage(response)
    }

    private func sendMessage(_ envelope: AppMessageEnvelope) {
        let bytes = AppMessageCodec.encode(envelope)
        let streamId = nextStreamId
        nextStreamId += 4
        var offset: UInt64 = 0
        var idx = bytes.startIndex
        while idx < bytes.endIndex {
            let end = bytes.index(idx, offsetBy: maxChunk, limitedBy: bytes.endIndex) ?? bytes.endIndex
            let chunk = Data(bytes[idx..<end])
            let fin = end == bytes.endIndex
            let frame = StreamFrame(streamId: streamId, offset: offset, data: chunk, fin: fin)
            sendPacket(frameBytes: [frame.encode()])
            offset += UInt64(chunk.count)
            idx = end
        }
    }

    private func sendPacket(frameBytes: [Data]) {
        let pn = packetNumber
        packetNumber += 1
        let header = PacketHeader(
            packetType: .data,
            flags: [.hasTimestamp, .hasEpoch],
            connectionId: 424242,
            packetNumber: pn
        )
        let plaintext = FudpPayload.assemble(
            includeTimestamp: true,
            timestamp: ReplayProtection.currentTimeMillis(),
            includeEpoch: true,
            sessionEpoch: 777,
            frameBytes: frameBytes
        )
        var iv = Data(count: AsyTwoWay.ivLength)
        iv.withUnsafeMutableBytes { _ = SecRandomCopyBytes(kSecRandomDefault, AsyTwoWay.ivLength, $0.baseAddress!) }
        let aad = header.encode()
        guard let bundle = try? AsyTwoWay.seal(
            plaintext: plaintext,
            aad: aad,
            peerPubkey: clientPubkey,
            localPrivkey: privkey,
            localPubkey: pubkey,
            iv: iv
        ) else { return }
        var packet = aad
        packet.append(bundle)
        transport.inject(packet)
    }
}

final class FudpClientStreamingTests: XCTestCase {

    private let clientPriv = Data(repeating: 0x11, count: 32)
    private let serverPriv = Data(repeating: 0x22, count: 32)

    private func makeLoopback() throws -> (FudpClient, LoopbackServer, FakeTransport) {
        let transport = FakeTransport()
        let clientPub = try Secp256k1.publicKey(fromPrivateKey: clientPriv)
        let server = try LoopbackServer(privkey: serverPriv, clientPubkey: clientPub, transport: transport)
        transport.setHandler { [weak server] data in server?.handle(data) }
        let client = try FudpClient(
            transport: transport,
            host: "127.0.0.1",
            port: 1,
            peerPubkey: server.pubkey,
            localPrivkey: clientPriv
        )
        return (client, server, transport)
    }

    /// Deterministic pseudo-random payload (seeded LCG — no crypto
    /// need). Word-wise generation so the 9 MB case stays fast.
    private func payload(bytes: Int, seed: UInt64 = 0x5eed) -> Data {
        var out = [UInt8]()
        out.reserveCapacity(bytes + 8)
        var state = seed
        while out.count < bytes {
            state = state &* 6364136223846793005 &+ 1442695040888963407
            withUnsafeBytes(of: state.bigEndian) { out.append(contentsOf: $0) }
        }
        out.removeLast(out.count - bytes)
        return Data(out)
    }

    func testChunkedRequestResponseRoundTrip() async throws {
        let (client, server, _) = try makeLoopback()
        defer { client.close() }

        // 100 KB each way: ~81 chunks per direction.
        let requestBody = payload(bytes: 100_000)
        server.makeResponse = { request in
            AppMessageEnvelope(
                type: .response,
                messageId: request.messageId,
                payload: request.payload   // echo
            )
        }

        let messageId: Int64 = 12345
        try await client.send(AppMessageEnvelope(
            type: .request, messageId: messageId, payload: requestBody))
        let response = try await client.receive(matching: messageId, timeoutMs: 20_000)
        XCTAssertEqual(Data(response.payload), requestBody)
        XCTAssertEqual(response.messageId, messageId)
    }

    func testUploadSurvivesPacketLoss() async throws {
        let (client, server, _) = try makeLoopback()
        defer { client.close() }

        server.dropEveryNth = 11   // drop ~9% of the first 60 client packets
        let requestBody = payload(bytes: 80_000, seed: 0x1055)
        server.makeResponse = { request in
            // Reply with the double-SHA of what actually arrived, so the
            // assertion proves the server got every retransmitted byte.
            AppMessageEnvelope(
                type: .response,
                messageId: request.messageId,
                payload: Hash.doubleSha256(Data(request.payload))
            )
        }

        let messageId: Int64 = 777
        try await client.send(AppMessageEnvelope(
            type: .request, messageId: messageId, payload: requestBody))
        let response = try await client.receive(matching: messageId, timeoutMs: 30_000)
        XCTAssertEqual(Data(response.payload), Hash.doubleSha256(requestBody))
        XCTAssertGreaterThan(server.droppedPackets, 0, "loss simulation must have dropped something")
        XCTAssertGreaterThan(client.transfer.sentPackets.retransmitCount, 0,
                             "recovery must have retransmitted the dropped chunks")
    }

    func testFapiUploadFromFile() async throws {
        let (client, server, _) = try makeLoopback()
        defer { client.close() }
        let fapi = FapiClient(fudp: client)

        // Server side: decode the FAPI request, verify the streamed
        // binary against its declared hash, echo the hash back as data.
        server.makeResponse = { request in
            guard let wrapper = try? RequestMessage.parse(Data(request.payload)),
                  let (fapiRequest, binary) = try? UnifiedCodec.decodeRequest(wrapper.data)
            else { return nil }
            let got = binary ?? Data()
            let gotHash = Hash.doubleSha256(got).map { String(format: "%02x", $0) }.joined()
            let ok = Int64(got.count) == fapiRequest.dataSize && gotHash == fapiRequest.dataHash
            var resp = FapiResponse()
            resp.requestId = fapiRequest.id
            resp.code = ok ? 0 : 1
            resp.data = Data("{\"did\":\"\(gotHash)\"}".utf8)
            guard let encoded = try? UnifiedCodec.encodeResponse(resp) else { return nil }
            return AppMessageEnvelope(
                type: .response,
                messageId: request.messageId,
                payload: ResponseMessage(status: .success, data: encoded).encode()
            )
        }

        // Write a 300 KB temp file to upload.
        let content = payload(bytes: 300_000, seed: 0xf17e)
        let fileURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("fudp-upload-test-\(UUID().uuidString).bin")
        try content.write(to: fileURL)
        defer { try? FileManager.default.removeItem(at: fileURL) }

        let progressHighWater = ByteHighWater()
        let reply = try await fapi.callUploadingFile(
            api: "disk.put",
            fileURL: fileURL,
            progress: { sent, total in progressHighWater.record(sent: sent, total: total) }
        )

        XCTAssertEqual(reply.response.code, 0)
        let expectedHash = Hash.doubleSha256(content).map { String(format: "%02x", $0) }.joined()
        let dataString = String(data: reply.response.data ?? Data(), encoding: .utf8) ?? ""
        XCTAssertTrue(dataString.contains(expectedHash), "server-computed hash must match the file")
        XCTAssertEqual(progressHighWater.maxSent, 300_000)
        XCTAssertEqual(progressHighWater.total, 300_000)
    }

    func testFapiDownloadToFileSpillsAndVerifies() async throws {
        let (client, server, _) = try makeLoopback()
        defer { client.close() }
        let fapi = FapiClient(fudp: client)

        // 9 MB body — crosses the 8 MB spill threshold, so the response
        // travels: stream chunks → spill file → mapped Data → sliced
        // decode → chunked write to the output file.
        let body = payload(bytes: 9_000_000, seed: 0xd07)
        server.makeResponse = { request in
            guard let wrapper = try? RequestMessage.parse(Data(request.payload)),
                  let (fapiRequest, _) = try? UnifiedCodec.decodeRequest(wrapper.data)
            else { return nil }
            var resp = FapiResponse()
            resp.requestId = fapiRequest.id
            resp.code = 0
            resp.data = Data("{\"size\":\(body.count)}".utf8)
            guard let encoded = try? UnifiedCodec.encodeResponse(resp, binary: body) else { return nil }
            return AppMessageEnvelope(
                type: .response,
                messageId: request.messageId,
                payload: ResponseMessage(status: .success, data: encoded).encode()
            )
        }

        let outputURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("fudp-download-test-\(UUID().uuidString).bin")
        defer { try? FileManager.default.removeItem(at: outputURL) }

        let reply = try await fapi.callDownloadingToFile(
            api: "disk.get",
            params: Data("{\"id\":\"test\"}".utf8),
            outputURL: outputURL,
            idleTimeoutMs: 60_000
        )

        XCTAssertEqual(reply.response.code, 0)
        XCTAssertNil(reply.binary, "binary must have been written to disk, not returned")
        let written = try Data(contentsOf: outputURL, options: .alwaysMapped)
        XCTAssertEqual(written.count, body.count)
        XCTAssertEqual(Hash.doubleSha256(written), Hash.doubleSha256(body))
    }
}

/// Thread-safe progress recorder.
private final class ByteHighWater: @unchecked Sendable {
    private let lock = NSLock()
    private var _maxSent: Int64 = 0
    private var _total: Int64 = 0

    func record(sent: Int64, total: Int64) {
        lock.lock(); defer { lock.unlock() }
        if sent > _maxSent { _maxSent = sent }
        _total = total
    }

    var maxSent: Int64 { lock.lock(); defer { lock.unlock() }; return _maxSent }
    var total: Int64 { lock.lock(); defer { lock.unlock() }; return _total }
}
