import Foundation

/// Plaintext FUDP node-pubkey discovery.
///
/// **Wire shape**, mirroring `FC-JDK fudp/Protocol.java`
/// (`CONTROL_HELLO = 0x01`, `CONTROL_PUBLIC_KEY = 0x02`):
///
/// ```
/// client → server   CONTROL packet, body = [0x01]                  ; HELLO
/// server → client   CONTROL packet, body = [0x02, pubkey(33 B)]    ; PUBLIC_KEY
/// ```
///
/// Both directions ride on the standard 21-byte ``PacketHeader`` —
/// type=control, version=1, connectionId=0, packetNumber=0. Plaintext;
/// no encryption, no prior knowledge of the peer's pubkey needed.
/// That's the whole point: this is the bootstrap that lets us
/// configure the encrypted side.
///
/// The server has a sliding-window rate limiter on PUBLIC_KEY
/// responses (see `Protocol.allowPublicKeyResponse`), so don't spam
/// — once per user-initiated Settings click is fine.
public enum FudpDiscovery {

    public static let helloTypeByte: UInt8       = 0x01
    public static let publicKeyTypeByte: UInt8   = 0x02
    public static let pubkeyLength = 33

    public enum Failure: Error, CustomStringConvertible {
        case invalidPort(UInt16)
        case timeout
        case headerDecode(Error)
        case unexpectedPacketType(PacketHeader.PacketType)
        case unexpectedControlByte(UInt8)
        case truncated(needed: Int, got: Int)
        case underlying(Error)

        public var description: String {
            switch self {
            case .invalidPort(let p):
                return "FudpDiscovery: invalid port \(p)"
            case .timeout:
                return "FudpDiscovery: no PUBLIC_KEY reply within the timeout"
            case .headerDecode(let e):
                return "FudpDiscovery: header decode failed — \(e)"
            case .unexpectedPacketType(let t):
                return "FudpDiscovery: expected CONTROL packet, got \(t)"
            case .unexpectedControlByte(let b):
                return String(format: "FudpDiscovery: expected control byte 0x02 (PUBLIC_KEY), got 0x%02x", b)
            case let .truncated(needed, got):
                return "FudpDiscovery: payload too short (need ≥ \(needed) B, got \(got))"
            case .underlying(let e):
                return "FudpDiscovery: \(e)"
            }
        }
    }

    /// Discover the FUDP node pubkey at `host:port`. Sends a HELLO,
    /// awaits a PUBLIC_KEY reply, returns the 33-byte SEC1-compressed
    /// pubkey.
    ///
    /// Default timeout is 3 s — over the loopback or LAN a healthy
    /// server replies in single-digit milliseconds.
    public static func discoverPubkey(
        host: String,
        port: UInt16,
        timeoutMs: Int = 3_000
    ) async throws -> Data {

        // Build the HELLO datagram once up-front so transient
        // construction failures surface before opening a socket.
        let request = try buildHelloDatagram()

        let connection: FudpConnection
        do {
            connection = try await FudpConnection(host: host, port: port)
        } catch {
            throw Failure.underlying(error)
        }
        defer { connection.close() }

        do {
            try await connection.send(request)
        } catch {
            throw Failure.underlying(error)
        }

        return try await withThrowingTaskGroup(of: Data.self) { group in
            group.addTask {
                for await datagram in connection.datagrams {
                    if Task.isCancelled { throw Failure.timeout }
                    if let pubkey = try? parsePublicKeyDatagram(datagram.data) {
                        return pubkey
                    }
                    // Datagram didn't parse as PUBLIC_KEY — keep waiting,
                    // the server might multiplex other traffic on the
                    // same source port (e.g. CHALLENGE if anti-DoS is
                    // armed). Discovery has its own timeout below.
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

    // MARK: - wire encoding (exposed for testability)

    /// Construct the bytes a HELLO datagram puts on the wire:
    /// `[PacketHeader(.control, conn=0, pkt=0)] ‖ [0x01]`.
    public static func buildHelloDatagram() throws -> Data {
        let header = PacketHeader(
            packetType: .control,
            flags: [],
            version: PacketHeader.currentVersion,
            connectionId: 0,
            packetNumber: 0
        )
        var datagram = header.encode()
        datagram.append(helloTypeByte)
        return datagram
    }

    /// Parse an inbound datagram as a PUBLIC_KEY control packet.
    /// Returns the 33-byte pubkey on success; throws a typed
    /// ``Failure`` otherwise so the caller can decide whether to
    /// keep waiting or surface the error.
    public static func parsePublicKeyDatagram(_ data: Data) throws -> Data {
        guard data.count >= PacketHeader.size else {
            throw Failure.truncated(needed: PacketHeader.size, got: data.count)
        }

        let header: PacketHeader
        do {
            header = try PacketHeader.decode(data)
        } catch {
            throw Failure.headerDecode(error)
        }
        guard header.packetType == .control else {
            throw Failure.unexpectedPacketType(header.packetType)
        }

        let body = Data(data.dropFirst(PacketHeader.size))
        let needed = 1 + pubkeyLength
        guard body.count >= needed else {
            throw Failure.truncated(needed: needed, got: body.count)
        }
        let typeByte = body[body.startIndex]
        guard typeByte == publicKeyTypeByte else {
            throw Failure.unexpectedControlByte(typeByte)
        }
        return Data(body.dropFirst().prefix(pubkeyLength))
    }
}
