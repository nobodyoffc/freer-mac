import Foundation

/// FUDP application-level message types. The numeric codes are part of
/// the wire format (first byte of every encoded `AppMessage`).
public enum MessageType: UInt8, Sendable, CaseIterable {
    case request   = 0x10
    case response  = 0x11
    case error     = 0x12
    case notify    = 0x20
    case notifyAck = 0x21
    case ping      = 0x30
    case pong      = 0x31
}

/// Common envelope shared by every concrete message. Wire format:
///
/// ```
///   1 B    typeCode (MessageType.rawValue)
///   8 B    messageId (BE Int64)
///   1 B    flags
///   varint payloadLength (QUIC-style)
///   N B    payload (per-type)
/// ```
///
/// Concrete types live in sibling files (`PingMessage.swift`,
/// `RequestMessage.swift`, etc.) and provide their own payload codecs.
/// `AppMessageCodec` handles the envelope.
public struct AppMessageEnvelope: Equatable, Sendable {

    /// Flag bits, mirroring `FC-AJDK/.../message/AppMessage.java`.
    public struct Flags: OptionSet, Sendable, Hashable {
        public let rawValue: UInt8
        public init(rawValue: UInt8) { self.rawValue = rawValue }

        public static let needAck       = Flags(rawValue: 0x01)
        public static let compressed    = Flags(rawValue: 0x02)
        public static let encryptedApp  = Flags(rawValue: 0x04)
        public static let fragmented    = Flags(rawValue: 0x08)
        public static let wantPongInfo  = Flags(rawValue: 0x10)
    }

    public let type: MessageType
    public let messageId: Int64
    public let flags: Flags
    public let payload: Data

    public init(type: MessageType, messageId: Int64, flags: Flags = [], payload: Data) {
        self.type = type
        self.messageId = messageId
        self.flags = flags
        self.payload = Data(payload)
    }
}

public enum AppMessageCodec {

    public enum Failure: Error, CustomStringConvertible {
        case truncated(needed: Int, got: Int)
        case unknownType(UInt8)
        case payloadShorterThanLength(declared: Int, available: Int)
        case varint(FudpVarint.Failure)

        public var description: String {
            switch self {
            case let .truncated(needed, got):
                return "AppMessageCodec: input truncated (need ≥ \(needed), got \(got))"
            case let .unknownType(byte):
                return String(format: "AppMessageCodec: unknown type 0x%02x", byte)
            case let .payloadShorterThanLength(declared, available):
                return "AppMessageCodec: payload length declares \(declared) bytes but only \(available) remain"
            case .varint(let inner):
                return "AppMessageCodec: \(inner)"
            }
        }
    }

    public static func encode(_ envelope: AppMessageEnvelope) -> Data {
        var out = Data()
        out.append(envelope.type.rawValue)
        var idBE = UInt64(bitPattern: envelope.messageId).bigEndian
        out.append(Data(bytes: &idBE, count: 8))
        out.append(envelope.flags.rawValue)
        out.append(FudpVarint.encode(UInt64(envelope.payload.count)))
        out.append(envelope.payload)
        return out
    }

    /// Minimum bytes needed before we even know the payload length.
    /// 1B type + 8B id + 1B flags + at least 1B varint = 11.
    public static let minimumLength = 11

    public static func decode(_ data: Data) throws -> AppMessageEnvelope {
        let bytes = [UInt8](data)
        guard bytes.count >= minimumLength else {
            throw Failure.truncated(needed: minimumLength, got: bytes.count)
        }

        guard let type = MessageType(rawValue: bytes[0]) else {
            throw Failure.unknownType(bytes[0])
        }

        var id: UInt64 = 0
        for i in 0..<8 { id = (id << 8) | UInt64(bytes[1 + i]) }
        let messageId = Int64(bitPattern: id)
        let flags = AppMessageEnvelope.Flags(rawValue: bytes[9])

        // Decode the varint starting at offset 10.
        let varintData = data.advanced(by: 10)
        let (rawLen, consumed): (UInt64, Int)
        do {
            (rawLen, consumed) = try FudpVarint.decode(varintData)
        } catch let e as FudpVarint.Failure {
            throw Failure.varint(e)
        }
        let payloadLen = Int(rawLen)

        let payloadStart = 10 + consumed
        let available = bytes.count - payloadStart
        guard available >= payloadLen else {
            throw Failure.payloadShorterThanLength(declared: payloadLen, available: available)
        }

        let payload = Data(bytes[payloadStart..<(payloadStart + payloadLen)])
        return AppMessageEnvelope(type: type, messageId: messageId, flags: flags, payload: payload)
    }
}
