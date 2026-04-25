import Foundation

/// Body of a CHALLENGE control packet — what the FUDP server sends to
/// an unverified client. Sits *inside* the encrypted-payload portion of
/// a control-type packet (`PacketHeader` flags bits 0-1 = `0x02`),
/// starting at byte offset 21 of the on-wire packet.
///
/// Wire format (26 bytes):
/// ```
///   1 B   typeByte = 0x03 (CONTROL_CHALLENGE)
///  16 B   nonce
///   1 B   difficulty (UInt8)
///   8 B   timestamp (BE Int64, server's `currentTimeMillis()`)
/// ```
public struct ChallengePayload: Equatable, Hashable, Sendable {
    public static let length = 26
    public static let typeByte: UInt8 = 0x03

    public let nonce: Data
    public let difficulty: Int
    public let timestamp: Int64

    public enum Failure: Error, CustomStringConvertible {
        case wrongLength(got: Int)
        case wrongTypeByte(got: UInt8)
        case wrongNonceLength(got: Int)

        public var description: String {
            switch self {
            case .wrongLength(let n):       return "ChallengePayload: must be \(ChallengePayload.length) bytes, got \(n)"
            case .wrongTypeByte(let b):     return String(format: "ChallengePayload: expected type byte 0x%02x, got 0x%02x", ChallengePayload.typeByte, b)
            case .wrongNonceLength(let n):  return "ChallengePayload: nonce must be \(ProofOfWork.nonceLength) bytes, got \(n)"
            }
        }
    }

    public init(nonce: Data, difficulty: Int, timestamp: Int64) throws {
        guard nonce.count == ProofOfWork.nonceLength else {
            throw Failure.wrongNonceLength(got: nonce.count)
        }
        self.nonce = Data(nonce)
        self.difficulty = difficulty
        self.timestamp = timestamp
    }

    public func encode() -> Data {
        var out = Data(capacity: ChallengePayload.length)
        out.append(ChallengePayload.typeByte)
        out.append(nonce)
        out.append(UInt8(truncatingIfNeeded: difficulty))
        var ts = UInt64(bitPattern: timestamp).bigEndian
        out.append(Data(bytes: &ts, count: 8))
        return out
    }

    public static func decode(_ data: Data) throws -> ChallengePayload {
        let bytes = [UInt8](data)
        guard bytes.count == length else { throw Failure.wrongLength(got: bytes.count) }
        guard bytes[0] == typeByte else { throw Failure.wrongTypeByte(got: bytes[0]) }
        let nonce = Data(bytes[1..<17])
        let difficulty = Int(bytes[17])
        var ts: UInt64 = 0
        for i in 0..<8 { ts = (ts << 8) | UInt64(bytes[18 + i]) }
        let timestamp = Int64(bitPattern: ts)
        return try ChallengePayload(nonce: nonce, difficulty: difficulty, timestamp: timestamp)
    }
}

/// Body of a CHALLENGE_RESPONSE control packet — the client's reply
/// containing the PoW solution.
///
/// Wire format (25 bytes):
/// ```
///   1 B   typeByte = 0x04 (CONTROL_CHALLENGE_RESPONSE)
///  16 B   nonce  (echoed from the CHALLENGE)
///   8 B   solution (BE Int64)
/// ```
public struct ChallengeResponsePayload: Equatable, Hashable, Sendable {
    public static let length = 25
    public static let typeByte: UInt8 = 0x04

    public let nonce: Data
    public let solution: Data

    public enum Failure: Error, CustomStringConvertible {
        case wrongLength(got: Int)
        case wrongTypeByte(got: UInt8)
        case wrongNonceLength(got: Int)
        case wrongSolutionLength(got: Int)

        public var description: String {
            switch self {
            case .wrongLength(let n):           return "ChallengeResponsePayload: must be \(ChallengeResponsePayload.length) bytes, got \(n)"
            case .wrongTypeByte(let b):         return String(format: "ChallengeResponsePayload: expected type byte 0x%02x, got 0x%02x", ChallengeResponsePayload.typeByte, b)
            case .wrongNonceLength(let n):      return "ChallengeResponsePayload: nonce must be \(ProofOfWork.nonceLength) bytes, got \(n)"
            case .wrongSolutionLength(let n):   return "ChallengeResponsePayload: solution must be \(ProofOfWork.solutionLength) bytes, got \(n)"
            }
        }
    }

    public init(nonce: Data, solution: Data) throws {
        guard nonce.count == ProofOfWork.nonceLength else {
            throw Failure.wrongNonceLength(got: nonce.count)
        }
        guard solution.count == ProofOfWork.solutionLength else {
            throw Failure.wrongSolutionLength(got: solution.count)
        }
        self.nonce = Data(nonce)
        self.solution = Data(solution)
    }

    public func encode() -> Data {
        var out = Data(capacity: ChallengeResponsePayload.length)
        out.append(ChallengeResponsePayload.typeByte)
        out.append(nonce)
        out.append(solution)
        return out
    }

    public static func decode(_ data: Data) throws -> ChallengeResponsePayload {
        let bytes = [UInt8](data)
        guard bytes.count == length else { throw Failure.wrongLength(got: bytes.count) }
        guard bytes[0] == typeByte else { throw Failure.wrongTypeByte(got: bytes[0]) }
        let nonce = Data(bytes[1..<17])
        let solution = Data(bytes[17..<25])
        return try ChallengeResponsePayload(nonce: nonce, solution: solution)
    }
}
