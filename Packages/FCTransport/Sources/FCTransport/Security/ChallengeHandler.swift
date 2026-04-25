import Foundation

/// Client-side handler for FUDP's DDoS challenge flow. When the
/// FC-JDK / FC-AJDK server has DDoS defense enabled, an unverified
/// client's first packet is greeted with a `CHALLENGE` control packet;
/// the client must solve a PoW and reply with a `CHALLENGE_RESPONSE`
/// before the server will process any further data packets.
///
/// This class is a *minimal* port: it handles a single challenge
/// synchronously, with a per-attempt timeout and a difficulty cap.
/// FC-AJDK's reference impl additionally tracks per-peer reputation
/// (suspicious-peer detection on repeated high-difficulty challenges)
/// — that lands when we hit a real production server, not now.
public final class ChallengeHandler: Sendable {

    public static let defaultMaxAcceptableDifficulty = 16
    public static let defaultMaxPowTimeMs = 2_000

    public struct Outcome: Equatable, Sendable {
        public let nonce: Data
        public let difficulty: Int
        public let timestamp: Int64
        public let solution: Data
        public let responsePayload: Data
    }

    public enum Failure: Error, CustomStringConvertible {
        case excessiveDifficulty(requested: Int, maxAcceptable: Int)
        case malformedChallenge(underlying: Error)
        case solveFailed(underlying: Error)

        public var description: String {
            switch self {
            case let .excessiveDifficulty(requested, maxAcceptable):
                return "ChallengeHandler: server demanded difficulty \(requested), we cap at \(maxAcceptable)"
            case .malformedChallenge(let e):
                return "ChallengeHandler: malformed challenge — \(e)"
            case .solveFailed(let e):
                return "ChallengeHandler: PoW solve failed — \(e)"
            }
        }
    }

    public let maxAcceptableDifficulty: Int
    public let maxPowTimeMs: Int

    public init(
        maxAcceptableDifficulty: Int = ChallengeHandler.defaultMaxAcceptableDifficulty,
        maxPowTimeMs: Int = ChallengeHandler.defaultMaxPowTimeMs
    ) {
        self.maxAcceptableDifficulty = maxAcceptableDifficulty
        self.maxPowTimeMs = maxPowTimeMs
    }

    /// Decode an incoming CHALLENGE payload, validate that the demanded
    /// difficulty is within our cap, solve the PoW, and return a fully-
    /// formed CHALLENGE_RESPONSE payload along with the solve metadata.
    ///
    /// - Parameter challengePayload: the 26-byte payload at offset 21 of
    ///   the incoming control packet (the part *after* the 21-byte
    ///   PacketHeader).
    public func handle(challengePayload: Data) throws -> Outcome {
        let challenge: ChallengePayload
        do {
            challenge = try ChallengePayload.decode(challengePayload)
        } catch {
            throw Failure.malformedChallenge(underlying: error)
        }

        guard challenge.difficulty <= maxAcceptableDifficulty else {
            throw Failure.excessiveDifficulty(
                requested: challenge.difficulty,
                maxAcceptable: maxAcceptableDifficulty
            )
        }

        let solution: Data
        do {
            solution = try ProofOfWork.solve(
                nonce: challenge.nonce,
                difficulty: challenge.difficulty,
                timeoutMs: maxPowTimeMs
            )
        } catch {
            throw Failure.solveFailed(underlying: error)
        }

        let response = try ChallengeResponsePayload(nonce: challenge.nonce, solution: solution)
        return Outcome(
            nonce: challenge.nonce,
            difficulty: challenge.difficulty,
            timestamp: challenge.timestamp,
            solution: solution,
            responsePayload: response.encode()
        )
    }
}
