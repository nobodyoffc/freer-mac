import Foundation

/// Client-side handler for FUDP's DDoS challenge flow. When the
/// FC-JDK / FC-AJDK server has DDoS defense enabled, an unverified
/// client's first packet is greeted with a `CHALLENGE` control packet;
/// the client must solve a PoW and reply with a `CHALLENGE_RESPONSE`
/// before the server will process any further data packets.
///
/// Each challenge is handled synchronously with the three initiator
/// protections FUDP5V1 asks for: a difficulty cap, a solve timeout, and
/// a refusal to keep answering a responder that repeatedly demands
/// near-maximum work. The first two bound one challenge; without the
/// third, a hostile responder can spend our CPU two seconds at a time
/// for as long as we keep asking.
public final class ChallengeHandler: Sendable {

    public static let defaultMaxAcceptableDifficulty = 16
    public static let defaultMaxPowTimeMs = 2_000
    /// FUDP5V1 §Initiator-Side Protection: "Max Consecutive High
    /// Difficulty — 3 — Blacklist peer after this many high-difficulty
    /// challenges", where high is "difficulty > 75% of the initiator's
    /// max acceptable difficulty".
    public static let defaultMaxConsecutiveHighDifficulty = 3
    /// Recommended cooldown after refusing an over-cap challenge.
    public static let defaultRefusalCooldownMs: Int64 = 60_000
    /// Recommended refusal period once a responder looks malicious.
    public static let defaultSuspiciousCooldownMs: Int64 = 300_000

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
        case refusingResponder
        case suspiciousResponder(consecutiveHighDifficulty: Int)

        public var description: String {
            switch self {
            case let .excessiveDifficulty(requested, maxAcceptable):
                return "ChallengeHandler: server demanded difficulty \(requested), we cap at \(maxAcceptable)"
            case .malformedChallenge(let e):
                return "ChallengeHandler: malformed challenge — \(e)"
            case .solveFailed(let e):
                return "ChallengeHandler: PoW solve failed — \(e)"
            case .refusingResponder:
                return "ChallengeHandler: this responder asked for too much work too recently; not answering it yet"
            case .suspiciousResponder(let run):
                return "ChallengeHandler: \(run) near-maximum challenges in a row — treating this responder as hostile"
            }
        }
    }

    public let maxAcceptableDifficulty: Int
    public let maxPowTimeMs: Int
    public let maxConsecutiveHighDifficulty: Int
    public let refusalCooldownMs: Int64
    public let suspiciousCooldownMs: Int64

    private let state = Reputation()
    private let nowMs: @Sendable () -> Int64

    /// How many near-maximum challenges in a row this responder has
    /// asked for, and when we decided to stop answering it.
    private final class Reputation: @unchecked Sendable {
        private let lock = NSLock()
        private var consecutiveHigh = 0
        private var refuseUntilMs: Int64 = 0

        func refusingAt(_ now: Int64) -> Bool {
            lock.lock(); defer { lock.unlock() }
            return now < refuseUntilMs
        }

        func refuse(until: Int64) {
            lock.lock(); defer { lock.unlock() }
            refuseUntilMs = max(refuseUntilMs, until)
        }

        /// Returns the running count of consecutive high-difficulty
        /// challenges after folding this one in.
        func record(high: Bool) -> Int {
            lock.lock(); defer { lock.unlock() }
            consecutiveHigh = high ? consecutiveHigh + 1 : 0
            return consecutiveHigh
        }
    }

    public init(
        maxAcceptableDifficulty: Int = ChallengeHandler.defaultMaxAcceptableDifficulty,
        maxPowTimeMs: Int = ChallengeHandler.defaultMaxPowTimeMs,
        maxConsecutiveHighDifficulty: Int = ChallengeHandler.defaultMaxConsecutiveHighDifficulty,
        refusalCooldownMs: Int64 = ChallengeHandler.defaultRefusalCooldownMs,
        suspiciousCooldownMs: Int64 = ChallengeHandler.defaultSuspiciousCooldownMs,
        nowMs: @escaping @Sendable () -> Int64 = { Int64(Date().timeIntervalSince1970 * 1000) }
    ) {
        self.maxAcceptableDifficulty = maxAcceptableDifficulty
        self.maxPowTimeMs = maxPowTimeMs
        self.maxConsecutiveHighDifficulty = maxConsecutiveHighDifficulty
        self.refusalCooldownMs = refusalCooldownMs
        self.suspiciousCooldownMs = suspiciousCooldownMs
        self.nowMs = nowMs
    }

    /// The threshold above which a challenge counts as "high
    /// difficulty" — 75% of our cap, per FUDP5V1.
    public var highDifficultyThreshold: Int {
        (maxAcceptableDifficulty * 3) / 4
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

        let now = nowMs()
        guard !state.refusingAt(now) else {
            throw Failure.refusingResponder
        }

        guard challenge.difficulty <= maxAcceptableDifficulty else {
            // An over-cap demand earns a cooldown as well as a refusal:
            // answering "no" instantly and reconnecting is an invitation
            // to be asked again immediately.
            state.refuse(until: now + refusalCooldownMs)
            throw Failure.excessiveDifficulty(
                requested: challenge.difficulty,
                maxAcceptable: maxAcceptableDifficulty
            )
        }

        let run = state.record(high: challenge.difficulty > highDifficultyThreshold)
        if run > maxConsecutiveHighDifficulty {
            state.refuse(until: now + suspiciousCooldownMs)
            throw Failure.suspiciousResponder(consecutiveHighDifficulty: run)
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
