import XCTest
@testable import FCTransport

final class ChallengeHandlerTests: XCTestCase {

    /// Solving a real challenge from a recorded vector yields a valid
    /// CHALLENGE_RESPONSE payload that round-trips through the codec
    /// and verifies under the original PoW parameters.
    func testHandleSolvesRecordedChallenge() throws {
        let vectors = try FudpVectors.load()
        // Pick the lowest-difficulty challenge so the test runs quickly.
        guard let challengeVec = vectors.challengePacket.min(by: { $0.difficulty < $1.difficulty }) else {
            XCTFail("no challenge vectors"); return
        }
        XCTAssertLessThanOrEqual(challengeVec.difficulty, 12,
                                 "expected a tractable difficulty for tests")

        let handler = ChallengeHandler(maxAcceptableDifficulty: 16, maxPowTimeMs: 5_000)
        let outcome = try handler.handle(
            challengePayload: Data(fromHex: challengeVec.encodedHex)
        )

        XCTAssertEqual(outcome.nonce.hex, challengeVec.nonceHex)
        XCTAssertEqual(outcome.difficulty, challengeVec.difficulty)
        XCTAssertEqual(outcome.timestamp, challengeVec.timestamp)
        XCTAssertEqual(outcome.solution.count, ProofOfWork.solutionLength)

        // Solution must verify.
        XCTAssertTrue(ProofOfWork.verify(
            nonce: outcome.nonce,
            solution: outcome.solution,
            difficulty: outcome.difficulty
        ))

        // Response payload must be a well-formed CHALLENGE_RESPONSE.
        let parsed = try ChallengeResponsePayload.decode(outcome.responsePayload)
        XCTAssertEqual(parsed.nonce, outcome.nonce)
        XCTAssertEqual(parsed.solution, outcome.solution)
    }

    func testHandleRejectsExcessiveDifficulty() throws {
        let handler = ChallengeHandler(maxAcceptableDifficulty: 8, maxPowTimeMs: 1_000)
        let challenge = try ChallengePayload(
            nonce: Data(repeating: 0xab, count: 16),
            difficulty: 16,  // > 8
            timestamp: 0
        )
        XCTAssertThrowsError(try handler.handle(challengePayload: challenge.encode())) { e in
            guard case let ChallengeHandler.Failure.excessiveDifficulty(requested, max) = e else {
                XCTFail("wrong error: \(e)"); return
            }
            XCTAssertEqual(requested, 16)
            XCTAssertEqual(max, 8)
        }
    }

    func testHandleRejectsMalformedChallenge() throws {
        let handler = ChallengeHandler()
        XCTAssertThrowsError(try handler.handle(challengePayload: Data(repeating: 0, count: 25))) { e in
            guard case ChallengeHandler.Failure.malformedChallenge = e else {
                XCTFail("wrong error: \(e)"); return
            }
        }
    }

    func testHandleSurfacesSolveTimeout() throws {
        // A tiny timeout against a difficulty too high for that budget
        // should propagate as solveFailed (wrapping the underlying timeout).
        let handler = ChallengeHandler(maxAcceptableDifficulty: 24, maxPowTimeMs: 50)
        let challenge = try ChallengePayload(
            nonce: Data(repeating: 0xff, count: 16),
            difficulty: 24,
            timestamp: 0
        )
        XCTAssertThrowsError(try handler.handle(challengePayload: challenge.encode())) { e in
            guard case ChallengeHandler.Failure.solveFailed = e else {
                XCTFail("wrong error: \(e)"); return
            }
        }
    }
}
