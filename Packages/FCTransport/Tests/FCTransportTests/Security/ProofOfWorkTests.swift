import XCTest
import FCCore
@testable import FCTransport

final class ProofOfWorkTests: XCTestCase {

    // MARK: - byte parity vs Java reference

    /// FC-AJDK's solver scans solutions starting from 0 and returns the
    /// first one that meets the target. Our solver does the same, so for
    /// any fixed (nonce, difficulty) we must produce byte-identical
    /// output.
    func testSolveProducesSameBytesAsJava() throws {
        let vectors = try FudpVectors.load()
        XCTAssertFalse(vectors.proofOfWork.isEmpty)
        for vector in vectors.proofOfWork {
            let solution = try ProofOfWork.solve(
                nonce: Data(fromHex: vector.nonceHex),
                difficulty: vector.difficulty,
                timeoutMs: 5_000
            )
            XCTAssertEqual(solution.hex, vector.solutionHex,
                           "PoW solve mismatch (difficulty=\(vector.difficulty))")
        }
    }

    func testHashOfRecordedSolutionMatches() throws {
        let vectors = try FudpVectors.load()
        for vector in vectors.proofOfWork {
            let nonce = Data(fromHex: vector.nonceHex)
            let solution = Data(fromHex: vector.solutionHex)
            // Recompute SHA-256(nonce ‖ solution); must match Java's hash hex.
            let combined = nonce + solution
            // Hash is in FCCore; verify isn't exposed but verify() does
            // exactly this computation, so use it indirectly.
            XCTAssertTrue(ProofOfWork.verify(nonce: nonce, solution: solution, difficulty: vector.difficulty))
            XCTAssertGreaterThanOrEqual(
                ProofOfWork.leadingZeroBits(Hash.sha256(combined)),
                vector.difficulty
            )
            XCTAssertEqual(Hash.sha256(combined).hex, vector.expectedHashHex)
        }
    }

    // MARK: - verify

    func testVerifyAcceptsValidSolutions() throws {
        let vectors = try FudpVectors.load()
        for v in vectors.proofOfWork {
            XCTAssertTrue(ProofOfWork.verify(
                nonce: Data(fromHex: v.nonceHex),
                solution: Data(fromHex: v.solutionHex),
                difficulty: v.difficulty
            ))
        }
    }

    func testVerifyRejectsTamperedSolution() throws {
        let vectors = try FudpVectors.load()
        let v = vectors.proofOfWork[0]
        var bad = Array(Data(fromHex: v.solutionHex))
        bad[7] ^= 0x01
        XCTAssertFalse(ProofOfWork.verify(
            nonce: Data(fromHex: v.nonceHex),
            solution: Data(bad),
            difficulty: v.difficulty
        ))
    }

    func testVerifyRejectsWrongLengths() {
        XCTAssertFalse(ProofOfWork.verify(
            nonce: Data(repeating: 0, count: 15),  // 15 not 16
            solution: Data(repeating: 0, count: 8),
            difficulty: 8
        ))
        XCTAssertFalse(ProofOfWork.verify(
            nonce: Data(repeating: 0, count: 16),
            solution: Data(repeating: 0, count: 7),  // 7 not 8
            difficulty: 8
        ))
    }

    func testVerifyRejectsOutOfRangeDifficulty() {
        let nonce = Data(repeating: 0, count: 16)
        let solution = Data(repeating: 0, count: 8)
        XCTAssertFalse(ProofOfWork.verify(nonce: nonce, solution: solution, difficulty: 3))
        XCTAssertFalse(ProofOfWork.verify(nonce: nonce, solution: solution, difficulty: 25))
    }

    // MARK: - leadingZeroBits

    func testLeadingZeroBitsBoundaries() {
        XCTAssertEqual(ProofOfWork.leadingZeroBits(Data([0xFF])), 0)
        XCTAssertEqual(ProofOfWork.leadingZeroBits(Data([0x80])), 0)
        XCTAssertEqual(ProofOfWork.leadingZeroBits(Data([0x40])), 1)
        XCTAssertEqual(ProofOfWork.leadingZeroBits(Data([0x01])), 7)
        XCTAssertEqual(ProofOfWork.leadingZeroBits(Data([0x00])), 8)
        XCTAssertEqual(ProofOfWork.leadingZeroBits(Data([0x00, 0x80])), 8)
        XCTAssertEqual(ProofOfWork.leadingZeroBits(Data([0x00, 0x40])), 9)
        XCTAssertEqual(ProofOfWork.leadingZeroBits(Data([0x00, 0x00, 0x01])), 23)
        XCTAssertEqual(ProofOfWork.leadingZeroBits(Data([0x00, 0x00, 0x00, 0x00])), 32)
    }

    // MARK: - solve

    func testSolveRespectsTimeout() {
        // Difficulty 24 takes ~8 s on a typical CPU. With a 50 ms timeout
        // we should fail fast.
        XCTAssertThrowsError(
            try ProofOfWork.solve(
                nonce: Data(repeating: 0xff, count: 16),
                difficulty: 24,
                timeoutMs: 50
            )
        ) { error in
            guard case ProofOfWork.Failure.timeout = error else {
                XCTFail("expected timeout, got \(error)"); return
            }
        }
    }

    func testSolveRejectsBadParams() {
        XCTAssertThrowsError(try ProofOfWork.solve(
            nonce: Data(repeating: 0, count: 15),
            difficulty: 8, timeoutMs: 1000
        ))
        XCTAssertThrowsError(try ProofOfWork.solve(
            nonce: Data(repeating: 0, count: 16),
            difficulty: 3, timeoutMs: 1000
        ))
        XCTAssertThrowsError(try ProofOfWork.solve(
            nonce: Data(repeating: 0, count: 16),
            difficulty: 8, timeoutMs: 0
        ))
    }
}
