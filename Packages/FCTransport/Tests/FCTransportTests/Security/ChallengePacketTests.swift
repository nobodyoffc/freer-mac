import XCTest
@testable import FCTransport

final class ChallengePacketTests: XCTestCase {

    // MARK: - ChallengePayload

    func testChallengeEncodeMatchesVectors() throws {
        let vectors = try FudpVectors.load()
        XCTAssertFalse(vectors.challengePacket.isEmpty)
        for v in vectors.challengePacket {
            let payload = try ChallengePayload(
                nonce: Data(fromHex: v.nonceHex),
                difficulty: v.difficulty,
                timestamp: v.timestamp
            )
            XCTAssertEqual(payload.encode().hex, v.encodedHex,
                           "challenge encode '\(v.label)'")
        }
    }

    func testChallengeDecodeRoundTrips() throws {
        let vectors = try FudpVectors.load()
        for v in vectors.challengePacket {
            let parsed = try ChallengePayload.decode(Data(fromHex: v.encodedHex))
            XCTAssertEqual(parsed.nonce.hex, v.nonceHex)
            XCTAssertEqual(parsed.difficulty, v.difficulty)
            XCTAssertEqual(parsed.timestamp, v.timestamp)
            XCTAssertEqual(parsed.encode().hex, v.encodedHex)
        }
    }

    func testChallengeRejectsWrongLength() {
        XCTAssertThrowsError(try ChallengePayload.decode(Data(repeating: 0, count: 25))) { e in
            guard case ChallengePayload.Failure.wrongLength = e else {
                XCTFail("wrong error: \(e)"); return
            }
        }
        XCTAssertThrowsError(try ChallengePayload.decode(Data(repeating: 0, count: 27)))
    }

    func testChallengeRejectsWrongTypeByte() {
        var bytes = Array(repeating: UInt8(0), count: 26)
        bytes[0] = 0x42  // not 0x03
        XCTAssertThrowsError(try ChallengePayload.decode(Data(bytes))) { e in
            guard case ChallengePayload.Failure.wrongTypeByte = e else {
                XCTFail("wrong error: \(e)"); return
            }
        }
    }

    func testChallengeRejectsBadNonceLength() {
        XCTAssertThrowsError(try ChallengePayload(
            nonce: Data(repeating: 0, count: 15),
            difficulty: 8, timestamp: 0
        ))
    }

    // MARK: - ChallengeResponsePayload

    func testChallengeResponseEncodeMatchesVectors() throws {
        let vectors = try FudpVectors.load()
        XCTAssertFalse(vectors.challengeResponsePacket.isEmpty)
        for v in vectors.challengeResponsePacket {
            let payload = try ChallengeResponsePayload(
                nonce: Data(fromHex: v.nonceHex),
                solution: Data(fromHex: v.solutionHex)
            )
            XCTAssertEqual(payload.encode().hex, v.encodedHex,
                           "response encode '\(v.label)'")
        }
    }

    func testChallengeResponseDecodeRoundTrips() throws {
        let vectors = try FudpVectors.load()
        for v in vectors.challengeResponsePacket {
            let parsed = try ChallengeResponsePayload.decode(Data(fromHex: v.encodedHex))
            XCTAssertEqual(parsed.nonce.hex, v.nonceHex)
            XCTAssertEqual(parsed.solution.hex, v.solutionHex)
            XCTAssertEqual(parsed.encode().hex, v.encodedHex)
        }
    }

    func testChallengeResponseRejectsWrongLength() {
        XCTAssertThrowsError(try ChallengeResponsePayload.decode(Data(repeating: 0, count: 24)))
        XCTAssertThrowsError(try ChallengeResponsePayload.decode(Data(repeating: 0, count: 26)))
    }

    func testChallengeResponseRejectsWrongTypeByte() {
        var bytes = Array(repeating: UInt8(0), count: 25)
        bytes[0] = 0x42
        XCTAssertThrowsError(try ChallengeResponsePayload.decode(Data(bytes))) { e in
            guard case ChallengeResponsePayload.Failure.wrongTypeByte = e else {
                XCTFail("wrong error: \(e)"); return
            }
        }
    }
}
