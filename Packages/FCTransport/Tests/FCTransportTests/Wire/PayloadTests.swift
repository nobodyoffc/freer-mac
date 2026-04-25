import XCTest
@testable import FCTransport

final class PayloadTests: XCTestCase {

    func testPlaintextPayloadMatchesVectors() throws {
        let vectors = try FudpVectors.load()
        XCTAssertFalse(vectors.plaintextPayload.isEmpty)
        for vector in vectors.plaintextPayload {
            let frames = vector.framesHex.map { Data(fromHex: $0) }
            let payload = FudpPayload.assemble(
                includeTimestamp: vector.includeTimestamp,
                timestamp: vector.timestamp ?? 0,
                includeEpoch: vector.includeEpoch,
                sessionEpoch: vector.sessionEpoch ?? 0,
                frameBytes: frames
            )
            XCTAssertEqual(payload.hex, vector.encodedHex,
                           "'\(vector.label)'")
        }
    }
}
