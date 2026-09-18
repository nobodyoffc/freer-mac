import XCTest
@testable import FCTransport

/// Reassembly of one inbound stream, against a peer that is not
/// necessarily telling the truth. The happy paths live in
/// `InboundStreamBufferTests`; these are the ones that used to end the
/// process or let one frame rewrite another's bytes.
///
/// The offsets and lengths here arrive inside an authenticated packet,
/// which means they come from a peer whose identity is established —
/// not from a peer whose arithmetic can be trusted. Every case below
/// either terminated the process or let one frame rewrite another's
/// bytes.
final class InboundStreamBufferHostileInputTests: XCTestCase {

    private func bytes(_ b: UInt8, _ n: Int) -> Data {
        Data(repeating: b, count: n)
    }

    // MARK: - arithmetic off the wire

    /// `offset + length` wraps, and Swift traps on the wrap rather than
    /// returning a wrong answer. A peer naming an offset near the top of
    /// the range ended the process.
    func testAnOffsetThatWouldOverflowIsRefused() {
        let buffer = InboundStreamBuffer()
        XCTAssertThrowsError(
            try buffer.append(offset: UInt64.max - 4, data: bytes(0xAA, 16), fin: false)
        )
    }

    /// The same ceiling in its ordinary form: a length nobody is going
    /// to send is a claim about resources, not a file.
    func testAStreamBeyondTheCeilingIsRefused() {
        let buffer = InboundStreamBuffer(maxStreamBytes: 1 << 20)
        XCTAssertThrowsError(
            try buffer.append(offset: (1 << 20) - 2, data: bytes(0xAA, 8), fin: false)
        )
    }

    /// Every arriving chunk is merged into a list of disjoint ranges, so
    /// a peer that sends every other byte makes that list the attack.
    func testAnAbsurdlyFragmentedStreamIsRefused() {
        let buffer = InboundStreamBuffer(maxIntervals: 8)
        XCTAssertThrowsError(try {
            // Leave a gap between each chunk so nothing ever merges.
            for i in 0..<64 {
                try buffer.append(offset: UInt64(i * 4), data: bytes(0xAA, 1), fin: false)
            }
        }())
    }

    // MARK: - a peer contradicting itself

    /// A FIN fixes the stream's length. A second one naming a different
    /// length used to simply replace it, so a late frame could redefine
    /// how much of the message counted as all of it.
    func testASecondFinCannotRedefineTheFinalSize() throws {
        let buffer = InboundStreamBuffer()
        try buffer.append(offset: 0, data: bytes(0xAA, 100), fin: true)
        XCTAssertThrowsError(
            try buffer.append(offset: 0, data: bytes(0xBB, 60), fin: true)
        )
    }

    func testDataPastAnEstablishedFinalSizeIsRefused() throws {
        let buffer = InboundStreamBuffer()
        try buffer.append(offset: 0, data: bytes(0xAA, 100), fin: true)
        XCTAssertThrowsError(
            try buffer.append(offset: 90, data: bytes(0xBB, 40), fin: false)
        )
    }

    // MARK: - overlap

    /// FUDP2V1: "If a received frame's byte range overlaps with data
    /// already buffered or already delivered, the overlapping portion
    /// MUST be discarded."
    ///
    /// The in-memory path tiled its chunks and so already did. The spill
    /// path seeked to the chunk's offset and wrote all of it, letting a
    /// second frame rewrite bytes the first had already established —
    /// two frames could each claim a different content for one range and
    /// whichever arrived last won.
    func testAnOverlappingChunkCannotRewriteBytesAlreadyReceived() throws {
        // A threshold small enough that the first chunk spills.
        let buffer = InboundStreamBuffer(spillThreshold: 1024)
        try buffer.append(offset: 0, data: bytes(0xAA, 4096), fin: false)
        // Overlaps [2048, 4096) and extends to 6144. Only the new tail
        // may land; the overlap must be discarded, not rewritten.
        try buffer.append(offset: 2048, data: bytes(0xBB, 4096), fin: true)

        let assembled = try XCTUnwrap(buffer.assembleIfComplete())
        XCTAssertEqual(assembled.count, 6144)
        XCTAssertEqual(
            Array(assembled[0..<4096]), Array(repeating: 0xAA, count: 4096),
            "the bytes the first frame established must survive the overlap"
        )
        XCTAssertEqual(
            Array(assembled[4096..<6144]), Array(repeating: 0xBB, count: 2048),
            "and only the genuinely new tail comes from the second"
        )
    }

    /// The same, in memory, where the behaviour was already right —
    /// pinned so the two paths cannot drift apart.
    func testTheInMemoryPathDiscardsOverlapTheSameWay() throws {
        let buffer = InboundStreamBuffer(spillThreshold: 1 << 20)
        try buffer.append(offset: 0, data: bytes(0xAA, 100), fin: false)
        try buffer.append(offset: 50, data: bytes(0xBB, 100), fin: true)

        let assembled = try XCTUnwrap(buffer.assembleIfComplete())
        XCTAssertEqual(assembled.count, 150)
        XCTAssertEqual(Array(assembled[0..<100]), Array(repeating: 0xAA, count: 100))
        XCTAssertEqual(Array(assembled[100..<150]), Array(repeating: 0xBB, count: 50))
    }

    // MARK: - what must keep working

    /// FIN arriving before the data it ends is the ordinary case under
    /// loss, and completion is the contiguous offset reaching the final
    /// size — never the FIN alone (FUDP2V1, out-of-order FIN pitfall).
    func testAnOutOfOrderFinDoesNotCompleteTheStreamEarly() throws {
        let buffer = InboundStreamBuffer()
        try buffer.append(offset: 100, data: bytes(0xBB, 50), fin: true)
        XCTAssertNil(try buffer.assembleIfComplete(), "the first 100 bytes are still missing")

        try buffer.append(offset: 0, data: bytes(0xAA, 100), fin: false)
        let assembled = try XCTUnwrap(buffer.assembleIfComplete())
        XCTAssertEqual(assembled.count, 150)
    }

    func testAZeroLengthStreamCompletes() throws {
        let buffer = InboundStreamBuffer()
        try buffer.append(offset: 0, data: Data(), fin: true)
        XCTAssertEqual(try buffer.assembleIfComplete()?.count, 0)
    }
}
