import XCTest
@testable import FCVoice

final class OpusTests: XCTestCase {

    /// A voice-like tone: 200 Hz with harmonics, at a speaking level.
    static func tone(samples: Int, from start: Int = 0) -> [Int16] {
        (0..<samples).map { i in
            let t = Double(start + i) / Double(Opus.sampleRate)
            let v = 0.3 * sin(2 * .pi * 200 * t) + 0.15 * sin(2 * .pi * 400 * t) + 0.08 * sin(2 * .pi * 800 * t)
            return Int16(v * 12_000)
        }
    }

    func testFramesOf20And40MsRoundTripAndSayTheirLength() throws {
        for ms in [20, 40] {
            let n = Opus.sampleRate / 1000 * ms
            let enc = try Opus.Encoder(bitrate: 24_000, dtx: true, expectedLossPercent: 10)
            let dec = try Opus.Decoder()
            var energy = 0.0
            for f in 0..<25 {
                let packet = try enc.encode(Self.tone(samples: n, from: f * n))
                XCTAssertGreaterThan(packet.count, 2, "speech is sent, not DTX")
                XCTAssertEqual(OpusToc.samples(packet), n, "\(ms) ms from the TOC byte")
                let pcm = try dec.decode(packet, frameSize: n)
                XCTAssertEqual(pcm.count, n)
                if f > 5 { energy += pcm.reduce(0.0) { $0 + Double($1) * Double($1) } }
            }
            XCTAssertGreaterThan(energy, 1e9, "\(ms) ms: audio comes out")
        }
    }

    func testSilenceGoesDtxAndLossIsConcealed() throws {
        let n = 1920
        let enc = try Opus.Encoder(bitrate: 24_000, dtx: true, expectedLossPercent: 10)
        var small = 0
        for _ in 0..<50 where try enc.encode([Int16](repeating: 0, count: n)).count <= 2 { small += 1 }
        XCTAssertGreaterThan(small, 30, "DTX skips most silent frames")
        let dec = try Opus.Decoder()
        _ = try dec.decode(try Opus.Encoder(bitrate: 24_000, dtx: false, expectedLossPercent: 10)
            .encode(Self.tone(samples: n)), frameSize: n)
        XCTAssertEqual(try dec.conceal(frameSize: n).count, n)
    }

    func testTheTocReaderRefusesWhatWeNeverSend() {
        XCTAssertNil(OpusToc.samples(Data()))
        XCTAssertNil(OpusToc.samples(Data([UInt8(31 << 3 | 3)])), "code 3 without its count")
        XCTAssertNil(OpusToc.samples(Data([UInt8(11 << 3 | 1), 0])), "120 ms")
        XCTAssertEqual(OpusToc.samples(Data([UInt8(31 << 3 | 1), 0])), 1920, "two 20 ms CELT frames")
    }
}
