import XCTest
@testable import FCVoice

/// The send and receive sides together, without devices: what one end
/// encodes, the other plays, at either frame length and across a switch.
final class VoiceEngineTests: XCTestCase {

    func testSpeechTravelsEncoderToMixerAt40ThenAt20Ms() throws {
        var frames: [EncodedFrame] = []
        let enc = try FrameEncoder(ssrc: 7, frameMs: 40, bitrate: 24_000, expectedLossPercent: 10) { frames.append($0) }
        let mixer = Mixer()
        var now: Int64 = 0
        var heard = 0.0
        for tick in 0..<200 {
            if tick == 100 { enc.frameMs = 20 } // a switch mid-call (§9.1)
            enc.push(OpusTests.tone(samples: Mixer.tickSamples, from: tick * Mixer.tickSamples))
            for f in frames { mixer.onFrame(f, arrivalMs: now) }
            frames.removeAll()
            let out = mixer.renderTick(nowMs: now)
            if tick > 20 { heard += out.reduce(0.0) { $0 + Double($1) * Double($1) } }
            now += Int64(Mixer.tickMs)
        }
        XCTAssertGreaterThan(heard, 1e10, "the mix carries the speech")
        XCTAssertEqual(mixer.wrongFrameSize, 0)
        XCTAssertGreaterThan(enc.framesSent, 100)
        XCTAssertLessThan(enc.level, FrameEncoder.vadLevel, "the tone counts as voice")
    }

    func testMutedAudioSendsOnlyDtxUpdatesAndSilencedStreamsStayQuiet() throws {
        var frames: [EncodedFrame] = []
        let enc = try FrameEncoder(ssrc: 9, frameMs: 40, bitrate: 24_000, expectedLossPercent: 10) { frames.append($0) }
        enc.muted = true
        for i in 0..<100 { enc.push(OpusTests.tone(samples: Mixer.tickSamples, from: i * Mixer.tickSamples)) }
        XCTAssertGreaterThan(enc.dtxSkipped, 25, "muted is silence, and silence is mostly not sent")
        XCTAssertEqual(enc.level, 127)
        let mixer = Mixer()
        mixer.silence(9)
        for f in frames { mixer.onFrame(f, arrivalMs: 0) }
        XCTAssertTrue(mixer.snapshot().isEmpty)
    }

    func testSoftClipCompressesInsteadOfWrapping() {
        XCTAssertEqual(Mixer.softClip(1000), 1000)
        XCTAssertLessThanOrEqual(Mixer.softClip(100_000), Int16.max)
        XCTAssertGreaterThan(Mixer.softClip(100_000), 30_000)
        XCTAssertLessThan(Mixer.softClip(-100_000), -30_000)
    }
}
