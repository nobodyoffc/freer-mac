import Foundation

/// One Opus frame and what the jitter buffer needs to know about it.
/// `seq` counts every encoded frame, sent or not, so a gap after a DTX run
/// is silence, which `afterDtx` says. `level` is -dBov, 0 loudest, 127 silence.
public struct EncodedFrame: Sendable, Equatable {
    public let ssrc: UInt32
    public let seq: UInt64
    public let timestamp: UInt32
    public let level: Int
    public let voiceActive: Bool
    public let afterDtx: Bool
    public let opus: Data

    public init(ssrc: UInt32, seq: UInt64, timestamp: UInt32, level: Int, voiceActive: Bool, afterDtx: Bool, opus: Data) {
        self.ssrc = ssrc
        self.seq = seq
        self.timestamp = timestamp
        self.level = level
        self.voiceActive = voiceActive
        self.afterDtx = afterDtx
        self.opus = opus
    }
}

public enum AudioLevel {
    /// -dBov of the frame's RMS, 0...127 (RFC 6464).
    public static func of(_ pcm: ArraySlice<Int16>) -> Int {
        guard !pcm.isEmpty else { return 127 }
        let sum = pcm.reduce(0.0) { $0 + Double($1) * Double($1) }
        let rms = (sum / Double(pcm.count)).squareRoot() / 32768.0
        guard rms > 0 else { return 127 }
        return max(0, min(127, Int((-20 * log10(rms)).rounded())))
    }
}

/// The send side without a device (VOICE_SPEC §9.1): 48 kHz mono samples
/// in, one Opus frame out per `frameMs`. Muted audio is encoded as silence,
/// so DTX still sends an update every 400 ms. Frames DTX leaves unsent still
/// take a seq. The frame length may change between frames (§9.1).
public final class FrameEncoder: @unchecked Sendable {
    /// At or below this level (-dBov) a frame counts as voice for the relay's speaker ranking.
    public static let vadLevel = 50

    public let ssrc: UInt32
    private let encoder: Opus.Encoder
    private let lock = NSLock()
    private var fifo: [Int16] = []
    private var seq: UInt64 = 0
    private var timestamp: UInt32
    private var afterDtx = false
    private var _frameMs: Int
    private var _muted = false
    public private(set) var framesSent = 0
    public private(set) var dtxSkipped = 0
    public private(set) var level = 127
    private let sink: (EncodedFrame) -> Void

    public init(ssrc: UInt32, frameMs: Int, bitrate: Int, expectedLossPercent: Int, sink: @escaping (EncodedFrame) -> Void) throws {
        self.ssrc = ssrc
        self._frameMs = frameMs
        self.encoder = try Opus.Encoder(bitrate: bitrate, dtx: true, expectedLossPercent: expectedLossPercent)
        self.timestamp = UInt32.random(in: 0...UInt32.max) // a random start per ssrc (§5)
        self.sink = sink
    }

    public var frameMs: Int {
        get { lock.withLock { _frameMs } }
        set { lock.withLock { _frameMs = newValue } }
    }

    public var muted: Bool {
        get { lock.withLock { _muted } }
        set { lock.withLock { _muted = newValue } }
    }

    /// Captured samples, from the capture thread. Encodes every whole frame queued.
    public func push(_ samples: [Int16]) {
        var out: [EncodedFrame] = []
        lock.lock()
        fifo.append(contentsOf: samples)
        // A standing backlog adds its length to every frame: keep at most one frame's worth.
        let frameSamples = Opus.sampleRate / 1000 * _frameMs
        if fifo.count > 4 * frameSamples { fifo.removeFirst(fifo.count - 2 * frameSamples) }
        while fifo.count >= frameSamples {
            var pcm = Array(fifo[0..<frameSamples])
            fifo.removeFirst(frameSamples)
            if _muted { pcm = [Int16](repeating: 0, count: frameSamples) }
            let lvl = AudioLevel.of(pcm[...])
            level = lvl
            let thisSeq = seq
            let thisTs = timestamp
            seq += 1
            timestamp = timestamp &+ UInt32(frameSamples)
            guard let packet = try? encoder.encode(pcm) else { continue }
            if packet.count <= 2 {
                // DTX: nothing worth sending; the receiver's buffer pauses and restarts.
                dtxSkipped += 1
                afterDtx = true
                continue
            }
            out.append(EncodedFrame(ssrc: ssrc, seq: thisSeq, timestamp: thisTs, level: lvl,
                                    voiceActive: lvl <= FrameEncoder.vadLevel, afterDtx: afterDtx, opus: packet))
            afterDtx = false
            framesSent += 1
        }
        lock.unlock()
        for f in out { sink(f) }
    }
}

/// The receive side without a device (VOICE_SPEC §9.2-§9.3): a jitter
/// buffer and decoder per incoming ssrc, mixed into 20 ms ticks. Each
/// sender's frame length comes from its packets' TOC byte; a change of
/// length restarts that stream's buffer, which counts in frames.
public final class Mixer: @unchecked Sendable {
    public static let tickMs = 20
    public static let tickSamples = Opus.sampleRate / 1000 * tickMs
    /// A stream silent this long is dropped: DTX silences are normal.
    static let streamIdleMs: Int64 = 120_000
    /// Mix above this is compressed rather than clipped.
    static let knee = 24_576

    public final class Stream {
        public let ssrc: UInt32
        public let buffer: JitterBuffer
        let frameSamples: Int
        let decoder: Opus.Decoder
        public fileprivate(set) var level = 127
        var pcm: [Int16] = []
        var played = 0

        init(ssrc: UInt32, frameSamples: Int, decoder: Opus.Decoder) {
            self.ssrc = ssrc
            self.frameSamples = frameSamples
            self.buffer = JitterBuffer(frameMs: frameSamples * 1000 / Opus.sampleRate)
            self.decoder = decoder
        }
    }

    private let lock = NSLock()
    private var streams: [UInt32: Stream] = [:]
    private var silenced = Set<UInt32>()
    public private(set) var wrongFrameSize = 0

    public init() {}

    /// From the network thread.
    public func onFrame(_ f: EncodedFrame, arrivalMs: Int64) {
        guard let samples = OpusToc.samples(f.opus), samples % Mixer.tickSamples == 0 else {
            lock.withLock { wrongFrameSize += 1 }
            return
        }
        lock.lock()
        defer { lock.unlock() }
        if silenced.contains(f.ssrc) { return }
        let s: Stream
        if let old = streams[f.ssrc], old.frameSamples == samples {
            s = old
        } else {
            guard let decoder = streams[f.ssrc]?.decoder ?? (try? Opus.Decoder()) else { return }
            s = Stream(ssrc: f.ssrc, frameSamples: samples, decoder: decoder)
            streams[f.ssrc] = s
        }
        s.level = f.level
        s.buffer.put(seq: Int64(f.seq), timestamp: Int64(f.timestamp), data: f.opus, silent: !f.voiceActive,
                     afterDtx: f.afterDtx, level: f.level, arrivalMs: arrivalMs)
    }

    /// Stop playing one stream for good: its audio could not be attributed (§5.1).
    public func silence(_ ssrc: UInt32) {
        lock.withLock {
            streams[ssrc] = nil
            silenced.insert(ssrc)
        }
    }

    /// (ssrc, level, last arrival ms) of every stream, for the UI.
    public func snapshot() -> [(ssrc: UInt32, level: Int, lastArrivalMs: Int64)] {
        lock.withLock { streams.values.map { ($0.ssrc, $0.level, $0.buffer.lastArrivalMs) } }
    }

    public func stats(_ ssrc: UInt32) -> JitterBuffer.Stats? {
        lock.withLock { streams[ssrc]?.buffer.stats }
    }

    /// One 20 ms tick of the mix. From the playout thread, once per tick.
    public func renderTick(nowMs: Int64) -> [Int16] {
        lock.lock()
        let current = Array(streams.values)
        lock.unlock()
        var mix = [Int](repeating: 0, count: Mixer.tickSamples)
        for s in current {
            if nowMs - s.buffer.lastArrivalMs > Mixer.streamIdleMs {
                lock.withLock { if streams[s.ssrc] === s { streams[s.ssrc] = nil } }
                continue
            }
            if s.played >= s.pcm.count && !decodeNext(s, nowMs: nowMs) { continue }
            for i in 0..<Mixer.tickSamples { mix[i] += Int(s.pcm[s.played + i]) }
            s.played += Mixer.tickSamples
        }
        return mix.map(Mixer.softClip)
    }

    /// The stream's next frame into `s.pcm`: its buffer is asked once per frame of its length.
    private func decodeNext(_ s: Stream, nowMs: Int64) -> Bool {
        s.pcm = []
        s.played = 0
        let p = s.buffer.pull(nowMs: nowMs)
        let out: [Int16]?
        switch p.kind {
        case .nothing: out = nil
        case .frame: out = try? s.decoder.decode(p.data!, frameSize: s.frameSamples)
        case .fec: out = try? s.decoder.decodeFec(p.data!, frameSize: s.frameSamples)
        case .conceal: out = try? s.decoder.conceal(frameSize: s.frameSamples)
        }
        guard let pcm = out, !pcm.isEmpty else { return false }
        guard pcm.count == s.frameSamples else {
            lock.withLock { wrongFrameSize += 1 }
            return false
        }
        s.pcm = pcm
        return true
    }

    /// Linear below the knee, compressed smoothly towards full scale above it.
    static func softClip(_ x: Int) -> Int16 {
        let a = abs(x)
        if a <= knee { return Int16(x) }
        let room = Int(Int16.max) - knee
        let over = a - knee
        let y = knee + over * room / (over + room)
        return Int16(x < 0 ? -y : y)
    }
}
