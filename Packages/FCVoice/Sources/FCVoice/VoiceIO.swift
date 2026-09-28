import Foundation
import AVFoundation

/// The Mac's audio devices for a call (VOICE_SPEC §9.2, §11.2): one
/// AVAudioEngine with voice processing on, which gives the platform's echo
/// cancellation, noise suppression and gain control on the input, matched to
/// what the engine plays. Captured audio goes to `onCapture` as 48 kHz mono;
/// playout is pulled from `render` in 20 ms ticks by a thread that keeps
/// about 60 ms queued ahead of the device.
public final class VoiceIO: @unchecked Sendable {

    public enum Failure: Error {
        case noMicrophone, converter
    }

    /// Queued ahead of the device: enough to ride out a late tick, little enough to add no delay worth hearing.
    static let aheadSamples = 3 * Mixer.tickSamples

    private let engine = AVAudioEngine()
    private let ring = SampleRing(capacity: 16 * Mixer.tickSamples)
    private var converter: AVAudioConverter?
    private var playout: Thread?
    private let running = ManagedAtomicFlag()
    private let onCapture: ([Int16]) -> Void
    private let render: (Int64) -> [Int16]
    public private(set) var underruns = 0

    /// - Parameters:
    ///   - onCapture: 48 kHz mono samples, on the audio thread; return quickly
    ///   - render: one 20 ms tick of playout at a monotonic time in ms, on the playout thread
    public init(onCapture: @escaping ([Int16]) -> Void, render: @escaping (Int64) -> [Int16]) {
        self.onCapture = onCapture
        self.render = render
    }

    public func start() throws {
        let input = engine.inputNode
        try input.setVoiceProcessingEnabled(true)
        let inFormat = input.outputFormat(forBus: 0)
        guard inFormat.sampleRate > 0, inFormat.channelCount > 0 else { throw Failure.noMicrophone }
        // Voice processing may present several channels; the processed voice is the first.
        let monoIn = AVAudioFormat(standardFormatWithSampleRate: inFormat.sampleRate, channels: 1)!
        let out48 = AVAudioFormat(commonFormat: .pcmFormatInt16, sampleRate: Double(Opus.sampleRate), channels: 1,
                                  interleaved: false)!
        guard let conv = AVAudioConverter(from: monoIn, to: out48) else { throw Failure.converter }
        converter = conv
        input.installTap(onBus: 0, bufferSize: AVAudioFrameCount(inFormat.sampleRate / 50), format: inFormat) {
            [weak self] buffer, _ in
            self?.captured(buffer, monoIn: monoIn, out48: out48)
        }

        let playFormat = AVAudioFormat(standardFormatWithSampleRate: Double(Opus.sampleRate), channels: 1)!
        let ring = self.ring
        let source = AVAudioSourceNode(format: playFormat) { [weak self] _, _, frameCount, abl -> OSStatus in
            let buffers = UnsafeMutableAudioBufferListPointer(abl)
            guard let out = buffers.first?.mData?.assumingMemoryBound(to: Float.self) else { return noErr }
            let got = ring.read(into: out, count: Int(frameCount))
            if got < Int(frameCount) {
                for i in got..<Int(frameCount) { out[i] = 0 }
                if got == 0 { self?.underruns += 1 }
            }
            return noErr
        }
        engine.attach(source)
        engine.connect(source, to: engine.mainMixerNode, format: playFormat)
        engine.prepare()
        try engine.start()

        running.set(true)
        let t = Thread { [weak self] in self?.playoutLoop() }
        t.name = "voice-playout"
        t.qualityOfService = .userInteractive
        playout = t
        t.start()
    }

    public func stop() {
        running.set(false)
        engine.inputNode.removeTap(onBus: 0)
        engine.stop()
    }

    /// Keeps about three ticks queued: the device drains the ring at its own pace.
    private func playoutLoop() {
        let start = DispatchTime.now().uptimeNanoseconds
        while running.get() {
            while ring.count < VoiceIO.aheadSamples && running.get() {
                let nowMs = Int64((DispatchTime.now().uptimeNanoseconds - start) / 1_000_000)
                ring.write(render(nowMs).map { Float($0) / 32768 })
            }
            Thread.sleep(forTimeInterval: 0.005)
        }
    }

    private func captured(_ buffer: AVAudioPCMBuffer, monoIn: AVAudioFormat, out48: AVAudioFormat) {
        guard let conv = converter, let src = buffer.floatChannelData?[0],
              let mono = AVAudioPCMBuffer(pcmFormat: monoIn, frameCapacity: buffer.frameLength) else { return }
        mono.frameLength = buffer.frameLength
        mono.floatChannelData![0].update(from: src, count: Int(buffer.frameLength))
        let ratio = out48.sampleRate / monoIn.sampleRate
        let capacity = AVAudioFrameCount(Double(buffer.frameLength) * ratio) + 16
        guard let out = AVAudioPCMBuffer(pcmFormat: out48, frameCapacity: capacity) else { return }
        var fed = false
        var error: NSError?
        conv.convert(to: out, error: &error) { _, status in
            if fed {
                status.pointee = .noDataNow
                return nil
            }
            fed = true
            status.pointee = .haveData
            return mono
        }
        guard error == nil, let samples = out.int16ChannelData?[0] else { return }
        onCapture(Array(UnsafeBufferPointer(start: samples, count: Int(out.frameLength))))
    }
}

/// A single-producer, single-consumer ring of samples between the playout
/// thread and the device's render callback.
final class SampleRing: @unchecked Sendable {
    private var buffer: [Float]
    private var head = 0, size = 0
    private let lock = NSLock()

    init(capacity: Int) {
        buffer = [Float](repeating: 0, count: capacity)
    }

    var count: Int { lock.withLock { size } }

    func write(_ samples: [Float]) {
        lock.lock()
        defer { lock.unlock() }
        for s in samples {
            if size == buffer.count { // full: the oldest goes, rather than delay piling up
                head = (head + 1) % buffer.count
                size -= 1
            }
            buffer[(head + size) % buffer.count] = s
            size += 1
        }
    }

    /// Up to `count` samples into `out`. @return how many
    func read(into out: UnsafeMutablePointer<Float>, count: Int) -> Int {
        lock.lock()
        defer { lock.unlock() }
        let n = min(count, size)
        for i in 0..<n { out[i] = buffer[(head + i) % buffer.count] }
        head = (head + n) % buffer.count
        size -= n
        return n
    }
}

/// A flag read on one thread and written on another.
final class ManagedAtomicFlag: @unchecked Sendable {
    private var value = false
    private let lock = NSLock()

    func set(_ v: Bool) { lock.withLock { value = v } }
    func get() -> Bool { lock.withLock { value } }
}
