import AVFoundation
import Foundation
import FCDomain

/// Capturing a voice note — the Mac half of Android's `VoiceRecorder`,
/// with the same shape (AAC in an MPEG-4 container, 16 kHz mono, capped
/// at five minutes) and the same two ways to end: send it or throw it
/// away.
///
/// **Recording writes to a real file, not a scratch buffer.** A note
/// that turns out to be too long for its DOCK goes to DISK and travels
/// as a HAT, and that path shares a file *by reference* — see
/// ``FileVault/registerFile(at:name:desc:types:)`` — so the bytes have
/// to stay where they were written. Only the inline path deletes them,
/// once they are inside the message.
///
/// **Microphone access needs an `Info.plist`.** macOS refuses the
/// microphone to a process whose bundle does not carry
/// `NSMicrophoneUsageDescription`, and this app is still a bare SwiftPM
/// executable with no bundle at all — so `Package.swift` links the plist
/// into the binary's `__TEXT,__info_plist` section, which is where TCC
/// looks when there is no bundle to read. Phase 10 will replace that
/// with a real `.app`; until then this is what makes the prompt appear
/// instead of the process dying.
@Observable
@MainActor
final class VoiceRecorder {

    /// A finished recording, ready to send or to discard.
    struct Recording {
        /// Where the bytes are. Kept for the HAT path, deleted by the
        /// caller once an inline message carries them.
        let url: URL
        let data: Data
        let durationMs: Int64
        let sampleRate: Int
    }

    /// Whether a recording is in progress or waiting to be sent. The
    /// composer swaps to its recording bar on this.
    private(set) var isActive = false

    /// Whether the microphone is actually running. Goes false on its own
    /// at the five-minute cap, while ``isActive`` stays true — there is
    /// still a note to send.
    private(set) var isCapturing = false

    private(set) var elapsedMs: Int64 = 0

    /// Input level, 0…1, for the meter. Cosmetic, but a recorder that
    /// shows nothing moving is indistinguishable from a dead microphone.
    private(set) var level: Double = 0

    /// Why the last attempt did not start. Nil once one does.
    private(set) var failure: String?

    private var recorder: AVAudioRecorder?
    private var url: URL?
    private var ticker: Task<Void, Never>?

    var atLimit: Bool { isActive && !isCapturing }

    // MARK: - lifecycle

    /// Ask for the microphone, then start writing into `directory`.
    ///
    /// The directory is the session's data directory rather than a temp
    /// one, because a note that goes the HAT route is registered where
    /// it lies and a file the system may sweep is not somewhere to leave
    /// a shared file.
    func start(in directory: URL) async {
        guard !isActive else { return }
        failure = nil

        guard await requestMicrophone() else { return }

        let target = directory.appendingPathComponent(VoiceNote.fileName())
        do {
            try FileManager.default.createDirectory(
                at: directory, withIntermediateDirectories: true
            )
            let recorder = try AVAudioRecorder(url: target, settings: [
                AVFormatIDKey: Int(kAudioFormatMPEG4AAC),
                AVSampleRateKey: VoiceNote.sampleRate,
                AVNumberOfChannelsKey: 1,
                AVEncoderBitRateKey: VoiceNote.bitRate,
            ])
            recorder.isMeteringEnabled = true
            // The cap is the recorder's own, so five minutes is enforced
            // even if this view goes away mid-recording.
            guard recorder.record(forDuration: Double(VoiceNote.maxDurationMs) / 1000) else {
                throw Failure.couldNotStart
            }
            self.recorder = recorder
            self.url = target
            isActive = true
            isCapturing = true
            elapsedMs = 0
            level = 0
            tick()
        } catch {
            failure = "Could not start recording: \(error)"
            try? FileManager.default.removeItem(at: target)
        }
    }

    /// Stop and hand back what was captured.
    ///
    /// Returns nil for a press too short to have produced any audio —
    /// that is a mis-click, and the file is deleted rather than sent.
    func finish() -> Recording? {
        guard let recorder, let url else { return nil }
        // `currentTime` reads 0 once the recorder has stopped itself at
        // the cap, so the ticker's last reading is what a five-minute
        // note is measured by — taking `currentTime` alone would file
        // the longest possible note as "too short to send".
        let durationMs = max(Int64(recorder.currentTime * 1000), elapsedMs)
        recorder.stop()
        reset()

        guard durationMs >= VoiceNote.minDurationMs,
              let data = try? Data(contentsOf: url), !data.isEmpty
        else {
            try? FileManager.default.removeItem(at: url)
            failure = "Too short — hold the button long enough to say something."
            return nil
        }
        return Recording(
            url: url, data: data,
            durationMs: durationMs,
            sampleRate: VoiceNote.sampleRate
        )
    }

    /// Throw the recording away, bytes included.
    func cancel() {
        recorder?.stop()
        if let url { try? FileManager.default.removeItem(at: url) }
        reset()
        failure = nil
    }

    // MARK: - internals

    private func reset() {
        ticker?.cancel()
        ticker = nil
        recorder = nil
        url = nil
        isActive = false
        isCapturing = false
        level = 0
    }

    /// Drive the elapsed time and the meter, and notice the cap: when
    /// the recorder stops itself at five minutes there is no delegate
    /// callback worth wiring for a single boolean.
    private func tick() {
        ticker?.cancel()
        ticker = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(for: .milliseconds(100))
                guard let self, let recorder = self.recorder else { return }
                self.elapsedMs = Int64(recorder.currentTime * 1000)
                recorder.updateMeters()
                self.level = Self.normalize(recorder.averagePower(forChannel: 0))
                if !recorder.isRecording {
                    self.isCapturing = false
                    self.level = 0
                    return
                }
            }
        }
    }

    /// dBFS to a bar height. −50 dB is quiet-room noise; anything below
    /// it reads as silence rather than as a bar that never quite empties.
    private static func normalize(_ decibels: Float) -> Double {
        let floor = -50.0
        let clamped = max(floor, min(0, Double(decibels)))
        return (clamped - floor) / -floor
    }

    private func requestMicrophone() async -> Bool {
        switch AVCaptureDevice.authorizationStatus(for: .audio) {
        case .authorized:
            return true
        case .notDetermined:
            let granted = await AVCaptureDevice.requestAccess(for: .audio)
            if !granted { failure = Self.deniedMessage }
            return granted
        default:
            failure = Self.deniedMessage
            return false
        }
    }

    /// Names the terminal case on purpose. Until Phase 10 builds a real
    /// `.app`, macOS holds the permission against whatever *launched*
    /// this binary, so a `swift run` build's entry in that list is the
    /// terminal's — and looking for "Freer" there finds nothing.
    private static let deniedMessage =
        "Microphone access is off. Turn it on in System Settings ▸ Privacy & Security ▸ "
        + "Microphone, then try again. On a `swift run` build the entry is listed under "
        + "the app that launched this one, usually Terminal."

    private enum Failure: Error, CustomStringConvertible {
        case couldNotStart

        var description: String { "the audio device refused to start" }
    }
}
