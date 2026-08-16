import AVFoundation
import Foundation

/// Playing voice notes, one at a time.
///
/// **One at a time is the whole design.** Two notes talking over each
/// other is never what a click meant, so starting one stops the other —
/// the same rule Android's singleton `VoicePlayer` enforces, kept here
/// as one object per chat pane rather than a global, because there is
/// one transcript on screen.
///
/// The audio arrives as bytes inside the message, so playback needs no
/// file: `AVAudioPlayer(data:)` takes the AAC frames straight out of
/// ``ImMessage/data``.
@Observable
@MainActor
final class VoicePlayer {

    /// The id of the message now playing, which is also what the
    /// transcript draws its pause button on.
    private(set) var playingId: String?

    /// How far through, 0…1.
    private(set) var progress: Double = 0

    private(set) var failure: String?

    private var player: AVAudioPlayer?
    private var ticker: Task<Void, Never>?

    /// Play `data`, or stop if this message is the one already playing.
    func toggle(id: String, data: Data) {
        if playingId == id {
            stop()
            return
        }
        stop()
        do {
            let player = try AVAudioPlayer(data: data)
            guard player.play() else { throw Failure.couldNotPlay }
            self.player = player
            playingId = id
            progress = 0
            failure = nil
            follow()
        } catch {
            failure = "Could not play that voice note: \(error)"
        }
    }

    func stop() {
        ticker?.cancel()
        ticker = nil
        player?.stop()
        player = nil
        playingId = nil
        progress = 0
    }

    /// Advance the progress bar, and clear the playing state when the
    /// note ends. Polled rather than delegated: `AVAudioPlayerDelegate`
    /// arrives off the main actor and this needs a progress tick anyway.
    private func follow() {
        ticker = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(for: .milliseconds(100))
                guard let self, let player = self.player else { return }
                self.progress = player.duration > 0 ? player.currentTime / player.duration : 0
                if !player.isPlaying {
                    self.stop()
                    return
                }
            }
        }
    }

    private enum Failure: Error, CustomStringConvertible {
        case couldNotPlay

        var description: String { "the audio device refused to play it" }
    }
}
