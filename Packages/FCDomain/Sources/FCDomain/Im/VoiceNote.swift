import Foundation

/// A voice note: the metadata that rides beside the audio, and the size
/// rule that decides whether the audio can travel inline at all.
///
/// The port of Android's `VoiceMessageHelper`, and deliberately the same
/// shape, because the two clients have to agree on the one thing that
/// crosses between them — the `content` of a ``ContentType/voice``
/// message, which is
/// `{"durationMs":1985,"sampleRate":16000,"format":"aac"}`. The audio
/// itself is raw AAC-in-MPEG-4 bytes in ``ImMessage/data``; since FIMP
/// v2 the two are sealed together, so a note's duration is no more
/// readable to an intermediary than its sound.
///
/// **A voice note is not guaranteed to fit.** The DOCK's per-item
/// ceiling is 64 KB by default and each operator may advertise less, so
/// at any bitrate worth shipping a long note has to go to a DISK and
/// travel as a HAT, exactly like a shared file. That fallback is not a
/// failure mode to be engineered away — it is the reason
/// ``fitsInline(audioBytes:budget:)`` takes the budget as a parameter
/// rather than comparing against a constant the app invented.
public enum VoiceNote {

    // MARK: - recording shape

    /// 16 kHz mono, which is what Android records and what the metadata
    /// announces. Speech has nothing above 8 kHz that a listener misses.
    public static let sampleRate = 16_000

    /// 24 kbit/s — 3 KB of audio per second.
    ///
    /// Android records at 64 kbit/s, which was chosen when the app
    /// believed a DOCK would take 900 KB. Against the real 64 KB ceiling
    /// that is barely eight seconds inline, and every ordinary note
    /// would take the DISK detour. At 24 kbit/s an AAC-LC encoder is
    /// still clean on speech and a note stays inline for about twenty
    /// seconds, which is what most of them are.
    public static let bitRate = 24_000

    /// Five minutes, matching Android. Long notes are legal; they simply
    /// go via DISK.
    public static let maxDurationMs: Int64 = 300_000

    /// Below this there is nothing to hear, and an encoder asked to
    /// close a file with no frames in it tends to produce an unplayable
    /// one. A press this short is a mis-click, not a message.
    public static let minDurationMs: Int64 = 500

    /// Headroom left for the envelope, the body framing and the seal
    /// when measuring audio against a DOCK's ceiling. The AsyTwoWay
    /// bundle alone is 52 bytes; the rest is ids, the timestamp and this
    /// metadata. The authoritative check is ``MessageCourier``'s, on the
    /// encoded envelope at send time — this one only avoids building a
    /// message that is certain to be refused.
    public static let wireOverheadAllowance = 1_024

    // MARK: - metadata

    public struct Meta: Equatable, Sendable {
        public let durationMs: Int64
        public let sampleRate: Int
        public let format: String

        public init(durationMs: Int64, sampleRate: Int = VoiceNote.sampleRate, format: String = "aac") {
            self.durationMs = durationMs
            self.sampleRate = sampleRate
            self.format = format
        }
    }

    /// The `content` of a voice message. Written by hand rather than by
    /// an encoder so the field order matches Android's byte for byte —
    /// nothing parses it positionally, but a golden vector does.
    public static func metaJson(durationMs: Int64, sampleRate: Int = VoiceNote.sampleRate) -> String {
        "{\"durationMs\":\(durationMs),\"sampleRate\":\(sampleRate),\"format\":\"aac\"}"
    }

    /// What a voice message says about itself, or nil if it is not a
    /// voice message or its metadata is unreadable.
    ///
    /// Tolerant on purpose: a note whose duration we cannot parse is
    /// still a note we can play, so a missing or malformed field falls
    /// back to a default instead of throwing the message away. Only the
    /// content type is load-bearing.
    public static func meta(in message: ImMessage) -> Meta? {
        guard message.contentType == .voice else { return nil }
        guard let json = message.content, !json.isEmpty,
              let object = try? JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String: Any]
        else { return Meta(durationMs: 0) }
        return Meta(
            durationMs: (object["durationMs"] as? NSNumber)?.int64Value ?? 0,
            sampleRate: (object["sampleRate"] as? NSNumber)?.intValue ?? sampleRate,
            format: object["format"] as? String ?? "aac"
        )
    }

    /// `M:SS`, the only duration format a chat bubble has room for.
    public static func formatDuration(_ ms: Int64) -> String {
        let seconds = max(0, ms) / 1000
        return String(format: "%d:%02d", seconds / 60, seconds % 60)
    }

    // MARK: - composing

    /// The message that carries a recording, ready for
    /// ``ChatService/send(_:in:as:keys:now:)`` to name, seal and queue.
    public static func message(
        type: ImType,
        from: String,
        to: String,
        audio: Data,
        durationMs: Int64,
        sampleRate: Int = VoiceNote.sampleRate,
        now: Date = Date()
    ) -> ImMessage {
        ImMessage.voice(
            type: type, from: from, to: to,
            metaJson: metaJson(durationMs: durationMs, sampleRate: sampleRate),
            data: audio,
            now: now
        )
    }

    /// Whether a recording of `audioBytes` can travel inside a message
    /// to a DOCK advertising `budget`. False means the DISK-and-HAT
    /// path, not an error.
    public static func fitsInline(audioBytes: Int, budget: Int) -> Bool {
        audioBytes <= budget - wireOverheadAllowance
    }

    /// A file name for a recording, unique per note and sortable — the
    /// HAT path shares the file under this name, so it is what the
    /// receiver sees when a long note lands as an attachment.
    public static func fileName(at date: Date = Date()) -> String {
        "voice-\(Int64(date.timeIntervalSince1970 * 1000)).m4a"
    }
}
