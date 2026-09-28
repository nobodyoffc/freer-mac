import Foundation

/// Adaptive jitter buffer for one incoming stream (VOICE_SPEC §9.3), a port
/// of Android's `JitterBuffer`. It holds encoded frames and tells the playout
/// loop, once per frame period, what to play: a frame, the FEC copy carried
/// by the next frame, or concealment. No decoding in here.
///
/// - Target delay: the 95th percentile of arrival jitter over the last 2 s,
///   kept between 40 and 300 ms.
/// - Shrinking: while more than two frames over target, skip a quiet frame
///   (marked silent, or 15 dB below the speaker's recent loudest); after a
///   second over target without one, drop any, at most one per 200 ms.
/// - Growing: when the next frame is late and nothing after it has arrived,
///   conceal and wait for it.
/// - A lost frame comes back from the next frame's FEC when that is here.
/// - After a pause (DTX, or the sender stopped), playout restarts at the
///   first new frame behind a fresh target delay.
///
/// Thread-safe: `put` runs on the network thread, `pull` on the playout thread.
public final class JitterBuffer: @unchecked Sendable {

    public enum Kind: Equatable { case nothing, frame, fec, conceal }

    public struct Pull {
        public let kind: Kind
        public let data: Data?
        static let nothing = Pull(kind: .nothing, data: nil)
        static let conceal = Pull(kind: .conceal, data: nil)
    }

    public static let minTargetMs = 40
    public static let maxTargetMs = 300
    static let windowMs: Int64 = 2_000
    static let pauseMs: Int64 = 200
    static let quietDb = 15.0
    static let forceAfterMs: Int64 = 1_000
    static let forceGapMs: Int64 = 200

    private struct Entry {
        let data: Data
        let silent: Bool
        let afterDtx: Bool
        let level: Int
    }

    public let frameMs: Int
    private let lock = NSLock()
    private var frames: [Int64: Entry] = [:]
    /// (arrivalMs, transitMs) of recent frames, oldest first.
    private var window: [(Int64, Int64)] = []

    private var playing = false
    private var nextSeq = Int64.min
    private var maxSeq: Int64 = -1
    private var spurtStartMs: Int64 = 0
    private var lastArrival: Int64 = 0
    private var waitedFrames = 0
    private var loudest = 127.0
    private var overSinceMs: Int64 = -1
    private var lastForcedMs = Int64.min / 2

    private var received = 0, played = 0, fecRecovered = 0, concealed = 0, dtxGap = 0, late = 0, skipped = 0, forced = 0,
                stretched = 0, duplicates = 0

    public init(frameMs: Int) {
        self.frameMs = frameMs
    }

    /// - Parameters:
    ///   - timestamp: media timestamp, 48 kHz samples
    ///   - silent: a quiet frame, safe to skip
    ///   - afterDtx: the sender skipped the frames before this one as DTX
    ///   - level: -dBov, 0 loudest, 127 silence
    public func put(seq: Int64, timestamp: Int64, data: Data, silent: Bool, afterDtx: Bool, level: Int, arrivalMs: Int64) {
        lock.lock()
        defer { lock.unlock() }
        if seq < nextSeq {
            late += 1
            return
        }
        if frames[seq] != nil {
            duplicates += 1
            return
        }
        frames[seq] = Entry(data: data, silent: silent, afterDtx: afterDtx, level: level)
        received += 1
        loudest = Double(level) < loudest ? Double(level) : min(127, loudest + 0.05)
        if seq > maxSeq { maxSeq = seq }
        if frames.count == 1 && !playing { spurtStartMs = arrivalMs }
        lastArrival = arrivalMs
        window.append((arrivalMs, arrivalMs - timestamp / 48))
        while let first = window.first, first.0 < arrivalMs - JitterBuffer.windowMs { window.removeFirst() }
    }

    /// Called once per frame period by the playout loop.
    public func pull(nowMs: Int64) -> Pull {
        lock.lock()
        defer { lock.unlock() }
        let fm = Int64(frameMs)
        if !playing {
            guard let firstSeq = frames.keys.min() else { return .nothing }
            let queued = (maxSeq - firstSeq + 1) * fm >= Int64(targetLocked())
            if !queued && nowMs - spurtStartMs < Int64(targetLocked()) { return .nothing }
            playing = true
            nextSeq = firstSeq
            waitedFrames = 0
        }

        let target = Int64(targetLocked())
        let depth = maxSeq - nextSeq + 1
        let targetFrames = (target + fm - 1) / fm
        let over = depth > targetFrames + 2
        if !over { overSinceMs = -1 } else if overSinceMs < 0 { overSinceMs = nowMs }
        var head = frames[nextSeq]
        if over, let h = head, frames[nextSeq + 1] != nil {
            let quiet = h.silent || Double(h.level) >= loudest + JitterBuffer.quietDb
            let force = nowMs - overSinceMs >= JitterBuffer.forceAfterMs && nowMs - lastForcedMs >= JitterBuffer.forceGapMs
            if quiet || force {
                frames[nextSeq] = nil
                nextSeq += 1
                skipped += 1
                if !quiet {
                    forced += 1
                    lastForcedMs = nowMs
                }
                head = frames[nextSeq]
            }
        }
        // Far over the ceiling, whatever the content: catch up.
        let maxFrames = Int64(JitterBuffer.maxTargetMs) / fm + 2
        if depth > maxFrames {
            let to = maxSeq - targetFrames + 1
            for k in frames.keys where k < to {
                frames[k] = nil
                skipped += 1
            }
            nextSeq = to
            head = frames[nextSeq]
        }

        if let h = head {
            frames[nextSeq] = nil
            nextSeq += 1
            stretched += waitedFrames
            waitedFrames = 0
            played += 1
            return Pull(kind: .frame, data: h.data)
        }

        // Missing. Nothing newer has arrived: it is late, or the sender paused.
        if frames.isEmpty {
            if nowMs - lastArrival > JitterBuffer.pauseMs {
                playing = false
                waitedFrames = 0
                return .nothing
            }
            if Int64(waitedFrames) * fm < Int64(JitterBuffer.maxTargetMs) {
                waitedFrames += 1
                return .conceal
            }
        }

        // Not sent: the next frame says the sender was in DTX. Silence, not loss.
        if let followingSeq = frames.keys.filter({ $0 >= nextSeq }).min(), frames[followingSeq]!.afterDtx {
            nextSeq += 1
            waitedFrames = 0
            dtxGap += 1
            return .conceal
        }

        // Lost: something after it is here, or we waited long enough.
        nextSeq += 1
        stretched += waitedFrames
        waitedFrames = 0
        if let next = frames[nextSeq] {
            fecRecovered += 1
            return Pull(kind: .fec, data: next.data)
        }
        concealed += 1
        return .conceal
    }

    public var targetMs: Int {
        lock.lock()
        defer { lock.unlock() }
        return targetLocked()
    }

    private func targetLocked() -> Int {
        guard window.count >= 2 else { return JitterBuffer.minTargetMs }
        let low = window.map(\.1).min()!
        let jitter = window.map { $0.1 - low }.sorted()
        let p95 = jitter[Int((0.95 * Double(jitter.count)).rounded(.up)) - 1]
        return Int(max(Int64(JitterBuffer.minTargetMs), min(Int64(JitterBuffer.maxTargetMs), p95)))
    }

    /// Frames queued ahead of playout, ms.
    public var depthMs: Int {
        lock.lock()
        defer { lock.unlock() }
        return playing ? Int(max(0, (maxSeq - nextSeq + 1) * Int64(frameMs))) : frames.count * frameMs
    }

    public var lastArrivalMs: Int64 {
        lock.lock()
        defer { lock.unlock() }
        return lastArrival
    }

    /// `concealed` and `fecRecovered` are lost frames; `dtxGap` were never sent;
    /// `stretched` is concealment played while waiting for a late frame.
    public struct Stats {
        public let received, played, fecRecovered, concealed, dtxGap, late, skipped, forced, stretched, duplicates: Int
        public let targetMs, depthMs: Int

        public var lossPercent: Double {
            let lost = fecRecovered + concealed
            let expected = played + lost
            return expected == 0 ? 0 : 100.0 * Double(lost) / Double(expected)
        }
    }

    public var stats: Stats {
        let t = targetMs, d = depthMs
        lock.lock()
        defer { lock.unlock() }
        return Stats(received: received, played: played, fecRecovered: fecRecovered, concealed: concealed, dtxGap: dtxGap,
                     late: late, skipped: skipped, forced: forced, stretched: stretched, duplicates: duplicates,
                     targetMs: t, depthMs: d)
    }
}
