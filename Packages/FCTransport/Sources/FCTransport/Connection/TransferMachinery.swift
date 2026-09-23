import Foundation

/// Bundles the per-connection reliability machinery — RTT estimation,
/// CUBIC congestion control, send-side packet tracking, receive-side
/// ACK generation, and QUIC-style rate pacing — the pieces
/// `FC-AJDK/.../fudp/connection/PeerConnection.java` carries inline.
/// One instance per `PeerConnection`.
public final class TransferMachinery: @unchecked Sendable {

    public let rtt: RttEstimator
    public let congestion: CongestionControl
    public let sentPackets: SentPacketTracker
    public let ackGenerator: AckGenerator

    // === Rate-based send pacing (QUIC-style leaky bucket) ===
    // Bulk senders must not emit line-rate bursts: shallow bottleneck
    // buffers and ingress policers clip bursts even when the AVERAGE
    // rate is far below path capacity. Packets are spread at
    // PACING_GAIN · cwnd / sRTT — slightly above the ACK-clocked rate
    // so the window can still grow, but never a burst.
    private static let pacingGain = 1.25
    private static let minPacingRateBps: Double = 10_000 // 10 KB/s floor
    private static let pacerBurstAllowanceNanos: Int64 = 2_000_000 // 2 ms

    private let lock = NSLock()
    private var pacerNextNanos: Int64 = 0
    private var lastLossSignalMs: Int64 = 0
    private var _streamRateCapBps: Int64 = 0

    private let nowMs: @Sendable () -> Int64

    public init(
        minTimeThresholdMs: Int64 = 2000,
        nowMs: @escaping @Sendable () -> Int64 = { Int64(Date().timeIntervalSince1970 * 1000) }
    ) {
        self.nowMs = nowMs
        self.rtt = RttEstimator()
        self.congestion = CongestionControl(nowMs: nowMs)
        self.sentPackets = SentPacketTracker(minTimeThresholdMs: minTimeThresholdMs, nowMs: nowMs)
        self.ackGenerator = AckGenerator(nowMs: nowMs)
    }

    /// Process one inbound ACK frame: release acked packets, take the
    /// RTT sample (corrected by the peer's reported ack delay), grow the
    /// window, adapt the reorder threshold. Numbers we never tracked
    /// (our ACK-only and DATAGRAM-only packets) are ignored.
    ///
    /// The RTT is sampled when this ACK newly covers a tracked packet
    /// sent after every tracked packet acknowledged so far — QUIC's
    /// "largest acknowledged is newly acked", restated over tracked
    /// packets (FUDP3 §3.2). The frame's Largest Acknowledged may be a
    /// packet we never tracked, and requiring `pn == largest` starved
    /// the estimator whenever datagrams were flowing.
    public func processAckFrame(_ frame: AckFrame) {
        let previousLargestSeq = sentPackets.largestAckedTrackedSeq
        var rttRecord: SentPacketRecord?
        for record in sentPackets.onAckFrame(intervals: frame.acknowledgedIntervals()) {
            if rttRecord.map({ record.trackedSeq > $0.trackedSeq }) ?? true {
                rttRecord = record
            }
            congestion.onAck(record.size)
        }
        if let rttRecord, rttRecord.trackedSeq > previousLargestSeq {
            let sampleMs = nowMs() - rttRecord.sentTimeMs
            let delayMs = Int64(frame.ackDelay) / 1000
            rtt.update(latestRttMs: max(1, sampleMs - delayMs))
        }
    }

    /// Run loss detection with the current RTT estimate.
    public func detectLostPackets() -> SentPacketTracker.LossDetection {
        sentPackets.detectLostPackets(
            smoothedRttMs: rtt.smoothedRttMs,
            rttVarianceMs: rtt.rttVarianceMs
        )
    }

    /// Throttled congestion signal: at most one `onLoss` per second.
    @discardableResult
    public func trySignalLoss() -> Bool {
        lock.lock(); defer { lock.unlock() }
        let now = nowMs()
        if now - lastLossSignalMs > 1000 {
            lastLossSignalMs = now
            congestion.onLoss()
            return true
        }
        return false
    }

    // Optional ceiling on the pacing rate of stream data, in bits per
    // second (0 = none). A call layer sets it while a call is live:
    // loss-based congestion control fills whatever queue sits downstream
    // (the receiver's socket buffer, a bottleneck router), and DATAGRAM
    // audio waits in that queue behind the upload. Capping streams below
    // the path rate keeps it empty. Datagrams are not paced, so the cap
    // never applies to them (FUDP3 §5.4.3).

    /// The stream rate cap in bits per second; 0 when there is none.
    public var streamRateCapBps: Int64 {
        lock.lock(); defer { lock.unlock() }
        return _streamRateCapBps
    }

    /// Cap the rate stream data is sent at, in bits per second; 0
    /// removes the cap. Retransmissions are budgeted to it too.
    public func setStreamRateCap(bitsPerSecond: Int64) {
        precondition(bitsPerSecond >= 0, "Stream rate cap must not be negative: \(bitsPerSecond)")
        lock.lock(); defer { lock.unlock() }
        _streamRateCapBps = bitsPerSecond
    }

    /// Pacing rate in bytes per second: PACING_GAIN · cwnd / sRTT,
    /// floored, then capped. Caller holds `lock`.
    private func pacingRateBytesPerSecLocked() -> Double {
        let srttMs = max(1, rtt.smoothedRttMs)
        var rate = TransferMachinery.pacingGain * Double(congestion.congestionWindow) * 1000.0 / Double(srttMs)
        if rate < TransferMachinery.minPacingRateBps { rate = TransferMachinery.minPacingRateBps }
        if _streamRateCapBps > 0 { rate = min(rate, Double(_streamRateCapBps) / 8.0) }
        return rate
    }

    /// Reserve a pacing slot for `bytes` about to be sent. Returns the
    /// nanoseconds the caller should sleep before sending (0 = now).
    public func reservePacingDelayNanos(bytes: Int) -> Int64 {
        lock.lock(); defer { lock.unlock() }
        let rateBps = pacingRateBytesPerSecLocked()
        let nanosForBytes = Int64(Double(bytes) * 1_000_000_000.0 / rateBps)

        let now = Int64(DispatchTime.now().uptimeNanoseconds)
        if pacerNextNanos < now - TransferMachinery.pacerBurstAllowanceNanos {
            pacerNextNanos = now // idle: restart the bucket, allow a small burst
        }
        let delay = pacerNextNanos - now
        pacerNextNanos += nanosForBytes
        return max(0, delay)
    }

    /// Bytes the pacer allows within `intervalMs` (for the retransmit
    /// loop, which budgets per cycle instead of sleeping per packet).
    public func pacingBudgetBytes(intervalMs: Int64) -> Int64 {
        lock.lock(); defer { lock.unlock() }
        return Int64(pacingRateBytesPerSecLocked() * Double(intervalMs) / 1000.0)
    }

    public func resetForRestart() {
        sentPackets.resetForRestart()
        ackGenerator.resetForRestart()
    }
}
