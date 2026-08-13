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
    /// RTT sample (largest-acked only, corrected by the peer's reported
    /// ack delay), grow the window, adapt the reorder threshold.
    public func processAckFrame(_ frame: AckFrame) {
        let largest = Int64(frame.largestAcknowledged)
        for pn in frame.acknowledgedPackets() {
            if let record = sentPackets.onAcked(pn) {
                if pn == largest {
                    let sampleMs = nowMs() - record.sentTimeMs
                    let delayMs = Int64(frame.ackDelay) / 1000
                    rtt.update(latestRttMs: max(1, sampleMs - delayMs))
                }
                congestion.onAck(record.size)
            }
        }
        sentPackets.noteLargestAcked(largest)
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

    /// Reserve a pacing slot for `bytes` about to be sent. Returns the
    /// nanoseconds the caller should sleep before sending (0 = now).
    public func reservePacingDelayNanos(bytes: Int) -> Int64 {
        lock.lock(); defer { lock.unlock() }
        let srttMs = max(1, rtt.smoothedRttMs)
        var rateBps = TransferMachinery.pacingGain * Double(congestion.congestionWindow) * 1000.0 / Double(srttMs)
        if rateBps < TransferMachinery.minPacingRateBps { rateBps = TransferMachinery.minPacingRateBps }
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
        let srttMs = max(1, rtt.smoothedRttMs)
        var rateBps = TransferMachinery.pacingGain * Double(congestion.congestionWindow) * 1000.0 / Double(srttMs)
        if rateBps < TransferMachinery.minPacingRateBps { rateBps = TransferMachinery.minPacingRateBps }
        return Int64(rateBps * Double(intervalMs) / 1000.0)
    }

    public func resetForRestart() {
        sentPackets.resetForRestart()
        ackGenerator.resetForRestart()
    }
}
