import Foundation

/// One tracked outbound packet awaiting acknowledgment.
public struct SentPacketRecord: Sendable {
    public let packetNumber: Int64
    /// The retransmittable frames the packet carried (STREAM only —
    /// ACK/PADDING frames are never retransmitted).
    public let frames: [StreamFrame]
    /// Full datagram size in bytes (header + crypto + frames), the unit
    /// congestion accounting uses.
    public let size: Int
    public let sentTimeMs: Int64
    public var retransmitCount: Int
    /// Position among TRACKED packets on this connection: 0, 1, 2, …
    /// in send order. Gap-based loss detection counts in this space, not
    /// in packet numbers, which untracked packets also use.
    public let trackedSeq: Int64
}

/// Send-side packet tracking + loss detection. Port of the sentPackets
/// map and `detectLostPackets` / reorder-threshold logic in
/// `FC-AJDK/.../fudp/connection/PeerConnection.java`.
///
/// Only ack-eliciting packets are tracked: ACK-only and DATAGRAM-only
/// packets are never acknowledged, so tracking them would make them
/// look permanently lost.
///
/// **Gap-based loss detection counts TRACKED packets, not packet
/// numbers** (FUDP3 §4.1.1). Packet numbers are also spent on packets
/// that are never tracked, and the peer may list those in its ACKs.
/// Measured in packet numbers, ten audio datagrams sent after a stream
/// packet put it ten numbers behind the next acknowledgment, so it was
/// declared lost with only one tracked packet after it — and an ACK for
/// an untracked number counted as evidence against it.
public final class SentPacketTracker: @unchecked Sendable {

    /// Loss detection result: packets to retransmit, plus whether any
    /// were detected by an ACK GAP (real drop evidence). Per QUIC
    /// RFC 9002, only gap-detected loss is a congestion signal —
    /// timeout-detected "loss" is retransmitted but must not shrink
    /// the window (on jittery paths timeouts are routinely spurious).
    public struct LossDetection: Sendable {
        public let packets: [SentPacketRecord]
        public let gapLoss: Bool
    }

    // Same constants as the Java implementation.
    private static let timeThresholdMultiplier = 2.0
    private static let maxTimeThresholdMs: Int64 = 4000
    private static let initialPacketThreshold: Int64 = 6
    private static let maxPacketThreshold: Int64 = 64
    /// Cap on remembered suspected-lost packet numbers.
    private static let maxSuspectedLost = 4096

    private let lock = NSLock()
    private var sentPackets: [Int64: SentPacketRecord] = [:]
    /// Packets marked suspected-lost: packet number → its tracked seq,
    /// for measuring the reordering extent if it is acknowledged after all.
    private var suspectedLost: [Int64: Int64] = [:]
    private var nextTrackedSeq: Int64 = 0
    private var _largestAckedTrackedSeq: Int64 = -1
    private var _packetReorderThreshold: Int64 = SentPacketTracker.initialPacketThreshold

    // Statistics.
    private var _retransmitCount: Int64 = 0
    private var _suspectedLostCount: Int64 = 0
    private var _ackedAfterSuspectedLost: Int64 = 0

    private let minTimeThresholdMs: Int64
    private let nowMs: @Sendable () -> Int64

    public init(
        minTimeThresholdMs: Int64 = 2000,
        nowMs: @escaping @Sendable () -> Int64 = { Int64(Date().timeIntervalSince1970 * 1000) }
    ) {
        self.minTimeThresholdMs = minTimeThresholdMs
        self.nowMs = nowMs
    }

    /// Record an ack-eliciting packet the moment it is handed to the
    /// network. Must be called BEFORE the actual socket write — on
    /// localhost the ACK can arrive before a post-write record would run.
    public func recordSent(packetNumber: Int64, frames: [StreamFrame], size: Int, retransmitCount: Int = 0) {
        lock.lock(); defer { lock.unlock() }
        sentPackets[packetNumber] = SentPacketRecord(
            packetNumber: packetNumber,
            frames: frames,
            size: size,
            sentTimeMs: nowMs(),
            retransmitCount: retransmitCount,
            trackedSeq: nextTrackedSeq
        )
        nextTrackedSeq += 1
    }

    /// Process one ACK frame, given its acknowledged ranges as
    /// intervals. Returns the records it newly acknowledges (the caller
    /// feeds their sizes to congestion control and picks the RTT
    /// sample). Advances the largest acknowledged tracked seq, and
    /// performs the spurious-loss reorder-threshold adaptation.
    ///
    /// **It walks the outstanding packets, not the acknowledged numbers.**
    /// An ACK frame re-advertises every packet number the peer has
    /// retained — about 4 seconds of them (FUDP3 §2.1) — while what is
    /// outstanding here is bounded by the congestion window. Expanding
    /// the frame and looking up each number cost O(retained) per ACK:
    /// 1.5 ms at 6 000 retained, on every one of the thousands of ACKs a
    /// transfer receives per second. The sender fell irrecoverably behind
    /// the ACK stream, its RTT estimate climbed past the loss timeout,
    /// and it retransmitted packets that had already arrived.
    public func onAckFrame(intervals: [AckInterval]) -> [SentPacketRecord] {
        lock.lock(); defer { lock.unlock() }
        guard !intervals.isEmpty else { return [] }

        var acked: [SentPacketRecord] = []
        for (packetNumber, record) in sentPackets where SentPacketTracker.covers(intervals, packetNumber) {
            acked.append(record)
        }
        for record in acked {
            sentPackets.removeValue(forKey: record.packetNumber)
            if record.trackedSeq > _largestAckedTrackedSeq {
                _largestAckedTrackedSeq = record.trackedSeq
            }
        }

        // Previously marked suspected-lost but now ACKed → the path
        // reorders deeper than assumed. Widen the gap threshold to the
        // observed reordering extent (RACK-style) so heavily
        // load-balanced routes stop firing false congestion signals.
        let spurious = suspectedLost.filter { SentPacketTracker.covers(intervals, $0.key) }
        for (packetNumber, suspectedSeq) in spurious {
            suspectedLost.removeValue(forKey: packetNumber)
            _ackedAfterSuspectedLost += 1
            let extent = _largestAckedTrackedSeq - suspectedSeq + 2
            let widened = min(SentPacketTracker.maxPacketThreshold,
                              max(_packetReorderThreshold + 4, extent))
            if widened > _packetReorderThreshold {
                _packetReorderThreshold = widened
            }
        }
        return acked
    }

    /// Is `packetNumber` in one of the (descending, disjoint) intervals?
    private static func covers(_ intervals: [AckInterval], _ packetNumber: Int64) -> Bool {
        var lo = 0, hi = intervals.count - 1
        while lo <= hi {
            let mid = (lo + hi) / 2
            if packetNumber > intervals[mid].high {
                hi = mid - 1          // intervals descend, so look newer
            } else if packetNumber < intervals[mid].low {
                lo = mid + 1
            } else {
                return true
            }
        }
        return false
    }

    /// Detect lost packets. Does NOT remove them — the retransmit loop
    /// removes only what it actually retransmits or abandons, so a
    /// rate-limited cycle can't drop packets on the floor.
    public func detectLostPackets(smoothedRttMs: Int64, rttVarianceMs: Int64) -> LossDetection {
        lock.lock(); defer { lock.unlock() }
        var lost: [SentPacketRecord] = []
        var gapLoss = false

        // Timeout threshold: clamp(2·sRTT + 4·rttvar, floor, ceiling).
        let timeThreshold = min(
            SentPacketTracker.maxTimeThresholdMs,
            max(minTimeThresholdMs,
                Int64(Double(smoothedRttMs) * SentPacketTracker.timeThresholdMultiplier) + 4 * rttVarianceMs)
        )
        // Gap-detected loss must be at least ~1 RTT old — reordered
        // packets arrive within an RTT of their peers; a truly lost one
        // stays unACKed while later ones are ACKed past it.
        let gapMinAge = max(20, smoothedRttMs)
        let now = nowMs()

        for record in sentPackets.values {
            let age = now - record.sentTimeMs

            let lostByGap = _largestAckedTrackedSeq - record.trackedSeq >= _packetReorderThreshold
                && age > gapMinAge

            // Exponential backoff per retransmission (QUIC PTO): 1x, 2x,
            // then 4x the threshold, capped — single-packet messages have
            // no gap evidence and depend on this timer alone.
            let effectiveTimeThreshold = timeThreshold << Int64(min(record.retransmitCount, 2))
            let lostByTime = age > effectiveTimeThreshold

            if lostByGap || lostByTime {
                lost.append(record)
                if lostByGap { gapLoss = true }
            }
        }

        return LossDetection(packets: lost, gapLoss: gapLoss)
    }

    /// Pull a packet for retransmission (or abandonment). Marks it
    /// suspected-lost for the spurious-loss accounting. Returns nil if
    /// an ACK raced us and already removed it.
    public func removeForRetransmit(_ packetNumber: Int64) -> SentPacketRecord? {
        lock.lock(); defer { lock.unlock() }
        guard let removed = sentPackets.removeValue(forKey: packetNumber) else { return nil }
        _suspectedLostCount += 1
        suspectedLost[packetNumber] = removed.trackedSeq
        // Bounded: an entry is only useful until its ACK arrives, and a
        // long-lived connection that loses packets steadily would
        // otherwise keep every packet number it ever suspected. Trimming
        // in batches keeps the cost amortized; dropping the oldest costs
        // at most one threshold widening.
        if suspectedLost.count > SentPacketTracker.maxSuspectedLost {
            let keep = SentPacketTracker.maxSuspectedLost * 3 / 4
            for pn in suspectedLost.keys.sorted().prefix(suspectedLost.count - keep) {
                suspectedLost.removeValue(forKey: pn)
            }
        }
        return removed
    }

    public func recordRetransmit() {
        lock.lock(); defer { lock.unlock() }
        _retransmitCount += 1
    }

    /// The highest tracked seq acknowledged so far (-1 before any).
    public var largestAckedTrackedSeq: Int64 {
        lock.lock(); defer { lock.unlock() }
        return _largestAckedTrackedSeq
    }

    public var packetReorderThreshold: Int64 {
        lock.lock(); defer { lock.unlock() }
        return _packetReorderThreshold
    }

    public var trackedCount: Int {
        lock.lock(); defer { lock.unlock() }
        return sentPackets.count
    }

    public var retransmitCount: Int64 {
        lock.lock(); defer { lock.unlock() }
        return _retransmitCount
    }

    public var ackedAfterSuspectedLost: Int64 {
        lock.lock(); defer { lock.unlock() }
        return _ackedAfterSuspectedLost
    }

    public func resetForRestart() {
        lock.lock(); defer { lock.unlock() }
        sentPackets.removeAll()
        suspectedLost.removeAll()
        _largestAckedTrackedSeq = -1
    }
}
