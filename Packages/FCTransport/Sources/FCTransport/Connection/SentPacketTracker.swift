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
}

/// Send-side packet tracking + loss detection. Port of the sentPackets
/// map and `detectLostPackets` / reorder-threshold logic in
/// `FC-AJDK/.../fudp/connection/PeerConnection.java`.
///
/// Only ack-eliciting packets are tracked: ACK-only packets are never
/// acknowledged, so tracking them would make them look permanently lost.
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

    private let lock = NSLock()
    private var sentPackets: [Int64: SentPacketRecord] = [:]
    private var suspectedLostPacketNumbers: Set<Int64> = []
    private var _largestAckedPacketNumber: Int64 = -1
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
            retransmitCount: retransmitCount
        )
    }

    /// Process one acknowledged packet number. Returns the record if it
    /// was still tracked (caller feeds size to congestion control and
    /// takes the RTT sample), nil if already removed by an earlier ACK.
    /// Also performs the spurious-loss reorder-threshold adaptation.
    public func onAcked(_ packetNumber: Int64) -> SentPacketRecord? {
        lock.lock(); defer { lock.unlock() }
        let record = sentPackets.removeValue(forKey: packetNumber)

        // Previously marked suspected-lost but now ACKed → the path
        // reorders deeper than assumed. Widen the gap threshold to the
        // observed reordering extent (RACK-style) so heavily
        // load-balanced routes stop firing false congestion signals.
        if suspectedLostPacketNumbers.remove(packetNumber) != nil {
            _ackedAfterSuspectedLost += 1
            let extent = _largestAckedPacketNumber - packetNumber + 2
            let widened = min(SentPacketTracker.maxPacketThreshold,
                              max(_packetReorderThreshold + 4, extent))
            if widened > _packetReorderThreshold {
                _packetReorderThreshold = widened
            }
        }
        return record
    }

    /// Advance the largest-acked watermark (gap-loss reference point).
    public func noteLargestAcked(_ largestAcked: Int64) {
        lock.lock(); defer { lock.unlock() }
        if largestAcked > _largestAckedPacketNumber {
            _largestAckedPacketNumber = largestAcked
        }
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

            let lostByGap = _largestAckedPacketNumber - record.packetNumber >= _packetReorderThreshold
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
        suspectedLostPacketNumbers.insert(packetNumber)
        return removed
    }

    public func recordRetransmit() {
        lock.lock(); defer { lock.unlock() }
        _retransmitCount += 1
    }

    public var largestAckedPacketNumber: Int64 {
        lock.lock(); defer { lock.unlock() }
        return _largestAckedPacketNumber
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
        suspectedLostPacketNumbers.removeAll()
        _largestAckedPacketNumber = -1
    }
}
