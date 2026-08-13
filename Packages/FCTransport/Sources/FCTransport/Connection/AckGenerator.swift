import Foundation

/// Receive-side ACK bookkeeping. Port of
/// `FC-AJDK/.../fudp/transport/AckManager.java`.
///
/// ACK frames ride in non-ack-eliciting packets that are never
/// retransmitted, so no single ACK frame may be load-bearing: every
/// generated frame re-advertises ALL recently received packet numbers
/// (QUIC-style ranges), retained for `ackRetainMs`. If one ACK packet
/// is lost, the next still covers the same numbers — without this a
/// lost ACK orphans the packets it covered, the sender falsely
/// declares them lost, and its congestion window collapses.
public final class AckGenerator: @unchecked Sendable {

    /// Packets received before an immediate ACK is due (1 = ACK every
    /// ack-eliciting packet, the low-latency setting the Java side uses).
    public static let ackThreshold = 1
    /// How long a received packet number keeps being re-advertised.
    public static let ackRetainMs: Int64 = 4000
    /// Memory cap on retained numbers.
    public static let maxRetained = 16384
    /// Bound on ranges encoded per frame.
    public static let maxRangesPerFrame = 128

    private let lock = NSLock()
    /// Received packet numbers, ascending, with their receive
    /// timestamps in lockstep. Kept sorted incrementally (packets
    /// arrive nearly in order, so inserts are O(1) appends in
    /// practice) — a bulk transfer generates one ACK per packet, and
    /// re-sorting thousands of retained entries per ACK is what
    /// throttled the first cut of this port to ~475 KB/s.
    private var packetNumbers: [Int64] = []
    private var receiveTimes: [Int64] = []
    private var newSinceLastAck = 0
    private var _largestReceived: Int64 = -1
    private var firstPendingAckTimeMs: Int64 = 0

    private let nowMs: @Sendable () -> Int64

    public init(nowMs: @escaping @Sendable () -> Int64 = { Int64(Date().timeIntervalSince1970 * 1000) }) {
        self.nowMs = nowMs
    }

    /// Record one received ack-eliciting packet number.
    public func onPacketReceived(_ packetNumber: Int64) {
        lock.lock(); defer { lock.unlock() }
        if newSinceLastAck == 0 {
            firstPendingAckTimeMs = nowMs()
        }
        let now = nowMs()
        if let last = packetNumbers.last, packetNumber > last {
            packetNumbers.append(packetNumber)
            receiveTimes.append(now)
            newSinceLastAck += 1
        } else {
            // Out-of-order or duplicate: binary-insert / refresh.
            var lo = 0, hi = packetNumbers.count
            while lo < hi {
                let mid = (lo + hi) / 2
                if packetNumbers[mid] < packetNumber { lo = mid + 1 } else { hi = mid }
            }
            if lo < packetNumbers.count && packetNumbers[lo] == packetNumber {
                receiveTimes[lo] = now   // duplicate: refresh retention
            } else {
                packetNumbers.insert(packetNumber, at: lo)
                receiveTimes.insert(now, at: lo)
                newSinceLastAck += 1
            }
        }
        if packetNumber > _largestReceived {
            _largestReceived = packetNumber
        }
    }

    public var hasPendingAcks: Bool {
        lock.lock(); defer { lock.unlock() }
        return newSinceLastAck > 0
    }

    public var shouldSendAckImmediately: Bool {
        lock.lock(); defer { lock.unlock() }
        return newSinceLastAck >= AckGenerator.ackThreshold
    }

    public var largestReceived: Int64 {
        lock.lock(); defer { lock.unlock() }
        return _largestReceived
    }

    /// Build an ACK frame covering all retained packet numbers, or nil
    /// when nothing new arrived since the last generated frame.
    public func generateAckFrame() -> AckFrame? {
        lock.lock(); defer { lock.unlock() }
        guard newSinceLastAck > 0, !packetNumbers.isEmpty else { return nil }

        let now = nowMs()

        // Prune entries past the retention window / memory cap, oldest
        // first, always keeping at least one entry. Packet numbers and
        // receive times both ascend, so pruning is a front-drop.
        let cutoff = now - AckGenerator.ackRetainMs
        var dropCount = 0
        while packetNumbers.count - dropCount > 1 {
            let ts = receiveTimes[dropCount]
            if ts < cutoff || packetNumbers.count - dropCount > AckGenerator.maxRetained {
                dropCount += 1
            } else {
                break
            }
        }
        if dropCount > 0 {
            packetNumbers.removeFirst(dropCount)
            receiveTimes.removeFirst(dropCount)
        }

        let ackDelayUs: Int64 = firstPendingAckTimeMs > 0
            ? (now - firstPendingAckTimeMs) * 1000
            : 0

        // Fold the (ascending) numbers into descending (gap, length)
        // ranges. length = count-1 of consecutive numbers; gap =
        // distance from the previous (higher) range minus 2, per the
        // Java encoding.
        var ranges: [AckRange] = []
        var i = packetNumbers.count - 1
        var currentHigh = packetNumbers[i]
        var currentLow = currentHigh
        var prevLow: Int64 = -1

        while i > 0 {
            i -= 1
            let pn = packetNumbers[i]
            if currentLow - pn == 1 {
                currentLow = pn
            } else {
                if ranges.count >= AckGenerator.maxRangesPerFrame { break }
                let length = currentHigh - currentLow
                let gap = ranges.isEmpty ? 0 : prevLow - currentHigh - 2
                ranges.append(AckRange(gap: UInt64(max(0, gap)), length: UInt64(length)))
                prevLow = currentLow
                currentHigh = pn
                currentLow = pn
            }
        }
        if ranges.count < AckGenerator.maxRangesPerFrame {
            let length = currentHigh - currentLow
            let gap = ranges.isEmpty ? 0 : prevLow - currentHigh - 2
            ranges.append(AckRange(gap: UInt64(max(0, gap)), length: UInt64(length)))
        }

        newSinceLastAck = 0
        firstPendingAckTimeMs = 0
        return AckFrame(
            largestAcknowledged: UInt64(max(0, packetNumbers[packetNumbers.count - 1])),
            ackDelay: UInt64(max(0, ackDelayUs)),
            ranges: ranges
        )
    }

    public func resetForRestart() {
        lock.lock(); defer { lock.unlock() }
        packetNumbers.removeAll()
        receiveTimes.removeAll()
        newSinceLastAck = 0
        _largestReceived = -1
        firstPendingAckTimeMs = 0
    }
}

extension AckFrame {
    /// Expand the ranges into the concrete list of acknowledged packet
    /// numbers — port of the Java `getAcknowledgedPackets()`. Bounded
    /// defensively: a malformed/hostile frame can declare enormous
    /// ranges, so expansion stops at `limit` entries or when the
    /// running packet number would go negative.
    public func acknowledgedPackets(limit: Int = 1 << 16) -> [Int64] {
        var packets: [Int64] = []
        guard !ranges.isEmpty else { return packets }

        var pn = Int64(largestAcknowledged)

        let first = ranges[0]
        var i: Int64 = 0
        while i <= Int64(first.length) {
            let v = pn - i
            guard v >= 0 else { break }
            packets.append(v)
            if packets.count >= limit { return packets }
            i += 1
        }
        pn = pn - Int64(first.length) - 1

        for range in ranges.dropFirst() {
            pn = pn - Int64(range.gap) - 1
            var j: Int64 = 0
            while j <= Int64(range.length) {
                let v = pn - j
                guard v >= 0 else { break }
                packets.append(v)
                if packets.count >= limit { return packets }
                j += 1
            }
            pn = pn - Int64(range.length) - 1
        }

        return packets
    }
}
