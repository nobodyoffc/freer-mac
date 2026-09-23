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
    /// Index of the oldest retained entry; everything before it has been
    /// pruned. Pruning runs on every non-eliciting packet, so it only
    /// advances this, and the arrays are compacted once the dead prefix
    /// outgrows the live part — `removeFirst` there moved every retained
    /// entry on each ACK-only packet received.
    private var head = 0
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
        let now = nowMs()
        if newSinceLastAck == 0 {
            firstPendingAckTimeMs = now
        }
        if insertLocked(packetNumber, now: now) {
            newSinceLastAck += 1
        }
    }

    /// Record a received packet number that does not elicit an ACK
    /// (ACK-only, DATAGRAM-only, or both).
    ///
    /// It is listed in the next ACK frame sent for other reasons, so the
    /// ranges have holes only where packets were really lost, but it
    /// never triggers an ACK on its own. The sender ignores the number,
    /// since it does not track such packets.
    ///
    /// Leaving these out put a hole in the ranges for every packet the
    /// peer sent without eliciting an ACK. With data flowing both ways
    /// that is every other packet: ACK frames hit `maxRangesPerFrame`
    /// while covering only the last ~250 packet numbers, so the
    /// retention window that protects against lost ACKs shrank to a
    /// fraction of a second (FUDP3 §2.1).
    public func onNonElicitingPacketReceived(_ packetNumber: Int64) {
        lock.lock(); defer { lock.unlock() }
        let now = nowMs()
        insertLocked(packetNumber, now: now)
        // No ACK frame may follow for a long time (a receive-only
        // datagram flow), and pruning otherwise happens only when one
        // is generated.
        pruneLocked(now: now)
    }

    /// Insert a packet number in order. Returns false for a duplicate.
    @discardableResult
    private func insertLocked(_ packetNumber: Int64, now: Int64) -> Bool {
        defer {
            if packetNumber > _largestReceived {
                _largestReceived = packetNumber
            }
        }
        if packetNumbers.last.map({ packetNumber > $0 }) ?? true {
            packetNumbers.append(packetNumber)
            receiveTimes.append(now)
            return true
        }
        // Out-of-order or duplicate: binary-insert.
        var lo = head, hi = packetNumbers.count
        while lo < hi {
            let mid = (lo + hi) / 2
            if packetNumbers[mid] < packetNumber { lo = mid + 1 } else { hi = mid }
        }
        if lo < packetNumbers.count && packetNumbers[lo] == packetNumber {
            // **A duplicate keeps its original receive time.**
            // Refreshing it looked like extending the retention of
            // something still arriving, but the prune is a front-drop
            // that stops at the first entry newer than the cutoff — so
            // moving an *old* entry's timestamp forward stops the prune
            // at that entry, permanently. Replaying the lowest retained
            // packet number then pins the whole set open, size cap
            // included, because that check lives inside the same loop.
            // The retention window asks how long ago we first saw a
            // number, which a second copy does not change.
            return false
        }
        packetNumbers.insert(packetNumber, at: lo)
        receiveTimes.insert(now, at: lo)
        return true
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

    /// Build an ACK frame covering the retained packet numbers, newest
    /// first, encoded in at most `maxBytes`. Ranges that do not fit are
    /// left out, oldest first; they stay retained and later frames
    /// re-advertise them.
    ///
    /// Returns nil when nothing new arrived since the last generated
    /// frame, or when not even the newest range fits in `maxBytes` —
    /// the ACK then stays pending for a caller with more room.
    public func generateAckFrame(maxBytes: Int) -> AckFrame? {
        lock.lock(); defer { lock.unlock() }
        guard newSinceLastAck > 0, packetNumbers.count > head else { return nil }

        let now = nowMs()
        pruneLocked(now: now)

        let ackDelayUs: Int64 = firstPendingAckTimeMs > 0
            ? (now - firstPendingAckTimeMs) * 1000
            : 0

        // Fold the (ascending) numbers into descending (gap, length)
        // ranges. length = count-1 of consecutive numbers; gap =
        // distance from the previous (higher) range minus 2, per the
        // Java encoding.
        //
        // Each run of consecutive numbers is found by binary search
        // rather than walked: within a run `packetNumbers[j] - j` is
        // constant, and it never decreases across the (ascending) array,
        // so a run's first index is the first one with that difference.
        // Walking cost O(retained) per ACK — and an ACK is generated for
        // every packet received.
        var ranges: [AckRange] = []
        var i = packetNumbers.count - 1
        var prevLow: Int64 = -1
        while i >= head && ranges.count < AckGenerator.maxRangesPerFrame {
            let high = packetNumbers[i]
            let key = high - Int64(i)
            var lo = head, hi = i
            while lo < hi {
                let mid = (lo + hi) / 2
                if packetNumbers[mid] - Int64(mid) < key { lo = mid + 1 } else { hi = mid }
            }
            let low = packetNumbers[lo]
            let gap = ranges.isEmpty ? 0 : prevLow - high - 2
            ranges.append(AckRange(gap: UInt64(max(0, gap)), length: UInt64(high - low)))
            prevLow = low
            i = lo - 1
        }

        var frame = AckFrame(
            largestAcknowledged: UInt64(max(0, packetNumbers[packetNumbers.count - 1])),
            ackDelay: UInt64(max(0, ackDelayUs)),
            ranges: ranges
        )
        // Trim the oldest ranges against a running total: this runs for
        // every ACK, so the frame is measured once, not per range dropped.
        var size = frame.encodedSize
        while size > maxBytes && frame.ranges.count > 1 {
            let dropped = frame.ranges.removeLast()
            size -= FudpVarint.encodedLength(dropped.gap) + FudpVarint.encodedLength(dropped.length)
            size += FudpVarint.encodedLength(UInt64(frame.ranges.count)) - FudpVarint.encodedLength(UInt64(frame.ranges.count + 1))
        }
        if size > maxBytes { return nil }

        newSinceLastAck = 0
        firstPendingAckTimeMs = 0
        return frame
    }

    /// Prune entries past the retention window / memory cap, oldest
    /// first, always keeping at least one entry. Packet numbers and
    /// receive times both ascend, so pruning is a front-drop.
    private func pruneLocked(now: Int64) {
        let cutoff = now - AckGenerator.ackRetainMs
        while packetNumbers.count - head > 1 {
            if receiveTimes[head] < cutoff || packetNumbers.count - head > AckGenerator.maxRetained {
                head += 1
            } else {
                break
            }
        }
        if head > 1024 && head * 2 > packetNumbers.count {
            packetNumbers.removeFirst(head)
            receiveTimes.removeFirst(head)
            head = 0
        }
    }

    public func resetForRestart() {
        lock.lock(); defer { lock.unlock() }
        packetNumbers.removeAll()
        receiveTimes.removeAll()
        head = 0
        newSinceLastAck = 0
        _largestReceived = -1
        firstPendingAckTimeMs = 0
    }
}

/// One contiguous run of acknowledged packet numbers, inclusive.
public struct AckInterval: Equatable, Sendable {
    public let low: Int64
    public let high: Int64

    public init(low: Int64, high: Int64) {
        self.low = low
        self.high = high
    }
}

extension AckFrame {
    /// The acknowledged packet numbers as intervals, newest first —
    /// what the ranges already are, without expanding them.
    ///
    /// A sender wants this rather than ``acknowledgedPackets()``: an ACK
    /// frame re-advertises every packet number the peer has retained
    /// (~4 s of them, FUDP3 §2.1), while what the sender has outstanding
    /// is bounded by its congestion window. `maxIntervals` bounds the
    /// work a hostile frame can ask for.
    public func acknowledgedIntervals(maxIntervals: Int = 1024) -> [AckInterval] {
        var intervals: [AckInterval] = []
        guard !ranges.isEmpty else { return intervals }

        var pn = Int64(clamping: largestAcknowledged)
        for (i, range) in ranges.enumerated() {
            if i > 0 {
                // pn -= gap + 1. The fields are unsigned on the wire and
                // a peer may name anything, so every step saturates
                // rather than wrapping; running off the bottom ends the
                // frame's useful content.
                let (next, overflow) = pn.subtractingReportingOverflow(Int64(clamping: range.gap))
                if overflow || next <= 0 { break }
                pn = next - 1
            }
            let (lowRaw, overflow) = pn.subtractingReportingOverflow(Int64(clamping: range.length))
            let low = overflow ? 0 : max(0, lowRaw)
            intervals.append(AckInterval(low: low, high: pn))
            if low == 0 || intervals.count >= maxIntervals { break }
            pn = low - 1
        }
        return intervals
    }

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
