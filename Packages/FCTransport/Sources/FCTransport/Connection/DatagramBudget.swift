import Foundation

/// Outcome of sending one DATAGRAM frame. Every outcome other than
/// ``sent`` means the datagram was dropped; it is never queued or
/// retried.
public enum DatagramResult: String, Sendable, CaseIterable {
    /// Handed to the socket.
    case sent
    /// Datagrams are not enabled on this connection (peer capability
    /// unknown).
    case notEnabled
    /// Larger than one packet can carry; datagrams are never fragmented.
    case tooLarge
    /// Over the connection's datagram rate budget.
    case overBudget
    /// The socket refused the packet.
    case bufferFull
    /// The connection is closed, or its transport is gone.
    case noConnection
}

/// Per-connection send budget for DATAGRAM frames (FUDP7). Port of
/// `FC-JDK/.../fudp/transport/DatagramBudget.java`.
///
/// Datagrams are exempt from congestion control, so this token bucket
/// is what stops an application from flooding a path with them. It
/// counts DATAGRAM payload bytes (the application's bytes, not packet
/// overhead). A datagram that does not fit the budget is dropped at the
/// sender, never delayed: adapting to the network is the application's
/// job.
///
/// The bucket holds ``burstMs`` worth of budget, and never less than
/// one maximum-size datagram, so a single large datagram is always
/// sendable on an idle budget.
public final class DatagramBudget: @unchecked Sendable {

    /// Default rate: 256 kbps.
    public static let defaultRateBps: Int64 = 256_000
    /// How much unused budget may accumulate, in milliseconds of rate.
    static let burstMs: Int64 = 100
    /// Floor on the bucket size, so any single datagram fits an idle budget.
    static let minBurstBytes: Int64 = 1500

    private let lock = NSLock()
    private var _rateBps: Int64 = 0
    private var capacityBytes: Int64 = 0
    private var tokens: Double = 0
    private var lastRefillNanos: UInt64 = 0
    private let nowNanos: @Sendable () -> UInt64

    public init(
        rateBps: Int64 = DatagramBudget.defaultRateBps,
        nowNanos: @escaping @Sendable () -> UInt64 = { DispatchTime.now().uptimeNanoseconds }
    ) {
        self.nowNanos = nowNanos
        setRate(rateBps)
        lock.lock()
        tokens = Double(capacityBytes)
        lock.unlock()
    }

    /// Change the rate. The bucket keeps what it holds, trimmed to the
    /// new size.
    ///
    /// - Parameter rateBps: bits per second of DATAGRAM payload; must be
    ///   positive.
    public func setRate(_ rateBps: Int64) {
        precondition(rateBps > 0, "Datagram rate must be positive: \(rateBps)")
        lock.lock(); defer { lock.unlock() }
        refillLocked(nowNanos())
        _rateBps = rateBps
        capacityBytes = max(DatagramBudget.minBurstBytes, rateBps / 8 * DatagramBudget.burstMs / 1000)
        if tokens > Double(capacityBytes) { tokens = Double(capacityBytes) }
    }

    public var rateBps: Int64 {
        lock.lock(); defer { lock.unlock() }
        return _rateBps
    }

    /// Take `bytes` from the budget if it holds that many. Returns true
    /// if the datagram may be sent, false if it must be dropped.
    public func tryConsume(_ bytes: Int) -> Bool {
        lock.lock(); defer { lock.unlock() }
        refillLocked(nowNanos())
        if tokens < Double(bytes) { return false }
        tokens -= Double(bytes)
        return true
    }

    private func refillLocked(_ now: UInt64) {
        if lastRefillNanos != 0, now > lastRefillNanos {
            let added = Double(now - lastRefillNanos) * (Double(_rateBps) / 8.0) / 1_000_000_000.0
            tokens = min(Double(capacityBytes), tokens + added)
        }
        lastRefillNanos = now
    }
}
