import Foundation

/// CUBIC-based congestion control. Port of
/// `FC-AJDK/.../fudp/congestion/CongestionControl.java`.
///
/// The CUBIC growth function operates on the window measured in
/// PACKETS (MSS units), per RFC 8312 — running it on a byte-denominated
/// window makes K come out in the tens of seconds, freezing growth
/// between losses (see the Java header comment for the field history).
///
/// The window is in bytes; `bytesInFlight` is reserved by `onSend`/
/// `trySend` and released by `onAck` (with growth) or
/// `onRetransmitRemove` (without growth — the retransmitted copy
/// re-reserves its own bytes).
public final class CongestionControl: @unchecked Sendable {

    public enum State: String, Sendable {
        case slowStart
        case congestionAvoidance
        case recovery
    }

    // Same constants as the Java implementation.
    public static let initialWindow: Int64 = 120_000
    public static let minWindow: Int64 = 14_400          // ~10 packets at 1350 B MTU
    public static let maxWindow: Int64 = 100_000_000     // 100 MB
    private static let mss: Double = 1350.0
    private static let beta: Double = 0.7
    private static let cubicC: Double = 0.4

    private let lock = NSLock()
    private var _congestionWindow: Int64 = CongestionControl.initialWindow
    private var _ssthresh: Int64 = .max
    private var _bytesInFlight: Int64 = 0
    private var _wMax: Int64 = 0
    private var _epochStartMs: Int64
    private var _state: State = .slowStart

    /// Injectable clock so unit tests can drive the cubic time axis.
    private let nowMs: @Sendable () -> Int64

    public init(nowMs: @escaping @Sendable () -> Int64 = { Int64(Date().timeIntervalSince1970 * 1000) }) {
        self.nowMs = nowMs
        self._epochStartMs = nowMs()
    }

    /// Bytes acknowledged: release them from the flight and grow the window.
    public func onAck(_ ackedBytes: Int) {
        lock.lock(); defer { lock.unlock() }
        _bytesInFlight -= Int64(ackedBytes)
        if _bytesInFlight < 0 { _bytesInFlight = 0 }

        switch _state {
        case .slowStart:
            _congestionWindow += Int64(ackedBytes)
            if _congestionWindow >= _ssthresh {
                _state = .congestionAvoidance
                _epochStartMs = nowMs()
                _wMax = _congestionWindow
            }
        case .congestionAvoidance, .recovery:
            // CUBIC in MSS units: K = cbrt(wMax·(1−β)/C);
            // W(t) = C·(t−K)³ + wMax. Reno floor keeps the flat region
            // moving; per-ACK growth is capped at the ACKed byte count.
            let t = Double(nowMs() - _epochStartMs) / 1000.0
            let wMaxPkts = Double(_wMax) / CongestionControl.mss
            let k = cbrt(wMaxPkts * (1 - CongestionControl.beta) / CongestionControl.cubicC)
            let targetPkts = CongestionControl.cubicC * pow(t - k, 3) + wMaxPkts
            let target = Int64(targetPkts * CongestionControl.mss)

            let renoIncrement = max(Int64(1),
                Int64(CongestionControl.mss * Double(ackedBytes) / Double(max(1, _congestionWindow))))

            var growth = max(renoIncrement, target - _congestionWindow)
            growth = min(growth, Int64(ackedBytes))
            if growth > 0 {
                _congestionWindow += growth
            }

            if _state == .recovery {
                _state = .congestionAvoidance
            }
        }

        _congestionWindow = min(_congestionWindow, CongestionControl.maxWindow)
    }

    /// Congestion signal: multiplicative decrease, floor at `minWindow`.
    public func onLoss() {
        lock.lock(); defer { lock.unlock() }
        _wMax = _congestionWindow
        _congestionWindow = Int64(Double(_congestionWindow) * CongestionControl.beta)
        _congestionWindow = max(_congestionWindow, CongestionControl.minWindow)
        _ssthresh = _congestionWindow
        _state = .recovery
        _epochStartMs = nowMs()
    }

    /// Bytes handed to the network (reserve flight space).
    public func onSend(_ sentBytes: Int) {
        lock.lock(); defer { lock.unlock() }
        _bytesInFlight += Int64(sentBytes)
    }

    /// A tracked packet was pulled for retransmission (not ACKed): release
    /// its bytes WITHOUT window growth. The retransmitted copy re-reserves
    /// via `onSend`, so flight accounting never leaks.
    public func onRetransmitRemove(_ removedBytes: Int) {
        lock.lock(); defer { lock.unlock() }
        _bytesInFlight -= Int64(removedBytes)
        if _bytesInFlight < 0 { _bytesInFlight = 0 }
    }

    /// Atomic canSend + onSend.
    public func trySend(_ bytes: Int) -> Bool {
        lock.lock(); defer { lock.unlock() }
        if _bytesInFlight + Int64(bytes) <= _congestionWindow {
            _bytesInFlight += Int64(bytes)
            return true
        }
        return false
    }

    public func canSend(_ bytes: Int) -> Bool {
        lock.lock(); defer { lock.unlock() }
        return _bytesInFlight + Int64(bytes) <= _congestionWindow
    }

    public var availableWindow: Int64 {
        lock.lock(); defer { lock.unlock() }
        return max(0, _congestionWindow - _bytesInFlight)
    }

    public var congestionWindow: Int64 {
        lock.lock(); defer { lock.unlock() }
        return _congestionWindow
    }

    public var bytesInFlight: Int64 {
        lock.lock(); defer { lock.unlock() }
        return _bytesInFlight
    }

    public var state: State {
        lock.lock(); defer { lock.unlock() }
        return _state
    }

    public func reset() {
        lock.lock(); defer { lock.unlock() }
        _congestionWindow = CongestionControl.initialWindow
        _ssthresh = .max
        _bytesInFlight = 0
        _state = .slowStart
        _epochStartMs = nowMs()
    }
}
