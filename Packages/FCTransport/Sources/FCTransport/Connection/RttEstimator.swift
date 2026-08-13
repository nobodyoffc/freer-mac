import Foundation

/// EWMA round-trip-time estimator. Port of
/// `FC-AJDK/.../fudp/congestion/RttEstimator.java` — same constants,
/// same integer arithmetic (including the `+2`/`+4` rounding terms),
/// so loss-detection thresholds computed from it match the Java peer's.
public final class RttEstimator: @unchecked Sendable {

    /// Initial estimate. 50 ms (not 333) so loss detection reacts
    /// quickly on LAN paths before the first sample lands.
    public static let initialRttMs: Int64 = 50
    private static let minRttMsFloor: Int64 = 1

    private let lock = NSLock()
    private var _smoothedRtt: Int64 = RttEstimator.initialRttMs
    private var _rttVariance: Int64 = RttEstimator.initialRttMs / 2
    private var _minRtt: Int64 = .max
    private var firstSample = true

    public init() {}

    /// Feed one RTT sample (milliseconds).
    public func update(latestRttMs: Int64) {
        var latest = latestRttMs
        if latest < RttEstimator.minRttMsFloor { latest = RttEstimator.minRttMsFloor }

        lock.lock(); defer { lock.unlock() }
        if latest < _minRtt { _minRtt = latest }

        if firstSample {
            _smoothedRtt = latest
            _rttVariance = latest / 2
            firstSample = false
            return
        }

        // smoothedRtt = 7/8 old + 1/8 new; rttVar = 3/4 old + 1/4 |diff|
        // (rounding terms match the Java integer math exactly)
        let rttDiff = abs(_smoothedRtt - latest)
        _rttVariance = (3 * _rttVariance + rttDiff + 2) / 4
        _smoothedRtt = (7 * _smoothedRtt + latest + 4) / 8
    }

    /// RTO = sRTT + 4·rttvar, clamped to [1 ms, 60 s].
    public var rtoMs: Int64 {
        lock.lock(); defer { lock.unlock() }
        return max(1, min(_smoothedRtt + 4 * _rttVariance, 60_000))
    }

    public var smoothedRttMs: Int64 {
        lock.lock(); defer { lock.unlock() }
        return _smoothedRtt
    }

    public var rttVarianceMs: Int64 {
        lock.lock(); defer { lock.unlock() }
        return _rttVariance
    }

    public var minRttMs: Int64 {
        lock.lock(); defer { lock.unlock() }
        return _minRtt == .max ? RttEstimator.initialRttMs : _minRtt
    }

    public func reset() {
        lock.lock(); defer { lock.unlock() }
        _smoothedRtt = RttEstimator.initialRttMs
        _rttVariance = RttEstimator.initialRttMs / 2
        _minRtt = .max
        firstSample = true
    }
}
