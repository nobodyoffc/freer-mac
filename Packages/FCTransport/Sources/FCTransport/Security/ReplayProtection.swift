import Foundation

/// FUDP replay protection: per-connection sliding-window bitmap with
/// session-epoch restart detection. Mirrors
/// `FC-JDK/src/main/java/fudp/security/ReplayProtection.java`.
///
/// Windows are keyed by `connectionId` (not peer FID) because each
/// connection has its own `packetNumber` sequence starting at 0; a peer
/// with two simultaneous connections needs two independent windows.
///
/// Session-epoch handling: each peer generates a random 8-byte epoch at
/// startup. If the epoch on a received packet differs from the one we've
/// seen on this connection, the peer has restarted; we atomically reset
/// the window so old packet numbers can be reused without false-replay.
///
/// The class uses an internal `NSLock`. The Linux receive loop is
/// single-threaded by convention, but we lock anyway so this works in
/// any threading model the Mac client picks.
public final class ReplayProtection {

    /// Bitmap width: large enough that out-of-order delivery on a fast
    /// link doesn't drop packets falsely. 65 536 is what the Linux side
    /// uses; smaller values caused 85%+ false-drops on multi-megabyte
    /// transfers under multi-threaded executors.
    public static let windowSize: Int = 65_536

    /// Default LRU cap on the number of tracked connections. Each window
    /// holds an 8 KB bitmap plus ~32 bytes of state, so 4 096 windows ≈
    /// 32 MB of RAM.
    public static let defaultMaxWindows: Int = 4_096

    /// 60 s timestamp tolerance. Tight enough to defeat captured-packet
    /// replays at the 8-minute scale of the pre-repair 500 s window;
    /// loose enough for NTP-synced peers and mobile clients with
    /// occasional clock drift.
    public static let defaultTimestampToleranceMs: Int64 = 60_000
    public static let minTimestampToleranceMs: Int64 = 1_000
    public static let maxTimestampToleranceMs: Int64 = 3_600_000

    public enum CheckResult: Equatable, Sendable {
        case ok
        case duplicate
        case invalidTimestamp
        case peerRestart
    }

    public enum Failure: Error, CustomStringConvertible {
        case invalidMaxWindows(Int)
        case invalidToleranceMs(Int64)

        public var description: String {
            switch self {
            case .invalidMaxWindows(let v):
                return "ReplayProtection: maxWindows must be > 0, got \(v)"
            case .invalidToleranceMs(let v):
                return "ReplayProtection: toleranceMs must be in [\(ReplayProtection.minTimestampToleranceMs), \(ReplayProtection.maxTimestampToleranceMs)] ms, got \(v)"
            }
        }
    }

    public let maxWindows: Int
    public let timestampToleranceMs: Int64

    private let lock = NSLock()
    private let lru: LruCache<Int64, PacketWindow>

    public init(
        maxWindows: Int = ReplayProtection.defaultMaxWindows,
        timestampToleranceMs: Int64 = ReplayProtection.defaultTimestampToleranceMs
    ) throws {
        guard maxWindows > 0 else { throw Failure.invalidMaxWindows(maxWindows) }
        guard (Self.minTimestampToleranceMs...Self.maxTimestampToleranceMs).contains(timestampToleranceMs) else {
            throw Failure.invalidToleranceMs(timestampToleranceMs)
        }
        self.maxWindows = maxWindows
        self.timestampToleranceMs = timestampToleranceMs
        self.lru = LruCache(capacity: maxWindows)
    }

    /// Test/monitoring counters. Reads acquire the lock briefly.
    public var evictionCount: Int64 {
        lock.lock(); defer { lock.unlock() }
        return Int64(lru.evictionCount)
    }
    public var windowCount: Int {
        lock.lock(); defer { lock.unlock() }
        return lru.count
    }

    /// Check that `(connectionId, packetNumber)` has not been seen, that
    /// the packet's `timestamp` is within tolerance of `nowMs` (defaults
    /// to the wall clock), and that `sessionEpoch` matches what we saw
    /// last on this connection. Returns the appropriate `CheckResult`
    /// and updates internal state in place.
    public func checkAndRecord(
        connectionId: Int64,
        packetNumber: Int64,
        timestamp: Int64,
        sessionEpoch: Int64,
        nowMs: Int64? = nil
    ) -> CheckResult {
        let now = nowMs ?? ReplayProtection.currentTimeMillis()
        if abs(timestamp - now) > timestampToleranceMs {
            return .invalidTimestamp
        }

        lock.lock()
        defer { lock.unlock() }

        let window = getOrCreateWindow(connectionId: connectionId)
        if window.detectAndHandleSessionEpochChange(newEpoch: sessionEpoch) {
            _ = window.checkAndRecord(packetNumber: packetNumber)
            return .peerRestart
        }
        return window.checkAndRecord(packetNumber: packetNumber) ? .ok : .duplicate
    }

    public func removeConnection(_ connectionId: Int64) {
        lock.lock(); defer { lock.unlock() }
        _ = lru.remove(connectionId)
    }

    public func clear() {
        lock.lock(); defer { lock.unlock() }
        lru.clear()
    }

    public static func currentTimeMillis() -> Int64 {
        Int64(Date().timeIntervalSince1970 * 1000.0)
    }

    // MARK: - private

    private func getOrCreateWindow(connectionId: Int64) -> PacketWindow {
        if let existing = lru.get(connectionId) {
            return existing
        }
        let window = PacketWindow()
        _ = lru.put(connectionId, window)
        return window
    }
}

// MARK: - PacketWindow

/// Per-connection sliding-window state. Caller (`ReplayProtection`) owns
/// the lock; methods here are not internally synchronised.
private final class PacketWindow {

    private var highestPacketNumber: Int64 = -1
    private var sessionEpoch: Int64 = 0
    private var previousSessionEpoch: Int64 = 0
    private var bitmap: [UInt64] = Array(
        repeating: 0,
        count: ReplayProtection.windowSize / 64
    )

    /// Updates the recorded session epoch and resets the bitmap if the
    /// peer has restarted. Returns `true` iff a restart was detected.
    func detectAndHandleSessionEpochChange(newEpoch: Int64) -> Bool {
        if sessionEpoch == 0 {
            sessionEpoch = newEpoch
            return false
        }
        if newEpoch != sessionEpoch {
            previousSessionEpoch = sessionEpoch
            sessionEpoch = newEpoch
            reset()
            return true
        }
        return false
    }

    func reset() {
        highestPacketNumber = -1
        for i in 0..<bitmap.count { bitmap[i] = 0 }
    }

    /// `true` iff the packet was new (not a replay) and was recorded.
    func checkAndRecord(packetNumber: Int64) -> Bool {
        if packetNumber < 0 { return false }

        // First packet on this window.
        if highestPacketNumber < 0 {
            highestPacketNumber = packetNumber
            setBit(0)
            return true
        }

        // Older than the bottom of the window.
        if packetNumber <= highestPacketNumber - Int64(ReplayProtection.windowSize) {
            return false
        }

        // Within the current window.
        if packetNumber <= highestPacketNumber {
            let offset = Int(highestPacketNumber - packetNumber)
            if testBit(offset) {
                return false  // replay
            }
            setBit(offset)
            return true
        }

        // New highest — slide the window. bit[i] (i ≥ shift) takes the
        // value of bit[i - shift]; bit[0..shift) is cleared.
        let shift = packetNumber - highestPacketNumber
        if shift >= Int64(ReplayProtection.windowSize) {
            for i in 0..<bitmap.count { bitmap[i] = 0 }
        } else {
            let s = Int(shift)
            // Iterate top-down so the read of bit[i-s] still reflects
            // the pre-shift state.
            for i in stride(from: ReplayProtection.windowSize - 1, through: s, by: -1) {
                if testBit(i - s) {
                    setBit(i)
                } else {
                    clearBit(i)
                }
            }
            for i in 0..<s { clearBit(i) }
        }

        highestPacketNumber = packetNumber
        setBit(0)
        return true
    }

    // MARK: - bitmap primitives

    @inline(__always)
    private func testBit(_ index: Int) -> Bool {
        let word = index >> 6
        let mask = UInt64(1) << UInt64(index & 63)
        return (bitmap[word] & mask) != 0
    }

    @inline(__always)
    private func setBit(_ index: Int) {
        let word = index >> 6
        let mask = UInt64(1) << UInt64(index & 63)
        bitmap[word] |= mask
    }

    @inline(__always)
    private func clearBit(_ index: Int) {
        let word = index >> 6
        let mask = UInt64(1) << UInt64(index & 63)
        bitmap[word] &= ~mask
    }
}

// MARK: - LruCache

/// Doubly-linked-list + dictionary LRU cache. Capacity is a hard cap;
/// inserting past capacity evicts the least-recently-used entry. `get`
/// promotes the entry to most-recently-used.
final class LruCache<Key: Hashable, Value> {

    final class Node {
        let key: Key
        var value: Value
        var prev: Node?
        var next: Node?

        init(key: Key, value: Value) {
            self.key = key
            self.value = value
        }
    }

    let capacity: Int
    private(set) var evictionCount: Int = 0

    private var dict: [Key: Node] = [:]
    private var head: Node?  // least recently used
    private var tail: Node?  // most recently used

    init(capacity: Int) {
        precondition(capacity > 0, "LruCache capacity must be positive")
        self.capacity = capacity
    }

    var count: Int { dict.count }

    func get(_ key: Key) -> Value? {
        guard let node = dict[key] else { return nil }
        moveToTail(node)
        return node.value
    }

    @discardableResult
    func put(_ key: Key, _ value: Value) -> Value? {
        if let existing = dict[key] {
            existing.value = value
            moveToTail(existing)
            return nil
        }
        let node = Node(key: key, value: value)
        dict[key] = node
        appendToTail(node)
        if dict.count > capacity, let old = head {
            removeNode(old)
            dict.removeValue(forKey: old.key)
            evictionCount += 1
            return old.value
        }
        return nil
    }

    @discardableResult
    func remove(_ key: Key) -> Value? {
        guard let node = dict.removeValue(forKey: key) else { return nil }
        removeNode(node)
        return node.value
    }

    func clear() {
        dict.removeAll()
        head = nil
        tail = nil
    }

    // MARK: - linked-list ops

    private func appendToTail(_ node: Node) {
        node.prev = tail
        node.next = nil
        tail?.next = node
        tail = node
        if head == nil { head = node }
    }

    private func removeNode(_ node: Node) {
        if let prev = node.prev { prev.next = node.next } else { head = node.next }
        if let next = node.next { next.prev = node.prev } else { tail = node.prev }
        node.prev = nil
        node.next = nil
    }

    private func moveToTail(_ node: Node) {
        if node === tail { return }
        removeNode(node)
        appendToTail(node)
    }
}
