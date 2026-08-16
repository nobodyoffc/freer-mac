import Foundation

/// One thing the app wants to tell you about itself.
public struct SystemMessage: Identifiable, Equatable, Sendable {

    public enum Level: String, Sendable, CaseIterable, Comparable {
        /// Something the user asked for did not happen.
        case error
        /// Something is degraded but the app carried on — a DOCK that
        /// is cooling down, a group whose home will not resolve.
        case warning
        /// Worth knowing, nothing wrong. Connections, syncs, arrivals.
        case info

        /// Most severe first, which is the order the pane lists them in
        /// when filtering by level.
        public static func < (lhs: Level, rhs: Level) -> Bool {
            let order: [Level] = [.error, .warning, .info]
            return order.firstIndex(of: lhs)! < order.firstIndex(of: rhs)!
        }
    }

    public let id: UUID
    public let at: Date
    public let level: Level
    /// Which part of the app is speaking, e.g. `"DOCK"`, `"FAPI"`.
    public let source: String
    /// One line. This is what the list shows.
    public let summary: String
    /// The unabridged version — an error description, a URL, a server
    /// message. Shown when the row is expanded, and included in a copy.
    public let detail: String?

    public init(
        id: UUID = UUID(),
        at: Date = Date(),
        level: Level,
        source: String,
        summary: String,
        detail: String? = nil
    ) {
        self.id = id
        self.at = at
        self.level = level
        self.source = source
        self.summary = summary
        self.detail = detail
    }
}

/// A ring buffer of what the app has been doing and failing to do.
///
/// **Why this exists.** Nearly everything under the chat pane fails
/// *quietly by design*: a DOCK that will not resolve is "no route", a
/// server that refuses is "try again later", a 404 from a lookup is "no
/// such record". Each of those is the right behaviour for the code —
/// none of them should throw a dialog at the user mid-send — and the
/// sum of them is an app that stops working and says nothing. Three
/// separate bugs in this area were invisible for exactly that reason:
/// the endpoint for service lookups was wrong and answered 404, a stale
/// client made every SID unresolvable, and a per-DOCK connection was
/// never attempted at all.
///
/// So the quiet paths write here instead of nowhere. It is a log, not a
/// notification system: nothing in the app blocks on it, and the user
/// goes looking when something seems wrong.
///
/// **Shared, deliberately.** The writers are value types built per use —
/// a `MessageCourier` is constructed for one drain and thrown away —
/// so threading a log through them all would put a parameter on every
/// initialiser to serve a page most users never open. Tests that care
/// about isolation make their own instance.
public final class SystemLog: @unchecked Sendable {

    /// The one the app writes to.
    public static let shared = SystemLog()

    /// Oldest entries are dropped past this. Generous enough to cover a
    /// long session, small enough to stay a memory rounding error.
    public static let capacity = 500

    private let lock = NSLock()
    private var entries: [SystemMessage] = []
    private var observers: [UUID: @Sendable (SystemMessage) -> Void] = [:]

    public init() {}

    // MARK: - reading

    /// Everything recorded, newest first.
    public var all: [SystemMessage] {
        lock.lock(); defer { lock.unlock() }
        return entries.reversed()
    }

    public var errorCount: Int {
        lock.lock(); defer { lock.unlock() }
        return entries.count { $0.level == .error }
    }

    // MARK: - writing

    public func record(_ message: SystemMessage) {
        lock.lock()
        entries.append(message)
        if entries.count > Self.capacity {
            entries.removeFirst(entries.count - Self.capacity)
        }
        let listeners = Array(observers.values)
        lock.unlock()
        // Outside the lock: an observer that reads the log back would
        // otherwise deadlock on it.
        for listener in listeners { listener(message) }
    }

    public func error(_ source: String, _ summary: String, detail: String? = nil) {
        record(.init(level: .error, source: source, summary: summary, detail: detail))
    }

    public func warning(_ source: String, _ summary: String, detail: String? = nil) {
        record(.init(level: .warning, source: source, summary: summary, detail: detail))
    }

    public func info(_ source: String, _ summary: String, detail: String? = nil) {
        record(.init(level: .info, source: source, summary: summary, detail: detail))
    }

    public func clear() {
        lock.lock(); entries.removeAll(); lock.unlock()
    }

    // MARK: - watching

    /// Call `handler` on every new entry. Returns a token to stop with.
    @discardableResult
    public func observe(_ handler: @escaping @Sendable (SystemMessage) -> Void) -> UUID {
        let token = UUID()
        lock.lock(); observers[token] = handler; lock.unlock()
        return token
    }

    public func stopObserving(_ token: UUID) {
        lock.lock(); observers[token] = nil; lock.unlock()
    }
}

extension String {
    /// Shorten an id for a log line, keeping both ends.
    ///
    /// Internal, and named differently from FCUI's `elidingMiddle` on
    /// purpose: two modules declaring the same member on `String` would
    /// be ambiguous wherever both are imported. The trailing characters
    /// are the ones a reader checks an id against, so they are never the
    /// half that gets dropped.
    func middleElided(head: Int = 8, tail: Int = 8) -> String {
        guard count > head + tail + 1 else { return self }
        return "\(prefix(head))…\(suffix(tail))"
    }
}

/// Well-known ``SystemMessage/source`` values, so the pane can filter on
/// something more stable than a free-form string.
public enum SystemSource {
    public static let fapi = "FAPI"
    public static let dock = "DOCK"
    public static let directory = "Directory"
    public static let messages = "Messages"
    public static let groups = "Groups"
}
