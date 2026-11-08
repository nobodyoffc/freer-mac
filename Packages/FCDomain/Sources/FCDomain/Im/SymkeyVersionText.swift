import Foundation

/// How a symkey version is shown to a person.
///
/// **A version is a time, so prose shows the time and never the number.**
/// It is seconds since the epoch (``SymkeyStore/nextVersion(for:now:)``),
/// which makes `v1789813689` both the literal truth and useless: what a
/// reader needs from an unopenable row is *which era of the conversation
/// they are missing*, because that is what tells them who to ask.
///
/// The number earns its width only where two of them are compared — a key
/// list, a distribution ledger row, an outstanding ask — and there it is
/// rendered fixed-width and year-first so a column can be diffed by eye.
/// See SYMKEY_IDENTITY_SPEC.md §6.
public enum SymkeyVersionText {

    /// The version a request uses for "whatever you hold now".
    static let current = KeyAsksStore.currentVersion

    // MARK: - prose

    /// `the symkey from 2026-09-19`, for a sealed row, a banner or a toast.
    ///
    /// `withTime` adds the clock, and the caller decides: two keys minted
    /// on one day are told apart only by it, and a date alone would then
    /// name both. ``needsTime(_:among:timeZone:)`` answers that.
    public static func inProse(
        _ version: Int64,
        withTime: Bool = false,
        timeZone: TimeZone = .current
    ) -> String {
        if version == current { return "the current symkey" }
        guard let minted = mintDate(version, withTime: withTime, timeZone: timeZone)
        else { return legacy(version) }
        return "the symkey from " + minted
    }

    /// `2026-09-19`, or `2026-09-19 18:01` with the clock: just the mint
    /// time, for a caller that writes its own sentence around it. Nil for
    /// the current-key sentinel and for a pre-spec counter, neither of
    /// which is a time.
    ///
    /// **One numeric form in every language, year always included.** A
    /// localised date put the month name in one language's order and the
    /// day in another's ("21 9月"), and dropping the year made a key from
    /// last September read as this one. ISO order is the same on the Mac
    /// and on Android, in Chinese and in English, so two members comparing
    /// keys read the same text.
    public static func mintDate(
        _ version: Int64,
        withTime: Bool = false,
        timeZone: TimeZone = .current
    ) -> String? {
        guard version != current, SymkeyStore.isTimestamp(version) else { return nil }
        return format(version, withTime ? "yyyy-MM-dd HH:mm" : "yyyy-MM-dd", timeZone)
    }

    // MARK: - tables

    /// `2026-09-19 18:01:59` — fixed-width, year-first, and meant to be
    /// set in monospaced digits.
    ///
    /// Seconds are kept because two keys of one entity are minted seconds
    /// apart in exactly the case where telling them apart matters.
    public static func inTable(
        _ version: Int64,
        timeZone: TimeZone = .current
    ) -> String {
        if version == current { return "current" }
        guard SymkeyStore.isTimestamp(version) else { return legacy(version) }
        return format(version, "yyyy-MM-dd HH:mm:ss", timeZone)
    }

    private static func format(_ version: Int64, _ pattern: String, _ timeZone: TimeZone) -> String {
        let formatter = DateFormatter()
        // Fixed, not localised: the same digits in every language.
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.calendar = Calendar(identifier: .gregorian)
        formatter.timeZone = timeZone
        formatter.dateFormat = pattern
        return formatter.string(from: date(of: version))
    }

    /// What a click copies: the version itself, which is what goes into a
    /// log, a request, or a message to another member.
    public static func raw(_ version: Int64) -> String { String(version) }

    // MARK: - deciding

    /// Whether `version` needs its clock shown to be distinguishable —
    /// true when another of `versions` was minted on the same day.
    public static func needsTime(
        _ version: Int64, among versions: [Int64], timeZone: TimeZone = .current
    ) -> Bool {
        guard SymkeyStore.isTimestamp(version) else { return false }
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = timeZone
        let day = calendar.startOfDay(for: date(of: version))
        return versions.contains { other in
            other != version
                && SymkeyStore.isTimestamp(other)
                && calendar.startOfDay(for: date(of: other)) == day
        }
    }

    // MARK: - helpers

    /// A pre-spec counter, marked as one. It cannot be shown as a time,
    /// and pretending otherwise would put a 1970 date on a key that is
    /// probably recent.
    private static func legacy(_ version: Int64) -> String { "v\(version)" }

    public static func isLegacy(_ version: Int64) -> Bool {
        version != current && !SymkeyStore.isTimestamp(version)
    }

    private static func date(of version: Int64) -> Date {
        Date(timeIntervalSince1970: TimeInterval(version))
    }
}
