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

    /// `the symkey from 19 Sep`, for a sealed row, a banner or a toast.
    ///
    /// `withTime` adds the clock, and the caller decides: two keys minted
    /// on one day are told apart only by it, and a date alone would then
    /// name both. ``needsTime(_:among:timeZone:)`` answers that.
    public static func inProse(
        _ version: Int64,
        withTime: Bool = false,
        locale: Locale = .autoupdatingCurrent,
        timeZone: TimeZone = .current
    ) -> String {
        if version == current { return "the current symkey" }
        guard SymkeyStore.isTimestamp(version) else { return legacy(version) }

        let formatter = DateFormatter()
        formatter.locale = locale
        formatter.timeZone = timeZone
        formatter.dateStyle = .medium
        formatter.timeStyle = withTime ? .short : .none
        return "the symkey from " + formatter.string(from: date(of: version))
    }

    // MARK: - tables

    /// `09-19 18:01:59`, or `2025-12-04 09:12:40` outside the current
    /// year — fixed-width, year-first, and meant to be set in monospaced
    /// digits.
    ///
    /// Year-first rather than `19-09-26`, because a leading `26` reads as
    /// a day to half the world and this app has users in both halves. The
    /// current year is dropped because every row in a list will share it,
    /// and seconds are kept because two keys of one entity are minted
    /// seconds apart in exactly the case where telling them apart matters.
    public static func inTable(
        _ version: Int64,
        now: Date = Date(),
        timeZone: TimeZone = .current
    ) -> String {
        if version == current { return "current" }
        guard SymkeyStore.isTimestamp(version) else { return legacy(version) }

        let minted = date(of: version)
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = timeZone
        let sameYear = calendar.component(.year, from: minted)
            == calendar.component(.year, from: now)

        let formatter = DateFormatter()
        // Fixed, not localised: the point of this form is that two rows
        // line up and can be compared character by character.
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = timeZone
        formatter.dateFormat = sameYear ? "MM-dd HH:mm:ss" : "yyyy-MM-dd HH:mm:ss"
        return formatter.string(from: minted)
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
