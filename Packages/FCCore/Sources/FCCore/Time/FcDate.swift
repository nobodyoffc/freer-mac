import Foundation

/// Freeverse Date (FVEP4) — a human-readable time built out of block
/// height rather than out of the Gregorian calendar.
///
/// `Y.D.H.M`, where a year is 400 days, a day is 24 hours, an hour is 60
/// minutes, and a minute is exactly one block. Height 0 is the Freecash
/// genesis block.
///
/// **On the epoch.** Android carries this constant twice and the two
/// copies disagree: `FcDate.GENESIS_UNIX_SECONDS` is `1577836802`
/// (2020-01-01 00:00:02 UTC, the real genesis timestamp) while
/// `TimeConvertActivity` hardcodes `1577836800000` ms. The two-second
/// gap makes its own height↔time conversions inconsistent with its own
/// `FcDate` near a block boundary. We keep the single value the FcDate
/// class defines and use it everywhere, so a height converted here and
/// converted back lands where it started.
public struct FcDate: Equatable, Hashable, Sendable {

    public static let daysPerYear = 400
    public static let hoursPerDay = 24
    public static let minutesPerHour = 60

    /// One block per minute, by target block interval.
    public static let blocksPerHour = minutesPerHour
    public static let blocksPerDay = hoursPerDay * blocksPerHour
    public static let blocksPerYear = daysPerYear * blocksPerDay

    /// Genesis block time, Unix seconds. See the note above.
    public static let genesisUnixSeconds: Int64 = 1_577_836_802

    public let year: Int64
    public let day: Int64
    public let hour: Int64
    public let minute: Int64

    public enum Failure: Error, CustomStringConvertible {
        case negativeHeight(Int64)
        case malformed(String)

        public var description: String {
            switch self {
            case let .negativeHeight(height):
                return "FcDate: block height \(height) is before genesis"
            case let .malformed(text):
                return "FcDate: expected Y.D.H.M, got '\(text)'"
            }
        }
    }

    public init(year: Int64, day: Int64, hour: Int64, minute: Int64) {
        self.year = year
        self.day = day
        self.hour = hour
        self.minute = minute
    }

    /// Decompose a block height into `Y.D.H.M`.
    public init(height: Int64) throws {
        guard height >= 0 else { throw Failure.negativeHeight(height) }
        let perYear = Int64(FcDate.blocksPerYear)
        let perDay = Int64(FcDate.blocksPerDay)
        let perHour = Int64(FcDate.blocksPerHour)

        year = height / perYear
        var rest = height % perYear
        day = rest / perDay
        rest %= perDay
        hour = rest / perHour
        minute = rest % perHour
    }

    /// Parse a `Y.D.H.M` string. Every component must be present and
    /// numeric — a partial date like `3.120` is rejected rather than
    /// zero-filled, because guessing which components were omitted
    /// would silently move the result by up to a year.
    public init(text: String) throws {
        let parts = text.trimmingCharacters(in: .whitespacesAndNewlines).split(separator: ".")
        guard parts.count == 4 else { throw Failure.malformed(text) }
        let numbers = parts.compactMap { Int64($0) }
        guard numbers.count == 4 else { throw Failure.malformed(text) }
        self.init(year: numbers[0], day: numbers[1], hour: numbers[2], minute: numbers[3])
    }

    /// Recompose to a block height. Out-of-range components (a minute
    /// of 90, say) roll over, matching Android.
    public var height: Int64 {
        year * Int64(FcDate.blocksPerYear)
            + day * Int64(FcDate.blocksPerDay)
            + hour * Int64(FcDate.blocksPerHour)
            + minute
    }

    /// Approximate wall-clock time: genesis plus one minute per block.
    /// Real block intervals vary, so this drifts from the chain's
    /// actual timestamps.
    public var approximateUnixSeconds: Int64 {
        FcDate.genesisUnixSeconds + height * 60
    }

    /// The block height a wall-clock instant falls in, by the same
    /// approximation. Instants before genesis give a negative height,
    /// which ``init(height:)`` will then reject.
    public static func height(fromUnixSeconds seconds: Int64) -> Int64 {
        let delta = seconds - genesisUnixSeconds
        // Truncating division rounds toward zero, which for negative
        // deltas would round *up* into a false height of 0.
        return delta >= 0 ? delta / 60 : -((-delta + 59) / 60)
    }

    public var text: String { "\(year).\(day).\(hour).\(minute)" }
}

extension FcDate: CustomStringConvertible {
    public var description: String { text }
}
