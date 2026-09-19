import Foundation

/// The inactivity clock behind the Auto-lock setting: how long the vault
/// may sit untouched before it is closed for the user.
///
/// **It is a type rather than two properties on the app shell** because
/// the interesting part is not the countdown, it is what counts as
/// activity and what does not. A security control whose rules live
/// inside a timer callback in a SwiftUI app is a control nobody can
/// test, and ``Preferences/autoLockSeconds`` spent a long time being
/// stored, reloaded into the form, and enforced by nothing at all.
///
/// **The clock is ``ContinuousClock``, deliberately.** Wall time can be
/// moved — by the user, by NTP, by a timezone-confused calendar app —
/// and a lock that can be postponed by putting the clock back is not a
/// lock. A continuous clock also keeps counting while the machine is
/// asleep, which is the answer this needs: a Mac closed for eight hours
/// has been unattended for eight hours, whatever the process was doing.
public struct AutoLock: Equatable, Sendable {

    /// How long the vault may be idle, or nil when auto-lock is off.
    public private(set) var timeout: Duration?

    /// When the user was last seen. Meaningless while ``timeout`` is nil.
    private var lastActivity: ContinuousClock.Instant

    public init(seconds: Int? = nil, now: ContinuousClock.Instant = .now) {
        self.timeout = Self.timeout(seconds: seconds)
        self.lastActivity = now
    }

    /// The stored setting as a duration. Nil, zero and anything negative
    /// all mean off — the Settings field writes nil for a blank box, and
    /// a row hand-edited to `0` must not be read as "lock immediately",
    /// which would make the vault unopenable.
    public static func timeout(seconds: Int?) -> Duration? {
        guard let seconds, seconds > 0 else { return nil }
        return .seconds(seconds)
    }

    /// Whether auto-lock is configured at all.
    public var isArmed: Bool { timeout != nil }

    /// Point the clock at a new setting, and treat the change itself as
    /// activity.
    ///
    /// Somebody who has just typed a timeout into Settings is at the
    /// keyboard by definition, and a shortened one — ten minutes down to
    /// one, after nine minutes of reading — would otherwise lock the
    /// vault out from under the person who set it.
    public mutating func setTimeout(seconds: Int?, now: ContinuousClock.Instant = .now) {
        timeout = Self.timeout(seconds: seconds)
        lastActivity = now
    }

    /// Note that the user is here.
    ///
    /// **Activity after the deadline is ignored**, and that is the rule
    /// the whole type exists for. The deadline can pass while nothing is
    /// running to notice — the machine was asleep, the app was frozen
    /// behind a beachball, the wake-up landed a moment late — and the
    /// first event afterwards is exactly as likely to be whoever found
    /// the unattended Mac as it is to be its owner. Once the idle window
    /// has elapsed the lock is owed, and no amount of typing may buy it
    /// back; only unlocking again re-arms the clock.
    public mutating func noteActivity(at now: ContinuousClock.Instant = .now) {
        guard !hasExpired(at: now) else { return }
        lastActivity = now
    }

    /// Whether the vault has now been idle for at least the timeout.
    /// Always false when auto-lock is off.
    public func hasExpired(at now: ContinuousClock.Instant = .now) -> Bool {
        guard let remaining = remaining(at: now) else { return false }
        return remaining <= .zero
    }

    /// How much of the idle window is left, or nil when auto-lock is
    /// off. Never negative: an overdue lock has zero left, which is what
    /// a caller sleeping on this value needs to see.
    public func remaining(at now: ContinuousClock.Instant = .now) -> Duration? {
        guard let timeout else { return nil }
        let idle = lastActivity.duration(to: now)
        let left = timeout - idle
        return left > .zero ? left : .zero
    }
}
