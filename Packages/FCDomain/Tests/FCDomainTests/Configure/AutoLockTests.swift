import XCTest
@testable import FCDomain

/// The inactivity clock: what arms it, what counts as activity, and the
/// one case that decides whether the setting is a security control or a
/// convenience — activity that arrives after the deadline.
final class AutoLockTests: XCTestCase {

    private let start = ContinuousClock.now

    private func at(_ seconds: Int) -> ContinuousClock.Instant {
        start.advanced(by: .seconds(seconds))
    }

    // MARK: - arming

    /// A blank Settings box writes nil, and nil means never.
    func testNoTimeoutNeverExpires() {
        let lock = AutoLock(seconds: nil, now: start)
        XCTAssertFalse(lock.isArmed)
        XCTAssertNil(lock.remaining(at: at(86_400)))
        XCTAssertFalse(lock.hasExpired(at: at(86_400)))
    }

    /// Zero and negative are off too. A row hand-edited to 0 read as
    /// "lock immediately" would make the vault unopenable.
    func testZeroAndNegativeAreOff() {
        for seconds in [0, -1, -600] {
            let lock = AutoLock(seconds: seconds, now: start)
            XCTAssertFalse(lock.isArmed, "\(seconds) should be off")
            XCTAssertFalse(lock.hasExpired(at: at(86_400)))
        }
    }

    // MARK: - counting down

    func testItExpiresExactlyAtTheTimeout() {
        let lock = AutoLock(seconds: 600, now: start)
        XCTAssertEqual(lock.remaining(at: at(0)), .seconds(600))
        XCTAssertEqual(lock.remaining(at: at(599)), .seconds(1))
        XCTAssertFalse(lock.hasExpired(at: at(599)))
        XCTAssertTrue(lock.hasExpired(at: at(600)))
    }

    /// What is left never goes negative — a caller sleeping on the value
    /// must not be asked to sleep backwards.
    func testAnOverdueLockHasNothingLeft() {
        let lock = AutoLock(seconds: 60, now: start)
        XCTAssertEqual(lock.remaining(at: at(3_600)), .zero)
    }

    func testActivityRestartsTheCountdown() {
        var lock = AutoLock(seconds: 600, now: start)
        lock.noteActivity(at: at(300))
        XCTAssertFalse(lock.hasExpired(at: at(800)), "300s idle, not 800")
        XCTAssertEqual(lock.remaining(at: at(800)), .seconds(100))
        XCTAssertTrue(lock.hasExpired(at: at(900)))
    }

    // MARK: - the rule that makes it a lock

    /// **The case the whole type is for.** The deadline can pass while
    /// nothing is running to notice — the machine slept, the app was
    /// stuck, the timer woke a moment late — and the first event
    /// afterwards is as likely to be whoever found the unattended Mac as
    /// its owner. Once the window has elapsed the lock is owed.
    func testActivityAfterTheDeadlineDoesNotBuyItBack() {
        var lock = AutoLock(seconds: 600, now: start)

        // Eight hours asleep, then the mouse moves before anything has
        // had a chance to check.
        lock.noteActivity(at: at(28_800))

        XCTAssertTrue(lock.hasExpired(at: at(28_800)), "still overdue")
        XCTAssertTrue(lock.hasExpired(at: at(28_801)), "and stays overdue")
        XCTAssertEqual(lock.remaining(at: at(28_800)), .zero)
    }

    /// Unlocking again is the one thing that does re-arm it.
    func testReconfiguringReArmsTheClock() {
        var lock = AutoLock(seconds: 600, now: start)
        XCTAssertTrue(lock.hasExpired(at: at(1_200)))

        lock.setTimeout(seconds: 600, now: at(1_200))
        XCTAssertFalse(lock.hasExpired(at: at(1_200)))
        XCTAssertTrue(lock.hasExpired(at: at(1_800)))
    }

    /// Typing a timeout into Settings is the user being present, so a
    /// shortened one does not lock the vault out from under them.
    func testShorteningTheTimeoutDoesNotLockImmediately() {
        var lock = AutoLock(seconds: 3_600, now: start)

        // Fifty minutes of reading, then "actually, one minute".
        lock.setTimeout(seconds: 60, now: at(3_000))

        XCTAssertFalse(lock.hasExpired(at: at(3_000)))
        XCTAssertEqual(lock.remaining(at: at(3_000)), .seconds(60))
        XCTAssertTrue(lock.hasExpired(at: at(3_060)))
    }

    /// Turning it off releases a vault that was already overdue, rather
    /// than leaving it expired forever.
    func testTurningItOffStopsTheClock() {
        var lock = AutoLock(seconds: 60, now: start)
        XCTAssertTrue(lock.hasExpired(at: at(120)))

        lock.setTimeout(seconds: nil, now: at(120))
        XCTAssertFalse(lock.isArmed)
        XCTAssertFalse(lock.hasExpired(at: at(86_400)))
    }
}
