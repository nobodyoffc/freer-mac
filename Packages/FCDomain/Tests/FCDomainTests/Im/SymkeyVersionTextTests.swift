import XCTest
@testable import FCDomain

/// How a version reaches a person: as the time it names, not as the
/// number it is. SYMKEY_IDENTITY_SPEC.md §6.
final class SymkeyVersionTextTests: XCTestCase {

    /// Fixed so the assertions are about the formatter and not about
    /// where the test is run.
    private let utc = TimeZone(identifier: "UTC")!
    private let english = Locale(identifier: "en_US")

    /// 2026-09-19 18:01:59 UTC.
    private let version: Int64 = 1_789_840_919

    func testProseNamesTheDayTheKeyWasMinted() {
        XCTAssertEqual(
            SymkeyVersionText.inProse(version, locale: english, timeZone: utc),
            "the symkey from Sep 19, 2026"
        )
    }

    /// Two keys minted on one day are told apart only by the clock, and a
    /// date alone would name both.
    func testProseAddsTheClockWhenAsked() {
        let withTime = SymkeyVersionText.inProse(
            version, withTime: true, locale: english, timeZone: utc
        )
        XCTAssertTrue(withTime.contains("6:01"), withTime)
    }

    /// **Never the raw number.** `v1789813689` is the literal truth and
    /// tells a reader nothing they can act on.
    func testProseNeverShowsTheNumber() {
        XCTAssertFalse(
            SymkeyVersionText.inProse(version, locale: english, timeZone: utc)
                .contains("\(version)")
        )
    }

    func testTableFormIsFixedWidthAndDropsTheCurrentYear() {
        let inYear = SymkeyVersionText.inTable(
            version, now: Date(timeIntervalSince1970: TimeInterval(version)), timeZone: utc
        )
        XCTAssertEqual(inYear, "09-19 18:01:59")

        // Read a year later, the year comes back: a row that is not from
        // this year must not read as if it were.
        let laterOn = SymkeyVersionText.inTable(
            version, now: Date(timeIntervalSince1970: TimeInterval(version) + 400 * 86_400),
            timeZone: utc
        )
        XCTAssertEqual(laterOn, "2026-09-19 18:01:59")
    }

    /// Year-first, because a leading `26` reads as a day to half the
    /// world and this app has users in both halves.
    func testTableFormIsYearFirst() {
        let text = SymkeyVersionText.inTable(
            version, now: Date(timeIntervalSince1970: 0), timeZone: utc
        )
        XCTAssertTrue(text.hasPrefix("2026-"), text)
    }

    /// Pre-spec counters cannot be shown as times — a 1970 date on a key
    /// that is probably recent would be a lie — so they are marked.
    func testLegacyCountersAreMarkedNotDated() {
        for legacy: Int64 in [1, 3, 999_999_999] {
            XCTAssertTrue(SymkeyVersionText.isLegacy(legacy))
            XCTAssertEqual(SymkeyVersionText.inProse(legacy), "v\(legacy)")
            XCTAssertEqual(SymkeyVersionText.inTable(legacy), "v\(legacy)")
        }
        XCTAssertFalse(SymkeyVersionText.isLegacy(version))
        XCTAssertFalse(SymkeyVersionText.isLegacy(KeyAsksStore.currentVersion))
    }

    /// An ask for "whatever you hold" names no version, and saying so is
    /// better than showing a 1970 timestamp.
    func testTheCurrentKeyHasItsOwnWording() {
        XCTAssertEqual(
            SymkeyVersionText.inProse(KeyAsksStore.currentVersion), "the current symkey"
        )
        XCTAssertEqual(SymkeyVersionText.inTable(KeyAsksStore.currentVersion), "current")
    }

    func testTheRawValueIsWhatAClickCopies() {
        XCTAssertEqual(SymkeyVersionText.raw(version), "1789840919")
    }

    func testNeedsTimeOnlyWhenTwoKeysShareADay() {
        let sameDay = version + 600
        let nextDay = version + 86_400

        XCTAssertTrue(
            SymkeyVersionText.needsTime(version, among: [version, sameDay], timeZone: utc)
        )
        XCTAssertFalse(
            SymkeyVersionText.needsTime(version, among: [version, nextDay], timeZone: utc)
        )
        XCTAssertFalse(
            SymkeyVersionText.needsTime(version, among: [version], timeZone: utc),
            "a version does not clash with itself"
        )
        XCTAssertFalse(
            SymkeyVersionText.needsTime(3, among: [3, 4], timeZone: utc),
            "counters carry no day to clash on"
        )
    }
}
