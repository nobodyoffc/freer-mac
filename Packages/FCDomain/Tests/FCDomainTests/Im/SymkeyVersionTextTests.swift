import XCTest
@testable import FCDomain

/// How a version reaches a person: as the time it names, not as the
/// number it is. SYMKEY_IDENTITY_SPEC.md §6.
final class SymkeyVersionTextTests: XCTestCase {

    /// Fixed so the assertions are about the formatter and not about
    /// where the test is run.
    private let utc = TimeZone(identifier: "UTC")!

    /// 2026-09-19 18:01:59 UTC.
    private let version: Int64 = 1_789_840_919

    func testProseNamesTheDayTheKeyWasMinted() {
        XCTAssertEqual(
            SymkeyVersionText.inProse(version, timeZone: utc),
            "the symkey from 2026-09-19"
        )
    }

    /// Two keys minted on one day are told apart only by the clock, and a
    /// date alone would name both.
    func testProseAddsTheClockWhenAsked() {
        XCTAssertEqual(
            SymkeyVersionText.inProse(version, withTime: true, timeZone: utc),
            "the symkey from 2026-09-19 18:01"
        )
    }

    /// **Never the raw number.** `v1789813689` is the literal truth and
    /// tells a reader nothing they can act on.
    func testProseNeverShowsTheNumber() {
        XCTAssertFalse(
            SymkeyVersionText.inProse(version, timeZone: utc)
                .contains("\(version)")
        )
    }

    /// Year always, seconds always: a row from this year and one from
    /// last year must not read alike, and two keys minted seconds apart
    /// must not either.
    func testTableFormIsFixedWidthYearFirstWithSeconds() {
        XCTAssertEqual(SymkeyVersionText.inTable(version, timeZone: utc), "2026-09-19 18:01:59")
    }

    /// **The same text in every language.** A localised date read
    /// "21 9月" in Chinese and "Sep 21" in English; a member comparing
    /// keys with another must read the same digits.
    func testTheMintDateIgnoresTheLocale() {
        XCTAssertEqual(SymkeyVersionText.mintDate(version, timeZone: utc), "2026-09-19")
        XCTAssertNil(SymkeyVersionText.mintDate(KeyAsksStore.currentVersion))
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
