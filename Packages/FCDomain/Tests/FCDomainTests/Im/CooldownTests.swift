import XCTest
@testable import FCDomain

final class CooldownTests: XCTestCase {

    func testOneGoPerWindow() {
        let t0 = Date(timeIntervalSince1970: 1_000)
        let cooldown = Cooldown(interval: 30)

        XCTAssertTrue(cooldown.claim(now: t0))
        XCTAssertFalse(cooldown.claim(now: t0.addingTimeInterval(29)))
        XCTAssertTrue(cooldown.claim(now: t0.addingTimeInterval(30)))
        // A refused claim does not restart the window.
        XCTAssertFalse(cooldown.claim(now: t0.addingTimeInterval(59)))
        XCTAssertTrue(cooldown.claim(now: t0.addingTimeInterval(60)))
    }
}
