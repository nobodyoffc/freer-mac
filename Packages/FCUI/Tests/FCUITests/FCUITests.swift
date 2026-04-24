import XCTest
@testable import FCUI

final class FCUITests: XCTestCase {
    func testVersionIsPresent() {
        XCTAssertFalse(FCUI.version.isEmpty)
    }
}
