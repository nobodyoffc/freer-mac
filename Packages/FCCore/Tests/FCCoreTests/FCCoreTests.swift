import XCTest
@testable import FCCore

final class FCCoreTests: XCTestCase {
    func testVersionIsPresent() {
        XCTAssertFalse(FCCore.version.isEmpty)
    }
}
