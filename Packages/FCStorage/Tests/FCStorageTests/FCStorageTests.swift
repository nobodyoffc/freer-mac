import XCTest
@testable import FCStorage

final class FCStorageTests: XCTestCase {
    func testVersionIsPresent() {
        XCTAssertFalse(FCStorage.version.isEmpty)
    }
}
