import XCTest
@testable import FCTransport

final class FCTransportTests: XCTestCase {
    func testVersionIsPresent() {
        XCTAssertFalse(FCTransport.version.isEmpty)
    }
}
