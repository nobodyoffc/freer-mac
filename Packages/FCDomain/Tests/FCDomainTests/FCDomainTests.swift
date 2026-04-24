import XCTest
@testable import FCDomain

final class FCDomainTests: XCTestCase {
    func testVersionIsPresent() {
        XCTAssertFalse(FCDomain.version.isEmpty)
    }
}
