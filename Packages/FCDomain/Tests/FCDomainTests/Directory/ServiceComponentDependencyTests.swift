import XCTest
@testable import FCDomain

final class ServiceComponentDependencyTests: XCTestCase {
    func testRoadPullsInMapJustBeforeIt() {
        XCTAssertEqual(
            ServiceName.withDependencies([ServiceName.dock, ServiceName.road]),
            [ServiceName.dock, ServiceName.map, ServiceName.road]
        )
    }

    func testMapAlreadyListedStaysWhereItIs() {
        let list = [ServiceName.road, ServiceName.disk, ServiceName.map]
        XCTAssertEqual(ServiceName.withDependencies(list), list)
    }

    func testMapOnItsOwnIsLeftAlone() {
        XCTAssertEqual(ServiceName.withDependencies([ServiceName.map]), [ServiceName.map])
    }
}
