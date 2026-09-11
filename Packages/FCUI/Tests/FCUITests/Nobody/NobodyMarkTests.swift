import XCTest
import SwiftUI
@testable import FCUI

/// The badge has to survive the circular clip every avatar gets, at any size.
final class NobodyMarkTests: XCTestCase {

    func testBadgeSitsInsideTheAvatarCircle() {
        for size in [16, 22, 40, 56, 150] as [CGFloat] {
            let center = NobodyMark.badgeCenter(size: size)
            let radius = size * NobodyMark.badgeRadiusRatio
            let fromMiddle = hypot(center.x - size / 2, center.y - size / 2)
            XCTAssertLessThanOrEqual(fromMiddle + radius, size / 2 + 0.001, "size \(size)")
            XCTAssertGreaterThan(center.x, size / 2, "bottom-right, size \(size)")
            XCTAssertGreaterThan(center.y, size / 2, "bottom-right, size \(size)")
        }
    }

    func testSkullFitsItsRect() {
        let rect = CGRect(x: 10, y: 20, width: 48, height: 48)
        let bounds = NobodySkullShape().path(in: rect).boundingRect
        XCTAssertTrue(rect.insetBy(dx: -0.01, dy: -0.01).contains(bounds))
    }
}
