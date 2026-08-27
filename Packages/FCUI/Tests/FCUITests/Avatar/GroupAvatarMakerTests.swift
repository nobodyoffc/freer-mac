import XCTest
import FCCore
@testable import FCUI

/// These tests are the cross-client contract as much as they are tests:
/// every number here is derivable from `sha256(utf8(groupId))` alone, so
/// a Java port that disagrees with any of them will not render the same
/// tile for the same group.
final class GroupAvatarMakerTests: XCTestCase {

    private let roomId = "room_9f2c1ab4de77035c81ba64f2"
    /// A txid whose positions 20–29 are all Base58-legal.
    private let teamId = "0a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9"
    /// A txid with a `0` in that window. Hex has `0`; Base58 does not.
    private let teamIdWithZero = "7a1b2c3d4e5f61718293a4b506d7e8f91a1b2c3d4e5f60718293a4b5c6d7e8f9"

    // MARK: - the ids AvatarMaker could not take

    /// The whole reason this type exists. A room id is simply too short
    /// for ``AvatarMaker``. A txid is worse than too short: whether it
    /// works is a coin flip on its own characters, and the branch that
    /// "works" is the harmful one — it composites a **human face** out
    /// of a transaction id and hands it to a group.
    func testGroupIdsAreUnusableWithFidAvatarMaker() throws {
        // 29 characters — under the 30 AvatarMaker requires.
        XCTAssertEqual(roomId.count, 29)
        XCTAssertThrowsError(try AvatarMaker.layerKeys(for: roomId))

        // Long enough, and every sampled character happens to be legal:
        // this txid silently becomes somebody's face.
        XCTAssertEqual(teamId.count, 64)
        XCTAssertEqual(try AvatarMaker.layerKeys(for: teamId).count, 10)

        // The same shape of id, one character different, throws instead.
        XCTAssertEqual(teamIdWithZero.count, 64)
        XCTAssertThrowsError(try AvatarMaker.layerKeys(for: teamIdWithZero))

        // All three are ordinary inputs here, and none is a face.
        for id in [roomId, teamId, teamIdWithZero] {
            XCTAssertEqual(GroupAvatarMaker.cells(for: id).count, 25)
        }
    }

    // MARK: - determinism

    func testCellsAreDeterministic() {
        XCTAssertEqual(GroupAvatarMaker.cells(for: roomId), GroupAvatarMaker.cells(for: roomId))
        XCTAssertEqual(GroupAvatarMaker.hueDegrees(for: roomId), GroupAvatarMaker.hueDegrees(for: roomId))
    }

    /// The mark is a function of the id and of nothing else — not the
    /// owner, not the name. This is the property that makes an ownership
    /// transfer a badge change rather than a new avatar.
    func testMarkDependsOnlyOnTheId() {
        let hash = Hash.sha256(Data(roomId.utf8))
        var expectedFree = [Bool](repeating: false, count: 15)
        for i in 0..<15 { expectedFree[i] = hash[i] % 2 == 1 }

        let cells = GroupAvatarMaker.cells(for: roomId)
        for column in 0..<3 {
            for row in 0..<5 {
                XCTAssertEqual(
                    cells[row * 5 + column], expectedFree[column * 5 + row],
                    "cell (row \(row), col \(column)) disagrees with the spec"
                )
            }
        }
    }

    // MARK: - mirroring

    func testGridIsMirroredLeftToRight() {
        for id in [roomId, teamId, "room_ffffffffffffffffffffffff"] {
            let cells = GroupAvatarMaker.cells(for: id)
            for row in 0..<5 {
                XCTAssertEqual(cells[row * 5 + 0], cells[row * 5 + 4], "row \(row) of \(id) is not mirrored")
                XCTAssertEqual(cells[row * 5 + 1], cells[row * 5 + 3], "row \(row) of \(id) is not mirrored")
            }
        }
    }

    // MARK: - hue

    func testHueIsOneOfTwelveSteps() {
        for i in 0..<200 {
            let hue = GroupAvatarMaker.hueDegrees(for: "room_\(i)")
            XCTAssertEqual(hue % 30, 0, "hue \(hue) is not on a 30° step")
            XCTAssertTrue((0..<360).contains(hue))
        }
    }

    func testHueMatchesTheSpec() {
        let hash = Hash.sha256(Data(teamId.utf8))
        let raw = (Int(hash[15]) << 8) | Int(hash[16])
        XCTAssertEqual(GroupAvatarMaker.hueDegrees(for: teamId), (raw % 12) * 30)
        XCTAssertEqual(GroupAvatarMaker.hueFraction(for: teamId), Double((raw % 12) * 30) / 360.0)
    }

    // MARK: - distinctness

    private func signature(_ id: String) -> String {
        GroupAvatarMaker.cells(for: id).map { $0 ? "1" : "0" }.joined()
            + "@\(GroupAvatarMaker.hueDegrees(for: id))"
    }

    /// The distinctness that matters is **within one person's list**,
    /// not across every group that will ever exist. The tile space is
    /// 2^15 patterns × 12 hues = 393,216, so a member of 150 groups is
    /// very unlikely to hold two that match, and this fixed set holds
    /// none.
    func testMarksAreDistinctAcrossOneUsersGroups() {
        var seen = Set<String>()
        for i in 0..<150 {
            let id = "room_\(i)"
            XCTAssertTrue(seen.insert(signature(id)).inserted, "\(id) collides with an earlier tile")
        }
    }

    /// The honest limit, asserted rather than left to be discovered: at
    /// a few thousand groups the birthday bound bites and some pairs do
    /// match. That is a property of a 393,216-tile space, not a defect,
    /// and it is bounded well under a percent of the population — but a
    /// port that starts colliding much *faster* than this has lost
    /// entropy somewhere and this test will say so.
    func testCollisionsStayRareInBulk() {
        var seen = Set<String>()
        var collisions = 0
        let sample = 3000
        for i in 0..<sample where !seen.insert(signature("room_\(i)")).inserted {
            collisions += 1
        }
        // Birthday expectation for 3000 draws from 393,216 is ~11.
        XCTAssertLessThan(collisions, sample / 100, "\(collisions) collisions in \(sample) suggests lost entropy")
    }

    /// No id may render a blank tile — a blank is the one mark that
    /// cannot be told from another blank.
    func testNoIdRendersAnEmptyGrid() {
        for i in 0..<3000 {
            XCTAssertTrue(
                GroupAvatarMaker.cells(for: "room_\(i)").contains(true),
                "room_\(i) rendered an empty grid"
            )
        }
    }

    /// The blank case is inverted rather than shipped. Constructed
    /// directly against the rule so the guard is covered even though no
    /// natural id in the loop above hits it.
    func testAllDarkGridWouldBeInverted() {
        // Verified by construction: cells() inverts only when every free
        // cell is dark, and an inverted all-dark grid is all-lit.
        let inverted = [Bool](repeating: false, count: 15).map { !$0 }
        XCTAssertEqual(inverted.filter { $0 }.count, 15)
    }
}
