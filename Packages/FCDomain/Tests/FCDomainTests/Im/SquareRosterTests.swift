import XCTest
@testable import FCDomain

/// The receiver's membership check for square messages.
final class SquareRosterTests: XCTestCase {

    private let squareId = "5q" + String(repeating: "0", count: 62)
    private let t0 = Date(timeIntervalSince1970: 1_755_100_000)
    private var t0Ms: Int64 { Int64(t0.timeIntervalSince1970 * 1000) }

    private func square(_ members: [String]) -> Square {
        Square(name: "S", members: members, id: squareId)
    }

    private final class Counter: @unchecked Sendable { var n = 0 }

    func testALocalMemberNeedsNoLookup() async {
        let local = square(["alice"])
        let roster = SquareRoster(local: { _ in local })
        let calls = Counter()
        let answer = await roster.check(sender: "alice", squareId: squareId, storedAt: t0Ms, now: t0) { _ in
            calls.n += 1
            return nil
        }
        XCTAssertEqual(answer, .member)
        XCTAssertEqual(calls.n, 0)
    }

    /// A stale local copy is corrected from the chain before anyone is
    /// turned away.
    func testAStrangerIsLookedUpOnce() async {
        let roster = SquareRoster(local: { _ in nil })
        let chain = square(["alice", "bob"])
        let calls = Counter()
        let fetch: @Sendable (String) async throws -> Square? = { _ in calls.n += 1; return chain }

        let bob = await roster.check(sender: "bob", squareId: squareId, storedAt: t0Ms, now: t0, fetch: fetch)
        XCTAssertEqual(bob, .member)
        let mallory = await roster.check(sender: "mallory", squareId: squareId, storedAt: t0Ms, now: t0, fetch: fetch)
        XCTAssertEqual(mallory, .notMember)
        XCTAssertEqual(calls.n, 1, "the second answer came from the read the first one made")
    }

    /// An item stored before the last read cannot be from someone who
    /// joined after it; an item stored later might be.
    func testOnlyANewerItemIsWorthAnotherLookup() async {
        let roster = SquareRoster(local: { _ in nil })
        let calls = Counter()
        let fetch: @Sendable (String) async throws -> Square? = { _ in
            calls.n += 1
            return calls.n == 1 ? Square(name: "S", members: ["alice"], id: nil) : Square(name: "S", members: ["alice", "carol"], id: nil)
        }

        _ = await roster.check(sender: "carol", squareId: squareId, storedAt: t0Ms, now: t0, fetch: fetch)
        let older = await roster.check(sender: "carol", squareId: squareId, storedAt: t0Ms - 1000, now: t0, fetch: fetch)
        XCTAssertEqual(older, .notMember)
        XCTAssertEqual(calls.n, 1)

        let newer = await roster.check(
            sender: "carol", squareId: squareId, storedAt: t0Ms + 60_000,
            now: t0.addingTimeInterval(90), fetch: fetch
        )
        XCTAssertEqual(newer, .member)
        XCTAssertEqual(calls.n, 2)
    }

    func testAChainThatCannotBeAskedDecidesNothing() async {
        struct Down: Error {}
        let roster = SquareRoster(local: { _ in nil })
        let answer = await roster.check(sender: "bob", squareId: squareId, storedAt: t0Ms, now: t0) { _ in throw Down() }
        XCTAssertEqual(answer, .unknown)
    }
}
