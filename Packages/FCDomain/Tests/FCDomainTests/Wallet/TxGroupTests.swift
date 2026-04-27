import XCTest
@testable import FCDomain

final class TxGroupTests: XCTestCase {

    private func cash(
        id: String? = nil,
        owner: String = "FAlice",
        value: Int64,
        birthTxId: String,
        birthIndex: Int = 0,
        birthHeight: Int64? = nil,
        birthTime: Int64? = nil,
        valid: Bool? = nil,
        spendTxId: String? = nil,
        spendHeight: Int64? = nil,
        spendTime: Int64? = nil
    ) -> Cash {
        Cash(
            id: id, owner: owner, value: value,
            birthTxId: birthTxId, birthIndex: birthIndex,
            birthHeight: birthHeight, birthTime: birthTime,
            valid: valid,
            spendTxId: spendTxId, spendHeight: spendHeight, spendTime: spendTime
        )
    }

    func testIncomingOnlyGroup() {
        let groups = TxGroup.group([
            cash(value: 1_000, birthTxId: "tx1", birthHeight: 100, birthTime: 1_700_000_000)
        ])
        XCTAssertEqual(groups.count, 1)
        let g = groups[0]
        XCTAssertEqual(g.txid, "tx1")
        XCTAssertEqual(g.role, .received)
        XCTAssertEqual(g.netSats, 1_000)
        XCTAssertEqual(g.height, 100)
        XCTAssertEqual(g.time, 1_700_000_000)
    }

    func testOutgoingOnlyGroup() {
        // A spent cash should be grouped under its spendTxId, not
        // its birthTxId. Net is negative.
        let groups = TxGroup.group([
            cash(
                value: 1_000,
                birthTxId: "txA", birthIndex: 3,
                birthHeight: 50,
                valid: false,
                spendTxId: "txB", spendHeight: 80, spendTime: 1_700_001_000
            )
        ])
        XCTAssertEqual(groups.count, 1)
        let g = groups[0]
        XCTAssertEqual(g.txid, "txB", "spent cash groups under spendTxId")
        XCTAssertEqual(g.role, .sent)
        XCTAssertEqual(g.netSats, -1_000)
        XCTAssertEqual(g.height, 80)
        XCTAssertEqual(g.time, 1_700_001_000)
    }

    /// A self-send produces both a spent input AND a change output
    /// referencing the same tx. Both rows should collapse into one
    /// "mixed" group whose net is the actual amount sent (negative).
    func testMixedGroupCollapsesSendInputsAndChange() {
        let groups = TxGroup.group([
            // Spent input from the user's previous receive: birth=tx0,
            // spent in tx1.
            cash(
                value: 1_000_000,
                birthTxId: "tx0", birthIndex: 0,
                birthHeight: 50,
                valid: false,
                spendTxId: "tx1", spendHeight: 100
            ),
            // Change output: born in tx1.
            cash(
                value: 800_000,
                birthTxId: "tx1", birthIndex: 1,
                birthHeight: 100, birthTime: 1_700_002_000,
                valid: true
            )
        ])
        XCTAssertEqual(groups.count, 1)
        let g = groups[0]
        XCTAssertEqual(g.txid, "tx1")
        XCTAssertEqual(g.role, .mixed)
        // 800_000 incoming change - 1_000_000 spent = -200_000.
        XCTAssertEqual(g.netSats, -200_000)
        XCTAssertEqual(g.incoming.count, 1)
        XCTAssertEqual(g.outgoing.count, 1)
        XCTAssertEqual(g.height, 100)
    }

    func testOrderingNewestFirstWithPendingOnTop() {
        let groups = TxGroup.group([
            // Confirmed at height 50.
            cash(value: 100, birthTxId: "old", birthHeight: 50),
            // Confirmed at height 200 (newest confirmed).
            cash(value: 200, birthTxId: "mid", birthHeight: 200),
            // Pending (no height).
            cash(value: 300, birthTxId: "pending", birthHeight: nil)
        ])
        XCTAssertEqual(groups.map { $0.txid }, ["pending", "mid", "old"])
    }

    func testDeduplicatesByCashId() {
        let groups = TxGroup.group([
            cash(id: "X", value: 100, birthTxId: "tx", birthIndex: 0),
            cash(id: "X", value: 100, birthTxId: "tx", birthIndex: 0)   // duplicate
        ])
        XCTAssertEqual(groups.count, 1)
        XCTAssertEqual(groups[0].incoming.count, 1)
        XCTAssertEqual(groups[0].netSats, 100)
    }
}
