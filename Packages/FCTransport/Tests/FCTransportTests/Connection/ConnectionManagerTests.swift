import XCTest
import Network
@testable import FCTransport

final class ConnectionManagerTests: XCTestCase {

    private let now0: Int64 = 1_700_000_000_000
    private let pubkey33 = Data(repeating: 0x02, count: 33)

    private func endpoint(_ port: UInt16) -> NWEndpoint {
        .hostPort(host: "127.0.0.1", port: NWEndpoint.Port(rawValue: port)!)
    }

    private func conn(
        id: Int64,
        port: UInt16,
        fid: String? = nil,
        nowMs: Int64? = nil
    ) throws -> PeerConnection {
        try PeerConnection(
            connectionId: id,
            peerPubkey: pubkey33,
            peerAddress: endpoint(port),
            peerFid: fid,
            nowMs: nowMs ?? now0
        )
    }

    private func makeMgr(
        perFid: Int = 5,
        total: Int = 4_096
    ) throws -> ConnectionManager {
        try ConnectionManager(maxConnectionsPerFid: perFid, maxTotalConnections: total)
    }

    // MARK: - basic indexing

    func testInsertAndLookup() throws {
        let mgr = try makeMgr()
        let c = try conn(id: 1, port: 9001, fid: "FAlice")
        let evicted = mgr.insert(c)
        XCTAssertTrue(evicted.isEmpty)
        XCTAssertEqual(mgr.totalConnections, 1)

        XCTAssertIdentical(mgr.connection(for: 1), c)
        XCTAssertIdentical(mgr.connection(for: endpoint(9001)), c)
        let listForAlice = mgr.connections(forFid: "FAlice")
        XCTAssertEqual(listForAlice.count, 1)
        XCTAssertIdentical(listForAlice[0], c)
    }

    func testLookupMissing() throws {
        let mgr = try makeMgr()
        XCTAssertNil(mgr.connection(for: 42))
        XCTAssertNil(mgr.connection(for: endpoint(9001)))
        XCTAssertTrue(mgr.connections(forFid: "FNobody").isEmpty)
    }

    func testRemoveCleansAllIndexes() throws {
        let mgr = try makeMgr()
        let c = try conn(id: 1, port: 9001, fid: "FAlice")
        mgr.insert(c)
        XCTAssertNotNil(mgr.remove(connectionId: 1))
        XCTAssertNil(mgr.connection(for: 1))
        XCTAssertNil(mgr.connection(for: endpoint(9001)))
        XCTAssertTrue(mgr.connections(forFid: "FAlice").isEmpty)
    }

    func testRemoveMissingReturnsNil() throws {
        let mgr = try makeMgr()
        XCTAssertNil(mgr.remove(connectionId: 99))
    }

    // MARK: - per-FID cap

    func testPerFidCapEvictsOldestForSameFid() throws {
        let mgr = try makeMgr(perFid: 2)
        let a = try conn(id: 1, port: 9001, fid: "FAlice", nowMs: now0)
        let b = try conn(id: 2, port: 9002, fid: "FAlice", nowMs: now0 + 100)
        let c = try conn(id: 3, port: 9003, fid: "FAlice", nowMs: now0 + 200)

        mgr.insert(a)
        mgr.insert(b)
        XCTAssertEqual(mgr.connections(forFid: "FAlice").count, 2)
        XCTAssertEqual(mgr.perFidEvictions, 0)

        let evicted = mgr.insert(c)  // FAlice is full → kick out oldest (a)
        XCTAssertEqual(evicted.count, 1)
        XCTAssertIdentical(evicted[0], a)
        XCTAssertEqual(mgr.perFidEvictions, 1)

        XCTAssertNil(mgr.connection(for: 1))
        XCTAssertNotNil(mgr.connection(for: 2))
        XCTAssertNotNil(mgr.connection(for: 3))
    }

    func testPerFidCapDoesNotEvictOtherFids() throws {
        let mgr = try makeMgr(perFid: 1)
        let a = try conn(id: 1, port: 9001, fid: "FAlice", nowMs: now0)
        let b = try conn(id: 2, port: 9002, fid: "FBob", nowMs: now0 + 100)
        let c = try conn(id: 3, port: 9003, fid: "FAlice", nowMs: now0 + 200)

        mgr.insert(a)
        mgr.insert(b)
        mgr.insert(c)  // evicts a (Alice's), keeps b (Bob's)

        XCTAssertNil(mgr.connection(for: 1))
        XCTAssertNotNil(mgr.connection(for: 2))
        XCTAssertNotNil(mgr.connection(for: 3))
    }

    // MARK: - global cap

    func testGlobalCapEvictsOldestAcrossAllFids() throws {
        let mgr = try makeMgr(perFid: 5, total: 2)
        let a = try conn(id: 1, port: 9001, fid: "FAlice", nowMs: now0)
        let b = try conn(id: 2, port: 9002, fid: "FBob",   nowMs: now0 + 100)
        let c = try conn(id: 3, port: 9003, fid: "FCarol", nowMs: now0 + 200)

        mgr.insert(a)
        mgr.insert(b)
        let evicted = mgr.insert(c)  // global cap of 2 → evict oldest (a)
        XCTAssertEqual(evicted.count, 1)
        XCTAssertIdentical(evicted[0], a)
        XCTAssertEqual(mgr.totalEvictions, 1)
        XCTAssertEqual(mgr.totalConnections, 2)
    }

    // MARK: - address routing

    func testAddressRoutingSurvivesReuseFromDifferentConn() throws {
        let mgr = try makeMgr()
        let a = try conn(id: 1, port: 9001, fid: "FAlice")
        mgr.insert(a)
        XCTAssertIdentical(mgr.connection(for: endpoint(9001)), a)

        // Same address, fresh connection. The address index should now
        // point at the new connection.
        let aPrime = try conn(id: 99, port: 9001, fid: "FAlice")
        mgr.insert(aPrime)
        XCTAssertIdentical(mgr.connection(for: endpoint(9001)), aPrime)

        // Removing the old connection must NOT clear the address mapping
        // (it now belongs to aPrime, not a).
        XCTAssertNotNil(mgr.remove(connectionId: 1))
        XCTAssertIdentical(mgr.connection(for: endpoint(9001)), aPrime)
    }

    // MARK: - clear + validation

    func testClearForgetsAll() throws {
        let mgr = try makeMgr()
        mgr.insert(try conn(id: 1, port: 9001, fid: "FAlice"))
        mgr.insert(try conn(id: 2, port: 9002, fid: "FBob"))
        mgr.clear()
        XCTAssertEqual(mgr.totalConnections, 0)
        XCTAssertNil(mgr.connection(for: 1))
        XCTAssertNil(mgr.connection(for: endpoint(9001)))
    }

    func testRejectsNonPositiveCaps() {
        XCTAssertThrowsError(try ConnectionManager(maxConnectionsPerFid: 0))
        XCTAssertThrowsError(try ConnectionManager(maxTotalConnections: 0))
    }
}
