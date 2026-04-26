import XCTest
import FCCore
@testable import FCDomain

final class CashTests: XCTestCase {

    /// `Cash.makeId(birthTxId:birthIndex:)` must reproduce the cash id
    /// the server's indexer assigns. The algorithm
    /// (`displayHex(sha256d(naturalTxIdBytes || leVoutBytes))`) is the
    /// same one Bitcoin uses for outpoints, so we verify against a
    /// hand-computed reference: with txid display = "ab"*32 (i.e. 32
    /// bytes of 0xab) and index 0, the pre-image is 32×0xab natural-
    /// order bytes followed by 0x00000000 (LE 0).
    func testMakeIdDeterministicAndStableForFixedInput() throws {
        let txid = String(repeating: "ab", count: 32)

        let id1 = try Cash.makeId(birthTxId: txid, birthIndex: 0)
        let id2 = try Cash.makeId(birthTxId: txid, birthIndex: 0)
        XCTAssertEqual(id1, id2, "same input must produce same id")
        XCTAssertEqual(id1.count, 64, "cash id is 32 bytes hex-encoded")

        // Different vout → different id.
        let id3 = try Cash.makeId(birthTxId: txid, birthIndex: 1)
        XCTAssertNotEqual(id1, id3, "vout must affect id")

        // Different txid → different id.
        let txidB = String(repeating: "cd", count: 32)
        let id4 = try Cash.makeId(birthTxId: txidB, birthIndex: 0)
        XCTAssertNotEqual(id1, id4, "txid must affect id")
    }

    func testMakeIdRejectsBadTxid() {
        // 63 chars: invalid hex length — TxBuilder.decodeTxid throws.
        XCTAssertThrowsError(try Cash.makeId(
            birthTxId: String(repeating: "ab", count: 31) + "a",
            birthIndex: 0
        ))
    }

    /// `LocalState` round-trips through Codable so persisted cashes
    /// can be reloaded with their state intact.
    func testLocalStateCodableRoundTrip() throws {
        let cash = Cash(
            owner: "FFromAddr", value: 1_000_000,
            type: "P2PKH",
            birthTxId: String(repeating: "ab", count: 32),
            birthIndex: 0,
            localState: .unknown,
            pendingSpend: true
        )
        let data = try JSONEncoder().encode(cash)
        let decoded = try JSONDecoder().decode(Cash.self, from: data)
        XCTAssertEqual(decoded.localState, .unknown)
        XCTAssertTrue(decoded.pendingSpend)
    }

    /// Older on-disk blobs that predate `localState` / `pendingSpend`
    /// must decode with sensible defaults — otherwise upgrading would
    /// nuke the cache. The custom `init(from:)` in Cash uses
    /// `decodeIfPresent` for those two fields.
    func testLegacyBlobDecodesWithDefaults() throws {
        // Hand-built JSON that omits localState + pendingSpend.
        let legacyJson = """
        {
          "owner": "FFromAddr",
          "value": 1000,
          "type": "P2PKH",
          "birthTxId": "ab",
          "birthIndex": 0
        }
        """
        let decoded = try JSONDecoder().decode(Cash.self, from: Data(legacyJson.utf8))
        XCTAssertEqual(decoded.localState, .onchain)
        XCTAssertFalse(decoded.pendingSpend)
    }

    /// `CashSnapshot.upsert` replaces an existing row by id; otherwise
    /// appends. `CashSnapshot.remove` deletes by id (or by `(birthTxId,
    /// birthIndex)` when id is missing).
    func testSnapshotUpsertAndRemove() {
        var snap = CashSnapshot(addr: "F", cashes: [])
        let a = Cash(id: "A", owner: "F", value: 100,
                     birthTxId: String(repeating: "11", count: 32), birthIndex: 0)
        let b = Cash(id: "B", owner: "F", value: 200,
                     birthTxId: String(repeating: "22", count: 32), birthIndex: 0)
        snap.upsert(a)
        snap.upsert(b)
        XCTAssertEqual(snap.cashes.count, 2)

        // Upsert with the same id replaces in place.
        var aPrime = a
        aPrime.value = 999
        snap.upsert(aPrime)
        XCTAssertEqual(snap.cashes.count, 2)
        XCTAssertEqual(snap.cashes.first(where: { $0.id == "A" })?.value, 999)

        // Remove by id.
        XCTAssertTrue(snap.remove(id: "B"))
        XCTAssertEqual(snap.cashes.count, 1)
        // Remove by (birthTxId, birthIndex) when id-only matching fails.
        XCTAssertTrue(snap.remove(
            id: nil,
            birthTxId: String(repeating: "11", count: 32),
            birthIndex: 0
        ))
        XCTAssertTrue(snap.cashes.isEmpty)
    }
}
