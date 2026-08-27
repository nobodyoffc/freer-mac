import XCTest
import FCCore
@testable import FCDomain

/// The three token record types: what the wire may legally throw at
/// them, and the derived state the pane's buttons are wired to.
final class TokenTests: XCTestCase {

    private func decodeToken(_ json: [String: Any]) throws -> Token {
        let data = try JSONSerialization.data(withJSONObject: json)
        return try JSONDecoder().decode(Token.self, from: data)
    }

    // MARK: - Token decoding

    func testDecodesAFullRecord() throws {
        let t = try decodeToken([
            "id": "tx1", "name": "Gold", "desc": "shiny",
            "consensusId": "F1", "capacity": "21000000", "decimal": "8",
            "transferable": true, "closable": true, "openIssue": false,
            "closed": false, "deployer": "FDeployer", "circulating": 1234.5,
            "birthTime": 1_700_000_000, "birthHeight": 900,
            "lastTxId": "tx9", "lastTime": 1_700_000_100, "lastHeight": 901
        ])
        XCTAssertEqual(t.id, "tx1")
        XCTAssertEqual(t.name, "Gold")
        XCTAssertEqual(t.capacity, "21000000")
        XCTAssertEqual(t.decimalPlaces, 8)
        XCTAssertEqual(t.deployer, "FDeployer")
        XCTAssertEqual(t.circulating, 1234.5)
        XCTAssertEqual(t.lastHeight, 901)
        XCTAssertFalse(t.isClosed)
    }

    /// A record missing everything but an id still decodes. One
    /// half-filled row must not cost the other twenty-four on the page.
    func testDecodesASparseRecord() throws {
        let t = try decodeToken(["id": "tx1"])
        XCTAssertEqual(t.id, "tx1")
        XCTAssertNil(t.name)
        XCTAssertEqual(t.decimalPlaces, 0)
        XCTAssertFalse(t.isClosed)
        XCTAssertEqual(t.displayName, "tx1")
    }

    /// The capacity of a token deployed by a client that carved it
    /// unquoted. A strict String decode throws here and takes the whole
    /// page with it.
    func testCapacityDecodesFromAJsonNumber() throws {
        XCTAssertEqual(try decodeToken(["id": "a", "capacity": 21_000_000]).capacity, "21000000")
        XCTAssertEqual(try decodeToken(["id": "a", "capacity": 1.5]).capacity, "1.5")
        XCTAssertEqual(try decodeToken(["id": "a", "decimal": 8]).decimal, "8")
        XCTAssertEqual(try decodeToken(["id": "a", "decimal": 8]).decimalPlaces, 8)
    }

    /// Same tolerance for the flags — `TokenHistory` declares its
    /// copies of these as String precisely because carves spell them
    /// both ways.
    func testFlagsDecodeFromStrings() throws {
        XCTAssertEqual(try decodeToken(["id": "a", "transferable": "true"]).transferable, true)
        XCTAssertEqual(try decodeToken(["id": "a", "closable": "false"]).closable, false)
        XCTAssertEqual(try decodeToken(["id": "a", "closed": "TRUE"]).closed, true)
        XCTAssertNil(try decodeToken(["id": "a", "openIssue": "maybe"]).openIssue)
    }

    /// The trap that `isClosed` exists for: an absent flag means open,
    /// and `closed == false` disagrees with `closed != true` on exactly
    /// the rows the indexer omitted it from.
    func testMissingClosedFlagMeansOpen() throws {
        XCTAssertFalse(try decodeToken(["id": "a"]).isClosed)
        XCTAssertFalse(try decodeToken(["id": "a", "closed": false]).isClosed)
        XCTAssertTrue(try decodeToken(["id": "a", "closed": true]).isClosed)
    }

    /// A malformed decimal must never make the amount formatter emit a
    /// hundred digits, and a negative one is not a scale.
    func testDecimalPlacesIsClampedAndTolerant() throws {
        XCTAssertEqual(try decodeToken(["id": "a", "decimal": "-3"]).decimalPlaces, 0)
        XCTAssertEqual(try decodeToken(["id": "a", "decimal": "999"]).decimalPlaces, 18)
        XCTAssertEqual(try decodeToken(["id": "a", "decimal": "eight"]).decimalPlaces, 0)
        XCTAssertEqual(try decodeToken(["id": "a", "decimal": " 4 "]).decimalPlaces, 4)
    }

    // MARK: - Token permissions

    func testCanIssueThroughEitherDoor() throws {
        let openToken = try decodeToken(["id": "a", "openIssue": true, "deployer": "DEP"])
        XCTAssertTrue(openToken.canIssue(as: "STRANGER"))
        XCTAssertTrue(openToken.canIssue(as: "DEP"))

        let closedIssue = try decodeToken(["id": "a", "openIssue": false, "deployer": "DEP"])
        XCTAssertFalse(closedIssue.canIssue(as: "STRANGER"))
        XCTAssertTrue(closedIssue.canIssue(as: "DEP"))
    }

    /// Closing stops issuing for everybody, the deployer included.
    /// That is the whole guarantee a closed token offers its holders.
    func testAClosedTokenIssuesNothingForAnyone() throws {
        let t = try decodeToken([
            "id": "a", "openIssue": true, "deployer": "DEP", "closed": true
        ])
        XCTAssertFalse(t.canIssue(as: "DEP"))
        XCTAssertFalse(t.canIssue(as: "STRANGER"))
        XCTAssertFalse(t.canTransfer)
    }

    /// Only the deployer of a token deployed `closable` can close it,
    /// and only once.
    func testCanCloseNeedsDeployerAndTheClosableFlag() throws {
        XCTAssertTrue(try decodeToken(
            ["id": "a", "deployer": "DEP", "closable": true]
        ).canClose(as: "DEP"))
        XCTAssertFalse(try decodeToken(
            ["id": "a", "deployer": "DEP", "closable": false]
        ).canClose(as: "DEP"))
        XCTAssertFalse(try decodeToken(
            ["id": "a", "deployer": "DEP", "closable": true]
        ).canClose(as: "OTHER"))
        XCTAssertFalse(try decodeToken(
            ["id": "a", "deployer": "DEP", "closable": true, "closed": true]
        ).canClose(as: "DEP"))
        // A token that never said it was closable is not closable.
        XCTAssertFalse(try decodeToken(["id": "a", "deployer": "DEP"]).canClose(as: "DEP"))
    }

    func testMatchesCoversTheIndexedSearchFields() throws {
        let t = try decodeToken([
            "id": "abc123", "name": "Gold", "desc": "a shiny thing",
            "consensusId": "FConsensus", "deployer": "FDeployer"
        ])
        XCTAssertTrue(t.matches(query: "gold"))
        XCTAssertTrue(t.matches(query: "SHINY"))
        XCTAssertTrue(t.matches(query: "fconsensus"))
        XCTAssertTrue(t.matches(query: "fdeployer"))
        XCTAssertTrue(t.matches(query: "abc"))
        XCTAssertFalse(t.matches(query: "silver"))
        XCTAssertFalse(t.matches(query: "   "))
    }

    // MARK: - TokenHolder

    /// Single sha256 of `fid + tokenId`, hex — Java's
    /// `TokenHolder.getTokenHolderId`. A double-sha256 here would
    /// produce a well-formed id that addresses nothing.
    func testHolderIdIsSingleSha256OfFidPlusTokenId() {
        let fid = "FEk4Cq4kfKcRZLYQaAeJMPqBGHkYDLXLZg"
        let tokenId = "deadbeef"
        let expected = Hex.encode(Hash.sha256(Data((fid + tokenId).utf8)))
        XCTAssertEqual(TokenHolder.id(fid: fid, tokenId: tokenId), expected)
        XCTAssertNotEqual(
            TokenHolder.id(fid: fid, tokenId: tokenId),
            Hex.encode(Hash.doubleSha256(Data((fid + tokenId).utf8)))
        )
        // Concatenation order matters, and swapping the two must not
        // land on the same row.
        XCTAssertNotEqual(
            TokenHolder.id(fid: fid, tokenId: tokenId),
            TokenHolder.id(fid: tokenId, tokenId: fid)
        )
    }

    /// Java derives the id lazily in `getId()`; this does it at the
    /// decode boundary so nothing downstream has to wonder.
    func testHolderDerivesItsIdWhenTheWireOmitsIt() throws {
        let data = try JSONSerialization.data(withJSONObject: [
            "fid": "FID1", "tokenId": "T1", "balance": 5
        ])
        let h = try JSONDecoder().decode(TokenHolder.self, from: data)
        XCTAssertEqual(h.id, TokenHolder.id(fid: "FID1", tokenId: "T1"))
        XCTAssertTrue(h.hasBalance)
    }

    func testHolderKeepsAnExplicitWireId() throws {
        let data = try JSONSerialization.data(withJSONObject: [
            "id": "explicit", "fid": "FID1", "tokenId": "T1"
        ])
        let h = try JSONDecoder().decode(TokenHolder.self, from: data)
        XCTAssertEqual(h.id, "explicit")
    }

    /// A spent-out holding stays on chain at zero. It is a row, but not
    /// a spendable one.
    func testZeroBalanceIsARowWithNothingToSpend() {
        let h = TokenHolder.local(fid: "F", tokenId: "T", balance: 0)
        XCTAssertFalse(h.hasBalance)
        XCTAssertFalse(h.id.isEmpty)
    }

    // MARK: - TokenHistory

    func testHistoryDecodesAnIssueRow() throws {
        let data = try JSONSerialization.data(withJSONObject: [
            "id": "tx1", "op": "issue", "tokenId": "T1", "signer": "DEP",
            "time": 1_700_000_000, "height": 900, "index": 2,
            "issueTo": [["fid": "A", "amount": 10.0], ["fid": "B", "amount": 2.5]]
        ])
        let h = try JSONDecoder().decode(TokenHistory.self, from: data)
        XCTAssertEqual(h.operation, .issue)
        XCTAssertEqual(h.affectedTokenIds, ["T1"])
        XCTAssertEqual(h.allocations.count, 2)
        XCTAssertEqual(h.totalAmount, 12.5)
        XCTAssertTrue(h.involves("A"))
        XCTAssertTrue(h.involves("DEP"))
        XCTAssertFalse(h.involves("C"))
    }

    /// `close` and `destroy` name their targets in `tokenIds`, not
    /// `tokenId` — a caller reading only one of the two fields misses
    /// half the ops.
    func testHistoryReadsBothTokenIdShapes() throws {
        let data = try JSONSerialization.data(withJSONObject: [
            "id": "tx2", "op": "close", "tokenIds": ["T1", "T2"], "signer": "DEP"
        ])
        let h = try JSONDecoder().decode(TokenHistory.self, from: data)
        XCTAssertEqual(h.operation, .close)
        XCTAssertEqual(h.affectedTokenIds, ["T1", "T2"])
        // Nothing moved, and that is different from moving zero.
        XCTAssertNil(h.totalAmount)
    }

    /// A history row echoes somebody else's carve, so its flags arrive
    /// as whatever that client wrote — string or bool, both readable.
    func testHistoryFlagsReadBackAsTextEitherWay() throws {
        let data = try JSONSerialization.data(withJSONObject: [
            "id": "tx3", "op": "deploy", "transferable": true,
            "closable": "false", "capacity": 21_000_000, "decimal": "8"
        ])
        let h = try JSONDecoder().decode(TokenHistory.self, from: data)
        XCTAssertEqual(h.transferable, "true")
        XCTAssertEqual(h.closable, "false")
        XCTAssertEqual(h.capacity, "21000000")
        XCTAssertEqual(h.decimal, "8")
    }

    /// An op this build has never heard of is still a displayable row.
    func testUnknownOpDecodesWithoutACase() throws {
        let data = try JSONSerialization.data(withJSONObject: [
            "id": "tx4", "op": "rename", "signer": "S"
        ])
        let h = try JSONDecoder().decode(TokenHistory.self, from: data)
        XCTAssertNil(h.operation)
        XCTAssertEqual(h.op, "rename")
        XCTAssertTrue(h.involves("S"))
    }
}
