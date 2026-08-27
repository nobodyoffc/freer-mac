import XCTest
@testable import FCDomain

/// The token carve payloads: what goes on the chain for each of the
/// five ops, and everything that has to fail *before* a miner fee is
/// spent.
final class TokenCarveTests: XCTestCase {

    private func data(from json: String) throws -> [String: Any] {
        let obj = try JSONSerialization.jsonObject(with: Data(json.utf8))
        let env = try XCTUnwrap(obj as? [String: Any])
        return try XCTUnwrap(env["data"] as? [String: Any])
    }

    private func op(_ json: String) throws -> [String: Any] {
        try XCTUnwrap(JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String: Any])
    }

    // MARK: - envelope

    func testEnvelopeCarriesSn20() throws {
        let json = TokenFeip.envelope(opJson: try TokenFeip.closeOp(tokenIds: ["T1"]))
        let env = try XCTUnwrap(
            JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String: Any]
        )
        XCTAssertEqual(env["type"] as? String, "FEIP")
        XCTAssertEqual(env["sn"] as? String, "20")
        XCTAssertEqual(env["ver"] as? String, "1")
        XCTAssertEqual(env["name"] as? String, "Token")
        // The registry and the builder have to agree, or a carve this
        // app writes is one it cannot label when it reads it back.
        XCTAssertEqual(FeipProtocol.token.sn, TokenFeip.sn)
        XCTAssertEqual(FeipProtocol.token.protocolName, TokenFeip.protocolName)
    }

    // MARK: - deploy

    func testDeployOmitsTheIdBecauseTheTxidIsTheId() throws {
        let d = try data(from: try TokenFeip.deployCarve(name: "Gold"))
        XCTAssertEqual(d["op"] as? String, "deploy")
        XCTAssertEqual(d["name"] as? String, "Gold")
        XCTAssertNil(d["tokenId"])
        XCTAssertNil(d["tokenIds"])
    }

    func testDeployCarriesTheWholeRuleSet() throws {
        let d = try data(from: try TokenFeip.deployCarve(
            name: "Gold", desc: "shiny", consensusId: "FC",
            capacity: "21000000", decimal: "8",
            transferable: true, closable: false, openIssue: true,
            maxAmtPerIssue: "100", minCddPerIssue: "10", maxIssuesPerAddr: "3"
        ))
        XCTAssertEqual(d["desc"] as? String, "shiny")
        XCTAssertEqual(d["consensusId"] as? String, "FC")
        // Carved as strings, exactly as typed — a capacity re-encoded
        // through a number type is not the capacity that was signed.
        XCTAssertEqual(d["capacity"] as? String, "21000000")
        XCTAssertEqual(d["decimal"] as? String, "8")
        XCTAssertEqual(d["transferable"] as? Bool, true)
        XCTAssertEqual(d["closable"] as? Bool, false)
        XCTAssertEqual(d["openIssue"] as? Bool, true)
        XCTAssertEqual(d["maxAmtPerIssue"] as? String, "100")
        XCTAssertEqual(d["minCddPerIssue"] as? String, "10")
        XCTAssertEqual(d["maxIssuesPerAddr"] as? String, "3")
    }

    /// The parser only applies the three limits when `openIssue` is
    /// true. Carving them otherwise writes a rule into the permanent
    /// record that nothing will ever enforce.
    func testDeployDropsTheIssueLimitsWhenIssuingIsNotOpen() throws {
        let d = try data(from: try TokenFeip.deployCarve(
            name: "Gold", openIssue: false,
            maxAmtPerIssue: "100", minCddPerIssue: "10", maxIssuesPerAddr: "3"
        ))
        XCTAssertNil(d["maxAmtPerIssue"])
        XCTAssertNil(d["minCddPerIssue"])
        XCTAssertNil(d["maxIssuesPerAddr"])
    }

    func testDeployOmitsEmptyOptionalsRatherThanCarvingBlanks() throws {
        let d = try data(from: try TokenFeip.deployCarve(
            name: "Gold", desc: "   ", consensusId: "", capacity: nil
        ))
        XCTAssertNil(d["desc"])
        XCTAssertNil(d["consensusId"])
        XCTAssertNil(d["capacity"])
    }

    func testDeployRefusesANamelessToken() {
        XCTAssertThrowsError(try TokenFeip.deployCarve(name: "   "))
    }

    // MARK: - issue and transfer

    func testIssueAndTransferUseTheirOwnAllocationKeys() throws {
        let lines = [TokenTransfer(fid: "FA", amount: "1.5")]
        let issue = try data(from: try TokenFeip.issueCarve(
            tokenId: "T1", issueTo: lines, scale: 8
        ))
        XCTAssertEqual(issue["op"] as? String, "issue")
        XCTAssertEqual(issue["tokenId"] as? String, "T1")
        XCTAssertNotNil(issue["issueTo"])
        XCTAssertNil(issue["transferTo"])

        let transfer = try data(from: try TokenFeip.transferCarve(
            tokenId: "T1", transferTo: lines, scale: 8
        ))
        XCTAssertEqual(transfer["op"] as? String, "transfer")
        XCTAssertNotNil(transfer["transferTo"])
        XCTAssertNil(transfer["issueTo"])
    }

    /// The point of holding an amount as digits: what the user typed is
    /// what the chain records, with no round trip through a binary
    /// float in between.
    func testAmountsGoOnTheWireAsTypedNotAsDoubles() throws {
        let json = try TokenFeip.transferCarve(
            tokenId: "T1",
            transferTo: [
                TokenTransfer(fid: "FA", amount: "0.1"),
                TokenTransfer(fid: "FB", amount: "0.00000001"),
                TokenTransfer(fid: "FC", amount: "12345678.87654321")
            ],
            scale: 8
        )
        // Read the raw text, not a re-parse: a re-parse through Double
        // is exactly the step this is here to rule out.
        XCTAssertTrue(json.contains(#""amount":0.1"#), json)
        XCTAssertTrue(json.contains(#""amount":0.00000001"#), json)
        XCTAssertTrue(json.contains(#""amount":12345678.87654321"#), json)
        XCTAssertFalse(json.contains("e-"), "no exponent form on the wire: \(json)")
    }

    /// Trailing zeros are normalised away — `1.50` and `1.5` are the
    /// same amount, and only the second is worth the bytes.
    func testTrailingZerosAreNormalised() throws {
        let json = try TokenFeip.transferCarve(
            tokenId: "T1", transferTo: [TokenTransfer(fid: "FA", amount: "1.50")], scale: 2
        )
        XCTAssertTrue(json.contains(#""amount":1.5"#), json)
    }

    /// The scale check is the difference between a message and a wasted
    /// miner fee: the parser rejects over-precise amounts outright.
    func testAmountsBeyondTheTokensScaleAreRefused() {
        XCTAssertThrowsError(try TokenFeip.transferCarve(
            tokenId: "T1", transferTo: [TokenTransfer(fid: "FA", amount: "1.234")], scale: 2
        ))
        // `1.50` on a one-decimal token is 1.5, which fits. Comparing
        // written digits rather than value scale would reject it.
        XCTAssertNoThrow(try TokenFeip.transferCarve(
            tokenId: "T1", transferTo: [TokenTransfer(fid: "FA", amount: "1.50")], scale: 1
        ))
        // A zero-decimal token takes integers only.
        XCTAssertThrowsError(try TokenFeip.transferCarve(
            tokenId: "T1", transferTo: [TokenTransfer(fid: "FA", amount: "1.5")], scale: 0
        ))
    }

    func testNonNumericAndNonPositiveAmountsAreRefused() {
        for bad in ["", "  ", "abc", "1.2.3", "-5", "1e3", "0"] {
            XCTAssertThrowsError(
                try TokenFeip.issueCarve(
                    tokenId: "T1", issueTo: [TokenTransfer(fid: "FA", amount: bad)], scale: 8
                ),
                "\"\(bad)\" should not be carvable"
            )
        }
    }

    func testEmptyRecipientListIsRefused() {
        XCTAssertThrowsError(try TokenFeip.issueCarve(tokenId: "T1", issueTo: [], scale: 8))
        XCTAssertThrowsError(try TokenFeip.transferCarve(tokenId: "", transferTo: [
            TokenTransfer(fid: "FA", amount: "1")
        ], scale: 8))
    }

    /// Which of two lines for the same FID the parser honours is not
    /// worth a miner fee to find out.
    func testDuplicateRecipientsAreRefused() {
        XCTAssertThrowsError(try TokenFeip.transferCarve(
            tokenId: "T1",
            transferTo: [
                TokenTransfer(fid: "FA", amount: "1"),
                TokenTransfer(fid: " FA ", amount: "2")
            ],
            scale: 8
        ))
    }

    func testRecipientFidsAreTrimmed() throws {
        let json = try TokenFeip.transferCarve(
            tokenId: "T1", transferTo: [TokenTransfer(fid: "  FA  ", amount: "1")], scale: 0
        )
        XCTAssertTrue(json.contains(#""fid":"FA""#), json)
    }

    // MARK: - destroy and close

    /// Destroy takes ids and no amount: there is no partial burn.
    func testDestroyTakesOneIdInAList() throws {
        let d = try data(from: try TokenFeip.destroyCarve(tokenId: " T1 "))
        XCTAssertEqual(d["op"] as? String, "destroy")
        XCTAssertEqual(d["tokenIds"] as? [String], ["T1"])
        XCTAssertNil(d["tokenId"])
        XCTAssertNil(d["transferTo"])
        XCTAssertThrowsError(try TokenFeip.destroyCarve(tokenId: "   "))
    }

    func testCloseTakesAListSoOneFeeCoversSeveral() throws {
        let d = try data(from: try TokenFeip.closeCarve(tokenIds: ["T1", " T2 ", ""]))
        XCTAssertEqual(d["op"] as? String, "close")
        XCTAssertEqual(d["tokenIds"] as? [String], ["T1", "T2"])
        XCTAssertThrowsError(try TokenFeip.closeCarve(tokenIds: ["", "  "]))
    }

    // MARK: - size

    /// A carve too big for an OP_RETURN has to fail before anything is
    /// signed, not after the fee is spent.
    func testAnOversizedCarveThrowsBeforeBroadcast() {
        let lines = (0..<400).map {
            TokenTransfer(fid: "F\(String(format: "%033d", $0))", amount: "1")
        }
        XCTAssertThrowsError(
            try TokenFeip.issueCarve(tokenId: "T1", issueTo: lines, scale: 0)
        ) { error in
            guard case TokenFeip.Failure.tooLarge = error else {
                return XCTFail("expected .tooLarge, got \(error)")
            }
        }
    }

    /// The budget the compose form shows: how many more recipients fit.
    /// It has to shrink as lines are added and reach zero before the
    /// carve stops encoding.
    func testRemainingRecipientsShrinksAndStaysHonest() throws {
        let empty = try XCTUnwrap(TokenFeip.remainingRecipients(
            op: .transfer, tokenId: "T1", lines: [], scale: 8
        ))
        XCTAssertGreaterThan(empty, 0)

        let some = (0..<10).map { TokenTransfer(fid: "F\(String(format: "%033d", $0))", amount: "1") }
        let after = try XCTUnwrap(TokenFeip.remainingRecipients(
            op: .transfer, tokenId: "T1", lines: some, scale: 8
        ))
        XCTAssertLessThan(after, empty)

        // Filling the budget must leave a carve that still encodes.
        let full = (0..<(some.count + after)).map {
            TokenTransfer(fid: "F\(String(format: "%033d", $0))", amount: "1")
        }
        XCTAssertNoThrow(
            try TokenFeip.transferCarve(tokenId: "T1", transferTo: full, scale: 8)
        )
        XCTAssertEqual(
            TokenFeip.remainingRecipients(op: .deploy, tokenId: "T1", lines: [], scale: 8),
            nil,
            "deploy has no recipient list to budget"
        )
    }

    // MARK: - decimal counting

    func testDecimalPlacesIgnoresTrailingZeros() {
        XCTAssertEqual(TokenTransfer.decimalPlaces(in: "1"), 0)
        XCTAssertEqual(TokenTransfer.decimalPlaces(in: "1."), 0)
        XCTAssertEqual(TokenTransfer.decimalPlaces(in: "1.5"), 1)
        XCTAssertEqual(TokenTransfer.decimalPlaces(in: "1.500"), 1)
        XCTAssertEqual(TokenTransfer.decimalPlaces(in: "1.0000"), 0)
        XCTAssertEqual(TokenTransfer.decimalPlaces(in: "0.00000001"), 8)
    }
}
