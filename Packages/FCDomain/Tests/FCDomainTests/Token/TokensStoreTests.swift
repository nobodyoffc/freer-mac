import XCTest
import FCCore
import FCTransport
@testable import FCDomain

/// The token cache: what a refresh may throw away, and what it must
/// never touch.
final class TokensStoreTests: XCTestCase {

    private var baseDir: URL!

    override func setUpWithError() throws {
        baseDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("TokensStoreTests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: baseDir, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        if let baseDir { try? FileManager.default.removeItem(at: baseDir) }
    }

    private func makeSessions() throws -> (ActiveSession, ActiveSession) {
        let mgr = try ConfigureManager(baseDirectory: baseDir)
        let configure = try mgr.createConfigure(
            password: Data("pwd".utf8), kdfKind: .legacySha256
        )
        let a = try configure.addMain(privkey: Data(repeating: 0xA1, count: 32), label: "A")
        let b = try configure.addMain(privkey: Data(repeating: 0xB2, count: 32), label: "B")
        return (
            try configure.unlockMain(fid: a.fid, fapi: MockFapiClient()),
            try configure.unlockMain(fid: b.fid, fapi: MockFapiClient())
        )
    }

    private func holder(_ tokenId: String, fid: String = "ME", balance: Double = 1, height: Int64 = 1) -> TokenHolder {
        TokenHolder(fid: fid, tokenId: tokenId, balance: balance, lastHeight: height)
    }

    // MARK: - holdings

    func testHoldersRoundTripAndSortByHeight() throws {
        let session = try makeSessions().0
        let store = session.tokens

        try store.upsertHolder(holder("T1", height: 10))
        try store.upsertHolder(holder("T2", height: 30))
        try store.upsertHolder(holder("T3", height: 20))

        XCTAssertEqual(try store.allHolders().map(\.tokenId), ["T2", "T3", "T1"])
        XCTAssertEqual(try store.holder(fid: "ME", tokenId: "T2")?.lastHeight, 30)
    }

    /// A holder record the chain no longer returns is one this FID no
    /// longer has; keeping the last copy would show a balance that
    /// cannot be spent.
    func testReplaceDropsRowsTheChainStoppedReturning() throws {
        let session = try makeSessions().0
        let store = session.tokens

        try store.replaceHolders(with: [holder("T1"), holder("T2")])
        try store.replaceHolders(with: [holder("T2", balance: 7)])

        XCTAssertEqual(try store.allHolders().map(\.tokenId), ["T2"])
        XCTAssertEqual(try store.allHolders().first?.balance, 7)
    }

    /// Paging fetches a slice, and a slice must not delete everything
    /// above the cursor.
    func testMergeKeepsRowsOutsideThePage() throws {
        let session = try makeSessions().0
        let store = session.tokens

        try store.replaceHolders(with: [holder("T1"), holder("T2")])
        try store.mergeHolders([holder("T3")])
        XCTAssertEqual(Set(try store.allHolders().compactMap(\.tokenId)), ["T1", "T2", "T3"])
    }

    /// "When did this first appear here" has to survive the refresh
    /// that exists to update everything else.
    func testReplacePreservesAddedAt() throws {
        let session = try makeSessions().0
        let store = session.tokens

        try store.replaceHolders(with: [holder("T1")])
        let first = try XCTUnwrap(try store.allHolders().first?.addedAt)
        try store.replaceHolders(with: [holder("T1", balance: 99)])
        let again = try XCTUnwrap(try store.allHolders().first)
        XCTAssertEqual(again.addedAt, first)
        XCTAssertEqual(again.balance, 99)
    }

    // MARK: - hiding

    /// Hiding is a local decision about a *list*; it never touches the
    /// balance and it is not a carve.
    func testHidingRemovesARowFromTheListAndNothingElse() throws {
        let session = try makeSessions().0
        let store = session.tokens

        let h1 = holder("T1"), h2 = holder("T2")
        try store.replaceHolders(with: [h1, h2])
        try store.hideHolders(ids: [h1.id])

        XCTAssertEqual(try store.visibleHolders().map(\.tokenId), ["T2"])
        XCTAssertEqual(try store.allHolders().count, 2)
        XCTAssertEqual(try store.hiddenHolders().map(\.tokenId), ["T1"])

        try store.unhideHolders(ids: [h1.id])
        XCTAssertEqual(try store.visibleHolders().count, 2)
    }

    func testHidingIsIdempotentAndKeepsOrder() throws {
        let session = try makeSessions().0
        let store = session.tokens

        try store.hideTokens(ids: ["A", "B", ""])
        try store.hideTokens(ids: ["A", "C"])
        XCTAssertEqual(try store.load().hiddenTokenIds, ["A", "B", "C"])
    }

    /// A refresh may drop the cached row a hidden id points at. The
    /// decision must outlive the row, or the next refresh silently
    /// un-hides it.
    func testAHiddenIdSurvivesItsRowLeavingTheCache() throws {
        let session = try makeSessions().0
        let store = session.tokens

        let h1 = holder("T1")
        try store.replaceHolders(with: [h1])
        try store.hideHolders(ids: [h1.id])
        try store.replaceHolders(with: [])

        XCTAssertTrue(try store.hiddenHolders().isEmpty)
        XCTAssertEqual(try store.hiddenHolderIds(), [h1.id])

        try store.replaceHolders(with: [h1])
        XCTAssertTrue(try store.visibleHolders().isEmpty)
    }

    // MARK: - windows

    func testTokenAndHistoryWindowsAreBoundedAndHideable() throws {
        let session = try makeSessions().0
        let store = session.tokens

        let tokens = (0..<(TokensStore.maxCachedTokens + 50)).map { Token(id: "T\($0)") }
        try store.saveTokenWindow(tokens)
        XCTAssertEqual(try store.tokenWindow().count, TokensStore.maxCachedTokens)
        XCTAssertEqual(try store.tokenWindow().first?.id, "T0")

        try store.hideTokens(ids: ["T0"])
        XCTAssertEqual(try store.visibleTokenWindow().first?.id, "T1")
        XCTAssertEqual(try store.hiddenTokens().map(\.id), ["T0"])

        let history = (0..<(TokensStore.maxCachedHistory + 10)).map { TokenHistory(id: "H\($0)") }
        try store.saveHistoryWindow(history)
        XCTAssertEqual(try store.historyWindow().count, TokensStore.maxCachedHistory)

        // Saving one window must not clear the other, or the hidden
        // lists that share the blob with them.
        XCTAssertEqual(try store.tokenWindow().count, TokensStore.maxCachedTokens)
        XCTAssertEqual(try store.hiddenTokenIds(), ["T0"])
        XCTAssertNotNil(try store.load().savedAt)
    }

    /// Holdings are per-identity: what one main holds is not the other
    /// main's business, and the per-main vault key is what enforces it.
    func testHoldingsDoNotLeakBetweenMains() throws {
        let (a, b) = try makeSessions()
        try a.tokens.replaceHolders(with: [holder("T1", fid: "A")])
        try a.tokens.hideTokens(ids: ["T9"])

        XCTAssertTrue(try b.tokens.allHolders().isEmpty)
        XCTAssertTrue(try b.tokens.hiddenTokenIds().isEmpty)
        XCTAssertEqual(try a.tokens.allHolders().count, 1)
    }
}
