import XCTest
import FCCore
import FCTransport
@testable import FCDomain

/// The cached feed window: round-trip, the forward-only watermark, the
/// bound on how much survives a restart, and the per-identity split.
final class NewsStoreTests: XCTestCase {

    private var baseDir: URL!

    override func setUpWithError() throws {
        baseDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("NewsStoreTests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: baseDir, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        if let baseDir { try? FileManager.default.removeItem(at: baseDir) }
    }

    private func makeTwoSessions() throws -> (ActiveSession, ActiveSession) {
        let mgr = try ConfigureManager(baseDirectory: baseDir)
        let configure = try mgr.createConfigure(
            password: Data("shared-pwd".utf8), kdfKind: .legacySha256
        )
        let aInfo = try configure.addMain(privkey: Data(repeating: 0xA1, count: 32), label: "A")
        let bInfo = try configure.addMain(privkey: Data(repeating: 0xB2, count: 32), label: "B")
        return (
            try configure.unlockMain(fid: aInfo.fid, fapi: MockFapiClient()),
            try configure.unlockMain(fid: bInfo.fid, fapi: MockFapiClient())
        )
    }

    private func rows(_ n: Int) -> [News] {
        (0..<n).map { News(height: Int64(900_000 + $0), time: Int64(1_770_000_000 + $0), id: "news-\($0)") }
    }

    func testEmptyOnFirstRun() throws {
        let (a, _) = try makeTwoSessions()

        let cache = try a.newsCache.load()

        XCTAssertTrue(cache.news.isEmpty)
        XCTAssertNil(cache.lastSeenHeight)
        XCTAssertNil(cache.savedAt)
    }

    func testSaveRoundTripsAndStamps() throws {
        let (a, _) = try makeTwoSessions()

        try a.newsCache.save(news: rows(3), bestHeight: 900_150)
        let cache = try a.newsCache.load()

        XCTAssertEqual(cache.news.map(\.id), ["news-0", "news-1", "news-2"])
        XCTAssertEqual(cache.lastSeenHeight, 900_150)
        XCTAssertNotNil(cache.savedAt)
    }

    /// A dot means "arrived since you last looked" — a fact about a
    /// session, not something to reload days later.
    func testIsNewIsStrippedOnTheWayIn() throws {
        let (a, _) = try makeTwoSessions()
        var item = News(height: 900_100, time: 1_770_000_000, id: "news-0")
        item.isNew = true

        try a.newsCache.save(news: [item])

        XCTAssertNil(try a.newsCache.load().news.first?.isNew)
    }

    /// A reply from a lagging server must not re-light items this
    /// device has already shown.
    func testWatermarkOnlyMovesForward() throws {
        let (a, _) = try makeTwoSessions()

        try a.newsCache.save(news: rows(1), bestHeight: 900_150)
        try a.newsCache.save(news: rows(1), bestHeight: 900_100)
        XCTAssertEqual(try a.newsCache.lastSeenHeight(), 900_150)

        try a.newsCache.save(news: rows(1), bestHeight: nil)
        XCTAssertEqual(try a.newsCache.lastSeenHeight(), 900_150)

        try a.newsCache.save(news: rows(1), bestHeight: 900_200)
        XCTAssertEqual(try a.newsCache.lastSeenHeight(), 900_200)
    }

    func testWindowIsCappedAtMaxCachedNews() throws {
        let (a, _) = try makeTwoSessions()
        let cap = NewsStore.maxCachedNews

        try a.newsCache.save(news: rows(cap + 40))
        let cached = try a.newsCache.load().news

        XCTAssertEqual(cached.count, cap)
        // Kept from the top: the newest end of the feed.
        XCTAssertEqual(cached.first?.id, "news-0")
        XCTAssertEqual(cached.last?.id, "news-\(cap - 1)")
    }

    func testClearRemovesTheWindowAndTheWatermark() throws {
        let (a, _) = try makeTwoSessions()
        try a.newsCache.save(news: rows(3), bestHeight: 900_150)

        try a.newsCache.clear()

        XCTAssertTrue(try a.newsCache.load().news.isEmpty)
        XCTAssertNil(try a.newsCache.lastSeenHeight())
    }

    /// The feed is the same chain for everyone; "what have I seen" is
    /// not, and this store is on the per-main encrypted DB.
    func testWatermarkIsPerIdentity() throws {
        let (a, b) = try makeTwoSessions()

        try a.newsCache.save(news: rows(2), bestHeight: 900_150)

        XCTAssertNil(try b.newsCache.lastSeenHeight())
        XCTAssertTrue(try b.newsCache.load().news.isEmpty)
    }
}
