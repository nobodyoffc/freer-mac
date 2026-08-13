import XCTest
import FCCore
import FCTransport
@testable import FCDomain

/// Query-surface tests for ``HatsStore`` — the Mac port of Android's
/// `HatManager`. The behaviours pinned here are the ones the Files pane
/// and the DISK sync path depend on: cipher HATs stay hidden, sorting
/// is by `last` descending, and paging is stable.
final class HatsStoreTests: XCTestCase {

    private var baseDir: URL!

    override func setUpWithError() throws {
        baseDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("HatsStoreTests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: baseDir, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        if let baseDir { try? FileManager.default.removeItem(at: baseDir) }
    }

    private func makeSession(label: String = "A", privkeyByte: UInt8 = 0xA1) throws -> ActiveSession {
        let mgr = try ConfigureManager(baseDirectory: baseDir)
        let configure = try mgr.createConfigure(
            password: Data("pwd-\(label)".utf8), kdfKind: .legacySha256
        )
        let info = try configure.addMain(privkey: Data(repeating: privkeyByte, count: 32), label: label)
        return try configure.unlockMain(fid: info.fid, fapi: MockFapiClient())
    }

    private func makeStore() throws -> HatsStore {
        try makeSession().hats
    }

    /// A raw HAT with a controlled `last`, so ordering assertions are
    /// deterministic (upsert bumps `last` unless we opt out).
    @discardableResult
    private func put(
        _ store: HatsStore,
        id: String,
        name: String? = nil,
        last: Int64,
        rawDid: String? = nil,
        locas: [String]? = nil,
        types: [String]? = nil,
        state: Hat.DataState? = nil
    ) throws -> Hat {
        let hat = Hat(
            last: last,
            name: name,
            types: types,
            rawDid: rawDid,
            state: state,
            locas: locas,
            id: id
        )
        return try store.upsert(hat, touch: false).wire
    }

    // MARK: - basics

    func testUpsertGetRemove() throws {
        let store = try makeStore()
        XCTAssertEqual(try store.count(), 0)

        try put(store, id: "a", name: "alpha.txt", last: 100)
        XCTAssertEqual(try store.count(), 1)
        XCTAssertEqual(try store.hat(id: "a")?.name, "alpha.txt")
        XCTAssertTrue(try store.exists(id: "a"))

        // Upsert replaces in place.
        try put(store, id: "a", name: "renamed.txt", last: 200)
        XCTAssertEqual(try store.count(), 1)
        XCTAssertEqual(try store.hat(id: "a")?.name, "renamed.txt")

        XCTAssertTrue(try store.remove(id: "a"))
        XCTAssertFalse(try store.remove(id: "a"))
        XCTAssertNil(try store.hat(id: "a"))
    }

    func testUpsertDerivesIdAndStampsTimestamps() throws {
        let store = try makeStore()
        // No id: the store must derive one the Android way.
        let record = try store.upsert(Hat(size: 5, name: "no-id.txt"))
        let id = try XCTUnwrap(record.wire.id)
        XCTAssertEqual(id.count, 64, "a derived DID is hex sha256x2")
        XCTAssertNotNil(record.wire.born)
        XCTAssertNotNil(record.wire.last)
        XCTAssertNotNil(try store.hat(id: id))

        // `born` is preserved across updates; `last` moves.
        let born = record.wire.born
        Thread.sleep(forTimeInterval: 0.002)
        let updated = try store.upsert(record.wire)
        XCTAssertEqual(updated.wire.born, born)
        XCTAssertGreaterThanOrEqual(updated.wire.last ?? 0, record.wire.last ?? 0)
    }

    func testSidecarSurvivesUpsertWhenNotSupplied() throws {
        let store = try makeStore()
        var local = HatLocal(appManagedCopy: true)
        local.setStamp(HatLocal.FileStamp(path: "/tmp/a.txt", size: 3, modifiedAtMs: 9))
        try store.upsert(Hat(name: "a.txt", id: "a"), local: local)

        // An update that says nothing about local state must not drop it.
        try store.upsert(Hat(name: "a-renamed.txt", id: "a"))
        let record = try XCTUnwrap(store.record(id: "a"))
        XCTAssertTrue(record.local.appManagedCopy)
        XCTAssertEqual(record.local.stamps["/tmp/a.txt"]?.size, 3)
        XCTAssertEqual(record.wire.name, "a-renamed.txt")
    }

    // MARK: - listing, sorting, paging

    func testSortedByLastDescHidesCipherHats() throws {
        let store = try makeStore()
        try put(store, id: "raw1", name: "one", last: 300)
        try put(store, id: "raw2", name: "two", last: 100)
        try put(store, id: "raw3", name: "three", last: 200)
        try put(store, id: "cipher1", last: 999, rawDid: "raw1")

        let listed = try store.sortedByLastDesc()
        XCTAssertEqual(listed.map(\.id), ["raw1", "raw3", "raw2"])
        XCTAssertEqual(try store.cipherHats().map(\.id), ["cipher1"])
        // The cipher HAT is still addressable directly.
        XCTAssertNotNil(try store.hat(id: "cipher1"))
    }

    /// Every stored row ends up with a `last`, even when the caller
    /// opts out of bumping it — Android's `preprocessEntity` always
    /// stamps one, and the Files pane's ordering depends on it.
    func testStoredHatAlwaysGetsALast() throws {
        let store = try makeStore()
        try store.upsert(Hat(name: "noLast", id: "noLast"), touch: false)
        XCTAssertNotNil(try store.hat(id: "noLast")?.last)
    }

    /// The comparator still sinks a `last`-less HAT, which is what
    /// protects the list if a foreign/legacy row ever arrives without
    /// one. Tested directly, since `upsert` makes it unreachable via
    /// the store.
    func testComparatorSinksHatsWithoutLast() {
        let withLast = Hat(last: 5, id: "withLast")
        let noLast = Hat(id: "noLast")
        XCTAssertTrue(HatsStore.byLastDescending(withLast, noLast))
        XCTAssertFalse(HatsStore.byLastDescending(noLast, withLast))

        let sorted = [noLast, withLast].sorted(by: HatsStore.byLastDescending)
        XCTAssertEqual(sorted.map(\.id), ["withLast", "noLast"])
    }

    /// Equal timestamps fall back to id so paging can't loop or skip.
    func testComparatorBreaksTiesById() {
        let a = Hat(last: 7, id: "aaa")
        let b = Hat(last: 7, id: "bbb")
        XCTAssertTrue(HatsStore.byLastDescending(b, a))
        XCTAssertFalse(HatsStore.byLastDescending(a, b))
    }

    func testPaginationByCursor() throws {
        let store = try makeStore()
        for i in 0..<10 {
            try put(store, id: "h\(i)", name: "file\(i)", last: Int64(100 - i))
        }
        let first = try store.sortedByLastDesc(pageSize: 4)
        XCTAssertEqual(first.map(\.id), ["h0", "h1", "h2", "h3"])

        let second = try store.sortedByLastDesc(pageSize: 4, afterId: "h3")
        XCTAssertEqual(second.map(\.id), ["h4", "h5", "h6", "h7"])

        let third = try store.sortedByLastDesc(pageSize: 4, afterId: "h7")
        XCTAssertEqual(third.map(\.id), ["h8", "h9"])

        // Past the end.
        XCTAssertTrue(try store.sortedByLastDesc(pageSize: 4, afterId: "h9").isEmpty)
    }

    func testPagingCursorThatNoLongerExistsStartsFromTop() throws {
        let store = try makeStore()
        try put(store, id: "a", last: 3)
        try put(store, id: "b", last: 2)
        let page = try store.sortedByLastDesc(pageSize: 2, afterId: "deleted-row")
        XCTAssertEqual(page.map(\.id), ["a", "b"])
    }

    // MARK: - search and filters

    func testSearchCoversEveryIndexedField() throws {
        let store = try makeStore()
        try put(store, id: "byname", name: "Report Q3.pdf", last: 10)
        try store.upsert(Hat(last: 9, desc: "quarterly numbers", id: "bydesc"), touch: false)
        try put(store, id: "bytype", last: 8, types: ["image/jpeg"])
        try put(store, id: "byloca", last: 7, locas: ["(sid)disk-service-7"])
        try store.upsert(Hat(last: 6, aids: ["freer-app"], id: "byaid"), touch: false)
        try store.upsert(Hat(last: 5, srcDid: "srcdid-marker", id: "bysrc"), touch: false)

        XCTAssertEqual(try store.search("report").map(\.id), ["byname"])
        XCTAssertEqual(try store.search("quarterly").map(\.id), ["bydesc"])
        XCTAssertEqual(try store.search("image/").map(\.id), ["bytype"])
        XCTAssertEqual(try store.search("disk-service").map(\.id), ["byloca"])
        XCTAssertEqual(try store.search("freer-app").map(\.id), ["byaid"])
        XCTAssertEqual(try store.search("srcdid-marker").map(\.id), ["bysrc"])
        // By id, and case-insensitively.
        XCTAssertEqual(try store.search("BYNAME").map(\.id), ["byname"])
        // Empty query matches nothing rather than everything.
        XCTAssertTrue(try store.search("   ").isEmpty)
    }

    func testSearchExcludesCipherHatsAndSortsByLast() throws {
        let store = try makeStore()
        try put(store, id: "old", name: "shared.txt", last: 100)
        try put(store, id: "new", name: "shared.txt", last: 500)
        try put(store, id: "cipher", name: "shared.txt", last: 999, rawDid: "new")

        XCTAssertEqual(try store.search("shared").map(\.id), ["new", "old"])
    }

    func testByStateAndModifiedSince() throws {
        let store = try makeStore()
        try put(store, id: "a", last: 100, state: .active)
        try put(store, id: "d", last: 200, state: .deleted)
        try put(store, id: "o", last: 300, state: .outdated)

        XCTAssertEqual(try store.byState(.deleted).map(\.id), ["d"])
        XCTAssertEqual(Set(try store.modifiedSince(150).map(\.id)), ["d", "o"])
        XCTAssertTrue(try store.modifiedSince(999).isEmpty)
    }

    func testByLocationPrefix() throws {
        let store = try makeStore()
        try put(store, id: "onDisk1", last: 3, locas: ["(sid)svc-1", "local:///tmp/a"])
        try put(store, id: "onDisk2", last: 2, locas: ["(sid)svc-2"])
        try put(store, id: "localOnly", last: 1, locas: ["local:///tmp/b"])

        XCTAssertEqual(Set(try store.byLocationPrefix("(sid)").map(\.id)), ["onDisk1", "onDisk2"])
        XCTAssertEqual(try store.byLocationPrefix("(sid)svc-2").map(\.id), ["onDisk2"])
        XCTAssertEqual(Set(try store.byLocationPrefix("local://").map(\.id)), ["onDisk1", "localOnly"])
        XCTAssertTrue(try store.byLocationPrefix("").isEmpty)
    }

    func testBySrcDid() throws {
        let store = try makeStore()
        try store.upsert(Hat(last: 3, srcDid: "lineage", id: "v1"), touch: false)
        try store.upsert(Hat(last: 2, srcDid: "lineage", id: "v2"), touch: false)
        try store.upsert(Hat(last: 1, srcDid: "other", id: "v3"), touch: false)
        XCTAssertEqual(Set(try store.bySrcDid("lineage").map(\.id)), ["v1", "v2"])
    }

    // MARK: - HatManager parity helpers

    func testAddLocaAndSetLocas() throws {
        let store = try makeStore()
        try put(store, id: "a", last: 1)

        try store.addLoca("local:///tmp/a", toId: "a")
        try store.addLoca("local:///tmp/a", toId: "a")   // idempotent
        XCTAssertEqual(try store.hat(id: "a")?.locas, ["local:///tmp/a"])

        try store.setLocas(["(sid)svc"], forId: "a")
        XCTAssertEqual(try store.hat(id: "a")?.locas, ["(sid)svc"])

        XCTAssertNil(try store.addLoca("x", toId: "missing"))
    }

    func testCreateCipherHatAndLink() throws {
        let store = try makeStore()
        try put(store, id: "raw", name: "photo.jpg", last: 1)

        let cipher = try store.createCipherHat(
            cipherId: "cipherdid",
            rawDid: "raw",
            kCipher: #"{"type":"AsyOneWay"}"#,
            size: 4096,
            locas: ["(sid)svc-1"]
        )
        XCTAssertTrue(cipher.isCipherHat)
        XCTAssertEqual(cipher.rawDid, "raw")
        XCTAssertEqual(cipher.size, 4096)

        try store.addCipherId("cipherdid", toRawId: "raw")
        XCTAssertEqual(try store.hat(id: "raw")?.cipherIds, ["cipherdid"])
        // The cipher HAT stays out of the file list.
        XCTAssertEqual(try store.sortedByLastDesc().map(\.id), ["raw"])
    }

    /// Receiving a HAT over IM must add the sender's key and DISK
    /// locations without discarding local `local://` paths — the bug
    /// `mergeImHatCredentials` exists to prevent.
    func testMergeIncomingKeepsLocalPathsAndAddsCredentials() throws {
        let store = try makeStore()
        try put(store, id: "shared", name: "a.txt", last: 1, locas: ["local:///tmp/mine"])

        let fromIm = Hat(
            key: "aabb",
            cipherIds: ["c1"],
            locas: ["(sid)svc-1"],
            id: "shared"
        )
        let merged = try XCTUnwrap(store.mergeIncoming(fromIm))
        XCTAssertEqual(merged.key, "aabb")
        XCTAssertEqual(merged.cipherIds, ["c1"])
        XCTAssertEqual(merged.locas, ["local:///tmp/mine", "(sid)svc-1"])
    }

    func testMergeIncomingInsertsWhenUnknown() throws {
        let store = try makeStore()
        let merged = try XCTUnwrap(store.mergeIncoming(Hat(name: "new.txt", key: "kk", id: "fresh")))
        XCTAssertEqual(merged.id, "fresh")
        XCTAssertEqual(try store.hat(id: "fresh")?.key, "kk")
    }

    func testMergeIncomingDoesNotOverwriteExistingKey() throws {
        let store = try makeStore()
        try store.upsert(Hat(key: "original", id: "x"))
        let merged = try XCTUnwrap(store.mergeIncoming(Hat(key: "other", id: "x")))
        XCTAssertEqual(merged.key, "original")
    }

    // MARK: - isolation

    /// Per-main vault keys must keep one identity's HATs invisible to
    /// another, same as every other store.
    func testHatsAreIsolatedPerIdentity() throws {
        let a = try makeSession(label: "A", privkeyByte: 0xA1)
        let b = try makeSession(label: "B", privkeyByte: 0xB2)
        try a.hats.upsert(Hat(name: "secret.txt", id: "only-in-a"))
        XCTAssertNotNil(try a.hats.hat(id: "only-in-a"))
        XCTAssertNil(try b.hats.hat(id: "only-in-a"))
        XCTAssertEqual(try b.hats.count(), 0)
    }
}
