import XCTest
@testable import FCDomain

/// The log the quiet paths write to.
final class SystemLogTests: XCTestCase {

    /// Newest first: the thing that just went wrong is the thing being
    /// looked for.
    func testEntriesComeBackNewestFirst() {
        let log = SystemLog()
        log.info("A", "first")
        log.warning("B", "second")
        log.error("C", "third")

        XCTAssertEqual(log.all.map(\.summary), ["third", "second", "first"])
        XCTAssertEqual(log.errorCount, 1)
    }

    /// Bounded, so a long session cannot grow it without limit — and it
    /// is the *oldest* that go.
    func testTheBufferIsBoundedAndDropsTheOldest() {
        let log = SystemLog()
        for index in 0..<(SystemLog.capacity + 25) {
            log.info("A", "entry-\(index)")
        }
        let all = log.all
        XCTAssertEqual(all.count, SystemLog.capacity)
        XCTAssertEqual(all.first?.summary, "entry-\(SystemLog.capacity + 24)", "newest kept")
        XCTAssertEqual(all.last?.summary, "entry-25", "oldest dropped")
    }

    /// Levels sort most-severe-first, which is what lets the pane filter
    /// with a single comparison.
    func testLevelsOrderBySeverity() {
        XCTAssertLessThan(SystemMessage.Level.error, .warning)
        XCTAssertLessThan(SystemMessage.Level.warning, .info)

        let log = SystemLog()
        log.error("A", "e")
        log.warning("A", "w")
        log.info("A", "i")
        // "Warnings and errors" is everything at or above .warning.
        let atLeastWarning = log.all.filter { $0.level <= .warning }
        XCTAssertEqual(Set(atLeastWarning.map(\.summary)), ["e", "w"])
    }

    /// The pane watches for entries that arrive while it is open, so a
    /// failure shows up without revisiting the page.
    func testObserversSeeNewEntries() {
        let log = SystemLog()
        let seen = Box()
        let token = log.observe { seen.append($0.summary) }

        log.error("A", "one")
        log.info("A", "two")
        XCTAssertEqual(seen.values, ["one", "two"])

        log.stopObserving(token)
        log.error("A", "three")
        XCTAssertEqual(seen.values, ["one", "two"], "and stop when told to")
    }

    /// An observer that reads the log back must not deadlock on the
    /// lock the write is holding — which it would if listeners were
    /// called inside it.
    func testAnObserverMayReadTheLogBack() {
        let log = SystemLog()
        let counted = Box()
        log.observe { _ in counted.append("\(log.all.count)") }

        log.error("A", "boom")
        XCTAssertEqual(counted.values, ["1"])
    }

    func testClearingEmptiesIt() {
        let log = SystemLog()
        log.error("A", "x")
        log.clear()
        XCTAssertTrue(log.all.isEmpty)
        XCTAssertEqual(log.errorCount, 0)
    }
}

private final class Box: @unchecked Sendable {
    private let lock = NSLock()
    private var storage: [String] = []

    var values: [String] { lock.lock(); defer { lock.unlock() }; return storage }
    func append(_ value: String) { lock.lock(); storage.append(value); lock.unlock() }
}
