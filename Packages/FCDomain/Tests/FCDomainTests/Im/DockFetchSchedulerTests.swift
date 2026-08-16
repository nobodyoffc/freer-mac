import XCTest
@testable import FCDomain

/// The polling schedule: how often each lane asks, which servers each
/// one covers, and what happens when a pass is still running.
///
/// The scheduler's real clock is injected, so these run in milliseconds
/// while still asserting the intervals the app actually uses.
final class DockFetchSchedulerTests: XCTestCase {

    private let dockA = "fudp://dock.a:8500"
    private let dockB = "fudp://dock.b:8500"

    /// A scheduler whose sleeps are recorded and then collapsed to
    /// something a test can wait out.
    private func makeScheduler(
        spy: SchedulerSpy,
        collect: (@Sendable (MessageCourier.DockSelection) async -> MessageCourier.ReceiveReport)? = nil
    ) -> DockFetchScheduler {
        DockFetchScheduler(
            collect: { selection in
                spy.record(selection)
                if let collect { return await collect(selection) }
                return .init(fetched: 0, filed: 0, sealed: 0, other: 0)
            },
            report: { spy.record(report: $0) },
            sleep: { duration in
                spy.record(sleep: duration)
                try await Task.sleep(for: .milliseconds(2))
            }
        )
    }

    /// Wait until `condition` holds, or fail. Polling beats a fixed
    /// delay: the scheduler is genuinely concurrent, and a sleep long
    /// enough to be reliable would be long enough to be slow.
    private func eventually(
        _ description: String,
        timeout: TimeInterval = 2,
        _ condition: @escaping () -> Bool
    ) async {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if condition() { return }
            try? await Task.sleep(for: .milliseconds(5))
        }
        XCTFail("timed out waiting for: \(description)")
    }

    // MARK: - lifecycle

    /// Starting polls at once rather than after a full interval. A
    /// minute of empty inbox at launch reads as "receiving is broken".
    func testStartingRunsAPassImmediately() async {
        let spy = SchedulerSpy()
        let scheduler = makeScheduler(spy: spy)
        await scheduler.start()
        await eventually("an immediate pass") { spy.selections.contains(.all) }
        await scheduler.stop()
    }

    func testStoppingEndsPolling() async {
        let spy = SchedulerSpy()
        let scheduler = makeScheduler(spy: spy)
        await scheduler.start()
        await eventually("polling underway") { spy.selections.count >= 3 }
        await scheduler.stop()

        // Whatever was in flight may still land; nothing new must.
        try? await Task.sleep(for: .milliseconds(30))
        let settled = spy.selections.count
        try? await Task.sleep(for: .milliseconds(60))
        XCTAssertEqual(spy.selections.count, settled, "no passes after stop")
    }

    // MARK: - layers

    /// Each layer asks at its own rate, and the rates are Android's.
    func testEachLayerPollsAtItsOwnInterval() async {
        for (layer, expected) in [
            (DockFetchScheduler.Layer.active, DockFetchScheduler.activeInterval),
            (.normal, DockFetchScheduler.normalInterval),
            (.background, DockFetchScheduler.backgroundInterval),
        ] {
            let spy = SchedulerSpy()
            let scheduler = makeScheduler(spy: spy)
            await scheduler.setLayer(layer)
            await scheduler.start()
            await eventually("a \(layer) sleep") { spy.sleeps.contains(expected) }
            await scheduler.stop()
        }
    }

    /// Moving to a faster layer takes effect now, not after the slower
    /// interval it replaces has elapsed.
    func testChangingLayerRestartsTheIntervalImmediately() async {
        let spy = SchedulerSpy()
        let scheduler = makeScheduler(spy: spy)
        await scheduler.start()
        await eventually("the normal cadence") {
            spy.sleeps.contains(DockFetchScheduler.normalInterval)
        }

        await scheduler.setLayer(.active)
        await eventually("the active cadence, without waiting out a minute") {
            spy.sleeps.contains(DockFetchScheduler.activeInterval)
        }
        await scheduler.stop()
    }

    // MARK: - the two lanes

    /// The lanes are disjoint: the open conversation's DOCK is polled
    /// fast, and the normal lane skips it rather than asking the same
    /// server twice per cycle.
    func testThePriorityLaneIsExcludedFromTheNormalOne() async {
        let spy = SchedulerSpy()
        let scheduler = makeScheduler(spy: spy)
        await scheduler.start()
        await scheduler.setPriorityDock(dockA)

        await eventually("a fast-lane pass") { spy.selections.contains(.only([self.dockA])) }
        await eventually("a slow-lane pass that skips it") {
            spy.selections.contains(.excluding([self.dockA]))
        }
        await scheduler.stop()
    }

    /// Clearing the fast lane hands its server back to the normal one,
    /// rather than leaving it polled by nobody.
    func testClearingThePriorityLaneReturnsItsDockToTheNormalOne() async {
        let spy = SchedulerSpy()
        let scheduler = makeScheduler(spy: spy)
        await scheduler.start()
        await scheduler.setPriorityDock(dockA)
        await eventually("the fast lane running") { spy.selections.contains(.only([self.dockA])) }

        await scheduler.clearPriorityDocks()
        await eventually("the normal lane covering everything again") {
            spy.selections.contains(.excluding([]))
        }

        // A pass already on the wire when the lane was cleared still
        // lands — that is one wasted round trip, not a lane that is
        // still running. So the property is that fast-lane passes stop
        // *growing*, not that none is ever seen again.
        try? await Task.sleep(for: .milliseconds(40))
        let settled = spy.selections.filter { $0 == .only([self.dockA]) }.count
        try? await Task.sleep(for: .milliseconds(80))
        XCTAssertEqual(
            spy.selections.filter { $0 == .only([self.dockA]) }.count, settled,
            "the fast lane has stopped"
        )
        await scheduler.stop()
    }

    /// A priority DOCK is matched by endpoint, so the URL a `home` map
    /// spells and the one the registry stores are the same lane.
    func testAPriorityDockIsNormalisedBeforeUse() async {
        let spy = SchedulerSpy()
        let scheduler = makeScheduler(spy: spy)
        await scheduler.setPriorityDock("https://dock.a:8500/path")
        let docks = await scheduler.currentPriorityDocks
        XCTAssertEqual(docks, [dockA])
        _ = spy
    }

    // MARK: - passes

    /// A pass still in flight is a reason to skip this turn, not to run
    /// a second one against the same servers.
    func testAPassStillRunningIsNotOverlapped() async {
        let spy = SchedulerSpy()
        let concurrency = Concurrency()
        let scheduler = makeScheduler(spy: spy) { _ in
            concurrency.enter()
            try? await Task.sleep(for: .milliseconds(40))
            concurrency.leave()
            return .init(fetched: 0, filed: 0, sealed: 0, other: 0)
        }
        await scheduler.start()
        await eventually("several ticks to have come round") { spy.sleeps.count >= 4 }
        await scheduler.stop()
        XCTAssertEqual(concurrency.peak, 1, "never two passes at once")
    }

    /// A pass that filed something wakes the UI; an empty one does not
    /// — a redraw every few seconds that changes nothing is pure cost.
    func testOnlyAPassThatFiledSomethingIsReported() async {
        let spy = SchedulerSpy()
        let filed = Counter()
        let scheduler = makeScheduler(spy: spy) { _ in
            // Nothing the first time, something the second.
            filed.increment()
            return filed.value == 1
                ? .init(fetched: 0, filed: 0, sealed: 0, other: 0)
                : .init(fetched: 1, filed: 1, sealed: 0, other: 0)
        }
        await scheduler.start()
        await eventually("a report once something was filed") { spy.reports.count >= 1 }
        await scheduler.stop()

        XCTAssertTrue(spy.reports.allSatisfy { $0.filed > 0 || $0.sealed > 0 })
    }

    /// A sealed message is news too: it is the cue to go and ask for the
    /// key, so it must not be swallowed as an empty pass.
    func testASealedMessageCountsAsSomethingToReport() async {
        let spy = SchedulerSpy()
        let scheduler = makeScheduler(spy: spy) { _ in
            .init(fetched: 1, filed: 0, sealed: 1, other: 0)
        }
        await scheduler.start()
        await eventually("the sealed message to be reported") { spy.reports.count >= 1 }
        await scheduler.stop()
    }

    // MARK: - the outbox lane

    /// A send that failed transiently has backed off and is waiting for
    /// someone to try again. On a timer, "again" happens on its own;
    /// without one it means the next time the user presses a button,
    /// which makes a recoverable failure look permanent.
    func testTheOutboxIsRetriedOnItsOwnTimer() async {
        let spy = SchedulerSpy()
        let drains = Counter()
        let scheduler = DockFetchScheduler(
            collect: { _ in .none },
            drain: { drains.increment() },
            sleep: { duration in
                spy.record(sleep: duration)
                try await Task.sleep(for: .milliseconds(2))
            }
        )
        await scheduler.start()
        await eventually("the outbox to be drained") { drains.value >= 2 }
        XCTAssertTrue(
            spy.sleeps.contains(DockFetchScheduler.drainInterval),
            "at Android's 30s cadence"
        )
        await scheduler.stop()
    }

    /// A scheduler given no drain is a pure poller, and must not stall
    /// waiting for a lane that does not exist.
    func testAPollerWithoutADrainStillPolls() async {
        let spy = SchedulerSpy()
        let scheduler = makeScheduler(spy: spy)
        await scheduler.start()
        await eventually("polling regardless") { spy.selections.count >= 2 }
        XCTAssertFalse(spy.sleeps.contains(DockFetchScheduler.drainInterval))
        await scheduler.stop()
    }
}

// MARK: - spies

/// Records what the scheduler asked for. A lock rather than an actor:
/// the report callback is synchronous and cannot await.
private final class SchedulerSpy: @unchecked Sendable {
    private let lock = NSLock()
    private var _selections: [MessageCourier.DockSelection] = []
    private var _sleeps: [Duration] = []
    private var _reports: [MessageCourier.ReceiveReport] = []

    var selections: [MessageCourier.DockSelection] {
        lock.lock(); defer { lock.unlock() }; return _selections
    }
    var sleeps: [Duration] {
        lock.lock(); defer { lock.unlock() }; return _sleeps
    }
    var reports: [MessageCourier.ReceiveReport] {
        lock.lock(); defer { lock.unlock() }; return _reports
    }

    func record(_ selection: MessageCourier.DockSelection) {
        lock.lock(); _selections.append(selection); lock.unlock()
    }
    func record(sleep duration: Duration) {
        lock.lock(); _sleeps.append(duration); lock.unlock()
    }
    func record(report: MessageCourier.ReceiveReport) {
        lock.lock(); _reports.append(report); lock.unlock()
    }
    func reset() {
        lock.lock(); _selections = []; _sleeps = []; _reports = []; lock.unlock()
    }
}

/// Highest number of passes seen running at the same time.
private final class Concurrency: @unchecked Sendable {
    private let lock = NSLock()
    private var current = 0
    private var _peak = 0

    var peak: Int { lock.lock(); defer { lock.unlock() }; return _peak }

    func enter() {
        lock.lock()
        current += 1
        _peak = max(_peak, current)
        lock.unlock()
    }
    func leave() {
        lock.lock(); current -= 1; lock.unlock()
    }
}

private final class Counter: @unchecked Sendable {
    private let lock = NSLock()
    private var _value = 0
    var value: Int { lock.lock(); defer { lock.unlock() }; return _value }
    func increment() { lock.lock(); _value += 1; lock.unlock() }
}
