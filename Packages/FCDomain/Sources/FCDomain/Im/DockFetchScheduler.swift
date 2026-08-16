import Foundation
import FCTransport

/// Polls the DOCKs on a timer, so messages arrive without anyone
/// pressing anything — the port of Android's `DockFetchScheduler`.
///
/// **Why polling at all.** DOCK is store-and-forward: the server holds
/// what arrived while we were away and says nothing when something new
/// lands. There is no push. So "receiving" is a question we have to keep
/// asking, and the only real design decision is *how often* — which is a
/// trade, not a constant. Ask too rarely and a live conversation feels
/// broken; ask too often and every idle group's server pays for it.
///
/// **Two lanes, three layers.** Android splits the answer the same way
/// and the split is worth keeping:
///
///   - The **priority lane** covers the DOCK of whatever conversation is
///     open, every ``priorityInterval``. It is a small set — usually one
///     server — so a fast cadence is cheap.
///   - The **normal lane** covers everything else at a rate that depends
///     on what the user is doing: ``Layer/active`` while a chat is on
///     screen, ``Layer/normal`` while the app is merely open,
///     ``Layer/background`` once it is not.
///
/// A DOCK in the priority lane is *excluded* from the normal one, so the
/// two lanes never ask the same server twice in a cycle.
///
/// **A third lane drains the outbox.** Android keeps that on its own
/// timer inside `MessageQueue` rather than in the scheduler, but it is
/// the same kind of thing and the same reason: a send that failed
/// transiently — a DOCK that was briefly down — has backed off and is
/// waiting for someone to try again. With nothing on a timer, "again"
/// means the next time the user presses a button, which makes a
/// recoverable failure look permanent.
///
/// **It owns the schedule and nothing else.** Every decision about what
/// a fetch means — which servers exist, where each one's cursor got to,
/// what to file and what to delete — belongs to ``MessageCourier`` and
/// ``DockRegistry``, and this drives them through one closure. That is
/// the one place it deliberately diverges from the Java: Android's
/// scheduler does its own fetching, paging and cursor-keeping because
/// nothing below it does, and duplicating that here would be a second
/// copy of the rules that could disagree with the first.
public actor DockFetchScheduler {

    /// How hard to poll everything that is not on screen.
    public enum Layer: String, Sendable, CaseIterable {
        /// A chat is open and being read.
        case active
        /// The app is open, but the user is elsewhere in it.
        case normal
        /// The app is not frontmost.
        case background

        var interval: Duration {
            switch self {
            case .active: return DockFetchScheduler.activeInterval
            case .normal: return DockFetchScheduler.normalInterval
            case .background: return DockFetchScheduler.backgroundInterval
            }
        }
    }

    public static let activeInterval: Duration = .seconds(10)
    public static let normalInterval: Duration = .seconds(60)
    public static let backgroundInterval: Duration = .seconds(180)
    public static let priorityInterval: Duration = .seconds(3)
    /// Matches Android's `MessageQueue.processPending` fixed delay.
    public static let drainInterval: Duration = .seconds(30)

    /// Runs one pass over the selected DOCKs. Supplied by the app shell,
    /// which owns the session the courier needs.
    public typealias Collect =
        @Sendable (MessageCourier.DockSelection) async -> MessageCourier.ReceiveReport

    /// Retries whatever in the outbox is due. Optional: a scheduler with
    /// no drain is a pure poller, which is what the receive-only tests
    /// want.
    public typealias Drain = @Sendable () async -> Void

    /// Told about every pass that filed something, so the UI can reload.
    /// Never called for an empty pass — a redraw every ten seconds that
    /// changes nothing is just a battery cost.
    public typealias Report = @Sendable (MessageCourier.ReceiveReport) -> Void

    private let collect: Collect
    private let drain: Drain?
    private let report: Report?
    /// Injected so tests can run a day of scheduling in microseconds.
    private let sleep: @Sendable (Duration) async throws -> Void

    private var layer: Layer = .normal
    private var priorityDocks: Set<String> = []
    private var running = false

    private var normalLoop: Task<Void, Never>?
    private var priorityLoop: Task<Void, Never>?
    private var drainLoop: Task<Void, Never>?
    private var draining = false

    /// Guards against a slow pass overlapping the next tick. A fetch
    /// that has not finished is not a reason to start a second one
    /// against the same servers — it is a reason to skip this turn.
    private var fetching = false

    public init(
        collect: @escaping Collect,
        drain: Drain? = nil,
        report: Report? = nil,
        sleep: @escaping @Sendable (Duration) async throws -> Void = {
            try await Task.sleep(for: $0)
        }
    ) {
        self.collect = collect
        self.drain = drain
        self.report = report
        self.sleep = sleep
    }

    // MARK: - lifecycle

    /// Begin polling. Runs one pass immediately, then settles into the
    /// current layer's interval.
    ///
    /// The immediate pass is a deliberate departure from the Java, which
    /// waits out a full interval first. On a desktop the scheduler
    /// starts when a vault is unlocked, and a minute of empty inbox
    /// before the first fetch reads as "receiving is broken" — which is
    /// exactly the impression this was written to remove.
    public func start() {
        guard !running else { return }
        running = true
        fetchNow()
        restartNormalLoop()
        restartPriorityLoop()
        restartDrainLoop()
    }

    /// Stop polling and drop the priority lane. Safe to call twice, and
    /// safe to call on a scheduler that never started.
    public func stop() {
        running = false
        normalLoop?.cancel()
        normalLoop = nil
        priorityLoop?.cancel()
        priorityLoop = nil
        drainLoop?.cancel()
        drainLoop = nil
        priorityDocks.removeAll()
    }

    public var isRunning: Bool { running }

    public var currentLayer: Layer { layer }

    public var currentPriorityDocks: Set<String> { priorityDocks }

    // MARK: - tuning

    /// Change how hard the normal lane polls. Takes effect at the next
    /// tick — the running interval is restarted, so moving to a faster
    /// layer does not wait out the slower one.
    public func setLayer(_ layer: Layer) {
        guard layer != self.layer else { return }
        self.layer = layer
        guard running else { return }
        restartNormalLoop()
    }

    /// Put these DOCKs on the fast lane, replacing whatever was there.
    /// Pass an empty set to clear it.
    ///
    /// Typically one URL: the server the open conversation lives on.
    public func setPriorityDocks(_ docks: Set<String>) {
        let normalized = Set(docks.compactMap { FudpUrl.normalize($0) })
        guard normalized != priorityDocks else { return }
        priorityDocks = normalized
        guard running else { return }
        // Both lanes change: one gains these servers, the other loses
        // them, and the exclusion has to be applied to the same set.
        restartPriorityLoop()
        restartNormalLoop()
    }

    public func setPriorityDock(_ dockUrl: String?) {
        setPriorityDocks(dockUrl.map { [$0] } ?? [])
    }

    public func clearPriorityDocks() {
        setPriorityDocks([])
    }

    /// Run a pass over every DOCK right now, without disturbing either
    /// lane's cadence. For "the user just asked", and for the moment a
    /// chat is opened.
    public func fetchNow() {
        Task { await self.runPass(.all) }
    }

    // MARK: - the loops

    private func restartNormalLoop() {
        normalLoop?.cancel()
        let interval = layer.interval
        normalLoop = Task { [weak self] in
            while !Task.isCancelled {
                guard let self else { return }
                do { try await self.sleepFor(interval) } catch { return }
                if Task.isCancelled { return }
                // Recomputed per tick: the priority set may have changed
                // while we slept, and the lanes must stay disjoint.
                await self.runPass(.excluding(self.currentPriorityDocks))
            }
        }
    }

    private func restartPriorityLoop() {
        priorityLoop?.cancel()
        guard !priorityDocks.isEmpty else {
            priorityLoop = nil
            return
        }
        priorityLoop = Task { [weak self] in
            while !Task.isCancelled {
                guard let self else { return }
                do { try await self.sleepFor(DockFetchScheduler.priorityInterval) } catch { return }
                if Task.isCancelled { return }
                await self.runPriorityPass()
            }
        }
    }

    private func restartDrainLoop() {
        drainLoop?.cancel()
        guard drain != nil else {
            drainLoop = nil
            return
        }
        drainLoop = Task { [weak self] in
            while !Task.isCancelled {
                guard let self else { return }
                do { try await self.sleepFor(DockFetchScheduler.drainInterval) } catch { return }
                if Task.isCancelled { return }
                await self.runDrain()
            }
        }
    }

    /// Retry what is due, skipped rather than queued if the last drain
    /// has not finished. Its own flag, not ``fetching``: a send and a
    /// collect touch different servers and there is no reason to make
    /// either wait for the other.
    private func runDrain() async {
        guard running, !draining, let drain else { return }
        draining = true
        defer { draining = false }
        await drain()
    }

    private func sleepFor(_ duration: Duration) async throws {
        try await sleep(duration)
    }

    /// Read the fast lane's servers and poll them without yielding in
    /// between.
    ///
    /// The two steps have to be one actor hop: read the set, `await`,
    /// then poll, and a chat closed in that window is polled anyway
    /// against a lane that no longer exists. It cannot be made airtight
    /// — a set cleared *during* a fetch is already on the wire — but a
    /// straggler mid-fetch is one wasted round trip, where a stale read
    /// would keep the fast lane alive for a whole further tick.
    private func runPriorityPass() async {
        let docks = priorityDocks
        guard !docks.isEmpty else { return }
        await runPass(.only(docks))
    }

    /// One pass, skipped rather than queued if another is still in
    /// flight.
    private func runPass(_ selection: MessageCourier.DockSelection) async {
        guard running, !fetching, !selection.isEmptySelection else { return }
        fetching = true
        defer { fetching = false }

        let result = await collect(selection)
        // Re-checked after the await: a pass that was on the wire when
        // the session was locked has still filed into a store nobody is
        // looking at, and waking the UI for it would redraw a screen
        // that is on its way out.
        guard running, result.filed > 0 || result.sealed > 0 else { return }
        report?(result)
    }
}
