import Foundation

/// Buffered single-consumer channel for the receive pump → `receive()`
/// hand-off.
///
/// **Why not `AsyncStream`:** cancelling a task that is suspended on an
/// `AsyncStream` iterator *terminates the stream* — every later yield
/// is dropped and every later iteration ends immediately. The
/// timeout-sliced receive loops (idle-refreshed waits during file
/// transfers) cancel their wait on every slice, which would kill the
/// shared inbound channel on the first slice. This mailbox's waits are
/// plain continuations with a timeout task: an expired or abandoned
/// wait resumes with `nil` and the mailbox itself stays fully usable.
final class InboundMailbox<Element: Sendable>: @unchecked Sendable {

    private let lock = NSLock()
    private var buffer: [Element] = []
    private var finished = false
    private var waiter: (id: UInt64, continuation: CheckedContinuation<Element?, Never>)?
    private var nextWaiterId: UInt64 = 0

    /// Deliver one element: hands it to the parked waiter if any,
    /// otherwise buffers it (unbounded — the transfer protocols above
    /// bound the in-flight volume).
    func put(_ element: Element) {
        lock.lock()
        if let parked = waiter {
            waiter = nil
            lock.unlock()
            parked.continuation.resume(returning: element)
            return
        }
        buffer.append(element)
        lock.unlock()
    }

    /// Mark the channel closed. Buffered elements remain drainable;
    /// a parked waiter resumes with nil.
    func finish() {
        lock.lock()
        finished = true
        let parked = waiter
        waiter = nil
        lock.unlock()
        parked?.continuation.resume(returning: nil)
    }

    /// Next element, or nil once `timeoutMs` elapses with nothing
    /// arriving (or the mailbox is finished and drained). Single
    /// consumer: a second overlapping `next` evicts the first waiter
    /// (it resumes nil) rather than corrupting state.
    func next(timeoutMs: Int) async -> Element? {
        switch takeBufferedOrTicket() {
        case .value(let value):
            return value
        case .ticket(let id):
            return await withCheckedContinuation { (continuation: CheckedContinuation<Element?, Never>) in
                park(continuation, id: id)
                Task { [weak self] in
                    await QuietClock.sleep(milliseconds: max(1, timeoutMs))
                    self?.expireWaiter(id: id)
                }
            }
        }
    }

    // MARK: - private (all locking lives in sync functions)

    private enum Fetch {
        case value(Element?)
        case ticket(UInt64)
    }

    private func takeBufferedOrTicket() -> Fetch {
        lock.lock(); defer { lock.unlock() }
        if !buffer.isEmpty {
            return .value(buffer.removeFirst())
        }
        if finished {
            return .value(nil)
        }
        let id = nextWaiterId
        nextWaiterId += 1
        return .ticket(id)
    }

    private func park(_ continuation: CheckedContinuation<Element?, Never>, id: UInt64) {
        let evicted: CheckedContinuation<Element?, Never>?
        lock.lock()
        // Re-check: an element may have landed since the fast path.
        if !buffer.isEmpty {
            let value = buffer.removeFirst()
            lock.unlock()
            continuation.resume(returning: value)
            return
        }
        if finished {
            lock.unlock()
            continuation.resume(returning: nil)
            return
        }
        evicted = waiter?.continuation
        waiter = (id, continuation)
        lock.unlock()
        evicted?.resume(returning: nil)
    }

    private func expireWaiter(id: UInt64) {
        lock.lock()
        guard let parked = waiter, parked.id == id else {
            lock.unlock()
            return
        }
        waiter = nil
        lock.unlock()
        parked.continuation.resume(returning: nil)
    }
}
