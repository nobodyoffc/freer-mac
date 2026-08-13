import Foundation

/// Non-throwing sleep for background maintenance loops (retransmit
/// timer, mailbox timeouts, pacing).
///
/// `Task.sleep` throws `CancellationError` when its task is cancelled.
/// In fire-and-forget loops that error is meaningless — it gets
/// swallowed with `try?` — but the throw itself is still observed by
/// error-tracing hooks (XCTest's failure reporting among them), which
/// then mis-attribute a real failure elsewhere to the background
/// loop's cancellation. Sleeping on a dispatch timer never throws, so
/// the only throws in the process are real ones. Callers remain
/// cancellation-responsive by checking `Task.isCancelled` around the
/// sleep; durations here are all short or explicitly bounded.
enum QuietClock {

    static func sleep(nanoseconds: UInt64) async {
        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            DispatchQueue.global(qos: .utility).asyncAfter(
                deadline: .now() + .nanoseconds(Int(min(nanoseconds, UInt64(Int.max))))
            ) {
                continuation.resume()
            }
        }
    }

    static func sleep(milliseconds: Int) async {
        await sleep(nanoseconds: UInt64(max(0, milliseconds)) * 1_000_000)
    }
}
