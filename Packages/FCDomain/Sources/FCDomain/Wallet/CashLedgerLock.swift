import Foundation

/// Serializes the read-check-write that reserves cashes for a
/// transaction.
///
/// **Why a lock and not an actor.** The section it guards is
/// synchronous by construction — read the snapshot, verify nothing is
/// already claimed, flag the inputs, save — and deliberately contains
/// no `await`. Making it an actor would let the compiler interleave
/// other work at a suspension point that does not exist, and would
/// force every caller to be async for no benefit. The cost of getting
/// this wrong is a double-spend the node rejects, so the simplest
/// construct that actually excludes is the right one.
///
/// **One lock, not one per address.** Two identities never share a
/// cash, so per-address locking would be strictly more correct and
/// entirely pointless: the section is microseconds long and taken
/// once per transaction. A single lock is easier to reason about and
/// impossible to acquire in the wrong order.
///
/// The lock is never held across a network call, a signature, or a
/// user prompt — the three things in this app that can take seconds
/// or minutes. Claims are made before those steps and released after
/// them, by ``WalletService``.
enum CashLedgerLock {

    private static let lock = NSLock()

    static func withLock<T>(_ body: () throws -> T) rethrows -> T {
        lock.lock()
        defer { lock.unlock() }
        return try body()
    }
}
