import Foundation

/// Whether the sender of a square message is one of the square's members —
/// the receiver's check in FIMP3V2 §8.
///
/// **The DOCK does not check.** It stores and serves items by recipient id
/// and asks nobody's membership, so anyone can post to a square's id and
/// anyone can read it. Keeping only members' messages is therefore up to
/// each receiver, and this is where this one does it.
///
/// **A member list can be stale, so a stranger is asked about once.** The
/// squares store is refreshed by the membership sync, which runs now and
/// then, while a new member can post the minute their join confirms. So a
/// sender the local copy does not list triggers one read of the square
/// from the chain before the message is dropped. That read is remembered,
/// and repeated only for an item stored after it — which is what stops a
/// stream of posts from a non-member turning into a stream of lookups,
/// while a member who joined after the read is still asked about again.
///
/// **What this does not stop.** Messages are not signed, so the sender is
/// the FID the message names. A non-member who writes a member's FID into
/// the sender field gets through. This removes posts from people who never
/// joined — spam, and joins that have not confirmed — not forgeries.
public actor SquareRoster {

    public enum Answer: Equatable, Sendable {
        case member
        case notMember
        /// The chain could not be asked. Nothing is decided.
        case unknown
    }

    /// The square as the squares store holds it, or nil.
    private let local: @Sendable (String) -> Square?

    private var fresh: [String: (square: Square?, readAt: Int64)] = [:]

    public init(local: @escaping @Sendable (String) -> Square?) {
        self.local = local
    }

    /// - parameters:
    ///   - storedAt: when the DOCK took the item, in epoch ms. An item
    ///     stored after the last chain read is worth another one.
    ///   - fetch: reads the square from the chain. Passed per call rather
    ///     than kept, because the FAPI client behind it is replaced when
    ///     the server changes and this roster outlives it. Nil means the
    ///     chain holds no such square; a throw means it could not be asked.
    public func check(
        sender: String,
        squareId: String,
        storedAt: Int64?,
        now: Date = Date(),
        fetch: @Sendable (String) async throws -> Square?
    ) async -> Answer {
        if local(squareId)?.isMember(sender) == true { return .member }

        let nowMs = Int64(now.timeIntervalSince1970 * 1000)
        if let cached = fresh[squareId] {
            if cached.square?.isMember(sender) == true { return .member }
            // No store time is no evidence of anything newer.
            guard let storedAt, storedAt > cached.readAt else { return .notMember }
        }
        do {
            let square = try await fetch(squareId)
            fresh[squareId] = (square, nowMs)
            return square?.isMember(sender) == true ? .member : .notMember
        } catch {
            return .unknown
        }
    }
}
