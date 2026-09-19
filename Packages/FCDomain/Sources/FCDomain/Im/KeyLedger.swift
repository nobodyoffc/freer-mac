import Foundation
import FCCore
import FCStorage

/// One symkey that left this device, or arrived at it — or was asked for
/// and not given.
///
/// FIMP4V3 §9.7 / FIMP2V3 §8.7 require this record, and until now
/// neither client kept one. The reason it is required is that **a device
/// answers a key request automatically, without asking its user**: the
/// membership check is made silently, and the key handed over opens every
/// message under its version, including messages sent long before the
/// requester joined. That is intended — a joiner has to get the key from
/// somewhere — but it means a member's device gives away the group's
/// readable history on the strength of a check nobody watched.
///
/// Three questions have no other answer:
///
/// - **Leak radius.** FIMP §9.6 tells an owner to rotate when a key may
///   have leaked. Deciding that, and knowing who must be re-keyed, means
///   knowing who holds which version. The chain does not say: membership
///   is public, delivery is not, and the two differ whenever a push was
///   skipped, refused, or answered by a member instead of the owner.
///   ``KeyLedger/holders(of:version:)`` is that question.
/// - **Anomaly.** A device that answered a request its user did not
///   expect — from a FID added to the team without their knowledge —
///   leaves no other trace that the key left at all.
/// - **Provenance.** Whose copy of the conversation am I reading? A key
///   that came from a member rather than the owner is worth knowing
///   about, because the plaintext it produces is only as good as they are.
public struct KeyLedgerEntry: Codable, Equatable, Sendable, Identifiable {

    public enum Direction: String, Codable, Sendable {
        case sent
        case received
    }

    /// What actually happened. The refusals are recorded too, and are
    /// often the most useful rows a user has: a member asking again and
    /// again for a version nobody holds is a recovery that has stalled
    /// and that the owner can fix, and a non-member asking at all is the
    /// anomaly FIMP §9.2 warns about, arriving somewhere it can be seen.
    public enum Outcome: String, Codable, Sendable {
        /// Sent: sealed to them and queued.
        case shared
        /// Received and kept.
        case stored
        /// Received, but this exact key was already here. Not a fault —
        /// two members answering one request is ordinary.
        case duplicate
        /// Received and **not admitted**: an unsolicited key from
        /// somebody who is neither the owner nor us (FIMP §4.2).
        case refused
        /// Received, admitted, and the cipher would not open.
        case unreadable
        /// They asked for a version we do not hold.
        case notHeld
        /// They asked, and our record of the entity does not list them.
        case notAMember
        /// We have no pubkey to seal to, so there was nothing to send.
        case noPubkey
    }

    /// The room or team whose key this was.
    public var entityId: String
    /// The version, or ``KeyAsksStore/currentVersion`` when the event was
    /// about no particular one.
    public var version: Int64
    /// Who it went to, or came from.
    public var counterparty: String
    public var direction: Direction
    public var outcome: Outcome
    /// Whether it answered a request, or was a proactive push.
    public var solicited: Bool
    /// The request answered, when there was one.
    public var requestId: String?
    /// Milliseconds since the epoch, first occurrence.
    public var at: Int64
    /// Milliseconds since the epoch, most recent occurrence. Differs
    /// from ``at`` only for a coalesced row — see ``KeyLedger``.
    public var lastAt: Int64
    /// How many times this same event has happened since ``at``.
    public var repeats: Int

    public var id: String { KeyLedger.storageKey(for: self) }

    public init(
        entityId: String,
        version: Int64,
        counterparty: String,
        direction: Direction,
        outcome: Outcome,
        solicited: Bool,
        requestId: String? = nil,
        at: Int64,
        lastAt: Int64? = nil,
        repeats: Int = 1
    ) {
        self.entityId = entityId
        self.version = version
        self.counterparty = counterparty
        self.direction = direction
        self.outcome = outcome
        self.solicited = solicited
        self.requestId = requestId
        self.at = at
        self.lastAt = lastAt ?? at
        self.repeats = repeats
    }
}

/// Where every symkey this device gave away or took in is written down.
///
/// **Local, and it never leaves.** It is a map of who can read what, and
/// it is more sensitive than the membership it derives from: membership is
/// already on the chain, while this is recoverable from no public source.
/// It is never put on a DOCK, never in a `HISTORY` response, and never in
/// an export or backup shared with a peer. Nothing in this codebase walks
/// namespaces, so that holds by construction rather than by vigilance —
/// and a test asserts it.
///
/// **Not a ring buffer.** FIMP §9.7 is explicit, and the reason is that
/// the row which matters after a suspected compromise is characteristically
/// the *oldest* one, which is exactly what a bounded diagnostic log has
/// already dropped. So nothing here expires, and there is no cap.
///
/// What keeps that safe is ``coalesceWindow`` rather than a limit. An
/// admitted key costs its sender a request we made or ownership of the
/// entity (FIMP §4.2), so those rows are bounded by honest activity — but
/// a **refusal** costs an attacker only the sending, and a member pushing
/// junk keys in a loop would otherwise write a row per attempt. Repeats of
/// the same event inside the window bump a counter on the row that is
/// already there. The signal a person needs — "Carol keeps pushing keys at
/// me" — is preserved exactly, at one row an hour instead of thousands.
public struct KeyLedger {

    public static let namespace = "im.keyledger.v1"

    /// Identical events inside this window fold into one row, carrying a
    /// ``KeyLedgerEntry/repeats`` count. See the type's note.
    public static let coalesceWindow: TimeInterval = 3600

    private let inner: TypedStore<KeyLedgerEntry>

    public init(kv: EncryptedKVStore) {
        self.inner = TypedStore(kv: kv, namespace: Self.namespace)
    }

    /// `<19-digit ms>_<12 hex of the event's identity>`.
    ///
    /// The timestamp leads so the row order is the time order and a
    /// listing needs no sort. The digest makes two different events in
    /// one millisecond distinct, and makes the *same* event in the same
    /// millisecond the same row — so a replayed delivery cannot write
    /// twice.
    static func storageKey(for entry: KeyLedgerEntry) -> String {
        let identity = [
            entry.entityId,
            String(entry.version),
            entry.counterparty,
            entry.direction.rawValue,
            entry.outcome.rawValue,
            entry.solicited ? "1" : "0",
        ].joined(separator: "\u{1F}")
        let digest = Hash.sha256(Data(identity.utf8))
            .prefix(6)
            .map { String(format: "%02x", $0) }
            .joined()
        return String(format: "%019lld", entry.at) + "_" + digest
    }

    // MARK: - writing

    /// Write one event down, or fold it into the identical one already
    /// there. Returns the row as it now stands.
    @discardableResult
    public func record(
        entityId: String,
        version: Int64,
        counterparty: String,
        direction: KeyLedgerEntry.Direction,
        outcome: KeyLedgerEntry.Outcome,
        solicited: Bool,
        requestId: String? = nil,
        now: Date = Date()
    ) throws -> KeyLedgerEntry {
        let stamp = Int64(now.timeIntervalSince1970 * 1000)
        var entry = KeyLedgerEntry(
            entityId: entityId,
            version: version,
            counterparty: counterparty,
            direction: direction,
            outcome: outcome,
            solicited: solicited,
            requestId: requestId,
            at: stamp
        )

        if var recent = try mostRecent(matching: entry),
           stamp - recent.lastAt <= Int64(Self.coalesceWindow * 1000) {
            recent.lastAt = stamp
            recent.repeats += 1
            // The newest id answered wins: it is the one a reader chasing
            // this row would look for.
            if let requestId { recent.requestId = requestId }
            try inner.put(recent, key: Self.storageKey(for: recent))
            return recent
        }

        // A second identical event inside one millisecond is the same
        // row, so folding it is the only correct answer.
        if var existing = try inner.get(Self.storageKey(for: entry)) {
            existing.lastAt = stamp
            existing.repeats += 1
            entry = existing
        }
        try inner.put(entry, key: Self.storageKey(for: entry))
        return entry
    }

    /// The newest row describing the same event, whenever it was.
    private func mostRecent(matching entry: KeyLedgerEntry) throws -> KeyLedgerEntry? {
        try inner.all()
            .map(\.value)
            .filter {
                $0.entityId == entry.entityId
                    && $0.version == entry.version
                    && $0.counterparty == entry.counterparty
                    && $0.direction == entry.direction
                    && $0.outcome == entry.outcome
                    && $0.solicited == entry.solicited
            }
            .max { $0.lastAt < $1.lastAt }
    }

    // MARK: - reading

    /// Everything recorded, newest first.
    public func all(limit: Int? = nil) throws -> [KeyLedgerEntry] {
        let rows = try inner.all().map(\.value).sorted { $0.lastAt > $1.lastAt }
        guard let limit else { return rows }
        return Array(rows.prefix(limit))
    }

    /// One entity's rows, newest first — what the member list shows.
    public func entries(for entityId: String, limit: Int? = nil) throws -> [KeyLedgerEntry] {
        let rows = try all().filter { $0.entityId == entityId }
        guard let limit else { return rows }
        return Array(rows.prefix(limit))
    }

    public func count() throws -> Int {
        try inner.keys().count
    }

    /// **Who we know can read this entity** — everyone we gave a key to,
    /// and everyone who gave us one.
    ///
    /// This is the leak-radius question of FIMP §9.7, and the answer is
    /// deliberately not "the membership": a member the owner never
    /// managed to push to cannot read anything, and a FID that was
    /// removed from the group still holds every version it was given.
    /// Only this record knows the difference.
    ///
    /// `version` nil asks about every version.
    public func holders(of entityId: String, version: Int64? = nil) throws -> [String] {
        var seen: Set<String> = []
        return try entries(for: entityId)
            .filter { row in
                guard row.outcome == .shared || row.outcome == .stored
                        || row.outcome == .duplicate
                else { return false }
                return version == nil || row.version == version
            }
            .compactMap { seen.insert($0.counterparty).inserted ? $0.counterparty : nil }
    }

    /// The versions we have a record of handing to `fid`.
    public func versionsGiven(to fid: String, of entityId: String) throws -> [Int64] {
        Set(
            try entries(for: entityId)
                .filter { $0.counterparty == fid && $0.direction == .sent && $0.outcome == .shared }
                .map(\.version)
        )
        .sorted()
    }

    // MARK: - deleting

    /// Forget one entity's rows.
    ///
    /// **Nothing calls this as housekeeping.** FIMP §9.7 says to keep the
    /// record at least as long as the keys, so this exists for the one
    /// case that outlives them: a user deleting a group outright, where
    /// keeping a map of who could read a conversation they have erased
    /// would be its own disclosure.
    @discardableResult
    public func removeAll(for entityId: String) throws -> Int {
        var removed = 0
        for (key, row) in try inner.all() where row.entityId == entityId {
            try inner.delete(key)
            removed += 1
        }
        return removed
    }
}
