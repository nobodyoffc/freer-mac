import Foundation
import FCStorage

/// A team this identity owns, from which members have gone since the
/// key last changed — FIMP4V3 §3.3.
///
/// **Derived from the chain, never from a message.** A manager can
/// dismiss and a member can leave, but only the owner can mint, so the
/// owner is the one who has to hear about it. Nobody sends a reminder:
/// the removal is on chain, and the owner's own team sync is what sees
/// it, whoever signed it — including a `leave` no manager took part in.
///
/// **A prompt, never a rotation.** FIMP4V3 §7.2 forbids rotating on
/// sight of an on-chain event: every one of the owner's devices would
/// mint in the same second. Rotating stays the owner's own act, through
/// ``TeamKeyService/resetSymkey(for:as:pubkeys:homes:now:)``.
///
/// Mirrors Android's `KEY_ROTATION_DUE` pending issue.
public struct KeyRotationReminder: Codable, Equatable, Sendable, Identifiable {

    /// The team's id — and this row's: one reminder per team gathers
    /// every removal until the owner acts.
    public var id: String
    public var teamName: String?
    /// Everyone who left `members` since this reminder was raised, in
    /// the order they were noticed.
    public var removedFids: [String]
    /// When this device first noticed, epoch ms. A key minted at or
    /// after this moment is the rotation the reminder asks for.
    public var noticedAt: Int64
    /// Set aside by the owner. A further removal brings it back.
    public var postponed: Bool?

    public init(
        id: String,
        teamName: String? = nil,
        removedFids: [String] = [],
        noticedAt: Int64,
        postponed: Bool? = nil
    ) {
        self.id = id
        self.teamName = teamName
        self.removedFids = removedFids
        self.noticedAt = noticedAt
        self.postponed = postponed
    }

    public var isPostponed: Bool { postponed ?? false }
}

/// The owner's due key rotations, keyed by team id.
public struct KeyRotationRemindersStore {

    public static let namespace = "im.keyrotation.due.v1"

    private let inner: TypedStore<KeyRotationReminder>

    public init(kv: EncryptedKVStore) {
        self.inner = TypedStore(kv: kv, namespace: Self.namespace)
    }

    public func get(teamId: String) throws -> KeyRotationReminder? {
        try inner.get(teamId)
    }

    public func upsert(_ reminder: KeyRotationReminder) throws {
        guard !reminder.id.isEmpty else { throw GroupStoreFailure.noId }
        try inner.put(reminder, key: reminder.id)
    }

    /// Everything open, oldest first.
    public func all() throws -> [KeyRotationReminder] {
        try inner.all().map(\.value).sorted { $0.noticedAt < $1.noticedAt }
    }

    /// The ones still asking. Postponed rows stay in the store.
    public func outstanding() throws -> [KeyRotationReminder] {
        try all().filter { !$0.isPostponed }
    }

    @discardableResult
    public func postpone(teamId: String) throws -> Bool {
        guard var reminder = try get(teamId: teamId) else { return false }
        reminder.postponed = true
        try upsert(reminder)
        return true
    }

    /// Drop a team's reminder — the key was rotated, or the team is no
    /// longer ours to rotate.
    @discardableResult
    public func remove(teamId: String) throws -> Bool {
        guard try inner.exists(teamId) else { return false }
        try inner.delete(teamId)
        return true
    }

    /// Fold one freshly-synced team into the store.
    ///
    /// `cached` is the row about to be replaced: only a copy this device
    /// already had can show who is gone, so a first sight of a team
    /// raises nothing. `currentVersion` is the newest symkey version
    /// held for the team, which is its mint time in seconds (FIMP0
    /// §Symkey id).
    ///
    /// - Not the owner any more, or disbanded → drop the row.
    /// - A key minted at or after the reminder was raised → drop it.
    ///   That covers a rotation from another of the owner's devices. A
    ///   key minted *before* the removal confirmed does not count: it
    ///   went to a member list that still had the removed FID in it.
    /// - Members gone since `cached` → add them, and un-postpone, since
    ///   a further removal is new information.
    @discardableResult
    public func reconcile(
        team: Team,
        cached: Team?,
        as fid: String,
        currentVersion: Int64,
        now: Date = Date()
    ) throws -> KeyRotationReminder? {
        guard let teamId = team.id, !teamId.isEmpty else { return nil }

        guard team.owner == fid, team.isActive else {
            try remove(teamId: teamId)
            return nil
        }

        var reminder = try get(teamId: teamId)
        if let open = reminder, currentVersion * 1000 >= open.noticedAt {
            try remove(teamId: teamId)
            reminder = nil
        }

        let remaining = Set(team.members ?? [])
        let removed = (cached?.members ?? []).filter { $0 != fid && !remaining.contains($0) }
        let added = removed.filter { !(reminder?.removedFids.contains($0) ?? false) }
        guard !added.isEmpty else { return reminder }

        var row = reminder ?? KeyRotationReminder(
            id: teamId,
            noticedAt: Int64(now.timeIntervalSince1970 * 1000)
        )
        row.removedFids += added
        row.teamName = team.displayName
        row.postponed = nil
        try upsert(row)
        return row
    }
}
