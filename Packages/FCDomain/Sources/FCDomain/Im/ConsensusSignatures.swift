import Foundation
import FCStorage

/// A team whose consensus document changed under us, and which is now
/// waiting for this identity to sign the new one.
///
/// **This is derived from the chain, never from a message.** An owner
/// who carves a new `consensusId` does not notify anybody; the indexer
/// simply refills ``Team/notAgreeMembers`` with every non-owner member,
/// and that list — public, on chain, readable by anyone — *is* the
/// notification. Detecting it from a P2P message instead would fail in
/// all the ordinary ways: a member who was offline, reinstalled, or lost
/// the message would never learn they owe a signature, while the chain
/// goes on listing them as not having agreed.
///
/// Reading it from the chain also means the state **self-clears**. Sign
/// from another device, or get dismissed from the team, and the next
/// sync simply does not list us any more, so the row goes away without
/// anything having to acknowledge anything.
public struct ConsensusSignatureRequest: Codable, Equatable, Sendable, Identifiable {

    /// The team's id — and this row's, since a member owes at most one
    /// signature per team.
    public var id: String
    public var teamName: String?
    /// The consensus we are being asked to agree to. Advisory rather
    /// than authoritative: the parser compares an `agree consensus`
    /// against the team's id **at the moment the carve lands**, so a
    /// signature is always sent with a freshly-read id, never this one.
    public var consensusId: String?
    /// What the team's consensus was before this change.
    ///
    /// **The only moment this value exists is the instant before the
    /// cached team is overwritten.** The chain holds one consensus id —
    /// the current one — and no history a client can query, so a device
    /// that does not capture the old id here can never show a member
    /// what they are being asked to move *away from*. Legitimately nil
    /// when this device had never seen the team before.
    public var previousConsensusId: String?
    /// The DISK the team published when the previous consensus was
    /// current. Kept for the same reason as the id: a team that also
    /// moved its DISK leaves the old document on the old server, and
    /// this is the only record of which one that was.
    public var previousDiskSid: String?
    /// When this device first noticed, epoch ms.
    public var noticedAt: Int64?
    /// Set aside by the member. Still reachable, no longer nagging —
    /// a signature is a transaction, and "not right now" is a reasonable
    /// answer to being asked to pay for one.
    public var postponed: Bool?

    public init(
        id: String,
        teamName: String? = nil,
        consensusId: String? = nil,
        previousConsensusId: String? = nil,
        previousDiskSid: String? = nil,
        noticedAt: Int64? = nil,
        postponed: Bool? = nil
    ) {
        self.id = id
        self.teamName = teamName
        self.consensusId = consensusId
        self.previousConsensusId = previousConsensusId
        self.previousDiskSid = previousDiskSid
        self.noticedAt = noticedAt
        self.postponed = postponed
    }

    public var isPostponed: Bool { postponed ?? false }
}

/// Why a team carve was refused before it was broadcast.
///
/// Every one of these is a condition the indexer checks and rejects on,
/// and rejection is not free: the transaction confirms, the fee is
/// spent, and the team's state does not change. Catching them here costs
/// one read of the chain.
public enum TeamConsensusFailure: Error, Equatable, CustomStringConvertible {
    case noSuchTeam(String)
    case disbanded(String)
    case noConsensus(String)
    case nothingToSign(teamId: String, fid: String)
    case nobodyNewToInvite(alreadyIn: [String], alreadyInvited: [String])

    public var description: String {
        switch self {
        case .noSuchTeam:
            return "The chain has no record of this team. It may not have confirmed yet."
        case .disbanded:
            return "This team has been disbanded, so there is nothing left to agree to."
        case .noConsensus:
            return "This team names no consensus document, so there is nothing to sign."
        case .nothingToSign:
            return "The chain does not list you as owing a signature on this team. Either it already arrived — from another device, perhaps — or the owner has changed the consensus again since you were asked."
        case let .nobodyNewToInvite(alreadyIn, alreadyInvited):
            if !alreadyIn.isEmpty && alreadyInvited.isEmpty {
                return "Already in this team. An invite carve would cost a fee and change nothing."
            }
            if !alreadyInvited.isEmpty && alreadyIn.isEmpty {
                return "Already invited and not yet joined. Re-adding them to the invite list is the same set, so the carve would cost a fee and change nothing — they still have to join themselves."
            }
            return "Nobody here is new to this team, so the carve would cost a fee and change nothing."
        }
    }
}

/// The teams this identity owes a signature to, keyed by team id.
///
/// A cache of a chain fact, like ``TeamsStore`` — except for one field
/// that is not on the chain and cannot be recovered from it: the
/// **previous** consensus id. Losing this store therefore costs a
/// member the ability to read what they used to be agreed to, which is
/// why it is written on the sync that first notices rather than
/// recomputed on demand.
public struct ConsensusSignaturesStore {

    public static let namespace = "im.consensus.pending.v1"

    private let inner: TypedStore<ConsensusSignatureRequest>

    public init(kv: EncryptedKVStore) {
        self.inner = TypedStore(kv: kv, namespace: Self.namespace)
    }

    public func get(teamId: String) throws -> ConsensusSignatureRequest? {
        try inner.get(teamId)
    }

    public func upsert(_ request: ConsensusSignatureRequest) throws {
        guard !request.id.isEmpty else { throw GroupStoreFailure.noId }
        try inner.put(request, key: request.id)
    }

    /// Everything outstanding, oldest first — the order they became the
    /// member's problem.
    public func all() throws -> [ConsensusSignatureRequest] {
        try inner.all().map(\.value).sorted { ($0.noticedAt ?? 0) < ($1.noticedAt ?? 0) }
    }

    /// The ones still asking. Postponed rows stay in the store and out
    /// of this list.
    public func outstanding() throws -> [ConsensusSignatureRequest] {
        try all().filter { !$0.isPostponed }
    }

    @discardableResult
    public func postpone(teamId: String) throws -> Bool {
        guard var request = try get(teamId: teamId) else { return false }
        request.postponed = true
        try upsert(request)
        return true
    }

    @discardableResult
    public func remove(teamId: String) throws -> Bool {
        guard try inner.exists(teamId) else { return false }
        try inner.delete(teamId)
        return true
    }

    /// Fold one freshly-synced team into the store.
    ///
    /// Called from the sync **before and after** the team is written, so
    /// `cached` is the row about to be replaced. Everything this has to
    /// decide follows from one question — does the chain still list
    /// `fid` in `notAgreeMembers`?
    ///
    /// - **No** → drop any row. The signature landed, possibly from
    ///   another device; or the member left, or was dismissed; or the
    ///   owner reverted the change. None of those need acknowledging.
    /// - **Yes** → record it, and this is the one chance to capture
    ///   `cached.consensusId` before it is gone. A row that already
    ///   exists keeps its `postponed` flag and its previously captured
    ///   ids: a later sync of an unrelated field must not resurrect a
    ///   dismissed prompt, nor overwrite the old id with nothing.
    @discardableResult
    public func reconcile(
        team: Team,
        cached: Team?,
        as fid: String,
        now: Date = Date()
    ) throws -> ConsensusSignatureRequest? {
        guard let teamId = team.id, !teamId.isEmpty else { return nil }

        let owes = team.isActive
            && team.isMember(fid)
            && (team.notAgreeMembers?.contains(fid) ?? false)
        guard owes else {
            try remove(teamId: teamId)
            return nil
        }

        var request = try get(teamId: teamId)
            ?? ConsensusSignatureRequest(
                id: teamId,
                noticedAt: Int64(now.timeIntervalSince1970 * 1000)
            )
        request.teamName = team.displayName
        request.consensusId = team.consensusId

        // Only on the transition. A sync that changes nothing about the
        // consensus must not overwrite the captured id with the current
        // one, which would leave the member comparing a document to
        // itself.
        if let cached, let was = cached.consensusId, was != team.consensusId {
            request.previousConsensusId = was
            request.previousDiskSid = TeamConsensus.diskSid(of: cached)
        }
        try upsert(request)
        return request
    }
}
