import Foundation
import FCStorage

/// A team that wants this identity in it — invited to join, or offered
/// ownership — and has not had an answer yet.
///
/// The port of two Android pieces that answer one question between
/// them: `JoinTeamActivity`'s invitation and pending-transfer lists (read
/// from the chain, with an ignore set) and the `TEAM_INVITE` pending
/// issue a notice raises. Here they are one row, because they are one
/// thing seen from two directions.
///
/// **The chain is the authority; a notice is a hint.** A row the chain
/// lists is ``onChain``. A row that exists only because somebody sent a
/// ``TeamNotice`` is not, and nothing may be carved on its strength: the
/// invitation it announces may not have confirmed yet, or may never have
/// existed, since anybody can send a notice naming any team.
public struct TeamOffer: Codable, Equatable, Sendable, Identifiable {

    public typealias Kind = TeamNotice.Kind

    /// The identity this offer is for. Kept on the row because one
    /// vault holds several identities and an invitation to one of them
    /// is not an invitation to the others.
    public var fid: String
    public var teamId: String
    /// A transfer outranks an invitation: taking a team over also makes
    /// the taker a member, so a team offering both is offering the
    /// larger thing.
    public var kind: Kind
    public var teamName: String?
    public var owner: String?
    public var memberNum: Int64?
    public var consensusId: String?
    /// The DISK the team publishes its consensus document on, so the
    /// document can be read before agreeing to it.
    public var diskSid: String?
    /// Who sent the notice, when one arrived. **Not** proof of anything
    /// about the team — it is who this device heard it from.
    public var notifiedBy: String?
    /// Whether the last chain read listed it.
    public var onChain: Bool?
    /// When this device first learned of it, epoch ms.
    public var noticedAt: Int64
    /// Set aside. Kept, so a resent notice does not raise it again, and
    /// reversible.
    public var ignored: Bool?
    /// When a join or a take-over was broadcast for it, epoch ms. The
    /// row hides while that confirms, and the chain removes it after.
    public var answeredAt: Int64?

    public var id: String { TeamOffersStore.key(fid: fid, teamId: teamId) }

    public var isOnChain: Bool { onChain ?? false }
    public var isIgnored: Bool { ignored ?? false }

    public init(
        fid: String,
        teamId: String,
        kind: Kind,
        teamName: String? = nil,
        owner: String? = nil,
        memberNum: Int64? = nil,
        consensusId: String? = nil,
        diskSid: String? = nil,
        notifiedBy: String? = nil,
        onChain: Bool? = nil,
        noticedAt: Int64,
        ignored: Bool? = nil,
        answeredAt: Int64? = nil
    ) {
        self.fid = fid
        self.teamId = teamId
        self.kind = kind
        self.teamName = teamName
        self.owner = owner
        self.memberNum = memberNum
        self.consensusId = consensusId
        self.diskSid = diskSid
        self.notifiedBy = notifiedBy
        self.onChain = onChain
        self.noticedAt = noticedAt
        self.ignored = ignored
        self.answeredAt = answeredAt
    }

    /// Whether this offer is waiting for a person: not set aside, and not
    /// answered recently enough that the answer may still be confirming.
    public func isWaiting(now: Date) -> Bool {
        guard !isIgnored else { return false }
        guard let answeredAt else { return true }
        return Self.millis(now) - answeredAt >= TeamOffersStore.answeredHideMs
    }

    static func millis(_ date: Date) -> Int64 { Int64(date.timeIntervalSince1970 * 1000) }
}

/// Offers of team membership and ownership, per identity.
public struct TeamOffersStore {

    public static let namespace = "im.team.offers.v1"

    /// How long an answered offer stays hidden. Android's is the same
    /// 24 hours: long enough for a join to confirm, short enough that a
    /// carve which never made it does not bury the invitation.
    public static let answeredHideMs: Int64 = 24 * 60 * 60 * 1000
    /// How long a notice the chain never confirmed is kept. An invite
    /// carve confirms in minutes; one that has not appeared in a week is
    /// not coming.
    public static let unconfirmedLifetimeMs: Int64 = 7 * 24 * 60 * 60 * 1000
    /// The most unconfirmed notices kept per identity. A notice costs its
    /// sender nothing but a DOCK put, so without a bound a stranger could
    /// fill this store; the oldest are dropped first.
    public static let maxUnconfirmed = 50

    private let inner: TypedStore<TeamOffer>

    public init(kv: EncryptedKVStore) {
        self.inner = TypedStore(kv: kv, namespace: Self.namespace)
    }

    static func key(fid: String, teamId: String) -> String { "\(fid)|\(teamId)" }

    public func get(fid: String, teamId: String) throws -> TeamOffer? {
        try inner.get(Self.key(fid: fid, teamId: teamId))
    }

    public func upsert(_ offer: TeamOffer) throws {
        guard !offer.fid.isEmpty, !offer.teamId.isEmpty else { throw GroupStoreFailure.noId }
        try inner.put(offer, key: offer.id)
    }

    /// Every offer for `fid`, newest first — ignored and answered ones
    /// included, for a sheet that lets them be restored.
    public func all(fid: String) throws -> [TeamOffer] {
        try inner.all().map(\.value)
            .filter { $0.fid == fid }
            .sorted { $0.noticedAt > $1.noticedAt }
    }

    /// The ones a person still has to answer.
    public func waiting(fid: String, now: Date = Date()) throws -> [TeamOffer] {
        try all(fid: fid).filter { $0.isWaiting(now: now) }
    }

    @discardableResult
    public func remove(fid: String, teamId: String) throws -> Bool {
        let key = Self.key(fid: fid, teamId: teamId)
        guard try inner.exists(key) else { return false }
        try inner.delete(key)
        return true
    }

    @discardableResult
    public func setIgnored(_ ignored: Bool, fid: String, teamId: String) throws -> Bool {
        guard var offer = try get(fid: fid, teamId: teamId) else { return false }
        offer.ignored = ignored ? true : nil
        try upsert(offer)
        return true
    }

    @discardableResult
    public func markAnswered(fid: String, teamId: String, now: Date = Date()) throws -> Bool {
        guard var offer = try get(fid: fid, teamId: teamId) else { return false }
        offer.answeredAt = TeamOffer.millis(now)
        try upsert(offer)
        return true
    }

    /// Record a notice. Returns true when it raised something a person
    /// has not already seen — a new row, or a transfer on a row that was
    /// only an invitation.
    ///
    /// An ignored row stays ignored: the chain's invitation is the same
    /// set however many times it is announced, and letting a resend undo
    /// the decision would let anyone keep a dismissed team on screen.
    @discardableResult
    public func note(
        _ notice: TeamNotice, from sender: String, for fid: String, now: Date = Date()
    ) throws -> Bool {
        if var existing = try get(fid: fid, teamId: notice.teamId) {
            let upgraded = existing.kind == .invitation && notice.kind == .transfer
            if upgraded { existing.kind = .transfer }
            existing.notifiedBy = sender
            if existing.teamName == nil { existing.teamName = notice.teamName }
            try upsert(existing)
            return upgraded && !existing.isIgnored
        }
        try upsert(TeamOffer(
            fid: fid, teamId: notice.teamId, kind: notice.kind,
            teamName: notice.teamName, notifiedBy: sender,
            onChain: false, noticedAt: TeamOffer.millis(now)
        ))
        try trimUnconfirmed(fid: fid)
        return true
    }

    /// Fold one chain read into the store.
    ///
    /// `invited` is every team listing `fid` in `invitees`, `transfers`
    /// every team naming it `transferee` — the two queries Android's
    /// join screen runs. What the chain lists is written with its current
    /// name, owner and consensus; what it **stopped** listing is dropped,
    /// since whether it was joined, withdrawn, taken over or disbanded,
    /// there is nothing left to answer. A notice the chain has never
    /// listed is kept for ``unconfirmedLifetimeMs``, because an
    /// invitation announced before its carve confirmed is the ordinary
    /// case, not a lie.
    ///
    /// Returns how many offers are new to this device.
    @discardableResult
    public func reconcile(
        invited: [Team], transfers: [Team], for fid: String, now: Date = Date()
    ) throws -> Int {
        var listed: [String: (Team, TeamOffer.Kind)] = [:]
        for team in invited {
            guard let id = team.id, !id.isEmpty, team.isActive,
                  team.isInvited(fid), !team.isMember(fid)
            else { continue }
            listed[id] = (team, .invitation)
        }
        // Second, so a team offering both is recorded as the transfer.
        // A member may be handed a team, so membership does not rule it
        // out the way it rules out an invitation.
        for team in transfers {
            guard let id = team.id, !id.isEmpty, team.isActive,
                  team.transferee == fid, !team.isOwner(fid)
            else { continue }
            listed[id] = (team, .transfer)
        }

        let nowMs = TeamOffer.millis(now)
        var fresh = 0
        for (id, (team, kind)) in listed {
            // A notice already on screen is not new news when the chain
            // confirms it, so only a row this device never had counts.
            let existing = try get(fid: fid, teamId: id)
            if existing == nil { fresh += 1 }
            var offer = existing ?? TeamOffer(fid: fid, teamId: id, kind: kind, noticedAt: nowMs)
            offer.kind = kind
            offer.teamName = team.displayName
            offer.owner = team.owner
            offer.memberNum = team.memberNum ?? team.members.map { Int64($0.count) }
            offer.consensusId = team.consensusId
            offer.diskSid = TeamConsensus.diskSid(of: team)
            offer.onChain = true
            try upsert(offer)
        }

        for offer in try all(fid: fid) where listed[offer.teamId] == nil {
            let stale = offer.isOnChain
                || offer.answeredAt != nil
                || nowMs - offer.noticedAt >= Self.unconfirmedLifetimeMs
            if stale { try remove(fid: fid, teamId: offer.teamId) }
        }
        return fresh
    }

    private func trimUnconfirmed(fid: String) throws {
        let unconfirmed = try all(fid: fid).filter { !$0.isOnChain }
        guard unconfirmed.count > Self.maxUnconfirmed else { return }
        for offer in unconfirmed.dropFirst(Self.maxUnconfirmed) {
            try remove(fid: fid, teamId: offer.teamId)
        }
    }
}
