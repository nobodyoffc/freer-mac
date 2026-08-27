import Foundation

/// Who may make a team's key, and who gets given it — the key half of
/// Android's `TeamHandler`, minus the sending.
///
/// **A team is not a room, and the difference is where the membership
/// lives.** A room's membership is the owner's own copy, so
/// ``RoomService`` spends its length deciding whose claims to believe. A
/// team's membership is on the chain, and the chain is the arbiter: a
/// peer cannot lie about who is in a team because a peer is not asked.
/// That leaves exactly one thing this type has to decide — **who may
/// make the key** — and the answer is the owner and nobody else.
///
/// Why that matters: a key is a claim about which conversation everyone
/// is having. If any member could mint one and push it out, a member
/// could split the team in two — half sealing under the owner's key,
/// half under theirs — and nothing on the chain would say which was
/// real. So a member's device may *receive* a key (``SymkeyStore``
/// still refuses to let a non-owner overwrite a version it holds) and
/// may *answer a request* for one (``SignalRouter``), but only the
/// owner's device mints and announces.
///
/// **The key travels P2P**, sealed to each member's own pubkey, and
/// never on the team's channel: the whole reason someone needs the key
/// is that they cannot read that channel yet. Same argument
/// ``KeyExchange`` makes, and this delegates the envelope to it.
///
/// Like every service on this path it **returns messages rather than
/// sending them**, so the rules are testable with no network under them.
public struct TeamKeyService {

    private let teams: TeamsStore
    private let symkeys: SymkeyStore

    public init(teams: TeamsStore, symkeys: SymkeyStore) {
        self.teams = teams
        self.symkeys = symkeys
    }

    public typealias PubkeyProvider = (String) throws -> Data?
    public typealias HomeProvider = (String) throws -> [String: String]?

    /// What making or rotating a team's key produced.
    public struct Keyed: Sendable {
        /// The version now current.
        public let version: Int64
        /// Whether a new key was actually minted. False from
        /// ``ensureSymkey(for:as:pubkeys:homes:now:)`` when one already
        /// existed.
        public let created: Bool
        /// One `SYMKEY` per member we could both seal to and reach.
        public let outbound: [ImMessage]
        /// Members skipped: no published pubkey to seal to, or no DOCK
        /// to leave it at.
        public let skipped: [String]

        public init(version: Int64, created: Bool, outbound: [ImMessage], skipped: [String] = []) {
            self.version = version
            self.created = created
            self.outbound = outbound
            self.skipped = skipped
        }
    }

    // MARK: - minting

    /// Give a team we own its first key, if it has none, and hand it to
    /// every member.
    ///
    /// This is what "a new team gets a key" means on this platform.
    /// Creating a team is a **transaction**: the id is the carve's own
    /// txid, so at the moment the user presses Create there is no team
    /// to key — it does not exist until the carve confirms and the
    /// group sync finds it. So the key is minted on the first sync that
    /// shows us a team we own without one, which is the earliest point
    /// where the operation is even well-defined, and is idempotent
    /// afterwards.
    ///
    /// Idempotent is the important word: this runs on every sync, and a
    /// team that already has a key must not get a second one. A rotation
    /// is a deliberate act — ``resetSymkey(for:as:pubkeys:homes:now:)``.
    @discardableResult
    public func ensureSymkey(
        for teamId: String,
        as liveFid: String,
        pubkeys: PubkeyProvider,
        homes: HomeProvider? = nil,
        now: Date = Date()
    ) throws -> Keyed {
        let team = try requireOwned(teamId, by: liveFid)
        let existing = try symkeys.currentVersion(for: teamId)
        if existing >= SymkeyStore.minimumVersion {
            return Keyed(version: existing, created: false, outbound: [])
        }
        let key = try symkeys.generate(for: teamId, version: SymkeyStore.minimumVersion, now: now)
        let (outbound, skipped) = try shares(
            of: teamId, version: key.version, to: team.others(than: liveFid),
            as: liveFid, pubkeys: pubkeys, homes: homes, now: now
        )
        return Keyed(version: key.version, created: true, outbound: outbound, skipped: skipped)
    }

    /// Rotate a team's key and give the new one to every member.
    /// **Owner only** — see the type's note.
    ///
    /// **Rotating is additive**, as everywhere else here: the old
    /// version stays, because it is the only thing that can still open
    /// what was said under it. So this closes off *future* messages from
    /// anyone who does not get the new key — a dismissed member, most
    /// of all — and changes nothing about the past.
    ///
    /// Rotating rather than generating also covers the owner whose
    /// device holds no key for a team it owns:
    /// ``SymkeyStore/rotate(for:now:)`` takes the next version up, which
    /// is 1 when there is nothing there, and never reuses a version
    /// number a different key may already be sealing messages under.
    @discardableResult
    public func resetSymkey(
        for teamId: String,
        as liveFid: String,
        pubkeys: PubkeyProvider,
        homes: HomeProvider? = nil,
        now: Date = Date()
    ) throws -> Keyed {
        let team = try requireOwned(teamId, by: liveFid)
        let rotated = try symkeys.rotate(for: teamId, now: now)
        let (outbound, skipped) = try shares(
            of: teamId, version: rotated.version, to: team.others(than: liveFid),
            as: liveFid, pubkeys: pubkeys, homes: homes, now: now
        )
        return Keyed(version: rotated.version, created: true, outbound: outbound, skipped: skipped)
    }

    /// Hand the current key to named members without rotating it — the
    /// owner's answer to "the new member still can't read anything".
    /// **Owner only**, because it is unsolicited; a member helping
    /// someone out answers a request instead.
    @discardableResult
    public func shareCurrent(
        of teamId: String,
        to fids: [String],
        as liveFid: String,
        pubkeys: PubkeyProvider,
        homes: HomeProvider? = nil,
        now: Date = Date()
    ) throws -> Keyed {
        let team = try requireOwned(teamId, by: liveFid)
        let version = try symkeys.currentVersion(for: teamId)
        guard version >= SymkeyStore.minimumVersion else {
            throw Failure.noKey(teamId: teamId)
        }
        // Only to people the chain says are in the team. A key handed to
        // someone outside it is a key handed away.
        let targets = fids.filter { $0 != liveFid && team.isMember($0) }
        let (outbound, skipped) = try shares(
            of: teamId, version: version, to: targets,
            as: liveFid, pubkeys: pubkeys, homes: homes, now: now
        )
        return Keyed(version: version, created: false, outbound: outbound, skipped: skipped)
    }

    // MARK: - helpers

    /// One sealed `SYMKEY` per member we can both seal to and reach.
    ///
    /// A member we cannot seal to (no published pubkey) or cannot reach
    /// (no DOCK) is **skipped rather than thrown over**: a rotation that
    /// failed because one of twelve members has not published a key
    /// would leave the other eleven unable to read anything said
    /// afterwards, which is far worse than that one member having to
    /// ask.
    private func shares(
        of teamId: String,
        version: Int64,
        to fids: [String],
        as liveFid: String,
        pubkeys: PubkeyProvider,
        homes: HomeProvider?,
        now: Date
    ) throws -> (outbound: [ImMessage], skipped: [String]) {
        var outbound: [ImMessage] = []
        var skipped: [String] = []
        for fid in fids where fid != liveFid {
            if let homes, !ChatGate.declaresDock(home: try homes(fid)) {
                skipped.append(fid)
                continue
            }
            guard let pubkey = try pubkeys(fid) else {
                skipped.append(fid)
                continue
            }
            guard let message = try KeyExchange.share(
                entityId: teamId, version: version, to: fid,
                recipientPubkey: pubkey, from: liveFid, symkeys: symkeys, now: now
            ) else {
                skipped.append(fid)
                continue
            }
            outbound.append(message)
        }
        return (outbound, skipped)
    }

    private func requireOwned(_ teamId: String, by liveFid: String) throws -> Team {
        guard let team = try teams.get(id: teamId) else { throw Failure.noSuchTeam(teamId) }
        guard team.isOwner(liveFid) else { throw Failure.notTheOwner(teamId: teamId) }
        return team
    }

    public enum Failure: Error, Equatable, CustomStringConvertible {
        case noSuchTeam(String)
        case notTheOwner(teamId: String)
        case noKey(teamId: String)

        public var description: String {
            switch self {
            case .noSuchTeam(let id):
                return "TeamKeyService: no team \(id)"
            case .notTheOwner(let id):
                return "TeamKeyService: only the owner of \(id) can make or reset its key"
            case .noKey(let id):
                return "TeamKeyService: no key held for \(id) to share"
            }
        }
    }
}
