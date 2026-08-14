import Foundation

/// A team: owner-managed group chat whose membership is **on the
/// chain**, mirroring `FC-AJDK/.../data/feipData/Team.java`.
///
/// This is the opposite arrangement from a ``Room``. A room has no
/// arbiter, so every membership claim has to be checked against the
/// owner we happen to have on file; a team's membership is a public,
/// indexed fact that both clients read from the same place. Nobody has
/// to be trusted to report it, which is why nothing in the team sync
/// resembles ``RoomService``'s owner checks — there is simply nothing
/// for a peer to lie about.
///
/// What that costs is privacy and money: who is in a team is public,
/// and joining or leaving is a transaction.
public struct Team: Codable, Equatable, Sendable, Identifiable {

    public var owner: String?
    /// The team's canonical name. Teams are named in a global namespace,
    /// so this is unique where a room's name is decoration.
    public var stdName: String?
    public var localNames: [String: String]?
    public var waiters: [String]?
    public var accounts: [String]?
    /// The DID of the consensus document members agree to when they
    /// join. Joining quotes it back, which is what makes agreement a
    /// signed act rather than a checkbox.
    public var consensusId: String?
    public var desc: String?
    public var members: [String]?
    public var memberNum: Int64?
    public var exMembers: [String]?
    public var managers: [String]?
    /// A transfer in flight: the FID offered ownership, who must
    /// `takeOver` to complete it.
    public var transferee: String?
    public var invitees: [String]?
    public var notAgreeMembers: [String]?

    public var birthTime: Int64?
    public var birthHeight: Int64?
    public var lastTxId: String?
    public var lastTime: Int64?
    public var lastHeight: Int64?
    public var tCdd: Int64?
    public var tRate: Double?
    /// `false` once the team has been disbanded on chain.
    public var active: Bool?
    public var home: [String: String]?
    public var onChain: Bool?

    /// The `create` carve's txid.
    public var id: String?

    public init(
        owner: String? = nil,
        stdName: String? = nil,
        localNames: [String: String]? = nil,
        waiters: [String]? = nil,
        accounts: [String]? = nil,
        consensusId: String? = nil,
        desc: String? = nil,
        members: [String]? = nil,
        memberNum: Int64? = nil,
        exMembers: [String]? = nil,
        managers: [String]? = nil,
        transferee: String? = nil,
        invitees: [String]? = nil,
        notAgreeMembers: [String]? = nil,
        birthTime: Int64? = nil,
        birthHeight: Int64? = nil,
        lastTxId: String? = nil,
        lastTime: Int64? = nil,
        lastHeight: Int64? = nil,
        tCdd: Int64? = nil,
        tRate: Double? = nil,
        active: Bool? = nil,
        home: [String: String]? = nil,
        onChain: Bool? = nil,
        id: String? = nil
    ) {
        self.owner = owner
        self.stdName = stdName
        self.localNames = localNames
        self.waiters = waiters
        self.accounts = accounts
        self.consensusId = consensusId
        self.desc = desc
        self.members = members
        self.memberNum = memberNum
        self.exMembers = exMembers
        self.managers = managers
        self.transferee = transferee
        self.invitees = invitees
        self.notAgreeMembers = notAgreeMembers
        self.birthTime = birthTime
        self.birthHeight = birthHeight
        self.lastTxId = lastTxId
        self.lastTime = lastTime
        self.lastHeight = lastHeight
        self.tCdd = tCdd
        self.tRate = tRate
        self.active = active
        self.home = home
        self.onChain = onChain
        self.id = id
    }

    public func isMember(_ fid: String?) -> Bool {
        guard let fid else { return false }
        return members?.contains(fid) ?? false
    }

    public func isOwner(_ fid: String?) -> Bool {
        guard let fid, let owner else { return false }
        return fid == owner
    }

    public func isManager(_ fid: String?) -> Bool {
        guard let fid else { return false }
        return isOwner(fid) || (managers?.contains(fid) ?? false)
    }

    public func isInvited(_ fid: String?) -> Bool {
        guard let fid else { return false }
        return invitees?.contains(fid) ?? false
    }

    /// A team is live unless the chain says otherwise. `nil` means the
    /// server did not report the field, which is not the same as
    /// disbanded — Android reads it the same way.
    public var isActive: Bool { active ?? true }

    /// The name to show: the canonical one, falling back to the id.
    public var displayName: String? { stdName ?? id }

    public func matches(query: String) -> Bool {
        let needle = query.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !needle.isEmpty else { return false }
        func hit(_ s: String?) -> Bool { s?.lowercased().contains(needle) ?? false }
        return hit(stdName) || hit(desc) || hit(id) || hit(owner)
    }

    public static func fromJson(_ json: String) throws -> Team {
        try JSONDecoder().decode(Team.self, from: Data(json.utf8))
    }
}

/// A square: **open** group chat with on-chain membership, mirroring
/// `FC-AJDK/.../data/feipData/Square.java`.
///
/// The simplest of the three flavours, and the one whose simplicity is a
/// deliberate design rather than an omission: **a square is not
/// encrypted**. Anyone may join by carving a `join`, so there is no
/// membership to keep a key from — a symkey shared with everyone who
/// asks is not a secret, it is a formality that would imply a privacy
/// the square does not have. There is no owner and no manager either;
/// `namers` may rename it, and that is the whole of its governance.
public struct Square: Codable, Equatable, Sendable, Identifiable {

    public var name: String?
    public var desc: String?
    /// FIDs allowed to rename the square — its only privileged role.
    public var namers: [String]?
    public var members: [String]?
    public var memberNum: Int64?

    public var birthTime: Int64?
    public var birthHeight: Int64?
    public var lastTxId: String?
    public var lastTime: Int64?
    public var lastHeight: Int64?
    /// The coin-days a rename costs, which is how a square resists being
    /// renamed on a whim.
    public var cddToUpdate: Int64?
    public var tCdd: Int64?
    public var home: [String: String]?
    public var onChain: Bool?

    public var id: String?

    public init(
        name: String? = nil,
        desc: String? = nil,
        namers: [String]? = nil,
        members: [String]? = nil,
        memberNum: Int64? = nil,
        birthTime: Int64? = nil,
        birthHeight: Int64? = nil,
        lastTxId: String? = nil,
        lastTime: Int64? = nil,
        lastHeight: Int64? = nil,
        cddToUpdate: Int64? = nil,
        tCdd: Int64? = nil,
        home: [String: String]? = nil,
        onChain: Bool? = nil,
        id: String? = nil
    ) {
        self.name = name
        self.desc = desc
        self.namers = namers
        self.members = members
        self.memberNum = memberNum
        self.birthTime = birthTime
        self.birthHeight = birthHeight
        self.lastTxId = lastTxId
        self.lastTime = lastTime
        self.lastHeight = lastHeight
        self.cddToUpdate = cddToUpdate
        self.tCdd = tCdd
        self.home = home
        self.onChain = onChain
        self.id = id
    }

    public func isMember(_ fid: String?) -> Bool {
        guard let fid else { return false }
        return members?.contains(fid) ?? false
    }

    public func isNamer(_ fid: String?) -> Bool {
        guard let fid else { return false }
        return namers?.contains(fid) ?? false
    }

    public var displayName: String? { name ?? id }

    public func matches(query: String) -> Bool {
        let needle = query.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !needle.isEmpty else { return false }
        func hit(_ s: String?) -> Bool { s?.lowercased().contains(needle) ?? false }
        return hit(name) || hit(desc) || hit(id)
    }

    public static func fromJson(_ json: String) throws -> Square {
        try JSONDecoder().decode(Square.self, from: Data(json.utf8))
    }
}
