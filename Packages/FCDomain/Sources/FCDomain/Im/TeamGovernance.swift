import Foundation

/// The team ops that change *who runs* a team rather than who is in it —
/// transfer and take over, disband, appoint and cancel appointment,
/// withdraw invitation, dismiss — and the checks that decide, before a
/// fee is paid, whether the indexer would do anything with them.
///
/// **Every rule here is `OrganizationParser.parseTeam`'s, restated.** The
/// indexer rejects a carve it does not like only after it confirms, and
/// rejection is not free: the transaction is mined, the fee is spent, and
/// the team is unchanged. Worse, several ops are *accepted and do
/// nothing* — appointing somebody who is not a member, dismissing the
/// owner, withdrawing an invitation nobody holds — and those still
/// re-index the team, bumping `lastTxId`/`lastHeight` for a write that
/// changed nothing. So each op gets a plan: who in the list would
/// actually be affected, and a refusal when the answer is nobody.
///
/// **Who may do what**, as the parser has it:
///
/// | op | signer |
/// |---|---|
/// | transfer | the owner (or the owner's master) |
/// | take over | the transferee |
/// | disband, appoint, cancel appointment, update | the owner |
/// | invite, withdraw invitation, dismiss | any manager — and the owner is always one |
/// | join | an invitee |
///
/// **A transfer to the owner is how a transfer is withdrawn.** The parser
/// clears `transferee` when the named FID is the owner, and there is no
/// other op that does; ``TeamGovernance/cancelTransferee`` names that
/// rather than leaving it a trick a reader has to know.
public enum TeamGovernance {

    /// The list ops, for naming them in a refusal.
    public enum ListOp: String, Sendable, Equatable {
        case appoint = "appoint"
        case cancelAppointment = "cancel appointment"
        case dismiss = "dismiss"
        case withdrawInvitation = "withdraw invitation"
    }

    /// What a list op would actually do.
    public struct Plan: Equatable, Sendable {
        /// The FIDs the indexer would act on — the only ones worth carving.
        public let effective: [String]
        /// Named, but the indexer would skip them.
        public let skipped: [String]

        public var isEmpty: Bool { effective.isEmpty }
    }

    /// Whom a transfer to the owner names — the op's only way to withdraw
    /// an offer of ownership.
    public static func cancelTransferee(of team: Team) -> String? { team.owner }

    // MARK: - who

    /// The owner, or one of the managers. The owner is put in `managers`
    /// by `create` and by `take over`, and no op can take them out of it,
    /// but this does not rely on the record saying so.
    public static func canManage(_ team: Team, _ fid: String?) -> Bool {
        team.isManager(fid)
    }

    // MARK: - plans

    /// `appoint`: members who are neither the owner nor already managers.
    /// The parser adds whatever is in `members` and skips the owner; a
    /// FID that is already a manager is the same set again.
    public static func appoint(_ team: Team, fids: [String]) -> Plan {
        partition(fids) { fid in
            team.isMember(fid) && !team.isOwner(fid) && !(team.managers?.contains(fid) ?? false)
        }
    }

    /// `cancel appointment`: current managers other than the owner, who
    /// is skipped by the parser and could never be removed anyway.
    public static func cancelAppointment(_ team: Team, fids: [String]) -> Plan {
        partition(fids) { fid in
            (team.managers?.contains(fid) ?? false) && !team.isOwner(fid)
        }
    }

    /// `dismiss`: current members other than the owner.
    public static func dismiss(_ team: Team, fids: [String]) -> Plan {
        partition(fids) { fid in team.isMember(fid) && !team.isOwner(fid) }
    }

    /// `withdraw invitation`: FIDs the team currently lists as invited.
    public static func withdrawInvitation(_ team: Team, fids: [String]) -> Plan {
        partition(fids) { fid in team.isInvited(fid) }
    }

    // MARK: - refusals

    /// Why `fid` may not carve a `join` to this team, or nil if it may.
    ///
    /// **Only an invitee may join.** The parser looks for the signer in
    /// `invitees` and rejects anyone else, so typing a team id into a
    /// join form is not a way in — it is a fee for nothing. It also
    /// compares the quoted consensus id with the team's, which is why a
    /// team naming none cannot be joined at all.
    public static func joinRefusal(_ team: Team, fid: String) -> TeamGovernanceFailure? {
        let id = team.id ?? ""
        if !team.isActive { return .disbanded(id) }
        if team.isMember(fid) { return .alreadyAMember(teamId: id) }
        if !team.isInvited(fid) { return .notInvited(teamId: id) }
        if (team.consensusId ?? "").isEmpty { return .noConsensus(teamId: id) }
        return nil
    }

    /// Why `fid` may not carve a `take over`, or nil if it may.
    public static func takeOverRefusal(_ team: Team, fid: String) -> TeamGovernanceFailure? {
        let id = team.id ?? ""
        if !team.isActive { return .disbanded(id) }
        guard let transferee = team.transferee, !transferee.isEmpty else {
            return .noTransferPending(teamId: id)
        }
        if transferee != fid { return .notTheTransferee(teamId: id) }
        return nil
    }

    /// Why `transferee` is not a transfer worth carving, or nil.
    ///
    /// Naming the FID the team already offered to changes nothing, and
    /// naming the owner when nothing is on offer clears a field that is
    /// already clear. The signer is **not** checked: the parser also
    /// accepts the owner's master, and refusing a master here would
    /// refuse a transfer the chain allows.
    public static func transferRefusal(_ team: Team, to transferee: String) -> TeamGovernanceFailure? {
        let id = team.id ?? ""
        let fid = transferee.trimmingCharacters(in: .whitespacesAndNewlines)
        if fid.isEmpty { return .noTransferee }
        if !team.isActive { return .disbanded(id) }
        if team.isOwner(fid) {
            return (team.transferee ?? "").isEmpty ? .noTransferPending(teamId: id) : nil
        }
        if team.transferee == fid { return .alreadyOffered(teamId: id, to: fid) }
        return nil
    }

    private static func partition(_ fids: [String], _ accept: (String) -> Bool) -> Plan {
        var seen: Set<String> = []
        var effective: [String] = [], skipped: [String] = []
        for raw in fids {
            let fid = raw.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !fid.isEmpty, seen.insert(fid).inserted else { continue }
            if accept(fid) { effective.append(fid) } else { skipped.append(fid) }
        }
        return Plan(effective: effective, skipped: skipped)
    }
}

/// Why a governance carve was refused before it was broadcast. Each case
/// is something the indexer would reject or ignore after the fee was paid.
public enum TeamGovernanceFailure: Error, Equatable, CustomStringConvertible {
    case noSuchTeam(String)
    case disbanded(String)
    case notTheOwner(teamId: String)
    case notAManager(teamId: String)
    case notInvited(teamId: String)
    case alreadyAMember(teamId: String)
    case noConsensus(teamId: String)
    case noTransferee
    case noTransferPending(teamId: String)
    case notTheTransferee(teamId: String)
    case alreadyOffered(teamId: String, to: String)
    case nothingToChange(TeamGovernance.ListOp, skipped: [String])

    public var description: String {
        switch self {
        case .noSuchTeam:
            return "The chain has no record of this team. It may not have confirmed yet."
        case .disbanded:
            return "This team has been disbanded. Nothing can be carved to it any more."
        case .notTheOwner:
            return "Only the team's owner can do this, and the chain does not list you as the owner."
        case .notAManager:
            return "Only the team's owner or one of its managers can do this, and the chain lists you as neither."
        case .notInvited:
            return "The chain does not list you as invited to this team. Only an invitee can join — a join from anyone else is paid for and ignored. Ask a manager to invite you first."
        case .alreadyAMember:
            return "You are already a member of this team."
        case .noConsensus:
            return "This team names no consensus document, and a join has to quote one. It cannot be joined until the owner sets one."
        case .noTransferee:
            return "Name the FID to hand the team to."
        case .noTransferPending:
            return "No transfer of this team is pending."
        case .notTheTransferee:
            return "The chain does not list you as the one this team is being handed to. The owner may have withdrawn the offer, or offered it to somebody else."
        case let .alreadyOffered(_, to):
            return "The team is already on offer to \(to). Carving the same transfer again would change nothing."
        case let .nothingToChange(op, skipped):
            let who = skipped.isEmpty ? "nobody" : "none of \(skipped.count) named"
            switch op {
            case .appoint:
                return "Nothing to appoint: \(who) is a member who isn't already a manager. The indexer would skip them and the fee would buy nothing."
            case .cancelAppointment:
                return "Nothing to cancel: \(who) is a manager other than the owner."
            case .dismiss:
                return "Nothing to dismiss: \(who) is a member other than the owner."
            case .withdrawInvitation:
                return "Nothing to withdraw: \(who) holds an invitation to this team."
            }
        }
    }
}

/// The P2P text Android sends after a team invitation or a transfer is
/// carved — `[TEAM_INVITE]<tid>|<name>` and `[TEAM_TRANSFER]<tid>|<name>`.
///
/// **A hint, never a fact.** The notice travels as an ordinary sealed
/// text message, and anybody can send one naming any team. What it is
/// good for is timing: the invitation itself is a chain record, and the
/// person invited has no reason to go and look for it unless something
/// tells them to. So a notice raises a ``TeamOffer`` marked unconfirmed,
/// and nothing can be carved on the strength of it — joining and taking
/// over both re-read the team first.
///
/// **Not a message in the transcript.** Android neither stores nor shows
/// these, and a Mac that did would put `[TEAM_INVITE]3f9c…|Name` in a
/// P2P thread — or, from somebody not yet accepted, in message requests,
/// where a stranger's invitation is exactly the thing that most needs to
/// be seen.
public struct TeamNotice: Equatable, Sendable {

    public enum Kind: String, Codable, Sendable {
        case invitation
        case transfer
    }

    public static let invitePrefix = "[TEAM_INVITE]"
    public static let transferPrefix = "[TEAM_TRANSFER]"

    /// Longer than any team id the chain issues (a txid is 64 hex). A
    /// notice naming something longer is not naming a team.
    static let maxTeamIdLength = 128
    /// Names are the sender's to write, so they are bounded before they
    /// reach a store.
    static let maxNameLength = 200

    public let kind: Kind
    public let teamId: String
    public let teamName: String?

    public init(kind: Kind, teamId: String, teamName: String?) {
        self.kind = kind
        self.teamId = teamId
        let name = teamName?.trimmingCharacters(in: .whitespacesAndNewlines)
        self.teamName = (name?.isEmpty ?? true) ? nil : name
    }

    /// The wire text. Android writes the id in the name's place when the
    /// team has no name, and so does this.
    public var text: String {
        let prefix = kind == .transfer ? Self.transferPrefix : Self.invitePrefix
        return prefix + teamId + "|" + (teamName ?? teamId)
    }

    public static func parse(_ content: String?) -> TeamNotice? {
        guard let content else { return nil }
        let kind: Kind
        let body: Substring
        if content.hasPrefix(transferPrefix) {
            kind = .transfer
            body = content.dropFirst(transferPrefix.count)
        } else if content.hasPrefix(invitePrefix) {
            kind = .invitation
            body = content.dropFirst(invitePrefix.count)
        } else {
            return nil
        }
        let parts = body.split(separator: "|", maxSplits: 1, omittingEmptySubsequences: false)
        let teamId = String(parts.first ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        guard !teamId.isEmpty, teamId.count <= maxTeamIdLength,
              !teamId.contains(where: \.isWhitespace)
        else { return nil }
        var name = parts.count > 1 ? String(parts[1]) : nil
        if name == teamId { name = nil }
        if let n = name, n.count > maxNameLength { name = String(n.prefix(maxNameLength)) }
        return TeamNotice(kind: kind, teamId: teamId, teamName: name)
    }

    /// The notice as a P2P text from `from` to `to`, named and unsealed —
    /// the caller seals it to the recipient, as every P2P body is.
    public func message(from: String, to: String, now: Date = Date()) -> ImMessage {
        ImMessage.text(type: .p2p, from: from, to: to, text, now: now).named()
    }
}
