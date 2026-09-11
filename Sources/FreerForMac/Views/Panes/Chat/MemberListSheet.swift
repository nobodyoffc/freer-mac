import SwiftUI
import FCCore
import FCDomain
import FCUI

/// Who is in this room, team or square — and, for whoever may change
/// that, how.
///
/// **The three memberships are three different things, and the sheet
/// says which.** A room's list is the owner's own copy and exists
/// nowhere else; a team's and a square's are on the chain, which makes
/// them public, authoritative, and expensive to change. So a room owner
/// removes somebody here and now, while a team owner's dismissal is a
/// transaction that says so before it is signed.
///
/// **Removing somebody is not the same as un-telling them.** Everyone
/// removed keeps every key they were ever given and everything those
/// keys open. For a room, removal rotates the key as part of the
/// operation, which is what makes it mean "from here on"; for a team,
/// the carve and the rotation are two separate acts and the sheet says
/// so rather than implying the first did the second.
struct MemberListSheet: View {

    @Environment(\.inspectFid) private var inspectFid

    let session: ActiveSession
    let style: ChatModeStyle
    let conversation: Conversation
    let onClose: () -> Void
    let onChanged: () -> Void

    @State private var members: [String] = []
    @State private var owner: String?
    @State private var managers: [String] = []
    /// Who has renamed a square. A **history**, not a role — kept apart
    /// from `managers` because chipping them "manager" would claim a
    /// privilege a square does not have: anyone may rename one who
    /// outbids the standing coin-day price.
    @State private var namers: [String] = []
    /// Members the chain lists as not having agreed to the team's
    /// current consensus. Read straight off the record — there is no
    /// list of who *has* agreed and no per-member signature stored, so
    /// this negative set is the only answer anybody has.
    @State private var notAgreed: [String] = []
    @State private var isOwner = false
    @State private var addFid = ""
    @State private var working = false
    @State private var error: String?
    @State private var note: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack {
                Text("Members of this \(style.noun)").font(.title3.bold())
                Spacer()
                Button("Done", action: onClose).keyboardShortcut(.defaultAction)
            }

            Text(membershipNote)
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            list

            // Label only: a nobody member's consent can be given by anyone,
            // but counting it is the protocol's business, not this sheet's.
            NobodyBanner(
                shown: style.mode == .team && !NobodyRegistry.shared.nobodies(among: members).isEmpty,
                message: NobodyText.consensus
            )

            if isOwner, style.mode != .square {
                addRow
            }

            if let note {
                Text(note).font(.caption).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if let error {
                CopyableText(error, font: .caption).foregroundStyle(.red)
            }
        }
        .padding(20)
        .frame(width: 520, height: 460)
        // Every row is a FID, and a sheet cannot present another sheet
        // through the window's host — so this one installs its own.
        .fidDetailsHost(session: session)
        .onAppear(perform: load)
        .task(id: members) {
            let directory = session.directory
            await NobodyRegistry.shared.resolve(members, retryFailed: false) { fids in
                await directory.nobodyFids(among: fids)
            }
        }
    }

    /// Where this membership actually lives, said once, at the top.
    private var membershipNote: String {
        switch style.mode {
        case .room:
            return "Nothing about this room is on the chain. The owner's copy is the membership, and everyone else holds what the owner last told them."
        case .team:
            var note = "This membership is on the chain: it is public, and every change to it is a transaction."
            if !notAgreed.isEmpty {
                // The negative set, stated as what it is. There is no
                // list of who *has* agreed, so "not agreed" is the only
                // fact available — and it clears itself when each
                // member carves their own agreement.
                note += " \(notAgreed.count) member(s) have not yet agreed to the current consensus document; until they carve an agreement of their own, what they signed and what this team runs on are two different documents."
            }
            return note
        case .square:
            return "A square's membership is on the chain and open — anyone may join, which is why there is no key and nothing here is encrypted. Nobody is in charge either: whoever destroys the most coin-days names it, and \"named it\" marks the ones who have."
        case .p2p:
            return ""
        }
    }

    private var list: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 0) {
                ForEach(members, id: \.self) { fid in
                    HStack(spacing: 8) {
                        Button { inspectFid(fid) } label: {
                            FidAvatarView(fid: fid, size: 24)
                        }
                        .buttonStyle(.plain)
                        .help("Show this FID's details, standing and ratings")
                        FidBadge(fid, font: .callout)
                        if fid == owner { ChatChip("owner", color: style.tint) }
                        if managers.contains(fid) { ChatChip("manager", color: .secondary) }
                        if namers.contains(fid) { ChatChip("named it", color: .secondary) }
                        if notAgreed.contains(fid) { ChatChip("not agreed", color: .orange) }
                        if fid == session.liveFid { ChatChip("you", color: .secondary) }
                        Spacer()
                        if canSendKey(fid) {
                            Button("Send the key") { sendKey(to: fid) }
                                .buttonStyle(.borderless)
                                .font(.caption)
                                .disabled(working)
                                .help("Hand this member the team's current key. Nothing is rotated — everyone else keeps reading as before.")
                        }
                        if canRemove(fid) {
                            Button("Remove") { remove(fid) }
                                .buttonStyle(.borderless)
                                .font(.caption)
                                .disabled(working)
                        }
                    }
                    .padding(.vertical, 5)
                    Divider()
                }
                if members.isEmpty {
                    Text("No members listed.").font(.caption).foregroundStyle(.secondary)
                }
            }
        }
    }

    private var addRow: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 8) {
                TextField("FID to add", text: $addFid)
                    .textFieldStyle(.roundedBorder)
                Button(style.mode == .team ? "Invite (carve)" : "Add") { add() }
                    .disabled(working || addFid.trimmingCharacters(in: .whitespaces).isEmpty)
            }
            Text(style.mode == .team
                 ? "An invitation is a transaction, and it is only an invitation: they still have to join themselves."
                 : "They are invited straight away, and the invitation carries this room's current key sealed to them. Someone whose public key we don't have is invited without one and has to ask.")
                .font(.caption2)
                .foregroundStyle(.tertiary)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    /// Only a room owner removes anybody from here. A team owner's
    /// dismissal is a carve, and it is offered — but never for
    /// themselves, and never for a square, which has no such thing.
    private func canRemove(_ fid: String) -> Bool {
        guard isOwner, fid != session.liveFid, fid != owner else { return false }
        return style.mode == .room || style.mode == .team
    }

    /// A team owner can hand any member the current key.
    ///
    /// **Teams only, and it is not an oversight that a room has no such
    /// button.** A room's key travels inside the `ROOM_INFO` that also
    /// carries the membership — the two are applied together or not at
    /// all — so the room's version of this is "Share the room's
    /// details". A team's membership comes from the chain and is not
    /// ours to announce, which leaves the key on its own.
    ///
    /// This is the gap a new member falls into: they join on the chain,
    /// the owner sees them at the next sync, and nothing has given them
    /// the key yet. They can ask for it, and this is the owner's way to
    /// answer before they have to.
    private func canSendKey(_ fid: String) -> Bool {
        guard isOwner, style.mode == .team, fid != session.liveFid else { return false }
        return (try? session.symkeys.has(entityId: conversation.targetId)) ?? false
    }

    // MARK: - actions

    private func load() {
        do {
            switch style.mode {
            case .room:
                let room = try session.rooms.get(id: conversation.targetId)
                members = room?.members ?? []
                owner = room?.owner
                managers = []
                namers = []
                notAgreed = []
                isOwner = room?.isOwner(session.liveFid) ?? false
            case .team:
                let team = try session.teams.get(id: conversation.targetId)
                members = team?.members ?? []
                owner = team?.owner
                managers = team?.managers ?? []
                namers = []
                notAgreed = team?.notAgreeMembers ?? []
                isOwner = team?.isOwner(session.liveFid) ?? false
            case .square:
                let square = try session.squares.get(id: conversation.targetId)
                members = square?.members ?? []
                owner = nil
                managers = []
                namers = square?.namers ?? []
                notAgreed = []
                isOwner = false
            case .p2p:
                members = []
                notAgreed = []
            }
            error = nil
        } catch {
            self.error = String(describing: error)
        }
    }

    private func add() {
        let fid = addFid.trimmingCharacters(in: .whitespaces)
        guard !fid.isEmpty else { return }
        working = true
        error = nil
        Task {
            // A nobody member is a member anyone can be.
            guard await NobodyGate.confirm(
                [fid], style.mode == .team ? .team : .room, session: session
            ) else {
                await MainActor.run { working = false }
                return
            }
            do {
                switch style.mode {
                case .room:
                    let service = try session.roomService
                    let (added, outbound, unreachable) = try service.addMembers(
                        [fid], to: conversation.targetId, as: session.liveFid,
                        pubkeys: { f in try session.knownPubkey(of: f) },
                        homes: { f in try session.knownHome(of: f) }
                    )
                    try session.roomConversations.sync(conversation.targetId)
                    try queue(outbound)
                    await MainActor.run {
                        note = summary(added: added, outbound: outbound, unreachable: unreachable)
                    }
                case .team:
                    // The carve filters the list against the chain and
                    // refuses one that names nobody new — the indexer
                    // would skip them silently while the transaction was
                    // paid for anyway, and re-index the team for a write
                    // that changed nothing.
                    let txid = try await session.carveTeamInviteOnChain(
                        teamId: conversation.targetId, fids: [fid]
                    )
                    await MainActor.run {
                        note = "Invitation broadcast — tx \(txid.elidingMiddle(head: 8, tail: 8)). They appear once they join and you refresh."
                    }
                case .square, .p2p:
                    break
                }
                await MainActor.run {
                    addFid = ""
                    working = false
                    load()
                    onChanged()
                }
            } catch {
                await MainActor.run {
                    working = false
                    self.error = String(describing: error)
                }
            }
        }
    }

    /// What just happened, said plainly — including the case the owner
    /// most needs told about: somebody who is now in the room and has
    /// nowhere for an invitation to wait. They will not hear about this
    /// room until they publish a DOCK and the owner shares its details
    /// again, and saying nothing would read as an invitation that was
    /// sent.
    private func summary(added: [String], outbound: [ImMessage], unreachable: [String]) -> String {
        guard !added.isEmpty else { return "Already a member." }
        var lines = ["Added. \(outbound.count) notification(s) queued."]
        if !unreachable.isEmpty {
            lines.append(
                "\(unreachable.count) member(s) publish no DOCK, so there is nowhere to leave one for them — they are in the room, and you can share its details again once they have a server."
            )
        }
        return lines.joined(separator: " ")
    }

    /// Hand one team member the current key. **Owner only, and the
    /// check is the service's** — see ``TeamKeyService``.
    private func sendKey(to fid: String) {
        Task {
            // The key sealed to a nobody is a key everyone holds.
            guard await NobodyGate.confirm([fid], .team, session: session) else { return }
            sendKeyConfirmed(to: fid)
        }
    }

    private func sendKeyConfirmed(to fid: String) {
        working = true
        error = nil
        do {
            let keyed = try session.teamKeys.shareCurrent(
                of: conversation.targetId,
                to: [fid],
                as: session.liveFid,
                pubkeys: { f in try session.knownPubkey(of: f) },
                homes: { f in try session.knownHome(of: f) }
            )
            try queue(keyed.outbound)
            note = keyed.outbound.isEmpty
                ? "Nothing to send: we have no public key for them, or they publish no DOCK to leave it at."
                : "Key v\(keyed.version) queued for them."
        } catch {
            self.error = String(describing: error)
        }
        working = false
    }

    private func remove(_ fid: String) {
        working = true
        error = nil
        Task {
            do {
                switch style.mode {
                case .room:
                    let service = try session.roomService
                    let (removed, outbound) = try service.removeMember(
                        fid, from: conversation.targetId, as: session.liveFid,
                        pubkeys: { f in try session.knownPubkey(of: f) }
                    )
                    try session.roomConversations.sync(conversation.targetId)
                    try queue(outbound)
                    await MainActor.run {
                        note = removed
                            ? "Removed, and the room's key rotated — that rotation is what makes removal mean anything. Everything said before it stays readable to them."
                            : "They were not a member."
                    }
                case .team:
                    let txid = try await session.carveTeamDismissOnChain(
                        teamId: conversation.targetId, fids: [fid]
                    )
                    await MainActor.run {
                        note = "Dismissal broadcast — tx \(txid.elidingMiddle(head: 8, tail: 8)). They still hold every key they were given, so reset the team's key as well."
                    }
                case .square, .p2p:
                    break
                }
                await MainActor.run {
                    working = false
                    load()
                    onChanged()
                }
            } catch {
                await MainActor.run {
                    working = false
                    self.error = String(describing: error)
                }
            }
        }
    }

    /// Room control traffic is P2P, so it queues into each recipient's
    /// own thread — an invitation has to reach someone who is not in the
    /// room yet, and a removal someone who is no longer in it.
    private func queue(_ outbound: [ImMessage]) throws {
        for message in outbound {
            guard let to = message.targetId else { continue }
            try session.outbox.enqueue(message, in: Conversation.id(type: .p2p, targetId: to))
        }
        Task { _ = try? await session.courier.drainOutbox(as: session.liveFid) }
    }
}
