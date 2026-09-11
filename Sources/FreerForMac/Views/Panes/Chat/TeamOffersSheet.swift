import SwiftUI
import FCCore
import FCDomain
import FCUI

/// Teams inviting you in, and teams being handed to you — the port of
/// Android's `JoinTeamActivity` and the `TeamInviteDialog` that sends
/// people to it.
///
/// **Two sources, one list, and the difference is shown.** The chain
/// lists who a team invited and who it is being transferred to; that is
/// the invitation. Somebody may also have sent a notice saying so, which
/// is what usually makes you look — but a notice is a sentence anyone can
/// write about any team, so a row the chain does not list yet is marked
/// unconfirmed and cannot be acted on. Joining and taking over both read
/// the team again at the moment of the carve.
///
/// **The consensus is one click away, on purpose.** A join is a signed
/// statement that you agree with the team's consensus document, and a
/// take-over says the same; the document is on the team's DISK, not on
/// the chain, and this sheet is the last place to read it before paying
/// to agree to it.
struct TeamOffersSheet: View {

    @Environment(\.inspectFid) private var inspectFid

    let session: ActiveSession
    let onClose: () -> Void
    /// Called after anything that changes what the Teams tab shows.
    let onChanged: () -> Void

    @State private var offers: [TeamOffer] = []
    @State private var selectedId: String?
    @State private var showIgnored = false
    @State private var refreshing = false
    @State private var working = false
    @State private var error: String?
    @State private var note: String?
    @State private var document: DocumentRequest?
    @State private var confirming: TeamOffer?

    @State private var searchText = ""
    @State private var searching = false
    @State private var found: [Team]?

    private struct DocumentRequest: Identifiable {
        let id = UUID()
        let consensusId: String
        let title: String
        let diskSids: [String]
    }

    private var now: Date { Date() }

    private var shown: [TeamOffer] {
        showIgnored ? offers : offers.filter { !$0.isIgnored }
    }

    private var selected: TeamOffer? {
        shown.first { $0.id == selectedId } ?? shown.first
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text("Team invitations").font(.title3.bold())
                Spacer()
                Button {
                    Task { await refresh() }
                } label: {
                    if refreshing {
                        ProgressView().controlSize(.small)
                    } else {
                        Label("Check the chain", systemImage: "arrow.clockwise")
                    }
                }
                .disabled(refreshing)
                .help("Ask the chain which teams list this FID as invited, or as the one they are being handed to")
                Button("Done", action: onClose).keyboardShortcut(.defaultAction)
            }

            Text("An invitation is a chain record: a team's managers carve it, and only an invitee can join. A notice somebody sends only tells you to look — it is marked unconfirmed until the chain lists it, and nothing can be carved on its strength.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            if shown.isEmpty {
                VStack(spacing: 6) {
                    Spacer()
                    Text(refreshing ? "Checking…" : "No team is waiting on you.")
                        .foregroundStyle(.secondary)
                    if !showIgnored, offers.contains(where: \.isIgnored) {
                        Button("Show ignored") { showIgnored = true }
                            .buttonStyle(.borderless)
                            .font(.caption)
                    }
                    Spacer()
                }
                .frame(maxWidth: .infinity)
            } else {
                HStack(alignment: .top, spacing: 12) {
                    VStack(alignment: .leading, spacing: 6) {
                        list
                        Toggle("Show ignored", isOn: $showIgnored)
                            .toggleStyle(.checkbox)
                            .font(.caption)
                    }
                    .frame(width: 220)
                    Divider()
                    detail
                }
            }

            Divider()
            searchSection

            if let note {
                Text(note).font(.caption).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if let error {
                CopyableText(error, font: .caption).foregroundStyle(.red)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .padding(20)
        .frame(width: 720, height: 600)
        .fidDetailsHost(session: session)
        .onAppear {
            load()
            Task { await refresh() }
        }
        .sheet(item: $document) { request in
            ConsensusDocumentSheet(
                session: session,
                title: request.title,
                consensusId: request.consensusId,
                diskSids: request.diskSids,
                editable: false,
                onSaved: { _ in document = nil },
                onClose: { document = nil }
            )
        }
        .confirmationDialog(
            confirmTitle(confirming),
            isPresented: Binding(
                get: { confirming != nil },
                set: { if !$0 { confirming = nil } }
            ),
            titleVisibility: .visible,
            presenting: confirming
        ) { offer in
            Button(offer.kind == .transfer ? "Take over (broadcast a carve)" : "Join (broadcast a carve)") {
                answer(offer)
            }
            if let consensusId = offer.consensusId, !consensusId.isEmpty {
                Button("Read the consensus first") { read(offer) }
            }
            Button("Cancel", role: .cancel) { confirming = nil }
        } message: { offer in
            Text(confirmMessage(offer))
        }
    }

    // MARK: - list

    private var list: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 0) {
                ForEach(shown) { offer in
                    Button {
                        selectedId = offer.id
                        note = nil
                        error = nil
                    } label: {
                        HStack(spacing: 8) {
                            GroupAvatarView(groupId: offer.teamId, ownerFid: offer.owner, size: 28)
                            VStack(alignment: .leading, spacing: 2) {
                                Text(offer.teamName ?? offer.teamId.elidingMiddle(head: 6, tail: 6))
                                    .font(.callout)
                                    .lineLimit(1)
                                HStack(spacing: 4) {
                                    Text(offer.kind == .transfer ? "ownership" : "invitation")
                                        .font(.caption2)
                                        .foregroundStyle(offer.kind == .transfer ? AnyShapeStyle(.orange) : AnyShapeStyle(.secondary))
                                    if !offer.isOnChain {
                                        Text("· unconfirmed").font(.caption2).foregroundStyle(.tertiary)
                                    }
                                    if offer.isIgnored {
                                        Text("· ignored").font(.caption2).foregroundStyle(.tertiary)
                                    } else if !offer.isWaiting(now: now) {
                                        Text("· answered").font(.caption2).foregroundStyle(.tertiary)
                                    }
                                }
                            }
                            Spacer(minLength: 0)
                        }
                        .padding(.vertical, 6)
                        .padding(.horizontal, 8)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .opacity(offer.isIgnored ? 0.6 : 1)
                        .background(
                            RoundedRectangle(cornerRadius: 6)
                                .fill(offer.id == selected?.id ? Color.accentColor.opacity(0.15) : .clear)
                        )
                    }
                    .buttonStyle(.plain)
                }
            }
        }
    }

    // MARK: - detail

    @ViewBuilder
    private var detail: some View {
        if let offer = selected {
            VStack(alignment: .leading, spacing: 10) {
                HStack(spacing: 8) {
                    Text(offer.teamName ?? "A team").font(.headline).lineLimit(1)
                    ChatChip(
                        offer.kind == .transfer ? "handed to you" : "invited",
                        color: offer.kind == .transfer ? .orange : .accentColor
                    )
                    if !offer.isOnChain { ChatChip("unconfirmed", color: .secondary) }
                }
                CopyableText(
                    display: offer.teamId.elidingMiddle(head: 10, tail: 10),
                    copy: offer.teamId,
                    font: .caption
                )
                .foregroundStyle(.tertiary)

                if let owner = offer.owner {
                    fidRow("Owner", owner)
                    // A team a nobody owns can be run by anyone.
                    NobodyBanner(fid: owner, message: NobodyConsequence.teamOwner.text)
                }
                if let sender = offer.notifiedBy, sender != offer.owner {
                    fidRow("Told by", sender)
                    NobodyBanner(fid: sender, message: NobodyText.inviter)
                }
                if let members = offer.memberNum {
                    Text("\(members) member\(members == 1 ? "" : "s")")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }

                consensusRow(offer)

                Spacer(minLength: 0)

                Text(explanation(offer))
                    .font(.caption)
                    .foregroundStyle(.tertiary)
                    .fixedSize(horizontal: false, vertical: true)

                HStack {
                    Button(working ? "Carving…" : (offer.kind == .transfer ? "Take over…" : "Join…")) {
                        confirming = offer
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(working || !offer.isOnChain || !session.canSign)
                    .help(offer.isOnChain
                          ? "Read the team again from the chain, then carve"
                          : "The chain does not list this yet — check again once the invitation has confirmed")
                    Spacer()
                    if offer.isIgnored {
                        Button("Restore") { setIgnored(false, offer) }
                    } else {
                        Button("Ignore") { setIgnored(true, offer) }
                            .help("Stops it showing. A resent notice will not bring it back; the Show ignored box will.")
                    }
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        } else {
            Spacer()
        }
    }

    private func fidRow(_ label: String, _ fid: String) -> some View {
        HStack(spacing: 6) {
            Text(label)
                .font(.caption).fontWeight(.semibold)
                .textCase(.uppercase).tracking(0.5)
                .foregroundStyle(.secondary)
                .frame(width: 64, alignment: .leading)
            Button { inspectFid(fid) } label: { FidAvatarView(fid: fid, size: 20) }
                .buttonStyle(.plain)
            NobodyChip(fid: fid)
            FidBadge(fid, font: .callout)
        }
    }

    @ViewBuilder
    private func consensusRow(_ offer: TeamOffer) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("Consensus")
                .font(.caption).fontWeight(.semibold)
                .textCase(.uppercase).tracking(0.5)
                .foregroundStyle(.secondary)
            if let id = offer.consensusId, !id.isEmpty {
                HStack(spacing: 8) {
                    CopyableText(
                        display: id.elidingMiddle(head: 8, tail: 8),
                        copy: id,
                        font: .system(.caption, design: .monospaced)
                    )
                    Button("Read…") { read(offer) }
                        .buttonStyle(.borderless)
                        .font(.caption)
                }
            } else {
                Text(offer.isOnChain
                     ? "This team names no consensus document, and a join has to quote one."
                     : "Known once the chain confirms the invitation.")
                    .font(.caption2)
                    .foregroundStyle(.tertiary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    private func explanation(_ offer: TeamOffer) -> String {
        if !offer.isOnChain {
            return "Nothing on the chain says this yet. Invitations take a few minutes to confirm — check again shortly. If it never appears, the notice was not true."
        }
        switch offer.kind {
        case .invitation:
            return "Joining is a transaction: it costs a miner fee, it is public, and it signs your agreement to the team's consensus document."
        case .transfer:
            return "Taking over makes you the owner and the only manager. It is a transaction, it is public, and it signs your agreement to the team's consensus document."
        }
    }

    // MARK: - search

    /// Android's "all teams" mode: find a team by name, to see where you
    /// stand with it. Read-only — finding a team is not being invited.
    private var searchSection: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 8) {
                SearchField("Find a team by name…", text: $searchText, minWidth: 200)
                    .onSubmit { Task { await search() } }
                Button("Search") { Task { await search() } }
                    .disabled(searching || searchText.trimmingCharacters(in: .whitespaces).isEmpty)
                if searching { ProgressView().controlSize(.small) }
                Spacer()
                if found != nil {
                    Button("Clear") { found = nil; searchText = "" }
                        .buttonStyle(.borderless)
                        .font(.caption)
                }
            }
            if let found {
                if found.isEmpty {
                    Text("No team by that name.").font(.caption).foregroundStyle(.secondary)
                } else {
                    ScrollView {
                        VStack(alignment: .leading, spacing: 4) {
                            ForEach(found, id: \.id) { team in
                                HStack(spacing: 8) {
                                    GroupAvatarView(groupId: team.id ?? "", ownerFid: team.owner, size: 20)
                                    Text(team.displayName ?? "").font(.callout).lineLimit(1)
                                    if let id = team.id {
                                        CopyableText(
                                            display: id.elidingMiddle(head: 6, tail: 6),
                                            copy: id,
                                            font: .system(.caption2, design: .monospaced)
                                        )
                                        .foregroundStyle(.tertiary)
                                    }
                                    Spacer()
                                    ChatChip(standing(in: team), color: .secondary)
                                }
                            }
                        }
                    }
                    .frame(maxHeight: 90)
                }
            }
        }
    }

    private func standing(in team: Team) -> String {
        let me = session.liveFid
        if !team.isActive { return "disbanded" }
        if team.isOwner(me) { return "yours" }
        if team.transferee == me { return "handed to you" }
        if team.isMember(me) { return "member" }
        if team.isInvited(me) { return "invited" }
        return "not invited"
    }

    // MARK: - actions

    private func load() {
        do {
            offers = try session.teamOffers.all(fid: session.liveFid)
            if selectedId == nil || !shown.contains(where: { $0.id == selectedId }) {
                selectedId = shown.first?.id
            }
        } catch {
            self.error = String(describing: error)
        }
    }

    private func refresh() async {
        await MainActor.run { refreshing = true; error = nil }
        do {
            let fresh = try await session.refreshTeamOffers()
            await MainActor.run {
                refreshing = false
                if fresh > 0 { note = "\(fresh) new from the chain." }
                load()
                onChanged()
            }
        } catch {
            await MainActor.run {
                refreshing = false
                self.error = "Couldn't check the chain: \(error)"
                load()
            }
        }
    }

    private func search() async {
        let term = searchText.trimmingCharacters(in: .whitespaces)
        guard !term.isEmpty else { return }
        await MainActor.run { searching = true; error = nil }
        do {
            let teams = try await session.groups.searchTeams(named: term)
            await MainActor.run { searching = false; found = teams }
        } catch {
            await MainActor.run {
                searching = false
                self.error = "Search failed: \(error)"
            }
        }
    }

    private func read(_ offer: TeamOffer) {
        confirming = nil
        guard let id = offer.consensusId, !id.isEmpty else { return }
        document = DocumentRequest(
            consensusId: id,
            title: "\(offer.teamName ?? "The team")'s consensus",
            diskSids: [offer.diskSid].compactMap { $0 }
        )
    }

    private func setIgnored(_ ignored: Bool, _ offer: TeamOffer) {
        do {
            try session.teamOffers.setIgnored(ignored, fid: offer.fid, teamId: offer.teamId)
            load()
            onChanged()
        } catch {
            self.error = String(describing: error)
        }
    }

    private func confirmTitle(_ offer: TeamOffer?) -> String {
        guard let offer else { return "" }
        let name = offer.teamName ?? "this team"
        return offer.kind == .transfer ? "Take over \(name)?" : "Join \(name)?"
    }

    private func confirmMessage(_ offer: TeamOffer) -> String {
        let sentence = offer.kind == .transfer ? TeamFeip.takeOverConfirm : TeamFeip.joinConfirm
        let consensus = offer.consensusId.map { " The consensus quoted is the one the chain holds when you sign — \($0.elidingMiddle(head: 8, tail: 8)) as of the last check." } ?? ""
        let role = offer.kind == .transfer
            ? " You become the owner and the only manager: anyone the current owner appointed loses the role."
            : ""
        return "This broadcasts a transaction that signs “\(sentence)”\(consensus)\(role) It costs a miner fee and is public."
    }

    /// Carve the join or the take-over, after reading the team again.
    private func answer(_ offer: TeamOffer) {
        confirming = nil
        working = true
        error = nil
        note = nil
        Task {
            do {
                let txid: String
                switch offer.kind {
                case .invitation:
                    // Read now, not from the row: the parser refuses a
                    // join from anyone not in `invitees`, and a join
                    // quoting anything but the current consensus.
                    guard let team = try await session.freshTeam(id: offer.teamId) else {
                        throw TeamGovernanceFailure.noSuchTeam(offer.teamId)
                    }
                    if let refusal = TeamGovernance.joinRefusal(team, fid: session.liveFid) {
                        throw refusal
                    }
                    guard await NobodyGate.confirm([team.owner], .teamOwner, session: session) else {
                        await MainActor.run { working = false }
                        return
                    }
                    txid = try await session.carveTeamJoinOnChain(
                        teamId: offer.teamId, consensusId: team.consensusId
                    )
                    session.notePendingGroup(.team, id: offer.teamId, name: team.displayName, act: .join, txid: txid)
                case .transfer:
                    txid = try await session.carveTeamTakeOverOnChain(teamId: offer.teamId)
                    session.notePendingGroup(.team, id: offer.teamId, name: offer.teamName, act: .takeOver, txid: txid)
                }
                await MainActor.run {
                    working = false
                    _ = try? session.teamOffers.markAnswered(fid: offer.fid, teamId: offer.teamId)
                    note = "Broadcast — tx \(txid.elidingMiddle(head: 8, tail: 8)). The team's thread appears once the carve confirms and the Teams tab refreshes."
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
}
