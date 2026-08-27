import SwiftUI
import FCCore
import FCDomain
import FCUI

/// Change what a team or a square *is* — the Mac port of Android's
/// `UpdateTeamActivity` and `UpdateSquareActivity`.
///
/// **This is a transaction, not a preference.** A room's record lives on
/// the devices that hold it, so ``RoomSettingsSheet`` saves by telling
/// the members; a team's and a square's live on the chain, so saving
/// here means carving an `update` op, paying for it, and waiting. There
/// is nothing to show afterwards until the carve confirms and the group
/// sync reads it back, which is why this sheet reports a txid rather
/// than a changed row — the same bargain ``NewChatSheet`` makes when it
/// creates one.
///
/// **Two flavours, one sheet, because the form really is the same.**
/// Name, description and DOCK on both; a team adds its consensus
/// document. What differs is who may do it and what it costs, and both
/// of those are stated on screen rather than assumed:
///
/// - A **team** is updated by its owner, and costs a miner fee.
/// - A **square** is updated by *anyone* whose transaction destroys more
///   CoinDays than the last update destroyed. There is no owner, no
///   manager and no list of who may rename it: the price is the
///   permission, and it rises each time somebody pays it. So the sheet
///   states the standing price before the button is pressed, and asks
///   nothing about who is asking.
///
/// **An empty box is not "clear this".** The `update` op omits fields it
/// does not carry, and an omitted field is one the update says nothing
/// about. Description is sent as an empty string when emptied, which is
/// as close to clearing as the protocol gets; an emptied DOCK box leaves
/// the chain's DOCK exactly where it was, and the sheet says so rather
/// than pretending otherwise.
struct GroupSettingsSheet: View {

    let session: ActiveSession
    /// `.team` or `.square`. Anything else is a programming error and
    /// the sheet refuses rather than guessing.
    let mode: ImType
    let groupId: String
    let onClose: () -> Void
    /// Handed the summary to show, so the note survives this sheet
    /// closing — a txid the user cannot read is a txid they cannot chase.
    let onSaved: (String) -> Void

    @State private var name = ""
    @State private var desc = ""
    @State private var consensusId = ""
    @State private var dock = ""

    /// What the record said when the sheet opened, so the carve can
    /// leave alone what the user did not touch.
    @State private var original: Loaded?
    @State private var pickingDock = false
    @State private var loaded = false
    @State private var working = false
    @State private var error: String?

    private struct Loaded {
        var name: String
        var desc: String
        var consensusId: String
        var dock: String
        /// What the last update to this square destroyed, in CoinDays —
        /// the price this one has to beat. Nil for a team, which is
        /// gated on its owner instead of on a price.
        var cddToUpdate: Int64?
        /// Whether the live FID is the team's owner. Squares do not use
        /// it: nobody is privileged in a square.
        var isTeamOwner: Bool
        /// Whether the team record names an owner at all. A team the
        /// indexer reported without one is not a team nobody owns; it is
        /// a team this device cannot answer for.
        var ownerIsKnown: Bool
    }

    private var style: ChatModeStyle { .of(mode) }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 8) {
                Image(systemName: style.systemImage).foregroundStyle(style.tint)
                Text(mode == .team ? "Team settings" : "Square settings").font(.title3.bold())
                Spacer()
            }

            CopyableText(
                display: groupId.elidingMiddle(head: 10, tail: 10),
                copy: groupId,
                font: .caption
            )
            .foregroundStyle(.tertiary)

            if let warning {
                Label(warning, systemImage: "exclamationmark.triangle")
                    .font(.caption)
                    .foregroundStyle(.orange)
                    .fixedSize(horizontal: false, vertical: true)
            }

            VStack(alignment: .leading, spacing: 4) {
                LabeledField(mode == .team ? "Team name" : "Square name") {
                    TextField("", text: $name, prompt: Text("required"))
                        .fieldInputStyle()
                }

                if mode == .team {
                    LabeledField(
                        "Consensus document id",
                        hint: "What members agree to when they join. Naming a different one here does not re-ask anybody: existing members keep the agreement they signed, and the chain lists them as not having agreed to the new one until each carves their own agreement."
                    ) {
                        TextField("", text: $consensusId, prompt: Text("required"))
                            .font(.system(.body, design: .monospaced))
                            .fieldInputStyle()
                    }
                }

                LabeledField("Description") {
                    TextField("", text: $desc, prompt: Text("optional"))
                        .fieldInputStyle()
                }

                LabeledField(
                    "DOCK",
                    hint: "Where this \(style.noun)'s messages rest until each member collects them. Emptying this box does not remove the \(style.noun)'s DOCK — the update op can move it, but has no way to say it has none."
                ) {
                    HStack(spacing: 8) {
                        TextField("", text: $dock, prompt: Text("service id, or host:port"))
                            .font(.system(.body, design: .monospaced))
                            .fieldInputStyle()
                        Button {
                            pickingDock = true
                        } label: {
                            Label("Find…", systemImage: "server.rack")
                        }
                        .help("Search the chain for a server that offers DOCK.")
                    }
                }
            }

            Text(costNote)
                .font(.caption)
                .foregroundStyle(.tertiary)
                .fixedSize(horizontal: false, vertical: true)

            if let error {
                CopyableText(error, font: .caption).foregroundStyle(.red)
            }

            HStack {
                Spacer()
                Button("Cancel", role: .cancel) { onClose() }
                Button(working ? "Carving…" : "Save on-chain") { save() }
                    .buttonStyle(.borderedProminent)
                    .keyboardShortcut(.defaultAction)
                    .disabled(!canSave)
            }
        }
        .padding(20)
        .frame(width: 500)
        .onAppear(perform: load)
        .sheet(isPresented: $pickingDock) {
            ServicePickerSheet(
                session: session,
                component: ServiceName.dock,
                title: "Choose this \(style.noun)'s DOCK",
                subtitle: "Every member re-resolves this id through the chain, so a server that moves does not take the \(style.noun) with it.",
                initialQuery: dock
            ) { service in
                dock = service.sid
                pickingDock = false
            } onCancel: {
                pickingDock = false
            }
        }
    }

    /// The one thing worth interrupting for: a carve that the chain will
    /// refuse. Said here rather than enforced by hiding the button —
    /// the record may simply be one we have not synced.
    ///
    /// **A square never warns about who is asking**, because in a square
    /// that is not a question: anyone may update one who outbids the
    /// standing coin-day price. Its only refusal is arithmetic, and the
    /// carve itself raises that before a fee is spent.
    private var warning: String? {
        guard session.canSign else {
            return "This is a watch-only identity, so there is no private key here to sign a carve with."
        }
        guard let original, mode == .team, !original.isTeamOwner else { return nil }
        if !original.ownerIsKnown {
            return "This Mac has no owner on file for this team, so it cannot tell whether the chain will accept an update from you."
        }
        return "You do not own this team. The chain accepts an update only from its owner, so this carve would cost a fee and change nothing."
    }

    private var costNote: String {
        switch mode {
        case .team:
            return "Saving is a transaction: it costs a miner fee and is public. Nothing changes here until the carve confirms and you refresh."
        case .square:
            let cdd = original?.cddToUpdate ?? 0
            let price = cdd > 0
                ? "Anyone in a square may change it — what decides it is coin-days, not permission. The last change destroyed \(cdd) CD, so this one has to destroy more than that, and whatever you destroy becomes the price of the next change. CD is value that has sat still: an old coin carries more of it than a large one."
                : "Anyone in a square may change it — what decides it is coin-days, not permission. Nobody has changed this one yet, so it costs what any carve costs: a miner fee and 1 CD. Whatever this destroys becomes the price of the next change."
            return "\(price) Nothing changes here until the carve confirms and you refresh."
        default:
            return ""
        }
    }

    private var canSave: Bool {
        guard !working, session.canSign, original != nil else { return false }
        guard !name.trimmingCharacters(in: .whitespaces).isEmpty else { return false }
        // Android refuses a team update with no consensus document, and
        // for the same reason it refuses a create without one: a team
        // whose constitution is blank has nothing for its members to
        // have agreed to.
        if mode == .team, consensusId.trimmingCharacters(in: .whitespaces).isEmpty { return false }
        return true
    }

    private func load() {
        guard !loaded else { return }
        loaded = true
        do {
            switch mode {
            case .team:
                guard let team = try session.teams.get(id: groupId) else {
                    error = "This team is not on this Mac. Refresh the Teams tab and try again."
                    return
                }
                original = Loaded(
                    name: team.stdName ?? "",
                    desc: team.desc ?? "",
                    consensusId: team.consensusId ?? "",
                    dock: team.home?[ServiceName.dock] ?? "",
                    cddToUpdate: nil,
                    isTeamOwner: team.isOwner(session.liveFid),
                    ownerIsKnown: team.owner != nil
                )
            case .square:
                guard let square = try session.squares.get(id: groupId) else {
                    error = "This square is not on this Mac. Refresh the Squares tab and try again."
                    return
                }
                original = Loaded(
                    name: square.name ?? "",
                    desc: square.desc ?? "",
                    consensusId: "",
                    dock: square.home?[ServiceName.dock] ?? "",
                    cddToUpdate: square.cddToUpdate,
                    isTeamOwner: false,
                    ownerIsKnown: true
                )
            default:
                error = "Only a team or a square is changed this way."
                return
            }
            guard let original else { return }
            name = original.name
            desc = original.desc
            consensusId = original.consensusId
            dock = original.dock
        } catch {
            self.error = String(describing: error)
        }
    }

    private func save() {
        guard let original else { return }
        working = true
        error = nil

        let newName = name.trimmingCharacters(in: .whitespaces)
        let newDesc = desc.trimmingCharacters(in: .whitespaces)
        let newDock = dock.trimmingCharacters(in: .whitespaces)
        let newConsensus = consensusId.trimmingCharacters(in: .whitespaces)

        // Only what actually changed goes into the op. A field the user
        // did not touch is one the update has no business speaking
        // about, and an unchanged `home` re-carved is a DOCK move
        // announced to everyone for no reason.
        let home = (newDock != original.dock && !newDock.isEmpty)
            ? [ServiceName.dock: newDock]
            : nil

        Task {
            do {
                let txid: String
                switch mode {
                case .team:
                    txid = try await session.carveTeamUpdateOnChain(
                        teamId: groupId,
                        stdName: newName,
                        consensusId: newConsensus,
                        desc: newDesc == original.desc ? nil : newDesc,
                        home: home
                    )
                default:
                    txid = try await session.carveSquareUpdateOnChain(
                        squareId: groupId,
                        name: newName,
                        desc: newDesc == original.desc ? nil : newDesc,
                        home: home,
                        cddToUpdate: original.cddToUpdate
                    )
                }
                await MainActor.run {
                    working = false
                    onSaved(
                        "Broadcast — tx \(txid.elidingMiddle(head: 8, tail: 8)). The \(style.noun)'s new details appear here once the carve confirms and you refresh."
                    )
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
