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
/// document and the DISK that document lives on. What differs is who may
/// do it and what it costs, and both of those are stated on screen
/// rather than assumed:
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
/// as close to clearing as the protocol gets; an emptied DOCK or DISK box
/// leaves the chain's exactly where it was, and the sheet says so rather
/// than pretending otherwise.
///
/// **`home` is merged, never rebuilt.** The indexer replaces the whole
/// map — see ``GroupHome`` — so a form that constructed a fresh map from
/// the boxes it happens to know about would delete every entry it does
/// not draw. That is not a cosmetic bug: erasing a team's
/// `DISK@No1_NrC7` leaves no member able to fetch the consensus document
/// they are on chain as having agreed to, permanently and silently.
///
/// **A consensus id is never carved unless something is behind it.**
/// Naming a document is a promise that it can be read, and the chain
/// enforces none of it: the id is an opaque string the indexer compares
/// for equality and never resolves. So a *changed* consensus is uploaded
/// to the team's DISK — or found already there, or pulled across from the
/// DISK the team is leaving — before the carve is built, and refused
/// rather than carved if none of that works. Failing while it is still
/// free is the point.
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
    @State private var disk = ""

    /// What the record said when the sheet opened, so the carve can
    /// leave alone what the user did not touch.
    @State private var original: Loaded?
    @State private var pickingDock = false
    @State private var pickingDisk = false
    /// The consensus sheet, and whether it may be typed in.
    @State private var document: DocumentRequest?
    @State private var loaded = false
    @State private var working = false
    @State private var workingNote: String?
    @State private var confirmingConsensusChange = false
    @State private var error: String?

    private struct Loaded {
        var name: String
        var desc: String
        var consensusId: String
        var dock: String
        var disk: String
        /// The stored `home` in full — what an update's map is merged
        /// over. Kept whole rather than picked apart into the two boxes
        /// above, because the entries this sheet does not draw are
        /// exactly the ones it must not lose.
        var home: [String: String]?
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
        /// Members other than the owner — how many people a consensus
        /// change would oblige to re-sign.
        var otherMembers: Int
    }

    private struct DocumentRequest: Identifiable {
        let id = UUID()
        let consensusId: String
        let editable: Bool
        let title: String
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
                    consensusField
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
                        Button { pickingDock = true } label: {
                            Label("Find…", systemImage: "server.rack")
                        }
                        .help("Search the chain for a server that offers DOCK.")
                    }
                }

                if mode == .team {
                    LabeledField(
                        "DISK",
                        hint: "Where the consensus document is stored, published in plain text so any member — or anyone weighing up joining — can fetch it without being sent anything. Move it and the current document is copied across first, because members who have not re-signed still need to read what they agreed to."
                    ) {
                        HStack(spacing: 8) {
                            TextField("", text: $disk, prompt: Text("service id"))
                                .font(.system(.body, design: .monospaced))
                                .fieldInputStyle()
                            Button { pickingDisk = true } label: {
                                Label("Find…", systemImage: "externaldrive")
                            }
                            .help("Search the chain for a server that offers DISK.")
                        }
                    }
                }
            }

            Text(costNote)
                .font(.caption)
                .foregroundStyle(.tertiary)
                .fixedSize(horizontal: false, vertical: true)

            if let workingNote {
                HStack(spacing: 8) {
                    ProgressView().controlSize(.small)
                    Text(workingNote).font(.caption).foregroundStyle(.secondary)
                }
            }
            if let error {
                CopyableText(error, font: .caption).foregroundStyle(.red)
                    .fixedSize(horizontal: false, vertical: true)
            }

            HStack {
                Spacer()
                Button("Cancel", role: .cancel) { onClose() }
                Button(working ? "Carving…" : "Save on-chain") { attemptSave() }
                    .buttonStyle(.borderedProminent)
                    .keyboardShortcut(.defaultAction)
                    .disabled(!canSave)
            }
        }
        .padding(20)
        .frame(width: 520)
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
        .sheet(isPresented: $pickingDisk) {
            ServicePickerSheet(
                session: session,
                component: ServiceName.disk,
                title: "Choose this team's DISK",
                subtitle: "The consensus document is stored here, unencrypted and permanently, and its id is published so anyone can check the bytes hash back to what was carved.",
                initialQuery: disk
            ) { service in
                disk = service.sid
                pickingDisk = false
            } onCancel: {
                pickingDisk = false
            }
        }
        .sheet(item: $document) { request in
            ConsensusDocumentSheet(
                session: session,
                title: request.title,
                consensusId: request.consensusId,
                diskSids: candidateDiskSids,
                editable: request.editable,
                onSaved: { newId in
                    consensusId = newId
                    document = nil
                },
                onClose: { document = nil }
            )
        }
        .confirmationDialog(
            "Every member will have to agree to this again",
            isPresented: $confirmingConsensusChange,
            titleVisibility: .visible
        ) {
            Button("Carve the new consensus") { save() }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text(consensusChangeWarning)
        }
    }

    // MARK: - the consensus row

    /// The consensus document: its id, and the three things that can be
    /// done with it.
    ///
    /// **View reads what the box names, not what the team stores.** They
    /// are the same until the moment somebody picks or writes a different
    /// document, and that moment is exactly when a viewer that went to
    /// the team's stored id would go hunting for the old one and report
    /// it missing — with the new document sitting right here on the Mac.
    private var consensusField: some View {
        LabeledField(
            "Consensus document",
            hint: "What members agree to when they join. Its id is the hash of the text, so a different document is always a different id. Carving a new one does not re-ask anybody: existing members keep the agreement they signed, and the chain lists them as not having agreed to the new one until each carves their own agreement."
        ) {
            VStack(alignment: .leading, spacing: 6) {
                TextField("", text: $consensusId, prompt: Text("required"))
                    .font(.system(.body, design: .monospaced))
                    .fieldInputStyle()
                HStack(spacing: 8) {
                    Button {
                        document = DocumentRequest(
                            consensusId: viewableConsensusId,
                            editable: false,
                            title: "This team's consensus"
                        )
                    } label: {
                        Label("View…", systemImage: "eye")
                    }
                    .disabled(viewableConsensusId.isEmpty)
                    .help("Read the document this id names — from this Mac if it is here, otherwise from the team's DISK or the one in the box above.")

                    Button {
                        document = DocumentRequest(
                            consensusId: viewableConsensusId,
                            editable: true,
                            title: "Write a new consensus"
                        )
                    } label: {
                        Label("Write…", systemImage: "square.and.pencil")
                    }
                    .help("Edit the text. Saving stores a new document on this Mac and puts its id here; nothing is published until you carve.")

                    Button {
                        pickDocument()
                    } label: {
                        Label("Choose file…", systemImage: "doc.badge.plus")
                    }
                    .help("Use a file from this Mac as the consensus. It is registered where it lies and hashed to get its id.")
                }
                .buttonStyle(.borderless)
                .font(.caption)

                if let consensusNote {
                    Text(consensusNote)
                        .font(.caption2)
                        .foregroundStyle(.tertiary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
        }
    }

    /// What View and Write open: the box's id, falling back to the
    /// team's stored one only when the box is empty.
    private var viewableConsensusId: String {
        let typed = consensusId.trimmingCharacters(in: .whitespaces)
        return typed.isEmpty ? (original?.consensusId ?? "") : typed
    }

    /// Both sides of a move. A team midway between two DISKs has its
    /// document on one of them and nothing says which, so a read tries
    /// the stored one and the typed one alike.
    private var candidateDiskSids: [String] {
        [original?.disk ?? "", disk].filter { !$0.trimmingCharacters(in: .whitespaces).isEmpty }
    }

    private var consensusNote: String? {
        guard let original, mode == .team else { return nil }
        let typed = consensusId.trimmingCharacters(in: .whitespaces)
        guard !typed.isEmpty, typed != original.consensusId else { return nil }
        let onDevice = session.teamConsensus.localURL(consensusId: typed) != nil
        return onDevice
            ? "A new document, held on this Mac. Saving uploads it to the team's DISK first — a consensus nobody can fetch is a promise nobody can check."
            : "This id does not match anything on this Mac. Saving will look for it on the team's DISK, and refuse rather than carve an id with nothing behind it."
    }

    // MARK: - warnings and costs

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

    private var consensusChangeWarning: String {
        let others = original?.otherMembers ?? 0
        guard others > 0 else {
            return "Carving a different consensus id replaces what this team runs on. You are its only member, so there is nobody to re-sign."
        }
        return "Carving a different consensus id puts all \(others) other member(s) on the chain's list of people who have not agreed to it, until each of them carves an agreement of their own — a transaction each, which they pay for. Until they do, what they signed and what the team runs on are two different documents. They can also leave instead."
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
        // The parser refuses an update with no consensus document, for
        // the same reason it refuses a create without one: a team whose
        // constitution is blank has nothing for its members to have
        // agreed to.
        if mode == .team, consensusId.trimmingCharacters(in: .whitespaces).isEmpty { return false }
        return true
    }

    // MARK: - loading

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
                let owner = team.owner
                original = Loaded(
                    name: team.stdName ?? "",
                    desc: team.desc ?? "",
                    consensusId: team.consensusId ?? "",
                    // Shown bare, carved prefixed. The two forms are the
                    // same id, and a picker that hands back the bare one
                    // must not read as a change.
                    dock: HomeServiceResolver.displayValue(team.home?[ServiceName.dock]),
                    disk: TeamConsensus.diskSid(of: team) ?? "",
                    home: team.home,
                    cddToUpdate: nil,
                    isTeamOwner: team.isOwner(session.liveFid),
                    ownerIsKnown: owner != nil,
                    otherMembers: (team.members ?? []).filter { $0 != owner }.count
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
                    dock: HomeServiceResolver.displayValue(square.home?[ServiceName.dock]),
                    disk: "",
                    home: square.home,
                    cddToUpdate: square.cddToUpdate,
                    isTeamOwner: false,
                    ownerIsKnown: true,
                    otherMembers: 0
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
            disk = original.disk
        } catch {
            self.error = String(describing: error)
        }
    }

    private func pickDocument() {
        let panel = NSOpenPanel()
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = false
        panel.message = "Choose the document this team's members agree to."
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            consensusId = try session.teamConsensus.importFile(at: url)
            error = nil
        } catch {
            self.error = String(describing: error)
        }
    }

    // MARK: - saving

    /// Ask before a consensus change, then save.
    ///
    /// Not a confirmation for its own sake: this is the one edit on the
    /// screen whose cost lands on **other people**, each of whom pays for
    /// a transaction to catch up with it. Renaming a team costs the owner
    /// a fee; replacing its consensus costs every member one.
    private func attemptSave() {
        guard let original else { return }
        let newConsensus = consensusId.trimmingCharacters(in: .whitespaces)
        // Any change, not only a replacement. The parser refills
        // `notAgreeMembers` whenever the carved id differs from the
        // stored one — **including when the team had none stored**,
        // which is its `else` branch and not an edge case: it is exactly
        // what happens the first time a team without a consensus gets
        // one, and it obliges every member just the same.
        let changed = newConsensus != original.consensusId
        if mode == .team, changed, original.otherMembers > 0 {
            confirmingConsensusChange = true
        } else {
            save()
        }
    }

    private func save() {
        guard let original else { return }
        working = true
        error = nil

        let newName = name.trimmingCharacters(in: .whitespaces)
        let newDesc = desc.trimmingCharacters(in: .whitespaces)
        let newDock = dock.trimmingCharacters(in: .whitespaces)
        let newDisk = disk.trimmingCharacters(in: .whitespaces)
        let newConsensus = consensusId.trimmingCharacters(in: .whitespaces)
        let consensusChanged = newConsensus != original.consensusId

        // Merged over what the chain holds, never rebuilt from these two
        // boxes — see ``GroupHome``. A nil means "this update says
        // nothing about that key", which is the only way the op has of
        // leaving an entry alone.
        let home = GroupHome.merged(
            over: original.home,
            changing: [
                ServiceName.dock: newDock.isEmpty ? nil : newDock,
                ServiceName.disk: mode == .team && !newDisk.isEmpty ? newDisk : nil,
            ]
        )

        Task {
            do {
                if mode == .team {
                    try await placeDocument(
                        consensusId: newConsensus,
                        // An emptied box does not withdraw the team's
                        // DISK — the op has no way to say that, and the
                        // merged `home` above leaves the stored entry
                        // alone — so the document still belongs on the
                        // DISK the team already publishes.
                        targetDiskSid: newDisk.isEmpty ? original.disk : newDisk,
                        storedDiskSid: original.disk,
                        consensusChanged: consensusChanged
                    )
                }
                await MainActor.run { workingNote = "Carving…" }
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
                    workingNote = nil
                    var lines = [
                        "Broadcast — tx \(txid.elidingMiddle(head: 8, tail: 8)). The \(style.noun)'s new details appear here once the carve confirms and you refresh."
                    ]
                    if consensusChanged, original.otherMembers > 0 {
                        lines.append("Every other member is now asked to agree to the new consensus before the chain counts them as having done so.")
                    }
                    onSaved(lines.joined(separator: " "))
                }
            } catch {
                await MainActor.run {
                    working = false
                    workingNote = nil
                    self.error = String(describing: error)
                }
            }
        }
    }

    /// Put the consensus document where members can read it, before the
    /// carve is built.
    ///
    /// **The ordering is ``TeamConsensus/place(consensusId:onDiskSid:fallbackDiskSid:progress:)``'s
    /// and the reason is money**: the target DISK is asked first, so an
    /// owner who only renamed their team does not re-upload — and re-pay
    /// for — a document that has not moved.
    ///
    /// The two outcomes this has to tell apart:
    ///
    /// - A **changed** consensus that could not be placed is refused.
    ///   Carving it would put an id on the chain that resolves to
    ///   nothing, permanently, and every member would be asked to agree
    ///   to a document none of them can read.
    /// - An **unchanged** one that could not be placed is allowed
    ///   through. The id is already on chain; refusing here would lock
    ///   the owner out of renaming a team whose document was never
    ///   uploaded — and this screen is how such a team gets repaired.
    private func placeDocument(
        consensusId: String,
        targetDiskSid: String,
        storedDiskSid: String,
        consensusChanged: Bool
    ) async throws {
        guard !targetDiskSid.isEmpty else {
            guard !consensusChanged else {
                throw SaveRefusal.newConsensusNeedsDisk
            }
            return
        }
        await MainActor.run { workingNote = "Checking the team's DISK for the document…" }
        let placement = try await session.teamConsensus.place(
            consensusId: consensusId,
            onDiskSid: targetDiskSid,
            // The DISK the team is leaving. Where the current document
            // still sits when this save is a move, and the only copy
            // members who have not re-signed can reach.
            fallbackDiskSid: storedDiskSid
        )
        switch placement {
        case .alreadyThere, .uploadedFromHere, .copiedFrom:
            return
        case .unavailable(let hadOtherDisk):
            guard consensusChanged else {
                // Quiet on purpose when there was no other DISK: a team
                // whose home carries none never had a document there to
                // move, so warning about one that "could not be moved"
                // would describe a loss that never happened.
                if hadOtherDisk {
                    await MainActor.run {
                        error = "The current consensus document could not be copied to the new DISK. It stays readable on the old one until that server drops it."
                    }
                }
                return
            }
            throw SaveRefusal.documentNotPlaceable
        }
    }

    private enum SaveRefusal: Error, CustomStringConvertible {
        case newConsensusNeedsDisk
        case documentNotPlaceable

        var description: String {
            switch self {
            case .newConsensusNeedsDisk:
                return "A new consensus needs a DISK to live on: the id carved on chain is only a hash, and without a server publishing the bytes no member can read what they are agreeing to. Set this team's DISK and save again."
            case .documentNotPlaceable:
                return "That consensus id names no document this Mac can find — not on the team's DISK, not here, and not on the DISK the team is moving from. Nothing was carved. Write the document or choose its file, and the id will follow from its contents."
            }
        }
    }
}
