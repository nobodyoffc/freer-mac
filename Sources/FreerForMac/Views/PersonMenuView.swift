import SwiftUI
import AppKit
import FCCore
import FCDomain
import FCUI

/// The person menu — the Mac take on Android's `PersonPopupMenuHelper`
/// popup: a popover anchored to the toolbar avatar showing who you're
/// *living as* and the identity roles you can switch to.
///
///   - header: live FID avatar + "Living: <role>" + copyable FID
///   - **Main FID** — switch back to the main (disabled when already
///     living as main)
///   - **My Master** — switch to the main's master; fetches its
///     KeyInfo from the directory when it isn't cached locally. The
///     key button next to it opens ``SetMasterSheet`` to name one (an
///     on-chain carve that publishes the main's private key — read
///     that sheet's note).
///   - **My Watched FIDs / My Multisig FIDs / My Servants** — entries
///     of that kind; click to switch. Watched and Servants each have
///     an Add flow, and both are asymmetric on purpose: a watched FID
///     is anyone you choose to follow, a servant is someone who has
///     already named *you* on chain, so one is typed in and the other
///     is looked up. Multisig still waits on its signing phase.
///     Multisig has two ways in — **Create** derives a new group
///     address from its members, **Find** looks up the ones the chain
///     already knows this FID belongs to — and its entries carry a
///     *Sign a transaction…* action, because a group is spent from by
///     collecting signatures rather than by living as it.
///     Right-click any entry to relabel or remove it.
///   - **Quit Main FID** — drop the session, back to the main chooser.
///
/// Same gating as Android: everything except *Main FID* and *Quit*
/// is disabled unless you're living as main.
struct PersonMenuView: View {
    @Environment(AppState.self) private var appState
    let session: ActiveSession
    /// Open the add-watched-FID sheet. Hoisted to HomeView because a
    /// sheet presented from inside a popover dies with the popover —
    /// so are the other two, for the same reason.
    let onAddWatched: () -> Void
    let onSetMaster: () -> Void
    let onAddServants: () -> Void
    let onCreateMultisig: () -> Void
    let onAddMultisig: () -> Void
    /// Open the co-sign sheet for one group.
    let onSignMultisig: (String) -> Void
    let onClose: () -> Void

    @State private var fetchingMaster = false
    @State private var note: String?
    @State private var noteIsError = false
    @State private var pendingRemoval: KeyInfo?
    @State private var pendingRename: KeyInfo?
    @State private var renameText = ""

    private var livingAsMain: Bool { session.liveFid == session.mainFid }
    private var masterFid: String? {
        guard let m = session.mainKeyInfo.master,
              !m.trimmingCharacters(in: .whitespaces).isEmpty else { return nil }
        return m
    }

    /// "Living: <role>" — Android's `determineFidType`: main and
    /// master are recognized by FID, everything else by its kind.
    private var liveRole: String {
        if session.liveFid == session.mainFid { return "Main FID" }
        if session.liveFid == masterFid { return "Master" }
        switch session.liveKeyInfo.kind {
        case .main:     return "Main FID"
        case .watched:  return "Watched"
        case .multisig: return "Multisig"
        case .servant:  return "Servant"
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header
            Divider()

            ScrollView {
                VStack(alignment: .leading, spacing: 2) {
                    mainFidRow
                    masterRow

                    kindSection(
                        "My Watched FIDs", kind: .watched,
                        emptyText: "No watched FIDs yet."
                    )
                    kindSection(
                        "My Multisig FIDs", kind: .multisig,
                        emptyText: "No multisig groups yet — create one, or find the ones you are already in."
                    )
                    kindSection(
                        "My Servants", kind: .servant,
                        emptyText: "No servants yet — adding them comes with the servant phase."
                    )
                }
                .padding(8)
            }
            .frame(maxHeight: 380)

            if let note {
                Divider()
                CopyableText(note, font: .caption)
                    .foregroundStyle(noteIsError ? .red : .secondary)
                    .fixedSize(horizontal: false, vertical: true)
                    .padding(10)
            }

            Divider()
            quitRow
        }
        .frame(width: 340)
        .alert(
            "Remove this identity?",
            isPresented: Binding(
                get: { pendingRemoval != nil },
                set: { if !$0 { pendingRemoval = nil } }
            ),
            presenting: pendingRemoval
        ) { info in
            // The escape hatch sits in the dialog itself, because by
            // the time someone is reading this warning the script is
            // one click from being gone.
            if info.kind == .multisig, let script = info.multisig?.redeemScript {
                Button("Copy redeem script first") {
                    copyToPasteboard(script)
                    noteIsError = false
                    note = "Redeem script copied. Keep it somewhere safe before removing the group."
                }
            }
            Button("Remove", role: .destructive) { remove(info) }
            Button("Cancel", role: .cancel) { pendingRemoval = nil }
        } message: { info in
            Text(removalWarning(for: info))
        }
        .alert(
            "Label this identity",
            isPresented: Binding(
                get: { pendingRename != nil },
                set: { if !$0 { pendingRename = nil } }
            ),
            presenting: pendingRename
        ) { info in
            TextField("Label", text: $renameText)
            Button("Save") { rename(info) }
            Button("Cancel", role: .cancel) { pendingRename = nil }
        } message: { info in
            Text("Shown in this menu instead of \(info.fid.elidingMiddle(head: 8, tail: 8)). Local to this Setting — nothing is published.")
        }
    }

    // MARK: - header

    private var header: some View {
        HStack(spacing: 10) {
            FidAvatarView(fid: session.liveFid, size: 40)
            VStack(alignment: .leading, spacing: 2) {
                Text("Living: \(liveRole)")
                    .font(.headline)
                CopyableText.elidingMiddle(
                    session.liveFid, head: 10, tail: 10,
                    font: .caption.monospaced()
                )
                .foregroundStyle(.secondary)
            }
            Spacer()
        }
        .padding(12)
    }

    // MARK: - rows

    private var mainFidRow: some View {
        row(
            avatarFid: session.mainFid,
            title: "Main FID",
            subtitle: session.mainFid.elidingMiddle(head: 8, tail: 8),
            disabled: livingAsMain,
            trailing: livingAsMain ? "checkmark" : nil
        ) {
            switchTo(fid: session.mainFid)
        }
    }

    private var masterRow: some View {
        HStack(spacing: 0) {
            row(
                avatarFid: masterFid,
                title: "My Master",
                subtitle: masterFid.map { $0.elidingMiddle(head: 8, tail: 8) } ?? "not set",
                disabled: !livingAsMain || fetchingMaster || masterFid == nil,
                trailing: fetchingMaster ? "progress"
                    : (session.liveFid == masterFid ? "checkmark" : nil)
            ) {
                Task { await switchToMaster() }
            }
            // Set/Change sits *outside* the switch-to row rather than in
            // a context menu: with no master set the row is disabled and
            // a right-click on a dead row is not a discoverable place to
            // hide the only way to get one.
            Button {
                onClose()
                onSetMaster()
            } label: {
                Image(systemName: "key.horizontal")
            }
            .buttonStyle(.plain)
            .foregroundStyle(livingAsMain ? Color.accentColor : .secondary)
            .disabled(!livingAsMain)
            .help(masterFid == nil
                  ? "Name a master for this FID — publishes its private key on chain"
                  : "Change this FID's master — publishes its private key on chain")
            .padding(.trailing, 10)
        }
    }

    @ViewBuilder
    private func kindSection(_ title: String, kind: KeyKind, emptyText: String) -> some View {
        let entries = entries(of: kind)
        VStack(alignment: .leading, spacing: 2) {
            HStack {
                Text(title)
                    .font(.caption)
                    .fontWeight(.semibold)
                    .textCase(.uppercase)
                    .tracking(0.5)
                    .foregroundStyle(.secondary)
                Spacer()
                if kind == .multisig {
                    // Two ways in, so a menu rather than a button: a
                    // group you just made is not on chain yet and a
                    // group the chain knows needs no deriving, and
                    // guessing which the user meant would be wrong
                    // half the time.
                    Menu {
                        Button("Create a group…") {
                            onClose()
                            onCreateMultisig()
                        }
                        Button("Find my groups…") {
                            onClose()
                            onAddMultisig()
                        }
                    } label: {
                        Image(systemName: "plus.circle")
                    }
                    .menuStyle(.borderlessButton)
                    .menuIndicator(.hidden)
                    .fixedSize()
                    .foregroundStyle(livingAsMain ? Color.accentColor : .secondary)
                    .disabled(!livingAsMain)
                    .help("Create a multisig group, or find the ones you are in")
                } else if let add = addAction(for: kind) {
                    Button {
                        onClose()
                        add.run()
                    } label: {
                        Image(systemName: "plus.circle")
                    }
                    .buttonStyle(.plain)
                    .foregroundStyle(livingAsMain ? Color.accentColor : .secondary)
                    .disabled(!livingAsMain)
                    .help(add.help)
                }
            }
            .padding(.horizontal, 8)
            .padding(.top, 10)

            if entries.isEmpty {
                Text(emptyText)
                    .font(.caption)
                    .foregroundStyle(.tertiary)
                    .padding(.horizontal, 8)
                    .padding(.bottom, 2)
                    .fixedSize(horizontal: false, vertical: true)
            } else {
                ForEach(entries, id: \.fid) { info in
                    row(
                        avatarFid: info.fid,
                        title: info.label.isEmpty
                            ? info.fid.elidingMiddle(head: 8, tail: 8)
                            : info.label,
                        subtitle: subtitle(for: info),
                        disabled: !livingAsMain || info.fid == session.liveFid,
                        trailing: info.fid == session.liveFid ? "checkmark" : nil
                    ) {
                        switchTo(fid: info.fid)
                    }
                    .contextMenu {
                        if info.kind == .multisig {
                            Button("Sign a transaction…") {
                                onClose()
                                onSignMultisig(info.fid)
                            }
                            .disabled(!livingAsMain)
                            Divider()
                        }
                        Button("Copy FID") { copyToPasteboard(info.fid) }
                        Button(info.label.isEmpty ? "Add label…" : "Rename…") {
                            renameText = info.label
                            pendingRename = info
                        }
                        .disabled(!livingAsMain)
                        Divider()
                        Button("Remove\(info.label.isEmpty ? "" : " “\(info.label)”")…", role: .destructive) {
                            pendingRemoval = info
                        }
                        .disabled(!livingAsMain)
                    }
                }
            }
        }
    }

    /// What the "+" on a section does, or nil for a kind that has no
    /// add flow yet. Multisig is the nil: an entry there is a group you
    /// are a member of, which needs the co-signing phase before it can
    /// mean anything.
    private func addAction(for kind: KeyKind) -> (help: String, run: () -> Void)? {
        switch kind {
        case .watched:
            return ("Add a watched FID", onAddWatched)
        case .servant:
            return ("Find FIDs that have named this one as their master", onAddServants)
        case .multisig, .main:
            // Multisig has its own two-way menu above.
            return nil
        }
    }

    /// "2-of-3" for a registered group, so the list says what each
    /// entry costs to spend from rather than just showing an address.
    private func subtitle(for info: KeyInfo) -> String? {
        let elided = info.fid.elidingMiddle(head: 8, tail: 8)
        if info.kind == .multisig, let m = info.multisig?.m, let n = info.multisig?.n {
            return "\(m)-of-\(n) · \(elided)"
        }
        return info.label.isEmpty ? nil : elided
    }

    private var quitRow: some View {
        Button {
            onClose()
            appState.returnToChooseMain()
        } label: {
            HStack(spacing: 10) {
                FidAvatarView(fid: session.mainFid, size: 24)
                Text("Quit Main FID")
                    .foregroundStyle(.red)
                Spacer()
                Image(systemName: "rectangle.portrait.and.arrow.right")
                    .foregroundStyle(.red)
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 10)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .help("Drop this session and pick another main FID — the vault stays unlocked.")
    }

    /// One clickable identity row: avatar + title/subtitle + optional
    /// trailing checkmark/progress.
    private func row(
        avatarFid: String?,
        title: String,
        subtitle: String?,
        disabled: Bool,
        trailing: String?,
        action: @escaping () -> Void
    ) -> some View {
        Button(action: action) {
            HStack(spacing: 10) {
                if let avatarFid {
                    FidAvatarView(fid: avatarFid, size: 28)
                } else {
                    ZStack {
                        Circle()
                            .fill(Color.secondary.opacity(0.12))
                            .frame(width: 28, height: 28)
                        Image(systemName: "person.fill.questionmark")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
                VStack(alignment: .leading, spacing: 1) {
                    Text(title)
                        .font(.body)
                        .lineLimit(1)
                    if let subtitle {
                        Text(subtitle)
                            .font(.caption.monospaced())
                            .foregroundStyle(.secondary)
                            .lineLimit(1)
                    }
                }
                Spacer()
                if trailing == "checkmark" {
                    Image(systemName: "checkmark")
                        .font(.caption.bold())
                        .foregroundStyle(.secondary)
                } else if trailing == "progress" {
                    ProgressView().controlSize(.small)
                }
            }
            .padding(.horizontal, 8)
            .padding(.vertical, 5)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .disabled(disabled)
        .opacity(disabled && trailing == nil ? 0.5 : 1)
    }

    // MARK: - actions

    private func entries(of kind: KeyKind) -> [KeyInfo] {
        // Read the revision first so a label edit or a removal made
        // from this menu redraws it. The Setting is encrypted state
        // SwiftUI cannot observe, so nothing else would — same reason
        // ``PaneHeader/liveLabel`` does it.
        _ = appState.identityRevision
        return session.setting.keyInfoMap.values
            .filter { info in
                guard info.kind == kind, info.fid != session.mainFid else { return false }
                // The master's fetched KeyInfo is stored as .watched
                // (no privkey) but belongs to the My Master row, not
                // the watched list.
                return info.fid != masterFid
            }
            .sorted { $0.fid < $1.fid }
    }

    private func switchTo(fid: String) {
        appState.switchLive(fid: fid)
        onClose()
    }

    private func copyToPasteboard(_ text: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
    }

    /// What removing this entry actually costs — and the three kinds
    /// do not cost the same thing.
    ///
    /// **Multisig is the dangerous one.** A watched FID is a bookmark
    /// and a servant is a fact already on chain, so removing either
    /// loses a label that can be recreated in seconds. A multisig entry
    /// holds the group's *redeem script*, which exists nowhere on chain
    /// — the address is only its hash. Delete the last copy and the
    /// group's coins cannot be moved by anyone, ever. Reusing the
    /// reassuring "nothing is destroyed" line here would be false in
    /// exactly the case where it matters most.
    private func removalWarning(for info: KeyInfo) -> String {
        let elided = info.fid.elidingMiddle(head: 10, tail: 10)
        switch info.kind {
        case .multisig:
            let threshold = (info.multisig?.m).flatMap { m in
                (info.multisig?.n).map { n in "\(m)-of-\(n) " }
            } ?? ""
            return """
                \(elided) is a \(threshold)group, and its redeem script goes with it.                 That script is not stored on chain — the address is only its hash — so it is                 the only way this wallet can ever spend the group's coins. Unless another                 member still has a copy, removing it locks whatever the group holds forever.
                """
        case .servant:
            return "\(elided) is removed from this Setting's list. The servant relationship itself lives on chain and is untouched — you are only dropping the local entry, and can find it again any time."
        case .watched, .main:
            return "\(elided) is removed from this Setting's list. It is not a key you hold, so nothing is destroyed — add it again any time."
        }
    }

    private func rename(_ info: KeyInfo) {
        pendingRename = nil
        do {
            try session.setLabel(renameText, forFid: info.fid)
            // The Setting is the source of truth and this view reads it
            // directly, but nothing about `session` is observable — the
            // revision counter is what redraws the rows.
            appState.bumpIdentityRevision()
            noteIsError = false
            note = renameText.trimmingCharacters(in: .whitespaces).isEmpty
                ? "Label cleared."
                : "Labelled “\(renameText.trimmingCharacters(in: .whitespaces))”."
        } catch {
            noteIsError = true
            note = String(describing: error)
        }
    }

    private func remove(_ info: KeyInfo) {
        pendingRemoval = nil
        do {
            _ = try session.removeSubIdentity(fid: info.fid)
            // removeSubIdentity falls back to the main when the removed
            // entry was live; the observable mirror has to follow or the
            // toolbar keeps showing a FID the Setting no longer holds.
            appState.syncLiveFid()
            appState.bumpIdentityRevision()
            noteIsError = false
            note = "Removed \(info.fid.elidingMiddle(head: 8, tail: 8))."
        } catch {
            noteIsError = true
            note = String(describing: error)
        }
    }

    /// Android `showMasterOptions` / `switchToMaster`: switch to the
    /// main's master, fetching its KeyInfo from the directory when it
    /// isn't cached in the Setting yet. Setting a master (an on-chain
    /// carve — `SetMasterActivity`) is a later sub-phase.
    @MainActor
    private func switchToMaster() async {
        guard let masterFid else {
            noteIsError = false
            note = "No master is set for this FID — setting a master arrives in a later phase."
            return
        }
        if session.setting.keyInfoMap[masterFid] == nil {
            fetchingMaster = true
            defer { fetchingMaster = false }
            do {
                guard let freer = try await session.directory.freer(byId: masterFid),
                      let info = KeyInfo.from(freer: freer)
                else {
                    noteIsError = true
                    note = "No on-chain record found for master \(masterFid.elidingMiddle(head: 8, tail: 8))."
                    return
                }
                try session.addSubIdentity(info)
            } catch {
                noteIsError = true
                note = String(describing: error)
                return
            }
        }
        switchTo(fid: masterFid)
    }
}
