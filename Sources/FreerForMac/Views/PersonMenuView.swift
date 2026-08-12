import SwiftUI
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
///     KeyInfo from the directory when it isn't cached locally.
///     Setting a master (an on-chain carve) lands in a later phase.
///   - **My Watched FIDs / My Multisig FIDs / My Servants** — entries
///     of that kind; click to switch. Only Watched has an Add flow.
///   - **Quit Main FID** — drop the session, back to the main chooser.
///
/// Same gating as Android: everything except *Main FID* and *Quit*
/// is disabled unless you're living as main.
struct PersonMenuView: View {
    @Environment(AppState.self) private var appState
    let session: ActiveSession
    /// Open the add-watched-FID sheet. Hoisted to HomeView because a
    /// sheet presented from inside a popover dies with the popover.
    let onAddWatched: () -> Void
    let onClose: () -> Void

    @State private var fetchingMaster = false
    @State private var note: String?
    @State private var noteIsError = false

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
                        emptyText: "No multisig FIDs yet — adding them comes with the multisig phase."
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
        row(
            avatarFid: masterFid,
            title: "My Master",
            subtitle: masterFid.map { $0.elidingMiddle(head: 8, tail: 8) } ?? "not set",
            disabled: !livingAsMain || fetchingMaster,
            trailing: fetchingMaster ? "progress"
                : (session.liveFid == masterFid ? "checkmark" : nil)
        ) {
            Task { await switchToMaster() }
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
                if kind == .watched {
                    Button {
                        onClose()
                        onAddWatched()
                    } label: {
                        Image(systemName: "plus.circle")
                    }
                    .buttonStyle(.plain)
                    .foregroundStyle(livingAsMain ? Color.accentColor : .secondary)
                    .disabled(!livingAsMain)
                    .help("Add a watched FID")
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
                        subtitle: info.label.isEmpty
                            ? nil
                            : info.fid.elidingMiddle(head: 8, tail: 8),
                        disabled: !livingAsMain || info.fid == session.liveFid,
                        trailing: info.fid == session.liveFid ? "checkmark" : nil
                    ) {
                        switchTo(fid: info.fid)
                    }
                }
            }
        }
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
        session.setting.keyInfoMap.values
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
