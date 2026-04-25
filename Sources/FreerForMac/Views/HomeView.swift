import SwiftUI
import FCDomain
import FCUI

/// The unlocked landing screen. Two-pane layout: sidebar of (currently
/// inert) feature labels, and a detail pane that shows the live FID.
/// The window's top-right toolbar holds Switch-live-FID, Switch-
/// identity, and Lock-vault as icon buttons — that lets the header
/// breathe and stops the FID from wrapping into the buttons.
/// Phase 7 fills the detail pane with real wallet UI.
struct HomeView: View {
    @Environment(AppState.self) private var appState

    var body: some View {
        if let session = appState.activeSession {
            content(for: session)
        } else {
            // Defensive: shouldn't happen because the router only
            // shows this view when activeSession exists.
            VStack {
                Text("No active session.")
                Button("Back to vault") { appState.lockAll() }
            }
            .padding()
        }
    }

    @ViewBuilder
    private func content(for session: ActiveSession) -> some View {
        NavigationSplitView {
            sidebar
                .navigationSplitViewColumnWidth(min: 200, ideal: 240, max: 320)
        } detail: {
            detail(for: session)
                .toolbar { toolbar(for: session) }
        }
    }

    private var sidebar: some View {
        List {
            Section("Wallet") {
                Label("Overview", systemImage: "house")
                Label("Send", systemImage: "paperplane")
                    .foregroundStyle(.secondary)
                Label("Receive", systemImage: "tray.and.arrow.down")
                    .foregroundStyle(.secondary)
                Label("Transactions", systemImage: "list.bullet")
                    .foregroundStyle(.secondary)
            }
            Section("Network") {
                Label("Contacts", systemImage: "person.2")
                    .foregroundStyle(.secondary)
                Label("Settings", systemImage: "gearshape")
                    .foregroundStyle(.secondary)
            }
        }
        .listStyle(.sidebar)
    }

    @ToolbarContentBuilder
    private func toolbar(for session: ActiveSession) -> some ToolbarContent {
        ToolbarItemGroup(placement: .primaryAction) {
            // Switch the live FID without re-auth.
            Menu {
                ForEach(switchableEntries(in: session), id: \.fid) { info in
                    Button {
                        appState.switchLive(fid: info.fid)
                    } label: {
                        if info.fid == session.liveFid {
                            Label(displayLabel(info), systemImage: "checkmark")
                        } else {
                            Text(displayLabel(info))
                        }
                    }
                }
            } label: {
                Image(systemName: "arrow.triangle.2.circlepath")
            }
            .help("Switch live FID")
            .disabled(switchableEntries(in: session).count < 2)

            // Drop the active session, return to ChooseMain.
            // Configure stays unlocked.
            Button {
                appState.returnToChooseMain()
            } label: {
                Image(systemName: "rectangle.portrait.and.arrow.right")
            }
            .help("Switch identity")

            // Full lock — symkey wiped, back to PasswordView.
            Button {
                appState.lockAll()
            } label: {
                Image(systemName: "lock.fill")
            }
            .keyboardShortcut("l", modifiers: [.command])
            .help("Lock vault (⌘L)")
        }
    }

    @ViewBuilder
    private func detail(for session: ActiveSession) -> some View {
        VStack(alignment: .leading, spacing: 16) {

            HStack(alignment: .center, spacing: 14) {
                FidAvatarView(fid: session.liveFid, size: 56)

                VStack(alignment: .leading, spacing: 4) {
                    Text(session.liveKeyInfo.label.isEmpty
                         ? "Live: \(session.liveKeyInfo.kind.rawValue)"
                         : session.liveKeyInfo.label)
                        .font(.title2).bold()
                        .lineLimit(1)
                        .truncationMode(.tail)

                    Text(session.liveFid)
                        .font(.system(.callout, design: .monospaced))
                        .foregroundStyle(.secondary)
                        .textSelection(.enabled)
                        .lineLimit(1)
                        .truncationMode(.middle)

                    HStack(spacing: 6) {
                        Image(systemName: session.canSign ? "key.fill" : "eye")
                        Text(session.canSign
                             ? "\(session.liveKeyInfo.kind.rawValue) — can sign"
                             : "\(session.liveKeyInfo.kind.rawValue) — watch only")
                    }
                    .font(.caption)
                    .foregroundStyle(session.canSign ? Color.blue : Color.orange)
                }

                Spacer(minLength: 0)
            }

            Divider()

            VStack(alignment: .leading, spacing: 8) {
                Text("Phase 5.8 landing").font(.headline)
                Text(
                    """
                    Avatar module is wired. Vault → Main FID → Live FID — \
                    switching live without re-auth, watch-only sub-identities \
                    blocked from operations that need a privkey.

                    Phase 7 fills this pane with the real wallet UI:
                    • balance + UTXO list (`base.balanceByIds`, `base.getUtxo`)
                    • send (FCH transactions, signed locally)
                    • receive (QR + address)
                    • transaction history
                    • contacts management

                    Networking is currently stubbed (`StubFapiClient` throws on \
                    every call). The `FudpClient` / `FapiClient` plumbing is \
                    already in `FCTransport`; the real client wires in once we \
                    have the FAPI server's pubkey for `localhost:8500`.
                    """
                )
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            }
            .padding()
            .background(Color(NSColor.controlBackgroundColor))
            .clipShape(RoundedRectangle(cornerRadius: 8))

            Spacer()
        }
        .padding()
        .frame(minWidth: 480)
    }

    /// All FIDs in `setting.keyInfoMap` that the user can pivot the
    /// live cursor to: the main itself plus every sub-identity. Sorted
    /// with main first.
    private func switchableEntries(in session: ActiveSession) -> [KeyInfo] {
        let entries = Array(session.setting.keyInfoMap.values)
        return entries.sorted { lhs, rhs in
            if lhs.fid == session.mainFid { return true }
            if rhs.fid == session.mainFid { return false }
            return lhs.fid < rhs.fid
        }
    }

    private func displayLabel(_ info: KeyInfo) -> String {
        let prefix = info.label.isEmpty ? info.kind.rawValue : info.label
        let kindAnnotation = info.label.isEmpty ? "" : " (\(info.kind.rawValue))"
        return "\(prefix)\(kindAnnotation) — \(info.fid.prefix(10))…"
    }
}
