import SwiftUI
import FCDomain

/// The unlocked landing screen. Phase 5.7d ships a simple two-pane
/// layout: sidebar of (currently inert) feature labels, and a detail
/// pane that shows the live FID with a switcher and quick lock.
/// Phase 7 fills the detail with real wallet UI.
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

    @ViewBuilder
    private func detail(for session: ActiveSession) -> some View {
        VStack(alignment: .leading, spacing: 16) {

            HStack(spacing: 12) {
                Image(systemName: "person.crop.circle.fill")
                    .font(.system(size: 40))
                    .foregroundStyle(session.canSign ? .blue : .orange)
                VStack(alignment: .leading, spacing: 2) {
                    Text(session.liveKeyInfo.label.isEmpty
                         ? "Live: \(session.liveKeyInfo.kind.rawValue)"
                         : session.liveKeyInfo.label)
                        .font(.title2).bold()
                    Text(session.liveFid)
                        .font(.system(.callout, design: .monospaced))
                        .foregroundStyle(.secondary)
                        .textSelection(.enabled)
                    HStack(spacing: 6) {
                        Image(systemName: session.canSign ? "key.fill" : "eye")
                        Text(session.canSign
                             ? "\(session.liveKeyInfo.kind.rawValue) — can sign"
                             : "\(session.liveKeyInfo.kind.rawValue) — watch only")
                    }
                    .font(.caption)
                    .foregroundStyle(.secondary)
                }
                Spacer()

                Menu {
                    Section("Switch live FID") {
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
                    }
                } label: {
                    Label("Switch", systemImage: "arrow.triangle.2.circlepath")
                }

                Button("Switch identity") {
                    appState.returnToChooseMain()
                }
                Button("Lock vault") {
                    appState.lockAll()
                }
                .keyboardShortcut("l", modifiers: [.command])
            }

            Divider()

            VStack(alignment: .leading, spacing: 8) {
                Text("Phase 5.7d landing").font(.headline)
                Text(
                    """
                    The new auth flow is live. Vault → Main FID → Live FID — \
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
                    already in `FCTransport`; Phase 6 wires it once we have \
                    the FAPI server's pubkey for `localhost:8500`.
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
