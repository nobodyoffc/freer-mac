import SwiftUI
import FCDomain
import FCUI

/// The unlocked landing screen. Sidebar-driven `NavigationSplitView`:
/// the sidebar selects a ``WalletPane``, the detail pane swaps based
/// on it. The window's top-right toolbar holds Switch-live-FID,
/// Switch-identity, and Lock-vault as icon buttons (so the detail
/// content is free to use its own column space).
struct HomeView: View {
    @Environment(AppState.self) private var appState

    @State private var selection: WalletPane = .overview

    var body: some View {
        if let session = appState.activeSession {
            content(for: session)
        } else {
            // Defensive: shouldn't happen — the router only shows
            // this view when activeSession is non-nil.
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
        List(selection: $selection) {
            Section("Wallet") {
                ForEach([WalletPane.overview, .send, .receive, .transactions]) { pane in
                    Label(pane.title, systemImage: pane.systemImage).tag(pane)
                }
            }
            Section("Network") {
                ForEach([WalletPane.contacts, .settings]) { pane in
                    Label(pane.title, systemImage: pane.systemImage).tag(pane)
                }
            }
        }
        .listStyle(.sidebar)
    }

    @ViewBuilder
    private func detail(for session: ActiveSession) -> some View {
        switch selection {
        case .overview:
            OverviewView(session: session)
        case .send:
            PlaceholderPaneView(
                session: session,
                title: "Send",
                systemImage: "paperplane",
                summary: "Build a signed FCH transaction and broadcast it via base.broadcastTx. Lands in Phase 7.2.",
                bullets: [
                    "Recipient FID + amount entry",
                    "Greedy coin selection from the cached UTXO set",
                    "Signed locally via FCCore.TxHandler — never leaves your Mac unsigned",
                    "Watch-only fallback: export an unsigned TxInfo for cold signing"
                ]
            )
        case .receive:
            ReceiveView(session: session)
        case .transactions:
            PlaceholderPaneView(
                session: session,
                title: "Transactions",
                systemImage: "list.bullet",
                summary: "History of inbound and outbound txs for the live FID. Lands in Phase 7.3.",
                bullets: [
                    "Pulled via base.search on the Cash index, paged with `last`",
                    "Each row shows direction, counterparty, amount, height, timestamp",
                    "Tap to expand → raw tx JSON + explorer link"
                ]
            )
        case .contacts:
            PlaceholderPaneView(
                session: session,
                title: "Contacts",
                systemImage: "person.2",
                summary: "Address book of FIDs you transact with — backed by the per-main ContactsStore.",
                bullets: [
                    "Add by FID (validated via FchAddress on insert)",
                    "Pin frequently-used contacts to the top",
                    "Cached pubkey lookups so sends to known peers skip a roundtrip"
                ]
            )
        case .settings:
            SettingsView(session: session)
        }
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

    // MARK: - helpers

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
