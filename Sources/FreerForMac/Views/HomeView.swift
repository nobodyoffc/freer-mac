import SwiftUI
import FCDomain
import FCUI



/// The unlocked landing screen. Sidebar-driven `NavigationSplitView`:
/// the sidebar selects a ``WalletPane``, the detail pane swaps based
/// on it. The window's top-right toolbar holds QR, the person menu
/// (live-FID avatar → identity-role popover, Android's `personView`),
/// and Lock-vault as icon buttons (so the detail content is free to
/// use its own column space).
struct HomeView: View {
    @Environment(AppState.self) private var appState

    @State private var selection: WalletPane = .overview
    @State private var showQrTool = false
    @State private var showPersonMenu = false
    @State private var showAddWatched = false

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
                // Rebuild the pane when the live FID switches so it
                // refreshes for the new identity (onAppear re-runs) —
                // the Mac analogue of Android's post-switch
                // `refreshCidInfoAsync`.
                .id(appState.liveFid)
                .toolbar { toolbar(for: session) }
        }
        .sheet(isPresented: $showQrTool) {
            QrToolSheet { showQrTool = false }
        }
        .sheet(isPresented: $showAddWatched) {
            AddWatchedFidSheet(session: session) { _ in
                showAddWatched = false
            } onCancel: {
                showAddWatched = false
            }
        }
    }

    /// Driven entirely by ``WalletPane/allCases``, so a new pane shows
    /// up here the moment it is added to the enum. Listing cases by
    /// hand here once meant a whole pane shipped unreachable.
    private var sidebar: some View {
        List(selection: $selection) {
            ForEach(WalletPane.Group.allCases) { group in
                Section(group.rawValue) {
                    ForEach(WalletPane.panes(in: group)) { pane in
                        Label(pane.title, systemImage: pane.systemImage).tag(pane)
                    }
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
            SendView(session: session)
        case .receive:
            ReceiveView(session: session)
        case .transactions:
            TransactionsView(session: session)
        case .contacts:
            ContactsView(session: session)
        case .files:
            FilesView(session: session)
        case .secrets:
            SecretsView(session: session)
        case .tools:
            ToolsView(session: session)
        case .settings:
            SettingsView(session: session)
        }
    }

    @ToolbarContentBuilder
    private func toolbar(for session: ActiveSession) -> some ToolbarContent {
        ToolbarItemGroup(placement: .primaryAction) {
            // The QR workbench — scan (camera / images) or make QR
            // codes from anywhere, without leaving the current pane.
            Button {
                showQrTool = true
            } label: {
                Image(systemName: "qrcode")
            }
            .keyboardShortcut("k", modifiers: [.command])
            .help("QR — scan or make QR codes (⌘K)")

            // The person menu — who am I living as, and every
            // identity role I can switch to (Android's `personView`).
            // Also hosts Quit-Main-FID, so no separate
            // switch-identity button.
            Button {
                showPersonMenu = true
            } label: {
                FidAvatarView(fid: session.liveFid, size: 22)
            }
            .help("Identity — switch the live FID (main / master / watched / …)")
            .popover(isPresented: $showPersonMenu, arrowEdge: .bottom) {
                PersonMenuView(session: session) {
                    showAddWatched = true
                } onClose: {
                    showPersonMenu = false
                }
            }

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
}
