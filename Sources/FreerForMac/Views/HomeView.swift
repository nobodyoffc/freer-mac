import SwiftUI
import FCDomain
import FCUI



/// The unlocked landing screen. Sidebar-driven `NavigationSplitView`:
/// the sidebar selects a ``WalletPane``, the detail pane swaps based
/// on it. The window's top-right toolbar holds QR, the person menu
/// (live-FID avatar → identity-role popover, Android's `personView`),
/// and Lock-vault as icon buttons (so the detail content is free to
/// use its own column space).
/// Which multisig group the co-sign sheet is open for. A wrapper
/// rather than a bare `String?` so `.sheet(item:)` can key on it.
private struct SigningGroup: Identifiable {
    let fid: String
    var id: String { fid }
}

struct HomeView: View {
    @Environment(AppState.self) private var appState

    @State private var showQrTool = false
    @State private var showPersonMenu = false
    @State private var showAddWatched = false
    @State private var showSetMaster = false
    @State private var showAddServants = false
    @State private var showCreateMultisig = false
    @State private var showAddMultisig = false
    /// The group a co-sign sheet is open for. Identifiable-by-value so
    /// the sheet is rebuilt when the group changes.
    @State private var signingGroup: SigningGroup?
    /// One-line result of the last person-menu action, shown as a
    /// banner. The popover that started it is gone by the time the
    /// answer arrives, so it has nowhere else to land.
    @State private var identityNote: String?

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
            sidebar(for: session)
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
        .sheet(isPresented: $showSetMaster) {
            SetMasterSheet(session: session) { txid in
                showSetMaster = false
                appState.bumpIdentityRevision()
                identityNote = "Master carve broadcast — \(txid.elidingMiddle(head: 8, tail: 8)). It takes effect when the block confirms."
            } onCancel: {
                showSetMaster = false
            }
        }
        .sheet(isPresented: $showCreateMultisig) {
            CreateMultisigSheet(session: session) { info in
                showCreateMultisig = false
                appState.bumpIdentityRevision()
                identityNote = "Created \(info.fid.elidingMiddle(head: 8, tail: 8)). Give every member its redeem script — without it the group's coins cannot be moved."
            } onCancel: {
                showCreateMultisig = false
            }
        }
        .sheet(isPresented: $showAddMultisig) {
            AddMultisigSheet(session: session) { count in
                showAddMultisig = false
                appState.bumpIdentityRevision()
                identityNote = count == 1
                    ? "Added 1 multisig group."
                    : "Added \(count) multisig groups."
            } onCancel: {
                showAddMultisig = false
            }
        }
        .sheet(item: $signingGroup) { target in
            SignMultisigTxSheet(session: session, groupFid: target.fid) { txid in
                signingGroup = nil
                identityNote = "Broadcast \(txid.elidingMiddle(head: 8, tail: 8))."
            } onCancel: {
                signingGroup = nil
            }
        }
        .sheet(isPresented: $showAddServants) {
            AddServantsSheet(session: session) { count in
                showAddServants = false
                appState.bumpIdentityRevision()
                identityNote = count == 1
                    ? "Added 1 servant."
                    : "Added \(count) servants."
            } onCancel: {
                showAddServants = false
            }
        }
        .safeAreaInset(edge: .bottom) {
            if let identityNote {
                HStack(spacing: 8) {
                    Image(systemName: "info.circle")
                    CopyableText(identityNote, font: .callout)
                        .fixedSize(horizontal: false, vertical: true)
                    Spacer()
                    Button {
                        self.identityNote = nil
                    } label: {
                        Image(systemName: "xmark.circle.fill")
                    }
                    .buttonStyle(.plain)
                    .foregroundStyle(.secondary)
                }
                .padding(.horizontal, 16)
                .padding(.vertical, 10)
                .background(.regularMaterial)
            }
        }
    }

    /// Driven entirely by ``WalletPane/allCases``, so a new pane shows
    /// up here the moment it is added to the enum. Listing cases by
    /// hand here once meant a whole pane shipped unreachable.
    ///
    /// **Panes the live identity cannot use are dimmed, not removed.**
    /// A sidebar that reflows when you switch identity reads as a bug —
    /// the entries you were using a second ago are simply gone, with
    /// nothing saying why. Greying them with a lock and a tooltip says
    /// the same thing and keeps the shape of the app still. It also
    /// matches how the rest of this app refuses: ``PersonMenuView``
    /// dims its rows rather than dropping them, and every action button
    /// pairs `.disabled` with a `.help` that names the reason.
    private func sidebar(for session: ActiveSession) -> some View {
        @Bindable var state = appState
        let canSign = session.canSign
        return List(selection: $state.selectedPane) {
            ForEach(WalletPane.Group.allCases) { group in
                Section(group.rawValue) {
                    ForEach(WalletPane.panes(in: group)) { pane in
                        let closed = pane.needsKey && !canSign
                        Label {
                            Text(pane.title)
                        } icon: {
                            // The lock replaces the pane's own glyph
                            // rather than sitting beside it: at sidebar
                            // size two icons in a row is mush, and the
                            // one fact worth reading here is that the
                            // pane is shut.
                            Image(systemName: closed ? "lock" : pane.systemImage)
                        }
                        .tag(pane)
                        .disabled(closed)
                        .foregroundStyle(closed ? AnyShapeStyle(.tertiary) : AnyShapeStyle(.primary))
                        .help(closed ? (pane.closedReason ?? "") : "")
                    }
                }
            }
        }
        .listStyle(.sidebar)
    }

    @ViewBuilder
    private func detail(for session: ActiveSession) -> some View {
        switch appState.selectedPane {
        case .overview:
            OverviewView(session: session)
        case .send:
            SendView(session: session)
        case .compose:
            CreateTxView(session: session)
        case .cash:
            CashView(session: session)
        case .transactions:
            TransactionsView(session: session)
        case .proofs:
            ProofsView(session: session)
        case .tokens:
            TokensView(session: session)
        case .contacts:
            ContactsView(session: session)
        case .chat:
            ChatView(session: session)
        case .mail:
            MailView(session: session)
        case .news:
            NewsView(session: session)
        case .firstFch:
            FirstFchBoardView(session: session)
        case .files:
            FilesView(session: session)
        case .secrets:
            SecretsView(session: session)
        case .publishText:
            PublishTextView(session: session)
        case .publishStatement:
            PublishStatementView(session: session)
        case .publishImage:
            PublishMediaView(session: session, kind: .image)
        case .publishSound:
            PublishMediaView(session: session, kind: .sound)
        case .publishVideo:
            PublishMediaView(session: session, kind: .video)
        case .protocols:
            ProtocolsView(session: session)
        case .services:
            ServicesView(session: session)
        case .codes:
            CodesView(session: session)
        case .apps:
            AppsView(session: session)
        case .crypto:
            ToolsView(session: session)
        case .convert:
            ConvertView(session: session)
        case .terminal:
            TerminalPaneView(session: session)
        case .logs:
            SystemMessagesView(session: session)
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
                } onSetMaster: {
                    showSetMaster = true
                } onAddServants: {
                    showAddServants = true
                } onCreateMultisig: {
                    showCreateMultisig = true
                } onAddMultisig: {
                    showAddMultisig = true
                } onSignMultisig: { fid in
                    signingGroup = SigningGroup(fid: fid)
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
