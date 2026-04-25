import SwiftUI
import FCDomain

/// Logged-in landing screen. Phase 6.1 ships a placeholder that
/// proves the auth flow works end-to-end. Phase 7 fills in the real
/// wallet UI (balance, send, transactions, contacts).
struct HomeView: View {
    @Environment(AppState.self) private var appState

    var body: some View {
        if let session = appState.session {
            content(for: session)
        } else {
            // Defensive: if we ended up on .home without a session
            // (shouldn't happen), bounce out cleanly.
            VStack {
                Text("No active session.")
                Button("Back to login") { appState.goToChooseIdentity() }
            }
            .padding()
        }
    }

    @ViewBuilder
    private func content(for session: IdentitySession) -> some View {
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
    private func detail(for session: IdentitySession) -> some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack(spacing: 12) {
                Image(systemName: "person.crop.circle.fill")
                    .font(.system(size: 40))
                    .foregroundStyle(.blue)
                VStack(alignment: .leading, spacing: 2) {
                    Text(session.displayName).font(.title2).bold()
                    Text(session.fid)
                        .font(.system(.callout, design: .monospaced))
                        .foregroundStyle(.secondary)
                        .textSelection(.enabled)
                }
                Spacer()
                Button {
                    appState.lock()
                } label: {
                    Label("Lock", systemImage: "lock")
                }
                .keyboardShortcut("l", modifiers: [.command])
            }

            Divider()

            VStack(alignment: .leading, spacing: 8) {
                Text("Phase 6.1 placeholder")
                    .font(.headline)
                Text(
                    """
                    The auth flow now works end-to-end. Phase 7 lights up:
                    • balance + UTXO list
                    • send (FCH transactions)
                    • receive (QR + address)
                    • transaction history
                    • contacts management

                    Underlying primitives (FCCore signing, FCTransport FUDP, FCStorage \
                    encryption, FCDomain wallet) are all in place. \
                    Networking is currently stubbed; Phase 6.2 wires a real FapiClient.
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
}
