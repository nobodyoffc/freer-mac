import SwiftUI
import AppKit
import FCCore
import FCDomain
import FCUI

/// SSH from inside Freer, authenticating with a key derived from the
/// main FID.
///
/// Named `TerminalPaneView` and not `TerminalView` because SwiftTerm
/// exports a public `TerminalView`; a same-named `View` in this module
/// shadows it and the resulting errors point everywhere except here.
///
/// The pane holds no session state of its own — sessions and the
/// ssh-agent live on ``AppState`` so they survive a trip to another
/// pane. What is `@State` here is only what the user is looking at.
struct TerminalPaneView: View {

    let session: ActiveSession
    @Environment(AppState.self) private var appState

    @State private var servers: [SshServer] = []
    @State private var selectedId: String?
    @State private var search: String = ""
    @State private var loadError: String?
    @State private var connectError: String?

    @State private var editor: SshServerEditorSheet.Mode?
    @State private var showingPublicKey = false
    @State private var confirmingDelete: SshServer?

    /// The SSH key comes from the **main** FID, so a watch-only live
    /// identity is fine — but a watch-only *main* is not, and that is
    /// the one case the pane cannot work in.
    private var mainCanDerive: Bool {
        session.mainKeyInfo.hasPrivkey
    }

    /// A server on its own key file works perfectly well in a vault
    /// whose main FID is watch-only — only the derived key is closed.
    private func canConnect(_ server: SshServer) -> Bool {
        server.credentialKind == .freer ? mainCanDerive : true
    }

    private var filtered: [SshServer] {
        let q = search.trimmingCharacters(in: .whitespaces).lowercased()
        guard !q.isEmpty else { return servers }
        return servers.filter {
            $0.name.lowercased().contains(q)
                || $0.host.lowercased().contains(q)
                || $0.user.lowercased().contains(q)
                || ($0.memo ?? "").lowercased().contains(q)
        }
    }

    private var selected: SshServer? {
        guard let selectedId else { return nil }
        return servers.first { $0.id == selectedId }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            PaneHeader(session: session)
            Divider()

            if !mainCanDerive {
                watchOnlyMainBanner
            }

            toolbar

            if let loadError {
                Label(loadError, systemImage: "exclamationmark.triangle")
                    .font(.callout)
                    .foregroundStyle(.orange)
            }

            HSplitView {
                serverList
                    .frame(minWidth: 220, idealWidth: 260, maxWidth: 380)
                detail
                    .frame(minWidth: 420)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
        .padding()
        .onAppear(perform: reload)
        .sheet(item: $editor) { mode in
            SshServerEditorSheet(
                session: session,
                mode: mode,
                onSaved: { editor = nil; reload() },
                onCancel: { editor = nil }
            )
        }
        .sheet(isPresented: $showingPublicKey) {
            SshPublicKeySheet(session: session) { showingPublicKey = false }
        }
        .confirmationDialog(
            "Remove \(confirmingDelete?.name ?? "")?",
            isPresented: Binding(
                get: { confirmingDelete != nil },
                set: { if !$0 { confirmingDelete = nil } }
            ),
            titleVisibility: .visible
        ) {
            Button("Remove", role: .destructive) {
                if let server = confirmingDelete { remove(server) }
                confirmingDelete = nil
            }
            Button("Cancel", role: .cancel) { confirmingDelete = nil }
        } message: {
            Text("This only forgets the entry here. Nothing changes on the server.")
        }
    }

    // MARK: - Chrome

    private var watchOnlyMainBanner: some View {
        Label(
            "This vault's main identity has no private key, so there is no Freer SSH key to derive. Servers set to use one of your own key files still work.",
            systemImage: "lock"
        )
        .font(.callout)
        .foregroundStyle(.secondary)
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(NSColor.controlBackgroundColor))
        .clipShape(RoundedRectangle(cornerRadius: 10))
    }

    private var toolbar: some View {
        HStack(spacing: 12) {
            SearchField("Search servers", text: $search, minWidth: 160, maxWidth: 260)

            Button {
                editor = .add
            } label: {
                Label("Add server", systemImage: "plus")
            }

            Spacer()

            if appState.sshAgentIsRunning {
                // An agent that can sign as you should never be running
                // invisibly — this is the only place that says so.
                Label("Agent running", systemImage: "key.fill")
                    .font(.caption)
                    .foregroundStyle(.green)
                    .help("Freer is holding your SSH key in memory for the open sessions. It stops when the last one closes, and when you lock the vault.")
            }

            Button {
                showingPublicKey = true
            } label: {
                Label("Public key", systemImage: "key")
            }
            .disabled(!mainCanDerive)
        }
    }

    // MARK: - Server list

    private var serverList: some View {
        List(selection: $selectedId) {
            ForEach(filtered) { server in
                row(server).tag(server.id)
            }
        }
        .listStyle(.sidebar)
        .overlay {
            if servers.isEmpty {
                ContentUnavailableView(
                    "No servers yet",
                    systemImage: "server.rack",
                    description: Text("Add one, then copy your public key onto it.")
                )
            }
        }
    }

    private func row(_ server: SshServer) -> some View {
        HStack(spacing: 8) {
            Circle()
                .fill(isRunning(server) ? Color.green : Color.secondary.opacity(0.35))
                .frame(width: 7, height: 7)
            VStack(alignment: .leading, spacing: 1) {
                Text(server.name).lineLimit(1)
                Text(server.label.isEmpty
                     ? server.credentialKind.summary
                     : "\(server.target) · \(server.credentialKind.summary)")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
            Spacer()
            if server.pinnedAt != nil {
                Image(systemName: "pin.fill").font(.caption2).foregroundStyle(.secondary)
            }
        }
        .contextMenu {
            Button("Edit…") { editor = .edit(server) }
            Button(server.pinnedAt == nil ? "Pin" : "Unpin") { togglePin(server) }
            Divider()
            Button("Remove…", role: .destructive) { confirmingDelete = server }
        }
    }

    // MARK: - Detail

    @ViewBuilder
    private var detail: some View {
        if let server = selected {
            VStack(alignment: .leading, spacing: 10) {
                sessionHeader(server)

                if let connectError {
                    Label(connectError, systemImage: "exclamationmark.triangle")
                        .font(.callout)
                        .foregroundStyle(.orange)
                }

                if let model = appState.terminalSessions[server.id] {
                    SshTerminalNSView(model: model)
                        // **Required, and its absence is invisible.**
                        // Reconnecting builds a new model with a new
                        // `LocalProcessTerminalView`, but a
                        // representable of the same type in the same
                        // position keeps its existing NSView and only
                        // gets `updateNSView` — `makeNSView` is never
                        // called again. Without this the second
                        // session's terminal is never put on screen:
                        // ssh runs, prints its prompt or its error into
                        // a view in no window, and the pane still shows
                        // the *previous* session's dead transcript. It
                        // looks exactly like the Connect button doing
                        // nothing. Tying identity to the model makes
                        // SwiftUI tear the old view down and build the
                        // new one.
                        .id(ObjectIdentifier(model))
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                        .clipShape(RoundedRectangle(cornerRadius: 8))
                    if let ended = model.endedMessage {
                        Text(ended).font(.caption).foregroundStyle(.secondary)
                    }
                } else {
                    idleDetail(server)
                }
            }
        } else {
            ContentUnavailableView(
                "Pick a server",
                systemImage: "terminal",
                description: Text("Your first login uses a password. Paste the public key, and the next one will not.")
            )
        }
    }

    private func sessionHeader(_ server: SshServer) -> some View {
        HStack(spacing: 10) {
            VStack(alignment: .leading, spacing: 1) {
                Text(appState.terminalSessions[server.id]?.remoteTitle ?? server.name)
                    .font(.headline)
                    .lineLimit(1)
                Text(server.target).font(.caption).foregroundStyle(.secondary)
            }
            Spacer()
            if isRunning(server) {
                Button("Disconnect", role: .destructive) {
                    // Stops the shell but keeps the transcript, so you
                    // can still read whatever it printed on the way out.
                    appState.stopTerminalSession(id: server.id)
                }
            } else {
                Button("Connect") { connect(server) }
                    .keyboardShortcut(.defaultAction)
                    .disabled(!canConnect(server))
            }
        }
    }

    private func idleDetail(_ server: SshServer) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            if let memo = server.memo, !memo.isEmpty {
                Text(memo).font(.callout).foregroundStyle(.secondary)
            }
            Spacer()
            HStack {
                Spacer()
                ContentUnavailableView(
                    "Not connected",
                    systemImage: "terminal",
                    description: Text("Connect to open a shell on \(server.host).")
                )
                Spacer()
            }
            Spacer()
        }
    }

    // MARK: - Actions

    private func isRunning(_ server: SshServer) -> Bool {
        appState.terminalSessions[server.id]?.isRunning ?? false
    }

    private func connect(_ server: SshServer) {
        connectError = nil
        do {
            let credential = try resolveCredential(for: server)
            let model = appState.terminalSession(for: server)
            if let error = model.start(credential: credential) {
                connectError = error
                appState.closeTerminalSession(id: server.id)
                return
            }
            try? session.sshServers.touchLastUsed(id: server.id)
            reload()
        } catch {
            connectError = "\(error)"
        }
    }

    /// Turn the server's stored choice into something ``SshLaunch`` can
    /// use — and start the agent only when the Freer key is the one
    /// being used. A server opened with your own key never brings the
    /// agent up, so the derived key is not sitting in a socket for
    /// connections that were never going to use it.
    private func resolveCredential(for server: SshServer) throws -> SshLaunch.Credential {
        switch server.credentialKind {
        case .freer:
            // Started here, not at launch: it can sign as you for as
            // long as it is up, so its window is the session's.
            let agent = try appState.sshAgent(for: session)
            return .freerAgent(publicKeyPath: agent.publicKeyPath, socketPath: agent.socketPath)
        case let .keyFile(path):
            let expanded = (path as NSString).expandingTildeInPath
            guard FileManager.default.fileExists(atPath: expanded) else {
                throw PaneError.missingKeyFile(expanded)
            }
            return .keyFile(path: expanded)
        case .systemDefaults:
            return .systemDefaults
        }
    }

    private enum PaneError: Error, CustomStringConvertible {
        case missingKeyFile(String)

        var description: String {
            switch self {
            case let .missingKeyFile(path):
                return "No key file at \(path). Edit the server and pick it again."
            }
        }
    }

    private func togglePin(_ server: SshServer) {
        _ = try? session.sshServers.togglePin(id: server.id)
        reload()
    }

    private func remove(_ server: SshServer) {
        appState.closeTerminalSession(id: server.id)
        _ = try? session.sshServers.remove(id: server.id)
        if selectedId == server.id { selectedId = nil }
        reload()
    }

    private func reload() {
        do {
            servers = try session.sshServers.all()
            loadError = nil
        } catch {
            loadError = "Could not read saved servers — \(error)"
        }
    }
}

extension SshServerEditorSheet.Mode: Identifiable {
    var id: String {
        switch self {
        case .add: return "add"
        case let .edit(server): return "edit-\(server.id)"
        }
    }
}
