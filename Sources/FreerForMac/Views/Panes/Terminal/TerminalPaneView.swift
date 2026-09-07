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

    /// Which session each server is showing, by ``SshServer/id`` →
    /// ``TerminalSessionModel/id``. **Per server, not one global
    /// selection**, for the same reason the chat pane keeps a draft per
    /// flavour: coming back to a box should show the shell you left,
    /// not whichever tab you touched last on some other machine.
    @State private var activeSessionIds: [String: String] = [:]

    /// The tab being renamed, by ``TerminalSessionModel/id``, and the
    /// text in the field. Held here rather than on the model so an
    /// abandoned rename leaves nothing behind.
    @State private var renamingSessionId: String?
    @State private var renameText: String = ""

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
        .alert(
            "Name this session",
            isPresented: Binding(
                get: { renamingSessionId != nil },
                set: { if !$0 { renamingSessionId = nil } }
            )
        ) {
            TextField("Name", text: $renameText)
            Button("Save") { commitRename() }
            Button("Cancel", role: .cancel) { renamingSessionId = nil }
        } message: {
            Text("Every shell on one server sets the same title, so the tabs read alike. A name of your own — \"build\", \"logs\" — is the one that will still mean something in an hour. Leave it empty to go back to the shell's own title.")
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
            // Only from the second: "1" next to every row is noise, and
            // the dot already says whether anything is open.
            let count = appState.terminalSessions(for: server.id).count
            if count > 1 {
                Text("\(count)")
                    .font(.caption2.monospacedDigit())
                    .foregroundStyle(.secondary)
                    .help("\(count) sessions open")
            }
            if server.pinnedAt != nil {
                Image(systemName: "pin.fill").font(.caption2).foregroundStyle(.secondary)
            }
        }
        .contextMenu {
            Button("New session") { selectedId = server.id; connect(server) }
                .disabled(!canConnect(server))
            Divider()
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
            let sessions = appState.terminalSessions(for: server.id)
            let active = active(for: server)
            VStack(alignment: .leading, spacing: 10) {
                sessionHeader(server, active: active)

                if let connectError {
                    Label(connectError, systemImage: "exclamationmark.triangle")
                        .font(.callout)
                        .foregroundStyle(.orange)
                }

                // The bar arrives with the second session, which is also
                // the first moment it has anything to switch between —
                // with one shell open the header already names it, and a
                // row of tabs holding a single tab is chrome for its own
                // sake.
                if sessions.count > 1 {
                    sessionTabs(server, sessions: sessions, active: active)
                }

                if let active {
                    SshTerminalNSView(model: active)
                        // **Required, and its absence is invisible.**
                        // Reconnecting or switching tabs puts a
                        // different model on screen, but a representable
                        // of the same type in the same position keeps
                        // its existing NSView and only gets
                        // `updateNSView` — `makeNSView` is never called
                        // again. Without this the other session's
                        // terminal is never put on screen: ssh runs,
                        // prints its prompt or its error into a view in
                        // no window, and the pane still shows the
                        // *previous* session's transcript. It looks
                        // exactly like the Connect button doing nothing.
                        // Tying identity to the model makes SwiftUI tear
                        // the old view down and build the new one.
                        .id(ObjectIdentifier(active))
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                        .clipShape(RoundedRectangle(cornerRadius: 8))
                    if let ended = active.endedMessage {
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

    private func sessionHeader(_ server: SshServer, active: TerminalSessionModel?) -> some View {
        HStack(spacing: 10) {
            // **The server, and only the server.** This heading used
            // to follow the active session's title, so renaming a tab
            // renamed the pane and switching tabs moved the heading —
            // which reads as the machine having changed. It is fixed
            // now: what varies belongs in the bar, where the thing it
            // varies with is on screen next to it.
            VStack(alignment: .leading, spacing: 1) {
                Text(server.name)
                    .font(.headline)
                    .lineLimit(1)
                // `name` is already the target when the entry has no
                // label, so printing the target under it would be the
                // same string twice. Same line the sidebar row shows.
                Text(server.label.isEmpty
                     ? server.credentialKind.summary
                     : "\(server.target) · \(server.credentialKind.summary)")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
            Spacer()
            if let active, active.isRunning {
                Button("Disconnect", role: .destructive) {
                    // Stops the shell but keeps the transcript, so you
                    // can still read whatever it printed on the way out.
                    appState.stopTerminalSession(id: active.id)
                }
            } else if let active {
                // Reconnect closes the finished tab and opens a new
                // one rather than restarting this one: its terminal
                // view holds a spent pty and the last login's
                // scrollback. The new tab lands at the end of the bar,
                // not in the old one's slot — moving a session under
                // the cursor is worse than moving the tab.
                Button("Reconnect") {
                    appState.closeTerminalSession(id: active.id)
                    connect(server)
                }
                .keyboardShortcut(.defaultAction)
                .disabled(!canConnect(server))
            } else {
                Button("Connect") { connect(server) }
                    .keyboardShortcut(.defaultAction)
                    .disabled(!canConnect(server))
            }
            if active != nil {
                Button {
                    connect(server)
                } label: {
                    Image(systemName: "plus")
                }
                .keyboardShortcut("t", modifiers: .command)
                .disabled(!canConnect(server))
                .help("Open another session on this server (⌘T) — one to watch a log in, one to type in.")
            }
        }
    }

    /// One chip per open session, in the order they were opened.
    ///
    /// Horizontally scrolling rather than compressing: a tab whose
    /// label has been squeezed to nothing is a tab you have to click to
    /// identify, and the titles are how you tell two shells on the same
    /// box apart.
    private func sessionTabs(
        _ server: SshServer,
        sessions: [TerminalSessionModel],
        active: TerminalSessionModel?
    ) -> some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 6) {
                ForEach(sessions, id: \.id) { model in
                    sessionTab(server, model: model, isActive: model.id == active?.id)
                }
            }
            .padding(.bottom, 2)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private func sessionTab(
        _ server: SshServer,
        model: TerminalSessionModel,
        isActive: Bool
    ) -> some View {
        HStack(spacing: 6) {
            Circle()
                .fill(model.isRunning ? Color.green : Color.secondary.opacity(0.35))
                .frame(width: 6, height: 6)
            // Always drawn, and drawn first: the number is the only
            // part of a tab guaranteed to differ from its neighbours.
            Text("\(model.ordinal)")
                .font(.caption.monospacedDigit())
                .foregroundStyle(.secondary)
            // Only what the heading above does not already say — the
            // directory the shell is in, a name the user typed, or
            // failing both the time it opened. Elided in the middle so
            // the tail, which is where a path differs, survives.
            Text(model.tabTitle)
                .lineLimit(1)
                .truncationMode(.middle)
                .frame(maxWidth: 170, alignment: .leading)
            Button {
                close(model, of: server)
            } label: {
                Image(systemName: "xmark")
                    .font(.caption2)
            }
            .buttonStyle(.plain)
            .help("Close this session")
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 5)
        .background(
            RoundedRectangle(cornerRadius: 7)
                .fill(isActive ? Color.accentColor.opacity(0.18) : Color(NSColor.controlBackgroundColor))
        )
        .overlay(
            RoundedRectangle(cornerRadius: 7)
                .stroke(isActive ? Color.accentColor : .clear, lineWidth: 1)
        )
        .contentShape(RoundedRectangle(cornerRadius: 7))
        .help(tabTooltip(model))
        // Declared before the single tap so the double is not eaten by
        // it. Renaming is on the double-click because that is where
        // every other tab strip on this machine puts it.
        .onTapGesture(count: 2) { beginRename(model) }
        .onTapGesture { activeSessionIds[server.id] = model.id }
        .contextMenu {
            Button("Rename…") { beginRename(model) }
            if model.displayName != nil {
                Button("Clear name") { model.displayName = nil }
            }
            Divider()
            Button("Close", role: .destructive) { close(model, of: server) }
        }
    }

    /// The part of a session's identity there is no room for in the
    /// chip: when it was opened, and the exact command that opened it.
    private func tabTooltip(_ model: TerminalSessionModel) -> String {
        var lines = [
            "Session \(model.ordinal) · opened \(model.openedAt.formatted(date: .omitted, time: .shortened))"
        ]
        if !model.commandLine.isEmpty { lines.append(model.commandLine) }
        lines.append("Double-click to rename.")
        return lines.joined(separator: "\n")
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

    /// The dot in the sidebar: **any** live shell on this box, not a
    /// particular one.
    private func isRunning(_ server: SshServer) -> Bool {
        appState.terminalSessions(for: server.id).contains { $0.isRunning }
    }

    /// The session on screen for a server: the tab the user last
    /// picked, or failing that the newest — which is the one they just
    /// opened.
    private func active(for server: SshServer) -> TerminalSessionModel? {
        let sessions = appState.terminalSessions(for: server.id)
        if let id = activeSessionIds[server.id],
           let chosen = sessions.first(where: { $0.id == id }) {
            return chosen
        }
        return sessions.last
    }

    /// Open one more shell on this server and show it.
    private func connect(_ server: SshServer) {
        connectError = nil
        do {
            let credential = try resolveCredential(for: server)
            let model = appState.openTerminalSession(for: server)
            if let error = model.start(credential: credential) {
                connectError = error
                appState.closeTerminalSession(id: model.id)
                return
            }
            activeSessionIds[server.id] = model.id
            try? session.sshServers.touchLastUsed(id: server.id)
            reload()
        } catch {
            connectError = "\(error)"
        }
    }

    private func beginRename(_ model: TerminalSessionModel) {
        renameText = model.displayName ?? ""
        renamingSessionId = model.id
    }

    /// An empty field clears the name rather than setting an empty one,
    /// so the tab falls back to the shell's title instead of going
    /// blank.
    private func commitRename() {
        defer { renamingSessionId = nil }
        guard let id = renamingSessionId,
              let model = appState.terminalSessions.first(where: { $0.id == id })
        else { return }
        let name = renameText.trimmingCharacters(in: .whitespacesAndNewlines)
        model.displayName = name.isEmpty ? nil : name
    }

    /// Close one tab, handing the pane to its neighbour on the way out
    /// — the tab to the left, or the one to the right when there is no
    /// left. Falling back to "the newest" instead would jump the user
    /// across the bar every time they closed the tab they were in.
    private func close(_ model: TerminalSessionModel, of server: SshServer) {
        if activeSessionIds[server.id] == model.id || active(for: server)?.id == model.id {
            let sessions = appState.terminalSessions(for: server.id)
            if let i = sessions.firstIndex(where: { $0.id == model.id }) {
                let neighbour = i > 0
                    ? sessions[i - 1]
                    : (i + 1 < sessions.count ? sessions[i + 1] : nil)
                activeSessionIds[server.id] = neighbour?.id
            }
        }
        appState.closeTerminalSession(id: model.id)
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
        appState.closeTerminalSessions(forServer: server.id)
        activeSessionIds[server.id] = nil
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
