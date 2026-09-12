import SwiftUI
import AppKit
import UniformTypeIdentifiers
import FCDomain
import FCUI

/// Add or edit one saved server.
///
/// Few fields, on purpose. Anything else `ssh` reads out of
/// `~/.ssh/config`, and `host` is passed through verbatim — so a `Host`
/// alias defined there works here and brings its own `ProxyJump`,
/// `Port` and `User` with it. Port forwards are the exception, because
/// a `LocalForward` in the config would be opened by every shell as
/// well as the tunnel, and the second one to bind would lose.
struct SshServerEditorSheet: View {

    enum Mode {
        case add
        case edit(SshServer)
    }

    let session: ActiveSession
    let mode: Mode
    let onSaved: () -> Void
    let onCancel: () -> Void

    @State private var label: String = ""
    @State private var host: String = ""
    @State private var port: String = "22"
    @State private var user: String = ""
    @State private var memo: String = ""
    @State private var saveError: String?

    @State private var identityKind: IdentityKind = .freer
    @State private var keyFilePath: String = ""

    @State private var forwards: [ForwardDraft] = []

    /// The picker's cases. Separate from ``SshServer/Identity`` because
    /// a `Picker` needs a tag that does not carry an associated value —
    /// the path lives beside it in `keyFilePath`.
    private enum IdentityKind: String, CaseIterable, Identifiable {
        case freer = "Freer key"
        case keyFile = "Key file"
        case systemDefaults = "System ssh"
        var id: String { rawValue }
    }

    /// One forward as typed: strings, so a half-typed port is a field
    /// the user is still editing rather than a value that failed to
    /// parse. The id is kept from the saved ``SshPortForward``.
    private struct ForwardDraft: Identifiable, Equatable {
        var id = UUID().uuidString
        var localPort = ""
        var remoteHost = "localhost"
        var remotePort = ""

        var forward: SshPortForward? {
            guard let local = Int(localPort.trimmingCharacters(in: .whitespaces)),
                  let remote = Int(remotePort.trimmingCharacters(in: .whitespaces))
            else { return nil }
            return SshPortForward(
                id: id,
                localPort: local,
                remoteHost: remoteHost.trimmingCharacters(in: .whitespaces),
                remotePort: remote
            )
        }
    }

    private var isEdit: Bool {
        if case .edit = mode { return true }
        return false
    }

    private var portValue: Int? {
        guard let n = Int(port.trimmingCharacters(in: .whitespaces)), (1...65535).contains(n) else { return nil }
        return n
    }

    /// Nil when every forward row is one the tunnel could open.
    private var forwardsError: String? {
        var parsed: [SshPortForward] = []
        for draft in forwards {
            guard let forward = draft.forward else { return "Ports are numbers from 1 to 65535." }
            parsed.append(forward)
        }
        return SshPortForward.firstProblem(in: parsed)
    }

    private var canSave: Bool {
        !host.trimmingCharacters(in: .whitespaces).isEmpty
            && !user.trimmingCharacters(in: .whitespaces).isEmpty
            && portValue != nil
            && (identityKind != .keyFile || !keyFilePath.trimmingCharacters(in: .whitespaces).isEmpty)
            && forwardsError == nil
    }

    private var identityHint: String {
        switch identityKind {
        case .freer:
            return "The ed25519 key derived from your main FID. After saving, put it on the server with Install Freer key in the server's menu."
        case .keyFile:
            return "A private key you already have. Freer's agent is never started; ssh reads the file, and asks here if it has a passphrase."
        case .systemDefaults:
            return "Plain ssh: your ~/.ssh/config, your own agent, your default keys. Freer adds no options at all."
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                Label(isEdit ? "Edit server" : "Add server", systemImage: "server.rack")
                    .font(.title3.weight(.semibold))
                Spacer()
            }
            .padding(16)

            Divider()

            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    LabeledField("Label", hint: "Optional. Falls back to user@host.") {
                        TextField("prod web", text: $label).fieldInputStyle()
                    }

                    LabeledField("Host", hint: "Hostname, IP, or a Host alias from ~/.ssh/config.") {
                        TextField("vps01.example.com", text: $host)
                            .fieldInputStyle()
                            .autocorrectionDisabled()
                    }

                    HStack(alignment: .top, spacing: 12) {
                        LabeledField("User") {
                            TextField("root", text: $user)
                                .fieldInputStyle()
                                .autocorrectionDisabled()
                        }
                        LabeledField(
                            "Port",
                            hint: portValue == nil ? "1–65535" : nil,
                            hintIsError: portValue == nil
                        ) {
                            TextField("22", text: $port)
                                .fieldInputStyle()
                                .frame(width: 90)
                        }
                    }

                    LabeledField("Key", hint: identityHint) {
                        VStack(alignment: .leading, spacing: 8) {
                            Picker("Key", selection: $identityKind) {
                                ForEach(IdentityKind.allCases) { Text($0.rawValue).tag($0) }
                            }
                            .pickerStyle(.segmented)
                            .labelsHidden()

                            if identityKind == .keyFile {
                                HStack(spacing: 8) {
                                    TextField("~/.ssh/id_ed25519", text: $keyFilePath)
                                        .fieldInputStyle()
                                        .autocorrectionDisabled()
                                    Button("Choose…", action: chooseKeyFile)
                                }
                            }
                        }
                    }

                    forwardsField

                    LabeledField("Memo", hint: "Optional.") {
                        TextField("what this box is for", text: $memo).fieldInputStyle()
                    }

                    if let saveError {
                        Label(saveError, systemImage: "exclamationmark.triangle")
                            .font(.callout)
                            .foregroundStyle(.orange)
                    }
                }
                .padding(20)
            }

            Divider()

            HStack {
                Spacer()
                Button("Cancel", action: onCancel).keyboardShortcut(.cancelAction)
                Button(isEdit ? "Save" : "Add", action: save)
                    .keyboardShortcut(.defaultAction)
                    .disabled(!canSave)
            }
            .padding(16)
        }
        .frame(width: 580, height: 680)
        .onAppear(perform: load)
    }

    private var forwardsField: some View {
        LabeledField(
            "Port forwards",
            hint: forwardsError ?? (forwards.isEmpty
                ? "Optional. Open tunnel, in the server's menu, opens these."
                : "Each port opens on this Mac's loopback only. The host on the right is looked up by the server, so localhost means the server itself."),
            hintIsError: forwardsError != nil
        ) {
            VStack(alignment: .leading, spacing: 8) {
                // By id, not `ForEach($forwards)`: removing a row while
                // its own text fields hold index-based bindings is the
                // classic SwiftUI out-of-range crash.
                ForEach(forwards) { draft in
                    HStack(spacing: 6) {
                        Text("localhost :")
                            .font(.system(.callout, design: .monospaced))
                            .foregroundStyle(.secondary)
                        TextField("8080", text: binding(draft.id, \.localPort))
                            .fieldInputStyle()
                            .frame(width: 72)
                        Image(systemName: "arrow.right")
                            .foregroundStyle(.secondary)
                        TextField("localhost", text: binding(draft.id, \.remoteHost))
                            .fieldInputStyle()
                            .autocorrectionDisabled()
                        Text(":")
                            .font(.system(.callout, design: .monospaced))
                            .foregroundStyle(.secondary)
                        TextField("80", text: binding(draft.id, \.remotePort))
                            .fieldInputStyle()
                            .frame(width: 72)
                        Button {
                            forwards.removeAll { $0.id == draft.id }
                        } label: {
                            Image(systemName: "minus.circle")
                        }
                        .buttonStyle(.borderless)
                        .help("Remove this forward")
                    }
                }
                Button {
                    forwards.append(ForwardDraft())
                } label: {
                    Label("Add forward", systemImage: "plus")
                }
                .buttonStyle(.borderless)
            }
        }
    }

    private func binding(_ id: String, _ field: WritableKeyPath<ForwardDraft, String>) -> Binding<String> {
        Binding(
            get: { forwards.first { $0.id == id }?[keyPath: field] ?? "" },
            set: { value in
                guard let i = forwards.firstIndex(where: { $0.id == id }) else { return }
                forwards[i][keyPath: field] = value
            }
        )
    }

    private func load() {
        guard case let .edit(server) = mode else { return }
        label = server.label
        host = server.host
        port = String(server.port)
        user = server.user
        memo = server.memo ?? ""
        switch server.credentialKind {
        case .freer:
            identityKind = .freer
        case let .keyFile(path):
            identityKind = .keyFile
            keyFilePath = path
        case .systemDefaults:
            identityKind = .systemDefaults
        }
        forwards = server.portForwards.map {
            ForwardDraft(
                id: $0.id,
                localPort: String($0.localPort),
                remoteHost: $0.remoteHost,
                remotePort: String($0.remotePort)
            )
        }
    }

    /// `~/.ssh` is `chflags hidden` on nothing, but it *is* a dotfile
    /// directory, so the panel has to be told to show hidden files or
    /// the one folder people keep keys in is invisible.
    private func chooseKeyFile() {
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        panel.showsHiddenFiles = true
        panel.treatsFilePackagesAsDirectories = true
        panel.message = "Pick the private key, not the .pub."
        panel.directoryURL = URL(fileURLWithPath: NSHomeDirectory()).appendingPathComponent(".ssh")
        guard panel.runModal() == .OK, let url = panel.url else { return }
        keyFilePath = url.path
    }

    private func save() {
        guard let portValue else { return }
        let trimmedMemo = memo.trimmingCharacters(in: .whitespaces)

        var server: SshServer
        switch mode {
        case .add:
            server = SshServer(host: host, port: portValue, user: user)
        case let .edit(existing):
            server = existing
            server.port = portValue
        }
        server.label = label
        server.host = host
        server.user = user
        server.memo = trimmedMemo.isEmpty ? nil : trimmedMemo

        switch identityKind {
        case .freer:
            server.identity = .freer
        case .keyFile:
            server.identity = .keyFile(path: keyFilePath.trimmingCharacters(in: .whitespaces))
        case .systemDefaults:
            server.identity = .systemDefaults
        }

        let parsed = forwards.compactMap(\.forward)
        server.forwards = parsed.isEmpty ? nil : parsed

        do {
            try session.sshServers.upsert(server)
            onSaved()
        } catch {
            saveError = "\(error)"
        }
    }
}
