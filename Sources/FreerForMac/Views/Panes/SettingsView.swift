import SwiftUI
import FCDomain

/// Per-main-FID preferences. Phase 7.1 ships the FAPI server form
/// (host / port / pubkey hex) and a couple of UI knobs (theme,
/// auto-lock seconds). Preferences persist to the per-main
/// ``PreferencesStore``; the actual `FapiClient` rebuild on save lands
/// in Phase 7.2 alongside the test-connection action.
struct SettingsView: View {
    let session: ActiveSession

    @State private var fapiHost: String = ""
    @State private var fapiPort: String = ""
    @State private var fapiPubkeyHex: String = ""
    @State private var theme: Preferences.Theme = .system
    @State private var autoLockMinutes: String = ""

    @State private var saveError: String?
    @State private var saveOk: Bool = false

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            PaneHeader(session: session)
            Divider()
            form
            Spacer()
        }
        .padding()
        .frame(minWidth: 480)
        .onAppear { load() }
    }

    private var form: some View {
        Form {
            Section {
                TextField("Host", text: $fapiHost, prompt: Text("localhost"))
                TextField("Port", text: $fapiPort, prompt: Text("8500"))
                    .frame(maxWidth: 140)
                TextField("Server pubkey (66 hex chars)",
                          text: $fapiPubkeyHex,
                          prompt: Text("03cd14…"))
                    .font(.system(.body, design: .monospaced))
                if !fapiPubkeyHex.isEmpty, !pubkeyLooksValid(fapiPubkeyHex) {
                    Text("Pubkey must be 66 hex characters (33 SEC1-compressed bytes).")
                        .font(.caption)
                        .foregroundStyle(.red)
                }
            } header: {
                Text("FAPI server")
            } footer: {
                Text("The FAPI server's pubkey lets the wallet establish an authenticated FUDP session. Without it, balance / send / broadcast are unavailable.")
                    .font(.caption)
            }

            Section("Appearance") {
                Picker("Theme", selection: $theme) {
                    ForEach(Preferences.Theme.allCases, id: \.self) { t in
                        Text(t.rawValue.capitalized).tag(t)
                    }
                }
            }

            Section("Security") {
                TextField("Auto-lock after (minutes, blank = never)",
                          text: $autoLockMinutes,
                          prompt: Text("e.g. 10"))
                    .frame(maxWidth: 240)
            }

            if let err = saveError {
                Section {
                    Text(err).foregroundStyle(.red).font(.callout)
                }
            }

            Section {
                HStack {
                    if saveOk {
                        Label("Saved", systemImage: "checkmark.circle.fill")
                            .foregroundStyle(.green)
                            .font(.callout)
                    }
                    Spacer()
                    Button {
                        save()
                    } label: {
                        Text("Save").frame(width: 100)
                    }
                    .keyboardShortcut(.defaultAction)
                    .buttonStyle(.borderedProminent)
                    .disabled(!canSave)
                }
            }
        }
        .formStyle(.grouped)
    }

    // MARK: - load / save

    private var canSave: Bool {
        // Pubkey may be empty (user hasn't configured FAPI yet) but
        // when present must validate.
        if !fapiPubkeyHex.isEmpty && !pubkeyLooksValid(fapiPubkeyHex) {
            return false
        }
        // Port if present must parse as a UInt16.
        if !fapiPort.isEmpty, UInt16(fapiPort) == nil {
            return false
        }
        // Auto-lock minutes if present must parse.
        if !autoLockMinutes.isEmpty, Int(autoLockMinutes) == nil {
            return false
        }
        return true
    }

    private func load() {
        do {
            let s = try session.preferences.load()
            // FAPI service field is stored as "host:port".
            if let svc = s.preferredFapiService, let (h, p) = parseHostPort(svc) {
                fapiHost = h
                fapiPort = String(p)
            }
            fapiPubkeyHex = s.preferredFapiServicePubkeyHex ?? ""
            theme = s.theme ?? .system
            if let secs = s.autoLockSeconds, secs > 0 {
                autoLockMinutes = String(secs / 60)
            }
        } catch {
            saveError = String(describing: error)
        }
    }

    private func save() {
        saveError = nil
        do {
            try session.preferences.update { s in
                if !fapiHost.isEmpty, !fapiPort.isEmpty, let port = UInt16(fapiPort) {
                    s.preferredFapiService = "\(fapiHost):\(port)"
                } else {
                    s.preferredFapiService = nil
                }
                s.preferredFapiServicePubkeyHex = fapiPubkeyHex.isEmpty ? nil : fapiPubkeyHex
                s.theme = theme
                if let mins = Int(autoLockMinutes), mins > 0 {
                    s.autoLockSeconds = mins * 60
                } else {
                    s.autoLockSeconds = nil
                }
            }
            saveOk = true
            Task {
                try? await Task.sleep(nanoseconds: 1_500_000_000)
                await MainActor.run { saveOk = false }
            }
        } catch {
            saveError = String(describing: error)
        }
    }

    // MARK: - validation

    private func pubkeyLooksValid(_ s: String) -> Bool {
        s.count == 66 && s.allSatisfy { $0.isHexDigit }
    }

    private func parseHostPort(_ s: String) -> (String, UInt16)? {
        guard let colon = s.lastIndex(of: ":") else { return nil }
        let host = String(s[s.startIndex..<colon])
        let portStr = String(s[s.index(after: colon)..<s.endIndex])
        guard let port = UInt16(portStr) else { return nil }
        return (host, port)
    }
}
