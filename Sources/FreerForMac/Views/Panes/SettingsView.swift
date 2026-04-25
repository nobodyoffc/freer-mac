import SwiftUI
import FCDomain
import FCTransport

/// Per-main-FID preferences. FAPI server config (host / port /
/// pubkey) plus a few UI knobs. Two ways to validate the FAPI form:
///
/// - **Test connection** — builds a one-shot `FapiClient` from the
///   live form values, runs `base.health`, reports the result.
///   Doesn't persist anything.
/// - **Save** — persists to the per-main `PreferencesStore` AND asks
///   the AppState to swap the active session's FAPI client to the
///   new server. Subsequent Overview Refreshes hit the live server
///   immediately.
struct SettingsView: View {
    @Environment(AppState.self) private var appState
    let session: ActiveSession

    @State private var fapiHost: String = ""
    @State private var fapiPort: String = ""
    @State private var fapiPubkeyHex: String = ""
    @State private var theme: Preferences.Theme = .system
    @State private var autoLockMinutes: String = ""

    @State private var saveError: String?
    @State private var saveOk: Bool = false

    @State private var testing: Bool = false
    @State private var testResult: TestResult?

    enum TestResult: Equatable {
        case ok(String)
        case fail(String)
    }

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

                HStack(spacing: 12) {
                    Button {
                        Task { await runTestConnection() }
                    } label: {
                        if testing {
                            HStack(spacing: 6) {
                                ProgressView().controlSize(.small)
                                Text("Testing…")
                            }
                        } else {
                            Label("Test connection", systemImage: "antenna.radiowaves.left.and.right")
                        }
                    }
                    .disabled(testing || !fapiFormLooksValid)

                    if let result = testResult {
                        switch result {
                        case .ok(let msg):
                            Label(msg, systemImage: "checkmark.circle.fill")
                                .foregroundStyle(.green)
                                .font(.callout)
                        case .fail(let msg):
                            Label(msg, systemImage: "xmark.octagon.fill")
                                .foregroundStyle(.red)
                                .font(.callout)
                        }
                    }
                }
            } header: {
                Text("FAPI server")
            } footer: {
                Text("The FAPI server's pubkey lets the wallet establish an authenticated FUDP session. Without it, balance / send / broadcast fall back to the stub client.")
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
                        Task { await saveAndApply() }
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

    // MARK: - load / save / apply

    private var fapiFormLooksValid: Bool {
        !fapiHost.isEmpty
            && UInt16(fapiPort) != nil
            && pubkeyLooksValid(fapiPubkeyHex)
    }

    private var canSave: Bool {
        if !fapiPubkeyHex.isEmpty && !pubkeyLooksValid(fapiPubkeyHex) {
            return false
        }
        if !fapiPort.isEmpty, UInt16(fapiPort) == nil {
            return false
        }
        if !autoLockMinutes.isEmpty, Int(autoLockMinutes) == nil {
            return false
        }
        return true
    }

    private func load() {
        do {
            let s = try session.preferences.load()
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

    @MainActor
    private func saveAndApply() async {
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
            // Persist succeeded — now (re)build the live FAPI client
            // so other panes pick it up immediately.
            await appState.applyFapiSettings(for: session)
            saveOk = true
            Task {
                try? await Task.sleep(nanoseconds: 1_500_000_000)
                await MainActor.run { saveOk = false }
            }
        } catch {
            saveError = String(describing: error)
        }
    }

    // MARK: - test connection

    @MainActor
    private func runTestConnection() async {
        testing = true
        testResult = nil
        defer { testing = false }

        guard let port = UInt16(fapiPort), pubkeyLooksValid(fapiPubkeyHex) else {
            testResult = .fail("Form has invalid values.")
            return
        }
        guard let pubkey = decodeHex(fapiPubkeyHex), pubkey.count == 33 else {
            testResult = .fail("Pubkey hex doesn't decode to 33 bytes.")
            return
        }

        let priv: Data
        do {
            priv = try session.mainPrikey()
        } catch {
            testResult = .fail("Couldn't read main privkey: \(error)")
            return
        }

        let host = fapiHost
        do {
            let fudp = try await FudpClient(
                host: host, port: port,
                peerPubkey: pubkey, localPrivkey: priv
            )
            defer { fudp.close() }
            let client = FapiClient(fudp: fudp)
            let reply = try await client.call(
                api: "base.health",
                params: nil, fcdsl: nil, binary: nil,
                sid: nil, via: nil, maxCost: nil,
                timeoutMs: 5_000
            )
            if reply.response.isSuccess {
                testResult = .ok("Connected — server replied OK")
            } else {
                let code = reply.response.code ?? -1
                let msg = reply.response.message ?? ""
                testResult = .fail("Server replied code \(code): \(msg)")
            }
        } catch {
            testResult = .fail("Failed: \(error)")
        }
    }

    // MARK: - validation / hex / parse

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

    private func decodeHex(_ s: String) -> Data? {
        guard s.count % 2 == 0 else { return nil }
        var data = Data(capacity: s.count / 2)
        var idx = s.startIndex
        while idx < s.endIndex {
            let next = s.index(idx, offsetBy: 2)
            guard let b = UInt8(s[idx..<next], radix: 16) else { return nil }
            data.append(b)
            idx = next
        }
        return data
    }
}
