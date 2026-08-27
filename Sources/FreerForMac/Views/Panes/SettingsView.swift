import SwiftUI
import FCDomain
import FCTransport
import FCUI

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

    @State private var discovering: Bool = false
    @State private var discoverError: String?

    @State private var purgeError: String?
    @State private var purgeOk: Bool = false
    @State private var showPurgeConfirm: Bool = false

    /// Mail. `myNoticeFee` is on-chain and carved on its own button;
    /// the other two are local preferences that ride the Save button.
    @State private var myNoticeFee: String = ""
    @State private var publishedNoticeFee: String?
    @State private var loadingFee: Bool = false
    @State private var carvingFee: Bool = false
    @State private var feeCarveError: String?
    @State private var feeCarveTxid: String?
    @State private var maxPayingNoticeFee: String = ""
    @State private var payBackNoticeFee: Bool = true
    @State private var confirmBeforeSigning: Bool = true

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
        .onAppear {
            load()
            Task { await loadNoticeFee() }
        }
        .alert("Purge cash cache for \(session.liveFid.elidingMiddle(head: 6, tail: 6))?",
               isPresented: $showPurgeConfirm) {
            Button("Cancel", role: .cancel) {}
            Button("Purge", role: .destructive) { runPurge() }
        } message: {
            Text("Removes the local cash cache for this FID. The next Refresh will re-fetch every spendable cash from `base.cashValid`. Pending-spend marks and unconfirmed change rows will be lost — only do this if the cache looks wrong.")
        }
    }

    private var form: some View {
        Form {
            Section {
                LabeledField("Host") {
                    TextField("", text: $fapiHost, prompt: Text("localhost"))
                        .fieldInputStyle()
                }
                LabeledField("Port") {
                    TextField("", text: $fapiPort, prompt: Text("8500"))
                        .fieldInputStyle()
                        .frame(maxWidth: 140)
                }

                LabeledField(
                    "Server pubkey",
                    hint: (!fapiPubkeyHex.isEmpty && !pubkeyLooksValid(fapiPubkeyHex))
                        ? "Pubkey must be 66 hex characters (33 SEC1-compressed bytes)."
                        : nil,
                    hintIsError: true
                ) {
                    HStack(spacing: 8) {
                        TextField("", text: $fapiPubkeyHex, prompt: Text("03cd14…"))
                            .font(.system(.body, design: .monospaced))
                            .fieldInputStyle()

                        Button {
                            Task { await runDiscover() }
                        } label: {
                            if discovering {
                                HStack(spacing: 4) {
                                    ProgressView().controlSize(.small)
                                    Text("Discovering…")
                                }
                            } else {
                                Label("Discover", systemImage: "magnifyingglass")
                            }
                        }
                        .disabled(discovering || !hostPortLooksValid)
                        .help("Send a plaintext HELLO to the host:port and auto-fill the pubkey from the reply.")
                    }
                }

                if let err = discoverError {
                    HStack(alignment: .top, spacing: 4) {
                        Image(systemName: "xmark.octagon.fill")
                        CopyableText(err, font: .caption)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    .foregroundStyle(.red)
                    .font(.caption)
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
                            HStack(alignment: .top, spacing: 4) {
                                Image(systemName: "checkmark.circle.fill")
                                CopyableText(msg, font: .callout)
                                    .fixedSize(horizontal: false, vertical: true)
                            }
                            .foregroundStyle(.green)
                        case .fail(let msg):
                            HStack(alignment: .top, spacing: 4) {
                                Image(systemName: "xmark.octagon.fill")
                                CopyableText(msg, font: .callout)
                                    .fixedSize(horizontal: false, vertical: true)
                            }
                            .foregroundStyle(.red)
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
                LabeledField("Theme") {
                    Picker("", selection: $theme) {
                        ForEach(Preferences.Theme.allCases, id: \.self) { t in
                            Text(t.rawValue.capitalized).tag(t)
                        }
                    }
                    .labelsHidden()
                }
            }

            Section {
                LabeledField(
                    "My notice fee",
                    hint: myNoticeFeeHint,
                    hintIsError: myNoticeFeeSats == nil && !myNoticeFee.isEmpty
                ) {
                    HStack(spacing: 8) {
                        TextField("", text: $myNoticeFee, prompt: Text("0"))
                            .fieldInputStyle()
                            .frame(maxWidth: 160)
                        Text("F").foregroundStyle(.secondary)

                        Button {
                            Task { await carveNoticeFee() }
                        } label: {
                            if carvingFee {
                                ProgressView().controlSize(.small)
                            } else {
                                Text("Carve")
                            }
                        }
                        .disabled(!canCarveNoticeFee)
                        .help(session.canSign
                              ? "Write this rate to the chain so senders' clients can read it"
                              : "Watch-only identity — no key to sign a carve with")

                        if loadingFee {
                            ProgressView().controlSize(.small)
                        }
                    }
                }

                LabeledField(
                    "Most I'll pay",
                    hint: maxPayingSats == nil && !maxPayingNoticeFee.isEmpty
                        ? "Not a valid amount."
                        : "Blank = \(NoticeFee.coinString(satoshis: NoticeFee.defaultMaxPayingSats)) F.",
                    hintIsError: maxPayingSats == nil && !maxPayingNoticeFee.isEmpty
                ) {
                    HStack(spacing: 8) {
                        TextField("", text: $maxPayingNoticeFee, prompt: Text("100"))
                            .fieldInputStyle()
                            .frame(maxWidth: 160)
                        Text("F").foregroundStyle(.secondary)
                    }
                }

                Toggle("Match what a sender paid me when I reply", isOn: $payBackNoticeFee)
                    .help("If someone paid more than the rate you'd normally pay them, your reply returns the same amount — still capped by the limit above.")

                if let err = feeCarveError {
                    CopyableText(err, font: .callout).foregroundStyle(.red)
                } else if let txid = feeCarveTxid {
                    CopyableText(
                        display: "Carved — tx \(txid.elidingMiddle(head: 8, tail: 8)). Senders see the new rate once a block confirms it.",
                        copy: txid,
                        font: .caption
                    )
                    .foregroundStyle(.green)
                }
            } header: {
                Text("Mail")
            } footer: {
                Text("Your notice fee is what other people pay **you** to land a mail in your inbox — it lives on the chain, so raising it costs a carve and only applies to mail sent after it confirms. The other two settings are local: they bound what you spend, and never leave this device.")
                    .font(.caption)
            }

            Section {
                Toggle("Show every transaction before signing it", isOn: $confirmBeforeSigning)

                LabeledField(
                    "Auto-lock after (minutes)",
                    hint: "Blank = never auto-lock."
                ) {
                    TextField("", text: $autoLockMinutes, prompt: Text("e.g. 10"))
                        .fieldInputStyle()
                        .frame(maxWidth: 240)
                }
            } header: {
                Text("Security")
            } footer: {
                Text("With confirmation on, **nothing is signed until you approve it** — payments, cash merges, and the on-chain writes that panes make on your behalf (a contact, a mail, a chat key). The dialog shows the built transaction: which cashes it spends, who each output pays, the fee, and the exact bytes of any data being written. Turn it off and those all go straight to the chain.")
                    .font(.caption)
            }

            Section {
                HStack(spacing: 12) {
                    Button(role: .destructive) {
                        showPurgeConfirm = true
                    } label: {
                        Label("Purge cash cache", systemImage: "trash")
                    }
                    if purgeOk {
                        Label("Purged", systemImage: "checkmark.circle.fill")
                            .foregroundStyle(.green)
                            .font(.callout)
                    }
                    if let err = purgeError {
                        CopyableText(err, font: .callout)
                            .foregroundStyle(.red)
                    }
                }
            } header: {
                Text("Maintenance")
            } footer: {
                Text("Drops the live FID's local cash cache. The next Refresh will rebootstrap from `base.cashValid`. Use this when the wallet's pending list looks wrong or after a stuck broadcast.")
                    .font(.caption)
            }

            if let err = saveError {
                Section {
                    CopyableText(err, font: .callout)
                        .foregroundStyle(.red)
                        .fixedSize(horizontal: false, vertical: true)
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

    // MARK: - mail fees

    private var myNoticeFeeSats: Int64? {
        myNoticeFee.isEmpty ? 0 : NoticeFee.satoshis(coinString: myNoticeFee)
    }

    private var maxPayingSats: Int64? {
        maxPayingNoticeFee.isEmpty ? nil : NoticeFee.satoshis(coinString: maxPayingNoticeFee)
    }

    /// The hint carries the one thing the field cannot: what the chain
    /// currently says, which may differ from what is typed and may have
    /// been carved from another device.
    private var myNoticeFeeHint: String? {
        if !myNoticeFee.isEmpty, myNoticeFeeSats == nil {
            return "Not a valid amount."
        }
        if let sats = myNoticeFeeSats, sats > NoticeFee.maxPublishableSats {
            return "Above the \(NoticeFee.coinString(satoshis: NoticeFee.maxPublishableSats)) F ceiling — a fee that high makes you unreachable."
        }
        guard let published = publishedNoticeFee else {
            return loadingFee ? nil : "Nothing published yet — senders pay the \(NoticeFee.coinString(satoshis: NoticeFee.defaultFeeSats)) F default."
        }
        return "On chain now: \(published) F."
    }

    private var canCarveNoticeFee: Bool {
        guard session.canSign, !carvingFee, let sats = myNoticeFeeSats else { return false }
        guard sats <= NoticeFee.maxPublishableSats else { return false }
        // Nothing to carve if the chain already says this. With
        // nothing published, any valid rate is worth carving —
        // including 0, which is a real statement ("I don't charge")
        // and not the same as saying nothing.
        guard let published = publishedNoticeFee else { return true }
        return NoticeFee.coinString(satoshis: sats) != published
    }

    private func loadNoticeFee() async {
        loadingFee = true
        defer { loadingFee = false }
        guard let sats = try? await session.publishedNoticeFee() else {
            publishedNoticeFee = nil
            return
        }
        let coins = NoticeFee.coinString(satoshis: sats)
        publishedNoticeFee = coins
        if myNoticeFee.isEmpty { myNoticeFee = coins }
    }

    private func carveNoticeFee() async {
        guard let sats = myNoticeFeeSats, canCarveNoticeFee else { return }
        carvingFee = true
        feeCarveError = nil
        feeCarveTxid = nil
        defer { carvingFee = false }
        do {
            feeCarveTxid = try await session.carveNoticeFeeOnChain(satoshis: sats)
            // Optimistic: the carve is broadcast, so stop offering to
            // carve the same value again. A later load re-reads truth.
            publishedNoticeFee = NoticeFee.coinString(satoshis: sats)
        } catch {
            feeCarveError = String(describing: error)
        }
    }

    // MARK: - load / save / apply

    private var fapiFormLooksValid: Bool {
        hostPortLooksValid && pubkeyLooksValid(fapiPubkeyHex)
    }

    private var hostPortLooksValid: Bool {
        !fapiHost.isEmpty && UInt16(fapiPort) != nil
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
        if !maxPayingNoticeFee.isEmpty, maxPayingSats == nil {
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
            if let cap = s.maxPayingNoticeFeeSats {
                maxPayingNoticeFee = NoticeFee.coinString(satoshis: cap)
            }
            payBackNoticeFee = s.payBackNoticeFee ?? true
            confirmBeforeSigning = s.confirmBeforeSigning ?? true
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
                s.maxPayingNoticeFeeSats = maxPayingSats
                s.payBackNoticeFee = payBackNoticeFee
                s.confirmBeforeSigning = confirmBeforeSigning
            }
            // The session caches one of these (the signing gate), so
            // tell it the row moved under its feet.
            session.reloadPreferences()
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

    // MARK: - discover

    @MainActor
    private func runDiscover() async {
        discoverError = nil
        guard let port = UInt16(fapiPort), !fapiHost.isEmpty else {
            discoverError = "Need host and port first."
            return
        }
        discovering = true
        defer { discovering = false }
        do {
            let pubkey = try await FudpDiscovery.discoverPubkey(
                host: fapiHost, port: port, timeoutMs: 3_000
            )
            // Display as lowercase hex — matches the canonical form
            // produced by Hash.hex / our test fixtures.
            fapiPubkeyHex = pubkey.map { String(format: "%02x", $0) }.joined()
        } catch {
            discoverError = "Discover failed: \(error)"
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
                // This proves the network is back. The live client may
                // still be sitting on a socket that died while the
                // machine slept, so retire it: the next call reconnects.
                appState.markFapiStale()
            } else {
                let code = reply.response.code ?? -1
                let msg = reply.response.message ?? ""
                testResult = .fail("Server replied code \(code): \(msg)")
            }
        } catch {
            testResult = .fail("Failed: \(error)")
        }
    }

    // MARK: - purge

    private func runPurge() {
        purgeError = nil
        do {
            try session.wallet.purgeCashes(forFid: session.liveFid)
            purgeOk = true
            Task {
                try? await Task.sleep(nanoseconds: 1_500_000_000)
                await MainActor.run { purgeOk = false }
            }
        } catch {
            purgeError = String(describing: error)
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
