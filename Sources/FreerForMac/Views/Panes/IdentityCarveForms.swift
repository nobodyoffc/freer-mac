import SwiftUI
import FCDomain
import FCUI

/// The CID and DOCK/DISK carve forms, each shown in two places: inline in
/// Settings › Identity, and as its own dialog from the getting-started
/// checklist. One view per carve, so both places share the preview, the
/// coin-age refusal and the pending record rather than drifting apart.

/// Rules every identity carve shares.
enum IdentityCarve {
    /// Why nothing can be carved yet, or nil when it can.
    ///
    /// **Carves wait for coin age.** Past ``FeipCdd/activationHeight`` a
    /// carve that destroys less than one coin day is ignored after it is
    /// paid for; the wallet refuses to build one, and the forms say so up
    /// front rather than letting the refusal arrive as a coin-selection error.
    @MainActor
    static func blocker(session: ActiveSession, info: LiveFidInfo?) -> String? {
        guard session.canSign else { return "Watch-only identity: there is no key to sign a carve with." }
        guard let info else { return nil }
        if (info.balance ?? 0) == 0 && (info.cd ?? 0) == 0 {
            return "This FID holds no coins, and every carve costs a fee. Get your first FCH first."
        }
        if case .coinDays(let have, let need, let days)? = Onboarding.coinDayWait(info) {
            let forecast = days.map { ", about \($0) day\($0 == 1 ? "" : "s") to go" } ?? ""
            return "Your coins are still aging: \(have) of \(need) CD\(forecast). A carve before then would be ignored by the chain."
        }
        return nil
    }

    /// Broadcast within the last day and not yet on the chain. An older one
    /// most likely failed, so it no longer holds the button.
    static func isWaiting(_ pending: PendingIdentityCarve?) -> Bool {
        guard let pending else { return false }
        return !pending.isOverdue(now: Date())
    }
}

struct CarveBlockerLabel: View {
    let text: String

    var body: some View {
        Label(text, systemImage: "hourglass")
            .font(.callout)
            .foregroundStyle(.orange)
            .fixedSize(horizontal: false, vertical: true)
    }
}

/// What became of the last carve: an error, a broadcast still waiting for
/// a block, or one a day old that probably failed.
struct CarveOutcome: View {
    let error: String?
    let pending: PendingIdentityCarve?
    /// Names the record, as in "your CID shows here once…".
    let what: String

    var body: some View {
        if let error {
            CopyableText(error, font: .callout, color: .red)
                .fixedSize(horizontal: false, vertical: true)
        } else if let pending {
            let tx = pending.txid.elidingMiddle(head: 8, tail: 8)
            if pending.isOverdue(now: Date()) {
                CopyableText(
                    display: "Carved a day ago and still not on the chain — tx \(tx) may have failed. Check it, then carve again.",
                    copy: pending.txid,
                    font: .caption
                )
                .foregroundStyle(.orange)
                .fixedSize(horizontal: false, vertical: true)
            } else {
                CopyableText(
                    display: "Carved — tx \(tx). Waiting for the chain; \(what) shows here once a block confirms it.",
                    copy: pending.txid,
                    font: .caption
                )
                .foregroundStyle(.green)
                .fixedSize(horizontal: false, vertical: true)
            }
        }
    }
}

// MARK: - CID

/// **What you type is not quite what you get.** A CID carve names a name,
/// and the parser picks the suffix, so the form shows the CID the chain
/// would assign right now, checked against every FID that ever used it.
struct CidCarveForm: View {
    @Environment(AppState.self) private var appState
    let session: ActiveSession
    /// Called once the carve is broadcast.
    var onCarved: () -> Void = {}

    @State private var cidName = ""
    @State private var preview: CidFeip.Preview?
    /// The name ``preview`` was computed for, so a stale answer never
    /// enables Carve for what is typed now.
    @State private var previewedName = ""
    @State private var previewError: String?
    @State private var carvingCid = false
    @State private var cidError: String?
    /// A CID carve already broadcast. While it is fresh the Carve button
    /// stays off: the chain still shows no CID, and a second press would
    /// pay for the same name twice.
    @State private var pendingCid: PendingIdentityCarve?

    private var info: LiveFidInfo? { appState.knownLiveFidInfo }

    var body: some View {
        Group {
            cidRow
            CarveOutcome(error: cidError, pending: pendingCid, what: "your CID")
        }
        .onAppear(perform: loadPending)
        // A refresh is what clears a carve that has landed.
        .onChange(of: info) { _, _ in loadPending() }
        .task(id: cidName) { await runPreview() }
    }

    private var trimmedName: String {
        cidName.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private var cidRow: some View {
        LabeledField("CID", hint: cidHint.text, hintIsError: cidHint.isError) {
            HStack(spacing: 8) {
                TextField("", text: $cidName, prompt: Text(currentCid ?? "Alice"))
                    .fieldInputStyle()
                    .frame(maxWidth: 240)
                    .onSubmit { Task { await carveCid() } }
                if let current = currentCid, cidName.isEmpty {
                    Text("Now: \(current)")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }
                Button {
                    Task { await carveCid() }
                } label: {
                    if carvingCid { ProgressView().controlSize(.small) } else { Text("Carve") }
                }
                .disabled(!canCarveCid)
                Spacer(minLength: 0)
            }
        }
    }

    private var currentCid: String? {
        guard let cid = info?.cid?.trimmingCharacters(in: .whitespaces), !cid.isEmpty else { return nil }
        return cid
    }

    private var cidHint: (text: String?, isError: Bool) {
        let name = trimmedName
        guard !name.isEmpty else {
            return ("Any name without spaces, @, # or /. A FID can hold four CIDs over its life.", false)
        }
        guard CidFeip.isGoodName(name) else {
            return ("No spaces, @, # or / — the chain ignores a name with any of them.", true)
        }
        if let previewError { return ("Couldn't check the name: \(previewError)", true) }
        guard previewedName == name, let preview else { return ("Checking…", false) }
        switch preview {
        case .new(let cid):
            return cid == currentCid ? ("That's already your CID.", false) : ("You'll be \(cid).", false)
        case .reactivate(let cid):
            return cid == currentCid
                ? ("That's already your CID.", false)
                : ("You used \(cid) before; carving makes it current again.", false)
        case .limitReached(let cid):
            let used = (info?.usedCids ?? []).joined(separator: ", ")
            return ("\(cid) would be a fifth CID, and the chain allows four. Reuse one of yours: \(used).", true)
        case .unavailable:
            return ("Every CID this name could become is taken.", true)
        }
    }

    private var canCarveCid: Bool {
        guard IdentityCarve.blocker(session: session, info: info) == nil,
              !carvingCid, !IdentityCarve.isWaiting(pendingCid) else { return false }
        guard previewedName == trimmedName else { return false }
        switch preview {
        case .new(let cid)?, .reactivate(let cid)?: return cid != currentCid
        default: return false
        }
    }

    private func runPreview() async {
        let name = trimmedName
        previewError = nil
        guard CidFeip.isGoodName(name) else {
            preview = nil
            previewedName = ""
            return
        }
        // Typing is not asking: wait for a pause before querying the chain.
        try? await Task.sleep(nanoseconds: 400_000_000)
        guard !Task.isCancelled else { return }
        do {
            let result = try await session.previewCid(name: name)
            guard !Task.isCancelled, name == trimmedName else { return }
            preview = result
            previewedName = name
        } catch {
            guard !Task.isCancelled else { return }
            previewError = String(describing: error)
        }
    }

    private func carveCid() async {
        guard canCarveCid else { return }
        carvingCid = true
        cidError = nil
        defer { carvingCid = false }
        do {
            try await session.carveCidOnChain(name: trimmedName)
            cidName = ""
            loadPending()
            await appState.refreshLiveFidInfo()
            onCarved()
        } catch {
            cidError = String(describing: error)
        }
    }

    private func loadPending() {
        pendingCid = try? session.pendingIdentityCarves.get(fid: session.liveFid, kind: .cid)
    }
}

// MARK: - DOCK and DISK

/// Both are chosen with the service picker and carved as one FEIP9
/// register, laid over the map the chain holds now, because register
/// replaces the whole map.
struct HomeCarveForm: View {
    @Environment(AppState.self) private var appState
    let session: ActiveSession
    /// Called once the carve is broadcast.
    var onCarved: () -> Void = {}

    @State private var dock = ""
    @State private var disk = ""
    @State private var loadedHome = false
    @State private var pickingDock = false
    @State private var pickingDisk = false
    @State private var carvingHome = false
    @State private var homeError: String?
    @State private var pendingHome: PendingIdentityCarve?
    /// The SID filled in from the server this app is connected to, so the
    /// hint can say where an unasked-for value came from.
    @State private var suggestedSid: String?

    private var info: LiveFidInfo? { appState.knownLiveFidInfo }

    var body: some View {
        Group {
            serviceRow("DOCK", value: $dock, kind: "DOCK") { pickingDock = true }
            serviceRow("DISK", value: $disk, kind: "DISK") { pickingDisk = true }
            HStack(spacing: 12) {
                Button {
                    Task { await carveHome() }
                } label: {
                    if carvingHome {
                        ProgressView().controlSize(.small)
                    } else {
                        Text("Carve DOCK and DISK")
                    }
                }
                .disabled(!canCarveHome)
                Spacer()
            }
            CarveOutcome(error: homeError, pending: pendingHome, what: "your DOCK and DISK")
        }
        .onAppear {
            loadHome()
            loadPending()
        }
        .onChange(of: info?.home) { _, _ in
            loadedHome = false
            loadHome()
        }
        .onChange(of: info) { _, _ in loadPending() }
        .task(id: loadedHome) { await suggestConnectedServer() }
        .sheet(isPresented: $pickingDock) {
            ServicePickerSheet(
                session: session,
                component: ServiceName.dock,
                title: "Choose your DOCK",
                subtitle: "Messages to you wait here while you're offline. Its service id is what gets carved, so the server can move without anyone losing you.",
                initialQuery: dock
            ) { service in
                dock = service.sid
                pickingDock = false
            } onCancel: {
                pickingDock = false
            }
        }
        .sheet(isPresented: $pickingDisk) {
            ServicePickerSheet(
                session: session,
                component: ServiceName.disk,
                title: "Choose your DISK",
                subtitle: "Your files and the bodies of what you publish are kept here.",
                initialQuery: disk
            ) { service in
                disk = service.sid
                pickingDisk = false
            } onCancel: {
                pickingDisk = false
            }
        }
    }

    private func serviceRow(
        _ label: String, value: Binding<String>, kind: String, choose: @escaping () -> Void
    ) -> some View {
        LabeledField(label, hint: hint(kind, value: value.wrappedValue)) {
            HStack(spacing: 8) {
                TextField("", text: value, prompt: Text("Service id or URL"))
                    .font(.system(.body, design: .monospaced))
                    .fieldInputStyle()
                Button("Choose…", action: choose)
            }
        }
    }

    private func hint(_ kind: String, value: String) -> String? {
        guard storedValue(kind) == nil else { return nil }
        if let suggestedSid, value == suggestedSid {
            return "Not on the chain yet. Filled in with the server this app is connected to."
        }
        return "Not on the chain yet."
    }

    /// A newcomer rarely knows a DOCK or DISK by name, but the server this
    /// app already talks to is one they evidently trust. When its service
    /// record offers both, its SID goes into whichever box the chain has
    /// nothing for and the user has not typed in. A record offering only
    /// one is left out: carving half a home to the same server would be a
    /// guess about the other half.
    private func suggestConnectedServer() async {
        guard loadedHome, storedValue("DOCK") == nil || storedValue("DISK") == nil,
              let url = try? session.preferences.load().preferredFapiService,
              let service = try? await session.directory.service(
                  at: url, offering: [ServiceName.dock, ServiceName.disk]
              ),
              !Task.isCancelled
        else { return }
        let sid = service.sid
        suggestedSid = sid
        if storedValue("DOCK") == nil, dock.isEmpty { dock = sid }
        if storedValue("DISK") == nil, disk.isEmpty { disk = sid }
    }

    /// The value the chain holds for `kind`, under the key this app writes
    /// or, failing that, any key another client wrote for it.
    private func storedValue(_ kind: String) -> String? {
        guard let home = info?.home else { return nil }
        let exact = kind == "DOCK" ? ServiceName.dock : ServiceName.disk
        let value = home[exact] ?? home.first { $0.key.uppercased().hasPrefix(kind) }?.value
        guard let value, !value.trimmingCharacters(in: .whitespaces).isEmpty else { return nil }
        return value
    }

    private var canCarveHome: Bool {
        guard IdentityCarve.blocker(session: session, info: info) == nil,
              !carvingHome, info != nil, !IdentityCarve.isWaiting(pendingHome) else { return false }
        return HomeFeip.merged(over: info?.home, dock: dock, disk: disk) != nil
    }

    private func loadHome() {
        guard !loadedHome, info != nil else { return }
        loadedHome = true
        dock = HomeServiceResolver.displayValue(storedValue("DOCK"))
        disk = HomeServiceResolver.displayValue(storedValue("DISK"))
    }

    private func carveHome() async {
        guard canCarveHome else { return }
        carvingHome = true
        homeError = nil
        defer { carvingHome = false }
        do {
            try await session.carveHomeOnChain(dock: dock, disk: disk)
            loadPending()
            await appState.refreshLiveFidInfo()
            onCarved()
        } catch {
            homeError = String(describing: error)
        }
    }

    private func loadPending() {
        pendingHome = try? session.pendingIdentityCarves.get(fid: session.liveFid, kind: .home)
    }
}

// MARK: - the checklist's dialogs

/// One carve form in a dialog of its own, for the getting-started
/// checklist. It closes when the carve is broadcast; the checklist step
/// takes over from there, showing the txid until a block confirms it.
struct IdentityCarveSheet: View {
    enum Kind: String, Identifiable {
        case cid, home
        var id: String { rawValue }
    }

    @Environment(AppState.self) private var appState
    let session: ActiveSession
    let kind: Kind
    let onCarved: () -> Void
    let onCancel: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 12) {
                Image(systemName: kind == .cid ? "person.text.rectangle" : "server.rack")
                    .font(.title2)
                    .foregroundStyle(Color.accentColor)
                Text(kind == .cid ? "Register a CID" : "Set your DOCK and DISK")
                    .font(.title2).bold()
                Spacer()
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 12)

            Form {
                Section {
                    if let blocker = IdentityCarve.blocker(session: session, info: appState.knownLiveFidInfo) {
                        CarveBlockerLabel(text: blocker)
                    }
                    switch kind {
                    case .cid: CidCarveForm(session: session, onCarved: onCarved)
                    case .home: HomeCarveForm(session: session, onCarved: onCarved)
                    }
                } footer: {
                    Text(explanation)
                        .font(.caption)
                }
            }
            .formStyle(.grouped)

            Divider()
            HStack {
                Text("A carve fee is paid from this FID, and the tx is confirmed separately.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                Spacer()
                Button("Close", role: .cancel) { onCancel() }
                    .keyboardShortcut(.cancelAction)
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 12)
        }
        .frame(minWidth: 540, minHeight: kind == .cid ? 320 : 400)
    }

    private var explanation: String {
        switch kind {
        case .cid:
            return "Your CID is the name people find you by; the last characters of your FID are added to keep it unique, and registering one puts your pubkey on the chain."
        case .home:
            return "Your DOCK holds messages while you're offline and your DISK keeps your files — until both are on the chain, nobody has anywhere to reach you."
        }
    }
}
