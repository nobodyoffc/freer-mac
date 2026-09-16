import SwiftUI
import FCDomain
import FCUI

/// Settings › Identity: the on-chain records that say who a FID is — its CID
/// (FEIP3), its master (FEIP6) and its DOCK and DISK (FEIP9 Home). The
/// getting-started checklist sends newcomers here for the CID and home.
///
/// **The master is here and not on the checklist.** It names another FID
/// of your own as this one's owner, which a beginner does not have, and it
/// is permanent. The row only shows state and opens ``SetMasterSheet``,
/// which carries the warnings.
///
/// **Both carves wait for coin age.** Past ``FeipCdd/activationHeight`` a
/// carve that destroys less than one coin day is ignored after it is paid
/// for; the wallet refuses to build one, and this section says so up front
/// rather than letting the refusal arrive as a coin-selection error.
///
/// **What you type is not quite what you get.** A CID carve names a name,
/// and the parser picks the suffix, so the form shows the CID the chain
/// would assign right now, checked against every FID that ever used it.
struct IdentitySettingsSection: View {
    @Environment(AppState.self) private var appState
    let session: ActiveSession

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

    @State private var dock = ""
    @State private var disk = ""
    @State private var loadedHome = false
    @State private var pickingDock = false
    @State private var pickingDisk = false
    @State private var carvingHome = false
    @State private var homeError: String?
    @State private var pendingHome: PendingIdentityCarve?
    @State private var pendingMaster: PendingIdentityCarve?

    private var info: LiveFidInfo? { appState.knownLiveFidInfo }

    /// Why nothing can be carved yet, or nil when it can.
    private var carveBlocker: String? {
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

    var body: some View {
        Section {
            if let carveBlocker {
                Label(carveBlocker, systemImage: "hourglass")
                    .font(.callout)
                    .foregroundStyle(.orange)
                    .fixedSize(horizontal: false, vertical: true)
            }
            cidRow
            outcome(error: cidError, pending: pendingCid, what: "your CID")
            masterRow
            homeRows
        } header: {
            Text("Identity")
        } footer: {
            Text("Your CID is the name people find you by; the last characters of your FID are added to keep it unique, and registering one puts your pubkey on the chain. A master is optional and permanent: only set one to a FID of your own that you trust completely. Your DOCK holds messages while you're offline and your DISK keeps your files — until both are on the chain, nobody has anywhere to reach you. Each is a carve with a small fee, and shows here once a block confirms it.")
                .font(.caption)
        }
        .onAppear {
            loadHome()
            loadPending()
        }
        .onChange(of: info?.home) { _, _ in
            loadedHome = false
            loadHome()
        }
        // A refresh is what clears a carve that has landed.
        .onChange(of: info) { _, _ in loadPending() }
        // The master sheet records its carve before any refresh.
        .onChange(of: appState.identityRevision) { _, _ in loadPending() }
        .task(id: cidName) { await runPreview() }
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

    // MARK: - CID

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
        guard carveBlocker == nil, !carvingCid, !isWaiting(pendingCid) else { return false }
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
        } catch {
            cidError = String(describing: error)
        }
    }

    // MARK: - master

    @ViewBuilder
    private var masterRow: some View {
        LabeledField("Master", hint: masterHint) {
            HStack(spacing: 8) {
                if let master = chainMaster {
                    CopyableText.elidingMiddle(master, font: .callout.monospaced())
                    Text("Permanent").font(.caption).foregroundStyle(.secondary)
                } else if session.liveFid != session.mainFid {
                    Text("Only the main FID can have a master.")
                        .font(.callout).foregroundStyle(.secondary)
                } else {
                    Text("None").font(.callout).foregroundStyle(.secondary)
                    Button("Set master…") { appState.openSetMaster() }
                        .disabled(carveBlocker != nil || isWaiting(pendingMaster))
                }
                Spacer(minLength: 0)
            }
        }
        if chainMaster == nil, session.liveFid == session.mainFid {
            outcome(error: nil, pending: pendingMaster, what: "the master")
        }
    }

    /// The master the chain holds for the main FID. Read from the live
    /// record only while living as the main; the local KeyInfo is written on
    /// broadcast and can name a master whose carve never landed.
    private var chainMaster: String? {
        guard session.liveFid == session.mainFid,
              let master = info?.master?.trimmingCharacters(in: .whitespaces),
              !master.isEmpty else { return nil }
        return master
    }

    private var masterHint: String? {
        if chainMaster != nil {
            return "The first master is the only one: the protocol ignores any later master carve."
        }
        guard session.liveFid == session.mainFid else { return nil }
        return "Another FID of yours that can recover this one. Setting it puts your prikey on the chain, sealed to the master, for good."
    }

    // MARK: - DOCK and DISK

    @ViewBuilder
    private var homeRows: some View {
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
        outcome(error: homeError, pending: pendingHome, what: "your DOCK and DISK")
    }

    private func serviceRow(
        _ label: String, value: Binding<String>, kind: String, choose: @escaping () -> Void
    ) -> some View {
        LabeledField(label, hint: storedValue(kind) == nil ? "Not on the chain yet." : nil) {
            HStack(spacing: 8) {
                TextField("", text: value, prompt: Text("Service id or URL"))
                    .font(.system(.body, design: .monospaced))
                    .fieldInputStyle()
                Button("Choose…", action: choose)
            }
        }
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
        guard carveBlocker == nil, !carvingHome, info != nil, !isWaiting(pendingHome) else { return false }
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
        } catch {
            homeError = String(describing: error)
        }
    }

    // MARK: - shared

    private func loadPending() {
        let fid = session.liveFid
        pendingCid = try? session.pendingIdentityCarves.get(fid: fid, kind: .cid)
        pendingHome = try? session.pendingIdentityCarves.get(fid: fid, kind: .home)
        pendingMaster = try? session.pendingIdentityCarves.get(fid: session.mainFid, kind: .master)
    }

    /// Broadcast within the last day and not yet on the chain. An older one
    /// most likely failed, so it no longer holds the button.
    private func isWaiting(_ pending: PendingIdentityCarve?) -> Bool {
        guard let pending else { return false }
        return !pending.isOverdue(now: Date())
    }

    @ViewBuilder
    private func outcome(error: String?, pending: PendingIdentityCarve?, what: String) -> some View {
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
