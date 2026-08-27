import SwiftUI
import FCCore
import FCDomain
import FCUI

/// Add a watch-only FID to the current Setting — the Mac port of
/// Android's `AddWatchedFidActivity`: type it, scan it, or go find it
/// with **Find…** (``FidPickerSheet``, the app's one search-and-choose
/// surface, which already excludes the FIDs this Setting holds).
/// **Look up** confirms the on-chain record (cid / pubkey) before
/// saving. The entry is stored as `KeyInfo(kind: .watched)` — no
/// privkey, so living as it puts Send into the cold-sign path.
struct AddWatchedFidSheet: View {
    let session: ActiveSession
    let onAdded: (KeyInfo) -> Void
    let onCancel: () -> Void

    @State private var fid: String = ""
    @State private var label: String = ""

    @State private var lookedUpFreer: Freer?
    @State private var lookingUp = false
    @State private var lookupError: String?
    @State private var lookupKnownOffChain = false

    @State private var pick: FidPickerRequest?

    @State private var showScan = false
    @State private var saveError: String?

    private var fidLooksValid: Bool {
        (try? FchAddress(fid: fid)) != nil
    }

    /// Why this FID can't be added, or nil when it can. Mirrors
    /// Android's duplicate checks when confirming.
    private var blockReason: String? {
        let trimmed = fid.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty, fidLooksValid else { return nil }
        if trimmed == session.mainFid {
            return "That's this Setting's main FID — it's already here."
        }
        if let existing = session.setting.keyInfoMap[trimmed] {
            return "Already registered as \(existing.kind.rawValue)\(existing.label.isEmpty ? "" : " “\(existing.label)”")."
        }
        return nil
    }

    private var canAdd: Bool {
        fidLooksValid && blockReason == nil
    }

    private var canLookup: Bool {
        !lookingUp && fidLooksValid
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header

            Form {
                Section("Watched FID") {
                    LabeledField(
                        "FID",
                        hint: (!fid.isEmpty && !fidLooksValid)
                            ? "Not a FID — use Find… to search CIDs."
                            : blockReason,
                        hintIsError: blockReason != nil
                    ) {
                        HStack(spacing: 8) {
                            TextField("", text: $fid, prompt: Text("F… or CID"))
                                .font(.system(.body, design: .monospaced))
                                .fieldInputStyle()
                                .onSubmit { Task { await runLookup() } }
                                .onChange(of: fid) { _, newValue in
                                    guard lookedUpFreer?.id != newValue else { return }
                                    lookedUpFreer = nil
                                    lookupKnownOffChain = false
                                    lookupError = nil
                                }

                            Button {
                                showScan = true
                            } label: {
                                Image(systemName: "qrcode.viewfinder")
                            }
                            .help("Scan a FID QR code")

                            Button {
                                pick = .one(
                                    title: "Find a FID to watch",
                                    subtitle: "Search your contacts, or look up a FID or CID on chain.",
                                    initialQuery: fid.trimmingCharacters(in: .whitespaces),
                                    excluded: Set(session.setting.keyInfoMap.keys)
                                )
                            } label: {
                                Label("Find…", systemImage: "person.text.rectangle")
                            }
                            .help("Search contacts and the chain by FID or CID.")

                            Button {
                                Task { await runLookup() }
                            } label: {
                                if lookingUp {
                                    HStack(spacing: 4) {
                                        ProgressView().controlSize(.small)
                                        Text("Looking up…")
                                    }
                                } else {
                                    Label("Look up", systemImage: "magnifyingglass")
                                }
                            }
                            .disabled(!canLookup)
                            .help("Fetch this FID's on-chain record (cid, pubkey).")
                        }
                    }

                    if let err = lookupError {
                        HStack(alignment: .top, spacing: 4) {
                            Image(systemName: "xmark.octagon.fill")
                            CopyableText(err, font: .caption)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                        .foregroundStyle(.red)
                        .font(.caption)
                    } else if lookupKnownOffChain {
                        HStack(spacing: 6) {
                            Image(systemName: "questionmark.circle")
                            Text("No on-chain record — this FID hasn't registered a Freer yet. You can still watch it.")
                                .fixedSize(horizontal: false, vertical: true)
                        }
                        .foregroundStyle(.orange)
                        .font(.caption)
                    } else if let f = lookedUpFreer {
                        onChainStatus(f)
                    }

                    LabeledField(
                        "Label",
                        hint: "Optional. Shown in the person menu; defaults to the CID when looked up."
                    ) {
                        TextField("", text: $label, prompt: Text("Cold wallet"))
                            .fieldInputStyle()
                    }
                }

                if let err = saveError {
                    Section {
                        CopyableText(err, font: .callout)
                            .foregroundStyle(.red)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
            }
            .formStyle(.grouped)

            Divider()

            HStack {
                Text("Watched FIDs are read-only: balances and history load normally, sending exports an unsigned tx for cold signing.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                Spacer()
                Button("Cancel", role: .cancel) { onCancel() }
                    .keyboardShortcut(.cancelAction)
                Button("Add") { add() }
                    .keyboardShortcut(.defaultAction)
                    .buttonStyle(.borderedProminent)
                    .disabled(!canAdd)
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 12)
        }
        .frame(minWidth: 540, minHeight: 420)
        .sheet(isPresented: $showScan) {
            QrScanSheet(title: "Scan FID") { scanned in
                fid = scanned
                showScan = false
                Task { await runLookup() }
            } onCancel: {
                showScan = false
            }
        }
        .sheet(item: $pick) { request in
            FidPickerSheet(session: session, request: request) { picked in
                pick = nil
                if let one = picked.first { adopt(one) }
            } onCancel: {
                pick = nil
            }
        }
    }

    /// Take a pick from the shared picker. When the picker already has
    /// the on-chain record, the status panel fills in without a second
    /// lookup; when it doesn't (a local contact, or a FID typed
    /// straight in) we ask the chain so the panel stays honest.
    private func adopt(_ picked: PickedFid) {
        fid = picked.fid
        lookupError = nil
        if label.isEmpty, let cid = picked.cid { label = cid }
        if let freer = picked.freer {
            lookedUpFreer = freer
            lookupKnownOffChain = false
        } else {
            lookedUpFreer = nil
            Task { await runLookup() }
        }
    }

    private var header: some View {
        HStack(spacing: 12) {
            if !fid.isEmpty, fidLooksValid {
                FidAvatarView(fid: fid, size: 40)
            } else {
                ZStack {
                    Circle()
                        .fill(Color.secondary.opacity(0.15))
                        .frame(width: 40, height: 40)
                    Image(systemName: "eye")
                        .font(.title3)
                        .foregroundStyle(.secondary)
                }
            }
            Text("Add watched FID")
                .font(.title2).bold()
            Spacer()
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 12)
    }

    @ViewBuilder
    private func onChainStatus(_ f: Freer) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 6) {
                Image(systemName: "checkmark.seal.fill").foregroundStyle(.green)
                Text("On-chain record").font(.caption.bold())
                    .foregroundStyle(.green)
                Spacer()
            }
            if let cid = f.cid, !cid.isEmpty {
                CopyableText(
                    display: "cid: \(cid)",
                    copy: cid,
                    font: .caption.monospaced()
                )
                .foregroundStyle(.secondary)
            }
            if let pkHex = f.pubkey, !pkHex.isEmpty {
                CopyableText(
                    display: "pubkey: \(pkHex.elidingMiddle(head: 10, tail: 10))",
                    copy: pkHex,
                    font: .caption.monospaced()
                )
                .foregroundStyle(.secondary)
            }
        }
        .padding(8)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(
            RoundedRectangle(cornerRadius: 6, style: .continuous)
                .fill(Color.green.opacity(0.08))
        )
    }

    // MARK: - lookup / save

    /// Confirm one exact FID against the chain. Anything that isn't a
    /// FID goes to ``FidPickerSheet`` instead — searching by CID is the
    /// picker's job, and this sheet no longer keeps a second copy of it.
    @MainActor
    private func runLookup() async {
        let term = fid.trimmingCharacters(in: .whitespaces)
        guard fidLooksValid, !term.isEmpty, !lookingUp else { return }
        lookingUp = true
        lookupError = nil
        lookupKnownOffChain = false
        defer { lookingUp = false }

        do {
            let freer = try await session.directory.freer(byId: term)
            if let freer {
                lookedUpFreer = freer
                if label.isEmpty, let cid = freer.cid { label = cid }
            } else {
                lookedUpFreer = nil
                lookupKnownOffChain = true
            }
        } catch {
            lookedUpFreer = nil
            lookupError = String(describing: error)
        }
    }

    private func add() {
        guard canAdd else { return }
        let trimmed = fid.trimmingCharacters(in: .whitespaces)
        // On-chain facts only when the looked-up record is for this
        // exact FID (a stale record from an earlier lookup must not
        // leak its pubkey onto a retyped address).
        let onChain: KeyInfo? = (lookedUpFreer?.id == trimmed)
            ? lookedUpFreer.flatMap { KeyInfo.from(freer: $0) }
            : nil
        do {
            let info = try session.addWatchedFid(
                trimmed,
                label: label.trimmingCharacters(in: .whitespaces),
                pubkey: onChain?.pubkey,
                master: onChain?.master
            )
            onAdded(info)
        } catch {
            saveError = String(describing: error)
        }
    }
}
