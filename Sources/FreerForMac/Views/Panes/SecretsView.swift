import SwiftUI
import FCCore
import FCDomain
import FCUI

/// Encrypted secrets vault — the Mac port of Android's `SecretActivity`
/// + `TotpActivity`. Two tabs: the secret list (create / reveal /
/// carve / delete) and live TOTP cards. Content is stored cipher-only
/// (Pattern B); revealing decrypts with the live privkey on demand.
struct SecretsView: View {
    let session: ActiveSession

    private enum Tab: String, CaseIterable, Identifiable {
        case secrets = "Secrets"
        case totp = "TOTP"
        var id: String { rawValue }
    }

    @State private var tab: Tab = .secrets
    @State private var rows: [Secret] = []
    @State private var loadError: String?

    @State private var syncing = false
    @State private var syncError: String?
    @State private var syncSummary: String?
    @State private var didAutoSync = false

    @State private var showEditor = false
    @State private var editorPresetTotp = false
    @State private var pendingDelete: Secret?
    @State private var pendingCarve: Secret?
    @State private var carving = false
    @State private var carveTxid: String?

    /// Secret id → revealed plaintext (in memory only, per pane life).
    @State private var revealed: [String: String] = [:]

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            PaneHeader(session: session)
            Divider()

            HStack(spacing: 12) {
                Picker("", selection: $tab) {
                    ForEach(Tab.allCases) { Text($0.rawValue).tag($0) }
                }
                .pickerStyle(.segmented)
                .labelsHidden()
                .frame(width: 220)

                Spacer()

                Button {
                    Task { await syncFromChain() }
                } label: {
                    if syncing {
                        ProgressView().controlSize(.small)
                    } else {
                        Label("Refresh", systemImage: "arrow.clockwise")
                    }
                }
                .disabled(syncing || !session.canSign)
                .help(session.canSign
                      ? "Pull your carved secrets from the chain"
                      : "Watch-only identity — cannot decrypt on-chain secrets")

                Button {
                    editorPresetTotp = (tab == .totp)
                    showEditor = true
                } label: {
                    Label(tab == .totp ? "Import" : "Add", systemImage: "plus")
                }
                .buttonStyle(.borderedProminent)
                .disabled(!session.canSign)
                .help(session.canSign
                      ? (tab == .totp ? "Import a TOTP secret (Base32)" : "Save a new secret")
                      : "Watch-only identity — no key to encrypt secrets with")
            }

            if let err = syncError {
                HStack(spacing: 6) {
                    Image(systemName: "exclamationmark.triangle").foregroundStyle(.orange)
                    CopyableText("Chain sync failed: \(err)", font: .caption)
                        .foregroundStyle(.orange)
                }
            } else if let txid = carveTxid {
                HStack(spacing: 6) {
                    Image(systemName: "checkmark.seal").foregroundStyle(.green)
                    CopyableText(
                        display: "Carve broadcast — tx \(txid.elidingMiddle(head: 8, tail: 8)). Shows as On-chain once a block confirms it.",
                        copy: txid,
                        font: .caption
                    )
                    .foregroundStyle(.green)
                }
            } else if let summary = syncSummary {
                CopyableText(summary, font: .caption).foregroundStyle(.secondary)
            }

            if let err = loadError {
                card {
                    Label("Couldn't load secrets", systemImage: "exclamationmark.triangle")
                        .foregroundStyle(.red)
                    CopyableText(err, font: .callout).foregroundStyle(.red)
                }
            } else {
                switch tab {
                case .secrets: secretList
                case .totp: TotpCardList(session: session, secrets: rows.filter(\.isTotp))
                }
            }

            Spacer(minLength: 0)
        }
        .padding()
        .frame(minWidth: 520)
        .onAppear {
            reload()
            if !didAutoSync {
                didAutoSync = true
                Task { await syncFromChain() }
            }
        }
        .sheet(isPresented: $showEditor) {
            SecretEditorSheet(
                session: session,
                presetTotp: editorPresetTotp,
                onSaved: { txid in
                    showEditor = false
                    if let txid {
                        syncError = nil
                        carveTxid = txid
                    }
                    reload()
                },
                onCancel: { showEditor = false }
            )
        }
        .alert(
            "Delete \(pendingDelete?.name.isEmpty == false ? pendingDelete!.name : "secret")?",
            isPresented: Binding(
                get: { pendingDelete != nil },
                set: { if !$0 { pendingDelete = nil } }
            )
        ) {
            Button("Cancel", role: .cancel) { pendingDelete = nil }
            Button("Delete locally", role: .destructive) {
                if let s = pendingDelete { delete(s) }
                pendingDelete = nil
            }
            if let s = pendingDelete, canDeleteOnChain(s) {
                Button("Delete locally + on-chain", role: .destructive) {
                    let secret = s
                    pendingDelete = nil
                    Task { await deleteOnChain(secret) }
                }
            }
        } message: {
            if let s = pendingDelete {
                if canDeleteOnChain(s) {
                    Text("This secret has an on-chain carve. Deleting only locally makes it come back on the next chain sync; deleting on-chain carves a removal record (small miner fee). The plaintext cannot be recovered after deletion.")
                } else {
                    Text("Removes the local entry. The encrypted content cannot be recovered after deletion.")
                }
            }
        }
        .alert(
            "Carve \(pendingCarve?.name ?? "secret") on-chain?",
            isPresented: Binding(
                get: { pendingCarve != nil },
                set: { if !$0 { pendingCarve = nil } }
            )
        ) {
            Button("Cancel", role: .cancel) { pendingCarve = nil }
            Button("Carve") {
                let secret = pendingCarve
                pendingCarve = nil
                if let secret { Task { await carve(secret) } }
            }
        } message: {
            Text("Writes this secret to the FCH chain, encrypted so only you can read it. Costs a small miner fee, and it then syncs to any device you unlock with this key.")
        }
    }

    // MARK: - secret list

    private var secretList: some View {
        Group {
            let visible = rows
            if visible.isEmpty {
                card {
                    Label("No secrets yet", systemImage: "lock")
                        .foregroundStyle(.secondary)
                    Text("Save passwords, keys, TOTP seeds, or any text — encrypted to your key. Carve them on-chain to sync across devices.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            } else {
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 0) {
                        ForEach(visible) { s in
                            row(s)
                                .padding(.vertical, 10)
                                .padding(.horizontal, 16)
                            Divider()
                        }
                    }
                    .background(Color(NSColor.controlBackgroundColor))
                    .clipShape(RoundedRectangle(cornerRadius: 12))
                }
            }
        }
    }

    @ViewBuilder
    private func row(_ s: Secret) -> some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: icon(for: s))
                .font(.title3)
                .foregroundStyle(.secondary)
                .frame(width: 40, height: 40)
                .background(Circle().fill(Color.secondary.opacity(0.1)))

            VStack(alignment: .leading, spacing: 4) {
                HStack(spacing: 6) {
                    Text(s.name.isEmpty ? "Untitled" : s.name)
                        .font(.body.bold())
                        .lineLimit(1)
                        .truncationMode(.middle)
                    if let type = s.type, !type.isEmpty {
                        chip(type, color: .purple)
                    }
                    if s.onChain {
                        chip("On-chain", color: .blue)
                    }
                }

                if let memo = s.memo, !memo.isEmpty {
                    Text(memo)
                        .font(.caption)
                        .foregroundStyle(.tertiary)
                        .lineLimit(2)
                }

                if let plain = revealed[s.id] {
                    CopyableText(plain, font: .system(.callout, design: .monospaced))
                        .padding(.top, 2)
                }
            }

            Spacer(minLength: 8)

            HStack(spacing: 4) {
                Button {
                    toggleReveal(s)
                } label: {
                    Image(systemName: revealed[s.id] == nil ? "eye" : "eye.slash")
                }
                .buttonStyle(.borderless)
                .disabled(!session.canSign)
                .help(session.canSign
                      ? (revealed[s.id] == nil ? "Reveal content" : "Hide content")
                      : "Watch-only identity — no key to decrypt with")

                if session.canSign && !s.onChain {
                    Button {
                        pendingCarve = s
                    } label: {
                        Image(systemName: "link.badge.plus")
                    }
                    .buttonStyle(.borderless)
                    .disabled(carving)
                    .help("Carve this secret on-chain (encrypted to your key)")
                }

                Button(role: .destructive) {
                    pendingDelete = s
                } label: {
                    Image(systemName: "trash")
                }
                .buttonStyle(.borderless)
                .help("Delete")
            }
            .foregroundStyle(.secondary)
        }
        .contentShape(Rectangle())
    }

    private func icon(for s: Secret) -> String {
        switch Secret.SecretType(rawValue: s.type ?? "") {
        case .prikey:   return "key"
        case .symkey:   return "key.horizontal"
        case .password: return "ellipsis.rectangle"
        case .totp:     return "timer"
        case .secret:   return "lock"
        case .text, nil: return "doc.text"
        }
    }

    private func chip(_ text: String, color: Color) -> some View {
        Text(text)
            .font(.caption2.bold())
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .background(Capsule().fill(color.opacity(0.15)))
            .foregroundStyle(color)
    }

    private func card(@ViewBuilder _ content: () -> some View) -> some View {
        VStack(alignment: .leading, spacing: 8, content: content)
            .padding(20)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Color(NSColor.controlBackgroundColor))
            .clipShape(RoundedRectangle(cornerRadius: 12))
    }

    // MARK: - actions

    private func reload() {
        do {
            rows = try session.secrets.all()
            loadError = nil
        } catch {
            loadError = String(describing: error)
        }
    }

    private func toggleReveal(_ s: Secret) {
        if revealed[s.id] != nil {
            revealed[s.id] = nil
            return
        }
        do {
            let priv = try session.livePrikey()
            revealed[s.id] = try s.decryptContent(privkey: priv)
        } catch {
            syncError = nil
            loadError = "Failed to decrypt: \(String(describing: error))"
        }
    }

    private func syncFromChain() async {
        guard session.canSign, !syncing else { return }
        syncing = true
        syncError = nil
        defer { syncing = false }
        do {
            let priv = try session.livePrikey()
            let result = try await session.secretService.syncOnChainSecrets(
                owner: session.liveFid, privkey: priv, into: session.secrets
            )
            carveTxid = nil
            if result.total == 0 {
                syncSummary = "No carved secrets on-chain."
            } else {
                var parts = ["\(result.merged) on-chain secret\(result.merged == 1 ? "" : "s") synced"]
                if result.removed > 0 {
                    parts.append("\(result.removed) removed (deleted on-chain)")
                }
                if result.undecryptable > 0 {
                    parts.append("\(result.undecryptable) could not be decrypted")
                    parts.append(contentsOf: result.failureReasons)
                }
                syncSummary = parts.joined(separator: " · ")
            }
            reload()
        } catch {
            syncError = String(describing: error)
        }
    }

    private func delete(_ s: Secret) {
        do {
            _ = try session.secrets.remove(id: s.id)
            revealed[s.id] = nil
            reload()
        } catch {
            loadError = String(describing: error)
        }
    }

    private func canDeleteOnChain(_ s: Secret) -> Bool {
        session.canSign && s.onChain && !(s.carveId ?? "").isEmpty
    }

    /// Carve a local-only secret on-chain: decrypt its content, carve,
    /// then re-key the local row to the broadcast txid so the next sync
    /// merges by id (mirrors Android setting `secret.setId(txId)`).
    private func carve(_ s: Secret) async {
        guard session.canSign, !carving else { return }
        carving = true
        syncError = nil
        carveTxid = nil
        defer { carving = false }
        do {
            let priv = try session.livePrikey()
            let content = try s.decryptContent(privkey: priv)
            let txid = try await session.carveSecretOnChain(s, content: content)
            carveTxid = txid
            var rekeyed = s
            rekeyed.id = txid
            rekeyed.carveId = txid
            try session.secrets.upsert(rekeyed)
            _ = try session.secrets.remove(id: s.id)
            reload()
        } catch {
            syncError = String(describing: error)
        }
    }

    private func deleteOnChain(_ s: Secret) async {
        guard let carveId = s.carveId, !carveId.isEmpty, !carving else { return }
        carving = true
        syncError = nil
        carveTxid = nil
        defer { carving = false }
        do {
            carveTxid = try await session.carveSecretDeleteOnChain(carveIds: [carveId])
            delete(s)
        } catch {
            syncError = String(describing: error)
        }
    }
}

// MARK: - TOTP cards

/// Live TOTP code cards — the Mac analogue of Android's `TotpCard`
/// list. Decrypts each TOTP secret once, then regenerates codes on a
/// 1-second tick; codes are hidden behind an eye toggle and click-copy.
private struct TotpCardList: View {
    let session: ActiveSession
    let secrets: [Secret]

    @State private var seeds: [String: Data] = [:]   // id → Base32-decoded seed
    @State private var codes: [String: String] = [:]
    @State private var visible: Set<String> = []
    @State private var countdown = 30
    @State private var decryptError: String?

    private let timer = Timer.publish(every: 1, on: .main, in: .common).autoconnect()

    var body: some View {
        Group {
            if secrets.isEmpty {
                VStack(alignment: .leading, spacing: 8) {
                    Label("No TOTP secrets", systemImage: "timer")
                        .foregroundStyle(.secondary)
                    Text("Import a Base32 TOTP seed (the code behind an authenticator QR) and this tab becomes your authenticator: fresh 6-digit codes every 30 seconds.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                .padding(20)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(Color(NSColor.controlBackgroundColor))
                .clipShape(RoundedRectangle(cornerRadius: 12))
            } else {
                VStack(alignment: .leading, spacing: 12) {
                    HStack {
                        Text("Codes rotate in")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                        Text("\(countdown)s")
                            .font(.caption.monospacedDigit().bold())
                            .foregroundStyle(countdown <= 5 ? .orange : .secondary)
                        if let err = decryptError {
                            Spacer()
                            CopyableText(err, font: .caption).foregroundStyle(.red)
                        }
                    }
                    ScrollView {
                        LazyVStack(spacing: 0) {
                            ForEach(secrets) { s in
                                cardRow(s)
                                    .padding(.vertical, 12)
                                    .padding(.horizontal, 16)
                                Divider()
                            }
                        }
                        .background(Color(NSColor.controlBackgroundColor))
                        .clipShape(RoundedRectangle(cornerRadius: 12))
                    }
                }
            }
        }
        .onAppear(perform: refreshAll)
        .onChange(of: secrets.map(\.id)) { _, _ in refreshAll() }
        .onReceive(timer) { _ in tick() }
    }

    @ViewBuilder
    private func cardRow(_ s: Secret) -> some View {
        HStack(spacing: 12) {
            VStack(alignment: .leading, spacing: 2) {
                Text(s.name.isEmpty ? "Untitled" : s.name)
                    .font(.body.bold())
                    .lineLimit(1)
                    .truncationMode(.middle)
                if let memo = s.memo, !memo.isEmpty {
                    Text(memo)
                        .font(.caption)
                        .foregroundStyle(.tertiary)
                        .lineLimit(1)
                }
            }

            Spacer()

            if let code = codes[s.id] {
                if visible.contains(s.id) {
                    CopyableText(code, font: .system(size: 22, weight: .bold, design: .monospaced))
                } else {
                    Text("••••••")
                        .font(.system(size: 22, weight: .regular, design: .monospaced))
                        .foregroundStyle(.secondary)
                }
            } else {
                Text("——————")
                    .font(.system(size: 22, design: .monospaced))
                    .foregroundStyle(.tertiary)
            }

            Button {
                if visible.contains(s.id) {
                    visible.remove(s.id)
                } else {
                    visible.insert(s.id)
                }
            } label: {
                Image(systemName: visible.contains(s.id) ? "eye.slash" : "eye")
            }
            .buttonStyle(.borderless)
            .foregroundStyle(.secondary)
        }
    }

    private func refreshAll() {
        decryptError = nil
        guard session.canSign, let priv = try? session.livePrikey() else {
            if !secrets.isEmpty {
                decryptError = "Watch-only identity — cannot decrypt TOTP seeds"
            }
            return
        }
        var failures = 0
        for s in secrets where seeds[s.id] == nil {
            if let content = try? s.decryptContent(privkey: priv),
               let seed = try? Base32.decode(content.trimmingCharacters(in: .whitespacesAndNewlines)) {
                seeds[s.id] = seed
            } else {
                failures += 1
            }
        }
        if failures > 0 {
            decryptError = "\(failures) TOTP seed\(failures == 1 ? "" : "s") could not be decrypted/decoded"
        }
        regenerate()
    }

    private func tick() {
        let now = Int64(Date().timeIntervalSince1970)
        let remaining = Totp.secondsRemaining(unixTime: now)
        // Regenerate on the window flip (or first tick).
        if remaining > countdown || codes.isEmpty {
            regenerate()
        }
        countdown = remaining
    }

    private func regenerate() {
        let now = Int64(Date().timeIntervalSince1970)
        for (id, seed) in seeds {
            codes[id] = Totp.generate(secret: seed, unixTime: now)
        }
    }
}
