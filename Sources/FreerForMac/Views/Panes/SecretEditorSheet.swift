import SwiftUI
import FCCore
import FCDomain
import FCUI

/// Create or edit a secret — the Mac port of Android's
/// `CreateSecretActivity` / `ImportTotpActivity` / `UpdateSecretActivity`.
/// Saves locally (encrypted to the live FID's pubkey) or saves + carves
/// on-chain. Editing a carved secret carves an `update`, which keeps its
/// id; editing a local-only one carves an `add`.
struct SecretEditorSheet: View {
    let session: ActiveSession
    /// The secret being edited; nil creates a new one.
    var editing: Secret? = nil
    /// Opened from the TOTP tab: preselects the TOTP type (whose
    /// content must be Base32) — Android's "import TOTP" flow.
    var presetTotp = false
    /// Called with the carve txid (nil for a local-only save).
    let onSaved: (String?) -> Void
    let onCancel: () -> Void

    @State private var type: Secret.SecretType = .secret
    @State private var title = ""
    @State private var content = ""
    @State private var memo = ""
    @State private var working = false
    @State private var error: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text(editing != nil ? "Edit secret" : (presetTotp ? "Import TOTP secret" : "New secret"))
                .font(.title3.bold())

            Form {
                Picker("Type", selection: $type) {
                    ForEach(Secret.SecretType.allCases, id: \.self) { t in
                        Text(t.displayName).tag(t)
                    }
                }

                TextField("Title", text: $title, prompt: Text("e.g. GitHub 2FA"))

                VStack(alignment: .leading, spacing: 4) {
                    TextField(
                        "Content",
                        text: $content,
                        prompt: Text(type == .totp ? "Base32 seed (A–Z, 2–7)" : "The secret itself"),
                        axis: .vertical
                    )
                    .lineLimit(2...6)
                    .font(.system(.body, design: .monospaced))

                    if type == .totp {
                        Button("Generate random seed") {
                            var bytes = Data(count: 16)
                            _ = bytes.withUnsafeMutableBytes {
                                SecRandomCopyBytes(kSecRandomDefault, 16, $0.baseAddress!)
                            }
                            content = Base32.encode(bytes)
                        }
                        .controlSize(.small)
                    }
                }

                TextField("Memo", text: $memo, prompt: Text("Optional note"))
            }
            .formStyle(.grouped)

            if isCarved {
                Text(isPendingCarve
                     ? "This secret's carve has not confirmed yet. Edit it once a block confirms it. A carve still unconfirmed after 2 hours is dropped at the next refresh, and the secret becomes local-only again."
                     : "This secret is on chain, so an edit is carved as an update (small miner fee).")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }

            if let error {
                CopyableText(error, font: .caption)
                    .foregroundStyle(.red)
            }

            HStack {
                Button("Cancel", role: .cancel, action: onCancel)
                    .keyboardShortcut(.cancelAction)
                Spacer()
                // A carved secret mirrors the chain: a local-only edit would
                // be replaced by the chain copy at the next sync.
                if !isCarved {
                    Button("Save locally") {
                        Task { await save(carve: false) }
                    }
                    .disabled(content.isEmpty || working)
                }
                Button(isCarved ? "Save & carve update" : "Save & carve on-chain") {
                    Task { await save(carve: true) }
                }
                .buttonStyle(.borderedProminent)
                .disabled(content.isEmpty || working || isPendingCarve)
                .help(isPendingCarve
                      ? "Wait for the earlier carve to confirm before carving an update"
                      : "Encrypted to your key and written to the FCH chain (small miner fee); syncs to any device you unlock with this key")
            }
        }
        .padding(20)
        .frame(width: 480)
        .onAppear {
            if let editing {
                load(editing)
            } else if presetTotp {
                type = .totp
            }
        }
        .disabled(working)
        .overlay {
            if working { ProgressView() }
        }
    }

    /// Has a carve on chain (confirmed or not), so a carve now is an `update`.
    private var isCarved: Bool { !(editing?.carveId ?? "").isEmpty }

    /// Carved but not yet confirmed by a sync. An update naming an add
    /// the chain has not accepted yet could be rejected, so wait.
    private var isPendingCarve: Bool { isCarved && editing?.onChain == false }

    private func load(_ secret: Secret) {
        type = Secret.SecretType.allCases.first {
            $0.rawValue.caseInsensitiveCompare(secret.type ?? "") == .orderedSame
        } ?? .text
        title = secret.title ?? ""
        memo = secret.memo ?? ""
        do {
            content = try secret.decryptContent(privkey: try session.livePrikey())
        } catch {
            self.error = "Failed to decrypt: \(String(describing: error))"
        }
    }

    private func save(carve: Bool) async {
        error = nil
        let trimmedContent = content.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmedContent.isEmpty else { return }

        // Android refuses a TOTP whose content is not Base32 — a broken
        // seed would render useless codes forever.
        if type == .totp, (try? Base32.decode(trimmedContent)) == nil {
            error = "A TOTP secret must be Base32 (letters A–Z and digits 2–7)."
            return
        }

        working = true
        defer { working = false }
        if let editing {
            await saveEdit(of: editing, content: trimmedContent, carve: carve)
            return
        }
        do {
            let priv = try session.livePrikey()
            let pubkey = try Secp256k1.publicKey(fromPrivateKey: priv)
            var secret = try Secret.createLocal(
                type: type,
                title: title.isEmpty ? nil : title,
                content: trimmedContent,
                memo: memo.isEmpty ? nil : memo,
                ownPubkey: pubkey
            )
            if try session.secrets.get(id: secret.id) != nil {
                error = "An identical secret already exists."
                return
            }
            var txid: String?
            if carve {
                txid = try await session.carveSecretOnChain(secret, content: trimmedContent)
                // Re-key to the carve txid so the next chain sync merges
                // by id (Android: secret.setId(txId)).
                secret.id = txid!
                secret.carveId = txid
                secret.carvedAt = Date()
            }
            try session.secrets.upsert(secret)
            onSaved(txid)
        } catch {
            self.error = String(describing: error)
        }
    }

    /// Edits keep the row's id. Carving a secret that already has a
    /// carve sends an `update` naming that carve; carving a local-only
    /// one sends an `add`, and the row is re-keyed to the add's txid so
    /// the next chain sync merges by id.
    private func saveEdit(of original: Secret, content: String, carve: Bool) async {
        do {
            let priv = try session.livePrikey()
            let pubkey = try Secp256k1.publicKey(fromPrivateKey: priv)
            var secret = original
            secret.type = type.rawValue
            secret.title = title.isEmpty ? nil : title
            secret.memo = memo.isEmpty ? nil : memo
            secret.contentCipher = try AsyOneWayCipher.encrypt(
                plaintext: Data(content.utf8), toPubkey: pubkey
            )
            secret.updatedAt = Date()

            var txid: String?
            if carve {
                let wasCarved = !(original.carveId ?? "").isEmpty
                txid = try await session.carveSecretOnChain(secret, content: content)
                if !wasCarved {
                    secret.id = txid!
                    secret.carveId = txid
                    secret.carvedAt = Date()
                }
            }
            try session.secrets.upsert(secret)
            if secret.id != original.id {
                _ = try session.secrets.remove(id: original.id)
            }
            onSaved(txid)
        } catch {
            self.error = String(describing: error)
        }
    }
}
