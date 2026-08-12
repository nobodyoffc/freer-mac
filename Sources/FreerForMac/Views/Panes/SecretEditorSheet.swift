import SwiftUI
import FCCore
import FCDomain
import FCUI

/// Create a new secret — the Mac port of Android's
/// `CreateSecretActivity` / `ImportTotpActivity` pair. Saves locally
/// (encrypted to the live FID's pubkey) or saves + carves on-chain.
struct SecretEditorSheet: View {
    let session: ActiveSession
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
            Text(presetTotp ? "Import TOTP secret" : "New secret")
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

            if let error {
                CopyableText(error, font: .caption)
                    .foregroundStyle(.red)
            }

            HStack {
                Button("Cancel", role: .cancel, action: onCancel)
                    .keyboardShortcut(.cancelAction)
                Spacer()
                Button("Save locally") {
                    Task { await save(carve: false) }
                }
                .disabled(content.isEmpty || working)
                Button("Save & carve on-chain") {
                    Task { await save(carve: true) }
                }
                .buttonStyle(.borderedProminent)
                .disabled(content.isEmpty || working)
                .help("Encrypted to your key and written to the FCH chain (small miner fee); syncs to any device you unlock with this key")
            }
        }
        .padding(20)
        .frame(width: 480)
        .onAppear {
            if presetTotp { type = .totp }
        }
        .disabled(working)
        .overlay {
            if working { ProgressView() }
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
            }
            try session.secrets.upsert(secret)
            onSaved(txid)
        } catch {
            self.error = String(describing: error)
        }
    }
}
