import SwiftUI
import FCCore
import FCDomain

/// Single password field. Two paths:
///
/// 1. **Existing vault**: the password's `passwordName` matches a
///    Configure in the index. We try to unlock it; wrong-password
///    surfaces inline.
/// 2. **New vault**: no Configure has that `passwordName`. The form
///    flips to a "create new vault" mode where the user can also
///    label the vault and pick a KDF.
///
/// The user never types the `passwordName` themselves — it's
/// derived from the password they're already entering.
struct PasswordView: View {
    @Environment(AppState.self) private var appState

    @State private var password: String = ""
    @State private var working: Bool = false
    @State private var newVaultLabel: String = ""
    @State private var newVaultKdf: KdfKind = .argon2id

    private var hasExisting: Bool {
        !appState.configures.isEmpty
    }

    /// Recompute as the user types. Read-only for the UI; never sent
    /// to disk in plaintext.
    private var passwordName: String? {
        guard !password.isEmpty else { return nil }
        return ConfigureCrypto.passwordName(from: Data(password.utf8))
    }

    /// Does the typed password match an existing Configure by name?
    /// Doesn't verify cryptographically — that happens on submit.
    private var matchesExistingConfigure: Bool {
        guard let pn = passwordName else { return false }
        return appState.configures.contains(where: { $0.passwordName == pn })
    }

    var body: some View {
        Form {
            Section {
                SecureField("Password", text: $password)
                    .textContentType(.password)
                    .onSubmit { Task { await submit() } }
                if let pn = passwordName {
                    HStack(spacing: 6) {
                        Text("Vault hint:")
                        Text(pn).font(.system(.body, design: .monospaced)).bold()
                        Spacer()
                        if matchesExistingConfigure {
                            Label("matches existing vault", systemImage: "checkmark.circle.fill")
                                .foregroundStyle(.green)
                        } else if hasExisting {
                            Label("would create a new vault", systemImage: "plus.circle")
                                .foregroundStyle(.orange)
                        }
                    }
                    .font(.caption)
                    .foregroundStyle(.secondary)
                }
            } header: {
                Text(hasExisting ? "Enter your password" : "Set a password")
            } footer: {
                Text("Each password unlocks one vault. The first 6 hex characters of dSHA-256(password) identify which vault — type the matching password and you'll unlock it.")
                    .font(.caption)
            }

            // Show the "new vault" sub-form only when we'd actually
            // create one (the password doesn't match anything).
            if !matchesExistingConfigure {
                Section {
                    TextField("Vault label (optional)", text: $newVaultLabel)
                    Picker("Key derivation", selection: $newVaultKdf) {
                        Text("Argon2id (recommended)").tag(KdfKind.argon2id)
                        Text("Legacy SHA-256 (Android import)").tag(KdfKind.legacySha256)
                    }
                    if let advisory = newVaultKdf.advisory {
                        Text(advisory)
                            .font(.callout)
                            .foregroundStyle(.orange)
                    }
                } header: {
                    Text("New vault")
                }
            }

            if let err = appState.lastError {
                Section {
                    Text(err)
                        .foregroundStyle(.red)
                        .font(.callout)
                }
            }

            Section {
                HStack {
                    if hasExisting {
                        Button("Show known vaults") {
                            // Tiny hint toggle — we just print the
                            // labels here for now. Could become a
                            // sheet in 6.x.
                        }
                        .disabled(true)
                        .help(appState.configures
                            .map { "\($0.passwordName) — \($0.label.isEmpty ? "(no label)" : $0.label)" }
                            .joined(separator: "\n"))
                    }
                    Spacer()
                    Button {
                        Task { await submit() }
                    } label: {
                        if working {
                            HStack(spacing: 6) {
                                ProgressView().controlSize(.small)
                                Text(matchesExistingConfigure ? "Unlocking…" : "Creating…")
                            }
                            .frame(width: 140)
                        } else {
                            Text(matchesExistingConfigure ? "Unlock" : "Create vault")
                                .frame(width: 140)
                        }
                    }
                    .keyboardShortcut(.defaultAction)
                    .buttonStyle(.borderedProminent)
                    .disabled(working || password.isEmpty)
                }
            }
        }
        .formStyle(.grouped)
        .frame(minWidth: 540, maxWidth: 620)
        .padding()
    }

    @MainActor
    private func submit() async {
        guard !password.isEmpty, !working else { return }
        working = true
        defer { working = false }
        let pwd = Data(password.utf8)
        let createIfMissing = !matchesExistingConfigure
        await appState.openOrCreate(
            password: pwd,
            createIfMissing: createIfMissing,
            newLabel: newVaultLabel,
            kdfKind: newVaultKdf
        )
        // Wipe the field on success or failure — same hygiene as 6.1.
        password = ""
    }
}
