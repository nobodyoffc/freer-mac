import SwiftUI
import FCCore

/// Mint a new identity from a passphrase. The KDF runs on a
/// background task (Argon2id is ~300 ms) so the form stays
/// responsive during derivation.
struct CreateIdentityView: View {
    @Environment(AppState.self) private var appState

    @State private var displayName: String = ""
    @State private var passphrase: String = ""
    @State private var confirmPassphrase: String = ""
    @State private var scheme: PhraseKey.Scheme = .argon2id
    @State private var working: Bool = false

    private var passphrasesAgree: Bool { passphrase == confirmPassphrase && !passphrase.isEmpty }

    private var canSubmit: Bool {
        !working && passphrasesAgree
    }

    var body: some View {
        Form {
            Section {
                TextField("Display name", text: $displayName)
                    .textContentType(.nickname)
            } header: {
                Text("Who is this identity?")
            } footer: {
                Text("Local label only — peers don't see it.")
                    .font(.caption)
            }

            Section {
                SecureField("Passphrase", text: $passphrase)
                SecureField("Confirm passphrase", text: $confirmPassphrase)
            } header: {
                Text("Passphrase")
            } footer: {
                if !passphrase.isEmpty && !passphrasesAgree {
                    Text("Passphrases don't match.")
                        .font(.caption)
                        .foregroundStyle(.red)
                } else {
                    Text("This is the only thing that unlocks your wallet. There is no recovery — write it down.")
                        .font(.caption)
                }
            }

            Section {
                Picker("Key derivation", selection: $scheme) {
                    ForEach(PhraseKey.Scheme.allCases, id: \.rawValue) { s in
                        Text(label(for: s)).tag(s)
                    }
                }
                if let advisory = scheme.advisory {
                    Text(advisory)
                        .font(.callout)
                        .foregroundStyle(.orange)
                        .padding(.vertical, 4)
                }
            } header: {
                Text("Advanced")
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
                    Button("Back") { appState.goToChooseIdentity() }
                        .disabled(working)
                    Spacer()
                    Button {
                        Task { await submit() }
                    } label: {
                        if working {
                            ProgressView().controlSize(.small)
                                .frame(maxWidth: .infinity)
                        } else {
                            Text("Create").frame(maxWidth: .infinity)
                        }
                    }
                    .keyboardShortcut(.defaultAction)
                    .buttonStyle(.borderedProminent)
                    .disabled(!canSubmit)
                }
            }
        }
        .formStyle(.grouped)
        .frame(minWidth: 460, maxWidth: 560)
        .padding()
    }

    private func label(for s: PhraseKey.Scheme) -> String {
        switch s {
        case .argon2id:     return "Argon2id (recommended)"
        case .legacySha256: return "Legacy SHA-256 (Android import)"
        }
    }

    @MainActor
    private func submit() async {
        guard canSubmit else { return }
        working = true
        defer { working = false }
        await appState.createIdentity(
            passphrase: passphrase, displayName: displayName, scheme: scheme
        )
        // Clear sensitive form state immediately on either success or error.
        passphrase = ""
        confirmPassphrase = ""
    }
}
