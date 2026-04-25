import SwiftUI
import FCCore

/// Mint a new main FID inside the unlocked Configure. Four sources:
///   - **Random** — `SecRandomCopyBytes(32)`. The most defensible
///     choice; picked by default.
///   - **Hex** — paste 64 hex chars.
///   - **WIF** — paste an `L`/`K`/`5`-prefix Bitcoin/FCH-mainnet WIF
///     (e.g. `L2bHRej6Fxxipvb4TiR5bu1rkT3tRp8yWEsUy4R1Zb8VMm2x7sd8`,
///     the project test fixture).
///   - **Passphrase** — derive via Argon2id (recommended) or legacy
///     SHA-256 (Android-import only). Same `PhraseKey` we use for
///     vanity wallets.
///
/// Validation happens before we touch the vault; the encrypt-and-
/// persist work runs on a background priority task.
struct AddMainView: View {
    @Environment(AppState.self) private var appState

    enum Source: String, CaseIterable, Identifiable {
        case random = "Random"
        case hex = "Hex"
        case wif = "WIF"
        case passphrase = "Passphrase"
        var id: String { rawValue }
    }

    @State private var source: Source = .random
    @State private var label: String = ""
    @State private var hexInput: String = ""
    @State private var wifInput: String = ""
    @State private var phrase: String = ""
    @State private var phraseScheme: PhraseKey.Scheme = .argon2id
    @State private var working: Bool = false
    @State private var localError: String?

    var body: some View {
        Form {
            Section {
                TextField("Label (optional)", text: $label)
            } header: {
                Text("New main FID")
            } footer: {
                Text("The label is shown in the chooser. Stays local to this Mac.")
                    .font(.caption)
            }

            Section {
                Picker("Source", selection: $source) {
                    ForEach(Source.allCases) { s in
                        Text(s.rawValue).tag(s)
                    }
                }
                .pickerStyle(.segmented)

                switch source {
                case .random:
                    Text("A 32-byte privkey will be generated using SecRandomCopyBytes.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                case .hex:
                    TextField("64 hex characters", text: $hexInput)
                        .font(.system(.body, design: .monospaced))
                case .wif:
                    TextField("Wallet Import Format (L… / K… / 5…)", text: $wifInput)
                        .font(.system(.body, design: .monospaced))
                case .passphrase:
                    SecureField("Passphrase", text: $phrase)
                    Picker("KDF", selection: $phraseScheme) {
                        Text("Argon2id (recommended)").tag(PhraseKey.Scheme.argon2id)
                        Text("Legacy SHA-256 (Android import)").tag(PhraseKey.Scheme.legacySha256)
                    }
                    if let advisory = phraseScheme.advisory {
                        Text(advisory)
                            .font(.callout)
                            .foregroundStyle(.orange)
                    }
                }
            }

            if let err = localError ?? appState.lastError {
                Section {
                    Text(err)
                        .foregroundStyle(.red)
                        .font(.callout)
                }
            }

            Section {
                HStack {
                    Button("Back") {
                        appState.route = .chooseMain
                    }
                    .disabled(working)

                    Spacer()

                    Button {
                        Task { await submit() }
                    } label: {
                        if working {
                            HStack(spacing: 6) {
                                ProgressView().controlSize(.small)
                                Text("Adding…")
                            }
                            .frame(width: 140)
                        } else {
                            Text("Add identity").frame(width: 140)
                        }
                    }
                    .keyboardShortcut(.defaultAction)
                    .buttonStyle(.borderedProminent)
                    .disabled(working || !inputLooksValid)
                }
            }
        }
        .formStyle(.grouped)
        .frame(minWidth: 540, maxWidth: 620)
        .padding()
    }

    private var inputLooksValid: Bool {
        switch source {
        case .random:     return true
        case .hex:        return hexInput.count == 64
        case .wif:        return wifInput.count >= 50    // L/K WIFs ≈ 52 chars; 5-WIFs ≈ 51
        case .passphrase: return !phrase.isEmpty
        }
    }

    @MainActor
    private func submit() async {
        guard inputLooksValid, !working else { return }
        localError = nil
        working = true
        defer { working = false }

        let priv: Data
        do {
            priv = try derivePrivkey()
        } catch {
            localError = String(describing: error)
            return
        }
        await appState.addMain(privkey: priv, label: label)
        // Wipe sensitive fields irrespective of success/error.
        hexInput = ""
        wifInput = ""
        phrase = ""
    }

    private func derivePrivkey() throws -> Data {
        switch source {
        case .random:
            var out = Data(count: 32)
            let status = out.withUnsafeMutableBytes { ptr -> Int32 in
                guard let base = ptr.baseAddress else { return -1 }
                return SecRandomCopyBytes(kSecRandomDefault, 32, base)
            }
            guard status == errSecSuccess else {
                throw NSError(domain: "SecRandom", code: Int(status))
            }
            return out

        case .hex:
            return try parseHex(hexInput)

        case .wif:
            let (priv, _) = try WifPrivkey.decode(wifInput)
            return priv

        case .passphrase:
            return try PhraseKey.privateKey(fromPhrase: phrase, scheme: phraseScheme)
        }
    }

    private func parseHex(_ s: String) throws -> Data {
        guard s.count == 64 else {
            throw NSError(domain: "AddMainView", code: 1,
                          userInfo: [NSLocalizedDescriptionKey: "Hex must be exactly 64 chars."])
        }
        var data = Data(capacity: 32)
        var idx = s.startIndex
        while idx < s.endIndex {
            let next = s.index(idx, offsetBy: 2)
            guard let byte = UInt8(s[idx..<next], radix: 16) else {
                throw NSError(domain: "AddMainView", code: 2,
                              userInfo: [NSLocalizedDescriptionKey: "Invalid hex byte: \(s[idx..<next])"])
            }
            data.append(byte)
            idx = next
        }
        return data
    }
}
