import SwiftUI
import AppKit
import FCCore
import FCDomain
import FCUI

/// Mint or import a main FID inside the unlocked Configure. Three sources:
///   - **Random** — `SecRandomCopyBytes(32)`. The most defensible
///     choice; picked by default.
///   - **Key** — one box that takes whatever key text the user has:
///     64 hex characters, `0x`-prefixed hex, a WIF (`L`/`K`/`5`), or a
///     password-encrypted backup in either of the two forms Freer
///     writes (the `{"type":"Password",…}` JSON envelope and the Base64
///     bundle). Typed, pasted, scanned from a QR code, or read from a
///     file — the shapes ``BackupPrikeySheet`` and Android's backup
///     dialog produce.
///   - **Passphrase** — derive via Argon2id (recommended) or legacy
///     SHA-256 (Android-import only). Same `PhraseKey` we use for
///     vanity wallets.
///
/// **One box instead of a Hex tab and a WIF tab**, following Android's
/// `ImportKeyActivity`: the user rarely knows which encoding they are
/// holding, and making them classify it first turns a paste into a
/// quiz. ``KeyInput`` classifies instead, and the verdict is shown
/// while typing so a near miss ("looks like a WIF, checksum fails") is
/// reported rather than guessed at — and so a watch-only pubkey or FID
/// is never silently mistaken for restoring a wallet.
///
/// A passphrase stays its own source on purpose: *any* text could be
/// one, so a mistyped key that happened to be treated as a phrase would
/// quietly mint a different identity.
///
/// Validation happens before we touch the vault; deriving (Argon2id for
/// a phrase or a cipher) and the encrypt-and-persist work run off the
/// main actor, so the window keeps painting while the KDF runs.
struct AddMainView: View {
    @Environment(AppState.self) private var appState

    enum Source: String, CaseIterable, Identifiable {
        case random = "Random"
        case key = "Key"
        case passphrase = "Passphrase"
        var id: String { rawValue }
    }

    @State private var source: Source = .random
    @State private var label: String = ""
    /// Whatever the user pasted: a privkey in some encoding, or a cipher.
    @State private var keyText: String = ""
    @State private var detected: KeyInput.Kind = .empty
    /// The password that opens ``keyText`` when it is a cipher. Not the
    /// vault password — the one whoever made the backup chose.
    @State private var cipherPassword: String = ""
    @State private var phrase: String = ""
    @State private var phraseScheme: PhraseKey.Scheme = .argon2id
    @State private var working: Bool = false
    @State private var localError: String?
    @State private var showScan: Bool = false

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
                    Text("A 32-byte prikey will be generated using SecRandomCopyBytes.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                case .key:
                    keyBox
                case .passphrase:
                    SecureField("Passphrase", text: $phrase)
                    Picker("KDF", selection: $phraseScheme) {
                        Text("Argon2id (recommended)").tag(PhraseKey.Scheme.argon2id)
                        Text("Legacy SHA-256 (Android import)").tag(PhraseKey.Scheme.legacySha256)
                        Text("Old FreerForMac Argon2id (recovery)").tag(PhraseKey.Scheme.legacyFreerMacArgon2id)
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
        .sheet(isPresented: $showScan) {
            QrScanSheet(title: "Scan a key QR") { scanned in
                showScan = false
                adopt(scanned)
            } onCancel: {
                showScan = false
            }
        }
    }

    // MARK: - the one key box

    @ViewBuilder
    private var keyBox: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(alignment: .top, spacing: 8) {
                // An axis-less TextField would clip a 300-character
                // cipher to one line with no way to see the rest.
                TextField("Prikey, or an encrypted backup", text: $keyText, axis: .vertical)
                    .font(.system(.body, design: .monospaced))
                    .lineLimit(1 ... 5)
                VStack(spacing: 4) {
                    Button { showScan = true } label: { Image(systemName: "qrcode.viewfinder") }
                        .disabled(working)
                        .help("Scan a key QR code — from the camera or an image file.")
                    Button(action: pickFile) { Image(systemName: "folder") }
                        .disabled(working)
                        .help("Read the key text from a file — the cipher a backup saved.")
                    Button(action: clear) { Image(systemName: "xmark.circle") }
                        .disabled(working || keyText.isEmpty)
                        .help("Clear the box.")
                }
                .buttonStyle(.borderless)
            }

            if detected == .cipher {
                SecureField("Password that opens this backup", text: $cipherPassword)
            }

            if let verdict {
                HStack(alignment: .firstTextBaseline, spacing: 6) {
                    Image(systemName: verdict.icon)
                        .foregroundStyle(verdict.tint)
                    Text(verdict.text)
                        .font(.caption)
                        .foregroundStyle(verdict.usable ? .secondary : verdict.tint)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
        }
        .onChange(of: keyText) { _, _ in
            detected = KeyInput.detect(keyText)
            localError = nil
        }
    }

    /// What the box says about what it is holding. Every kind gets a
    /// sentence: silence on a key that will not import is the failure
    /// mode this whole box exists to avoid.
    private struct Verdict {
        let text: String
        let icon: String
        let tint: Color
        /// Whether Add identity can act on it.
        let usable: Bool
    }

    private var verdict: Verdict? {
        switch detected {
        case .empty:
            return nil
        case .prikey:
            return Verdict(
                text: "Prikey. This becomes a main FID that can sign and spend.",
                icon: "checkmark.seal", tint: .green, usable: true
            )
        case .cipher:
            return Verdict(
                text: "Encrypted backup. Enter the password it was sealed with — not this vault's password, unless they are the same.",
                icon: "lock", tint: .accentColor, usable: true
            )
        case .nonPasswordCipher:
            return Verdict(
                text: "This cipher wasn't encrypted with a password, so a password can't open it. Decrypt it where its key lives, then paste the key itself.",
                icon: "lock.trianglebadge.exclamationmark", tint: .orange, usable: false
            )
        case .pubkey:
            return Verdict(
                text: "Pubkey — watch-only. A main FID has to be able to sign, so this can't be one. Unlock a main first, then add it under My Watched FIDs.",
                icon: "eye", tint: .orange, usable: false
            )
        case .fid:
            return Verdict(
                text: "An FID — watch-only. A main FID has to be able to sign, so this can't be one. Unlock a main first, then add it under My Watched FIDs.",
                icon: "eye", tint: .orange, usable: false
            )
        case .backup:
            return Verdict(
                text: "Key JSON — a backup of several entries. Importing a whole backup isn't supported here yet; paste one key, or one encrypted key, at a time.",
                icon: "doc.text", tint: .orange, usable: false
            )
        case .badPrikey:
            return Verdict(
                text: "Shaped like a prikey, but not a valid one — a character is wrong. Check the text against the original rather than retyping it.",
                icon: "exclamationmark.triangle", tint: .red, usable: false
            )
        case .badPubkey:
            return Verdict(
                text: "Shaped like a pubkey, but not a valid one.",
                icon: "exclamationmark.triangle", tint: .red, usable: false
            )
        case .badFid:
            return Verdict(
                text: "Shaped like an FID, but the checksum fails — a character is wrong.",
                icon: "exclamationmark.triangle", tint: .red, usable: false
            )
        case .multiple:
            return Verdict(
                text: "That looks like more than one item. Paste a single key.",
                icon: "square.stack", tint: .orange, usable: false
            )
        case .unknown:
            return Verdict(
                text: "Not a key this app recognizes — expected hex, a WIF, or an encrypted backup.",
                icon: "questionmark.circle", tint: .orange, usable: false
            )
        }
    }

    /// Scanned or opened text goes straight in the box; the detector
    /// decides what it is, exactly as it does for a paste.
    private func adopt(_ raw: String) {
        keyText = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        source = .key
    }

    private func pickFile() {
        let panel = NSOpenPanel()
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = false
        panel.prompt = "Read key"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            let text = try String(contentsOf: url, encoding: .utf8)
            adopt(text)
        } catch {
            localError = "Couldn't read \(url.lastPathComponent): \(error.localizedDescription)"
        }
    }

    private func clear() {
        keyText = ""
        cipherPassword = ""
        localError = nil
    }

    // MARK: - submit

    private var inputLooksValid: Bool {
        switch source {
        case .random:     return true
        case .key:        return detected == .prikey
                              || (detected == .cipher && !cipherPassword.isEmpty)
        case .passphrase: return !phrase.isEmpty
        }
    }

    @MainActor
    private func submit() async {
        guard inputLooksValid, !working else { return }
        localError = nil
        working = true
        defer { working = false }

        // Argon2id — for a phrase, and for a cipher's password — takes
        // long enough that running it here would freeze the window.
        let source = self.source
        let keyText = self.keyText
        let cipherPassword = self.cipherPassword
        let phrase = self.phrase
        let phraseScheme = self.phraseScheme

        let priv: Data
        do {
            priv = try await Task.detached(priority: .userInitiated) {
                try Self.derivePrivkey(
                    source: source, keyText: keyText,
                    cipherPassword: cipherPassword,
                    phrase: phrase, phraseScheme: phraseScheme
                )
            }.value
        } catch {
            localError = String(describing: error)
            return
        }
        // A key whose prikey is published is nobody's to own. Before a
        // session there is no FAPI to ask, so this knows what the registry
        // knows; the first refresh of the new identity checks the chain.
        if let fid = try? FchAddress(publicKey: Secp256k1.publicKey(fromPrivateKey: priv)).fid {
            guard await NobodyGate.confirm([fid], .importKey, session: appState.activeSession) else { return }
            // Already confirmed here: no separate "your key is public" alert later.
            _ = NobodyRegistry.shared.claimOwnKeyAlert(fid)
        }
        await appState.addMain(privkey: priv, label: label)
        // Wipe sensitive fields irrespective of success/error.
        self.keyText = ""
        self.cipherPassword = ""
        self.phrase = ""
        detected = .empty
    }

    /// Nonisolated so it can run off the main actor: it reads only the
    /// values handed to it, never the view's state.
    nonisolated private static func derivePrivkey(
        source: Source,
        keyText: String,
        cipherPassword: String,
        phrase: String,
        phraseScheme: PhraseKey.Scheme
    ) throws -> Data {
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

        case .key:
            if let privkey = KeyInput.prikey32(from: keyText) { return privkey }
            var plaintext = try KeyInput.openCipher(keyText, password: Data(cipherPassword.utf8))
            defer { plaintext.resetBytes(in: 0 ..< plaintext.count) }
            guard let privkey = KeyInput.prikey(fromPlaintext: plaintext) else {
                throw Failure.cipherHeldNoKey(wasJson: KeyInput.isJson(plaintext))
            }
            return privkey

        case .passphrase:
            return try PhraseKey.privateKey(fromPhrase: phrase, scheme: phraseScheme)
        }
    }

    enum Failure: Error, CustomStringConvertible {
        case cipherHeldNoKey(wasJson: Bool)

        var description: String {
            switch self {
            case .cipherHeldNoKey(let wasJson):
                return wasJson
                    ? "The password opened that backup, but it holds key JSON rather than a single prikey. Importing a whole backup isn't supported here yet."
                    : "The password opened that backup, but what's inside isn't a prikey."
            }
        }
    }
}
