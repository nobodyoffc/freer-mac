import SwiftUI
import AppKit
import FCCore
import FCDomain
import FCUI

/// Take a copy of this identity's private key — the Mac port of Android's
/// `BackupPrikeyDialog`, and the only way a key minted here ever leaves this Mac.
///
/// Three ways out, in the order they are safe:
///   - **An encrypted backup.** The key text is sealed with the vault password
///     (Argon2id, AES-256-GCM) into the `{"type":"Password",…}` envelope Freer,
///     Safe and Android all read. Copy it, save it as a file, or scan the QR code.
///     The cipher is the one form that is safe to keep where other people might
///     look, so it is what Save and the QR code offer.
///   - **The key itself**, hidden until asked for, in WIF or hex. For writing on
///     paper, and for nothing else.
///   - **An unencrypted QR code**, behind its own toggle, because a QR code of a
///     bare private key hands the wallet to anything that can see the screen.
///
/// **The password must be the vault's.** Verifying it costs a second Argon2id run
/// that the encryption does not need, and it is the point: a typo would otherwise
/// produce a backup nobody can open, discovered on the day the original is gone.
/// Freer and Safe open it with that same password.
struct BackupPrikeySheet: View {
    let session: ActiveSession
    /// The user says they have their copy — flips ``Setting/prikeyBackedUp``.
    let onDone: () -> Void
    /// Dismiss without claiming anything; the nudge comes back.
    let onLater: () -> Void

    enum Format: String, CaseIterable, Identifiable {
        case wif = "WIF"
        case hex = "Hex"
        var id: String { rawValue }
    }

    /// The 32 bytes, in a box that actually erases them. A `Data` in `@State`
    /// cannot be wiped — copy-on-write hands any mutation a fresh buffer and
    /// leaves the original where it was — so the bytes live in a class whose
    /// `deinit` zeroes the array in place, the same trick `ConfigureSession`
    /// uses for the symkey. The Strings derived below (hex, WIF, cipher) are a
    /// different matter: Swift gives no way to erase them, so they stay until
    /// the allocator reuses the memory. Keeping the sheet short-lived is the
    /// whole mitigation.
    private final class SecretBytes {
        var bytes: [UInt8]
        init(_ data: Data) { bytes = Array(data) }
        deinit { for i in bytes.indices { bytes[i] = 0 } }
    }

    @State private var secret: SecretBytes?
    @State private var fid: String = ""
    @State private var loadError: String?

    @State private var format: Format = .wif
    @State private var revealed = false

    @State private var vaultPassword = ""
    /// The cipher of the text the sheet is currently showing, and which format
    /// that was — switching WIF↔Hex re-seals rather than showing a cipher of
    /// something other than what is on screen.
    @State private var cipher: String?
    @State private var cipherFormat: Format?
    @State private var sealing = false

    /// Which of the two things the QR code is showing. The key itself is
    /// available as a code whether or not anything has been encrypted — the
    /// encrypted form is the one that is *safe to keep*, not the only one worth
    /// scanning, and the usual reason to want a code at all is to carry the key
    /// to a phone standing in front of you.
    private enum QrTarget { case plain, cipher }

    @State private var qrTarget: QrTarget?
    @State private var qrImages: [NSImage] = []
    @State private var qrPage = 0

    @State private var note: String?
    @State private var noteIsError = false

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header
            Divider()

            ScrollView {
                VStack(alignment: .leading, spacing: 18) {
                    if let loadError {
                        Label(loadError, systemImage: "exclamationmark.triangle")
                            .foregroundStyle(.red)
                            .font(.callout)
                    } else {
                        keySection
                        Divider()
                        encryptedSection
                        if !qrImages.isEmpty { qrSection }
                        warning
                    }
                }
                .padding(20)
            }

            if let note {
                Divider()
                HStack(spacing: 8) {
                    Image(systemName: noteIsError ? "exclamationmark.triangle" : "info.circle")
                    CopyableText(note, font: .caption)
                        .fixedSize(horizontal: false, vertical: true)
                    Spacer(minLength: 0)
                }
                .foregroundStyle(noteIsError ? .red : .secondary)
                .padding(.horizontal, 20)
                .padding(.vertical, 8)
            }

            Divider()
            footer
        }
        .frame(width: 560)
        .frame(maxHeight: 720)
        .onAppear(perform: load)
        .onDisappear { secret = nil }
        .onChange(of: format) { _, _ in
            // Whatever is on screen has to follow the format picker: a cipher
            // re-seals, a plain code redraws. Showing a WIF code under a Hex
            // label is how someone ends up scanning a backup of something they
            // didn't choose.
            if cipher != nil {
                Task { await seal() }
            } else {
                refreshQr()
            }
        }
    }

    // MARK: - header / footer

    private var header: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: "key.viewfinder")
                .font(.title2)
                .foregroundStyle(.orange)
            VStack(alignment: .leading, spacing: 3) {
                Text("Back up your prikey").font(.title3).bold()
                if !fid.isEmpty {
                    CopyableText.elidingMiddle(fid, font: .callout.monospaced())
                }
                Text("This key *is* the identity. Lose it and no one — not this app, not the chain — can give it back.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 0)
        }
        .padding(.horizontal, 20)
        .padding(.vertical, 14)
    }

    private var footer: some View {
        HStack {
            Button("Later", action: onLater)
                .help("Close without recording a backup — you'll be reminded again.")
            Spacer()
            Button("I have my copy") {
                onDone()
            }
            .keyboardShortcut(.defaultAction)
            .buttonStyle(.borderedProminent)
            .disabled(loadError != nil)
            .help("Stops the reminder. Say this only once the copy is somewhere you'll still have it if this Mac is gone.")
        }
        .padding(.horizontal, 20)
        .padding(.vertical, 12)
    }

    // MARK: - the key itself

    private var keySection: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Picker("", selection: $format) {
                    ForEach(Format.allCases) { f in Text(f.rawValue).tag(f) }
                }
                .pickerStyle(.segmented)
                .labelsHidden()
                .frame(width: 160)

                Spacer()

                Button {
                    revealed.toggle()
                } label: {
                    Label(
                        revealed ? "Hide" : "Reveal",
                        systemImage: revealed ? "eye.slash" : "eye"
                    )
                }
                .help(revealed ? "Hide the key again." : "Show the key — make sure nobody is looking over your shoulder or recording the screen.")

                Button {
                    qrTarget = qrTarget == .plain ? nil : .plain
                    refreshQr()
                } label: {
                    Label(
                        qrTarget == .plain ? "Hide QR" : "QR code",
                        systemImage: "qrcode"
                    )
                }
                .help("Show the key itself as a QR code, in the format above — unencrypted, so only where nothing else can see the screen.")
            }

            Group {
                if revealed {
                    CopyableText(
                        keyText,
                        font: .system(.body, design: .monospaced),
                        help: "Copy the prikey — it goes to the clipboard in the clear."
                    )
                } else {
                    // A fixed-width mask: repeating one star per character
                    // would publish which encoding this is before anything
                    // is revealed.
                    Text(String(repeating: "•", count: 24))
                        .font(.system(.body, design: .monospaced))
                        .foregroundStyle(.secondary)
                }
            }
            .textSelection(.enabled)
            .padding(10)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Color(NSColor.textBackgroundColor))
            .clipShape(RoundedRectangle(cornerRadius: 8))

            Text(format == .wif
                 ? "Wallet Import Format — the form most wallets take. Base58Check, so a single mistyped character is caught rather than opening the wrong wallet."
                 : "Raw 32 bytes as 64 hex characters.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    // MARK: - encrypted backup

    private var encryptedSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Encrypted backup").font(.headline)
            Text("Sealed with this vault's password, so Freer on another machine, Freer on Android and Safe all open it with the password you already know. It must be the vault's password: a typo would make a backup nobody can open.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            HStack(spacing: 8) {
                SecureField("Vault password", text: $vaultPassword)
                    .onSubmit { Task { await seal() } }
                Button {
                    Task { await seal() }
                } label: {
                    if sealing {
                        HStack(spacing: 6) {
                            ProgressView().controlSize(.small)
                            Text("Sealing…")
                        }
                        .frame(width: 110)
                    } else {
                        Text(cipher == nil ? "Encrypt" : "Re-encrypt").frame(width: 110)
                    }
                }
                .disabled(sealing || vaultPassword.isEmpty || secret == nil)
            }

            if let cipher {
                CopyableText(
                    display: cipher.elidingMiddle(head: 28, tail: 20),
                    copy: cipher,
                    font: .caption.monospaced(),
                    help: "Copy the whole encrypted backup."
                )
                .padding(8)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(Color(NSColor.textBackgroundColor))
                .clipShape(RoundedRectangle(cornerRadius: 6))

                HStack(spacing: 10) {
                    // The cipher line above copies on click like every other
                    // value in the app, but this is the one people come here
                    // to take away — Android gives it its own button, and a
                    // backup nobody noticed they could copy is no backup.
                    Button {
                        copyCipher(cipher)
                    } label: {
                        Label("Copy cipher", systemImage: "doc.on.doc")
                    }
                    .help("Put the whole encrypted backup on the clipboard.")
                    Button("Save cipher…") { saveCipher(cipher) }
                        .help("Write the encrypted backup to a text file. Safe to keep in cloud storage — the password is not in it.")
                    Button(qrTarget == .cipher ? "Hide QR" : "QR code") {
                        qrTarget = qrTarget == .cipher ? nil : .cipher
                        refreshQr()
                    }
                    if qrTarget == .cipher, !qrImages.isEmpty {
                        Button("Save QR…") { saveQr() }
                    }
                    Spacer()
                }
            }
        }
    }

    // MARK: - QR

    private var qrSection: some View {
        VStack(spacing: 6) {
            HStack(spacing: 12) {
                if qrImages.count > 1 {
                    Button { qrPage = max(0, qrPage - 1) } label: { Image(systemName: "chevron.left") }
                        .disabled(qrPage == 0)
                }
                Image(nsImage: qrImages[min(qrPage, qrImages.count - 1)])
                    .interpolation(.none)
                    .resizable()
                    .frame(width: 220, height: 220)
                    .padding(8)
                    .background(Color.white)
                    .clipShape(RoundedRectangle(cornerRadius: 8))
                if qrImages.count > 1 {
                    Button { qrPage = min(qrImages.count - 1, qrPage + 1) } label: { Image(systemName: "chevron.right") }
                        .disabled(qrPage >= qrImages.count - 1)
                }
            }
            if qrImages.count > 1 {
                Text("\(qrPage + 1)/\(qrImages.count) — scan every page; the pieces merge back together.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            if qrTarget == .plain {
                Label(
                    "The key itself, in the clear: anything that can see this screen can take the wallet. Use it only to move the key to a device in your own hands.",
                    systemImage: "exclamationmark.triangle.fill"
                )
                .font(.caption)
                .foregroundStyle(.red)
                .fixedSize(horizontal: false, vertical: true)
            } else {
                Text("The encrypted backup — scannable by Freer on another machine, or on Android.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
        .frame(maxWidth: .infinity)
    }

    private var warning: some View {
        VStack(alignment: .leading, spacing: 6) {
            Label("Nobody can recover this for you", systemImage: "lifepreserver")
                .font(.callout.bold())
            Text("Keep the copy somewhere that survives this Mac — paper in a drawer, or the encrypted file on a drive that isn't this one. Anyone who reads an unencrypted copy owns the identity: they can spend its coins and sign as you.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.orange.opacity(0.10))
        .clipShape(RoundedRectangle(cornerRadius: 8))
    }

    // MARK: - data

    /// The identity being backed up: whoever the user is living as when that
    /// identity can sign, otherwise the main FID. Living as a watch-only
    /// sub-identity is no reason to show them nothing — the key the vault is
    /// built on is the one worth saving.
    private func load() {
        do {
            if session.liveKeyInfo.hasPrivkey {
                fid = session.liveFid
                secret = SecretBytes(try session.livePrikey())
            } else {
                fid = session.mainFid
                secret = SecretBytes(try session.mainPrikey())
            }
        } catch {
            loadError = "Couldn't read the prikey: \(String(describing: error))"
        }
    }

    private var privkey: Data? { secret.map { Data($0.bytes) } }

    private var keyText: String {
        guard let privkey else { return "" }
        switch format {
        case .wif: return WifPrivkey.encode(privkey: privkey)
        case .hex: return privkey.map { String(format: "%02x", $0) }.joined()
        }
    }

    /// What gets encrypted: the raw bytes for Hex, the WIF characters for WIF —
    /// matching Android, so a backup made in either app opens in both. The
    /// import side (``KeyInput/prikey(fromPlaintext:)``) accepts both shapes.
    private var plaintextForSeal: Data? {
        guard let privkey else { return nil }
        switch format {
        case .hex: return privkey
        case .wif: return Data(WifPrivkey.encode(privkey: privkey).utf8)
        }
    }

    @MainActor
    private func seal() async {
        guard !sealing, !vaultPassword.isEmpty, let plaintext = plaintextForSeal else { return }
        sealing = true
        defer { sealing = false }
        note = nil

        let password = Data(vaultPassword.utf8)
        let configureSession = session.configureSession
        let format = self.format

        let result: Result<String, Error> = await Task.detached(priority: .userInitiated) {
            // Both steps are Argon2id (64 MiB); neither belongs on the main actor.
            guard configureSession.verifyPassword(password) else {
                return .failure(SealFailure.wrongPassword)
            }
            do {
                return .success(try TextCipher.encryptWithPassword(plaintext, password: password))
            } catch {
                return .failure(error)
            }
        }.value

        switch result {
        case .success(let sealed):
            cipher = sealed
            cipherFormat = format
            noteIsError = false
            note = "Encrypted. The cipher below is safe to keep anywhere — it opens only with this vault's password."
            // A code that was showing the bare key gives way to the sealed one:
            // the safe form is what should be on screen once there is one.
            qrTarget = .cipher
            refreshQr()
        case .failure(let error):
            cipher = nil
            cipherFormat = nil
            if qrTarget == .cipher { qrTarget = nil }
            qrImages = []
            noteIsError = true
            note = (error as? SealFailure)?.description
                ?? "Couldn't encrypt: \(String(describing: error))"
        }
    }

    private enum SealFailure: Error, CustomStringConvertible {
        case wrongPassword
        var description: String {
            "That isn't this vault's password. The backup has to open with the password you unlock with, so it is checked before sealing."
        }
    }

    private func refreshQr() {
        qrPage = 0
        let content: String?
        switch qrTarget {
        case .plain:
            content = keyText
        case .cipher:
            content = (cipherFormat == format) ? cipher : nil
        case nil:
            content = nil
        }
        guard let content, !content.isEmpty else {
            qrImages = []
            return
        }
        do {
            qrImages = try QrCoder.makeImages(for: content)
        } catch {
            qrImages = []
            noteIsError = true
            note = "Couldn't draw the QR code: \(String(describing: error))"
        }
    }

    // MARK: - saving

    private func copyCipher(_ cipher: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(cipher, forType: .string)
        noteIsError = false
        note = "Cipher copied. Paste it somewhere it will still be there when this Mac isn't — it opens only with this vault's password."
    }

    private func saveCipher(_ cipher: String) {
        let panel = NSSavePanel()
        panel.allowedContentTypes = [.plainText]
        panel.nameFieldStringValue = "\(fid.prefix(8))-prikey-backup.txt"
        panel.message = "The encrypted backup. It opens only with this vault's password."
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            try Data(cipher.utf8).write(to: url, options: [.atomic])
            noteIsError = false
            note = "Saved \(url.lastPathComponent). Put it somewhere that isn't this Mac."
        } catch {
            noteIsError = true
            note = "Save failed: \(error.localizedDescription)"
        }
    }

    private func saveQr() {
        guard !qrImages.isEmpty else { return }
        let panel = NSSavePanel()
        panel.allowedContentTypes = [.png]
        panel.nameFieldStringValue = "\(fid.prefix(8))-prikey-backup.png"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            let page = min(qrPage, qrImages.count - 1)
            guard let png = QrCoder.pngData(qrImages[page]) else {
                throw CocoaError(.fileWriteUnknown)
            }
            try png.write(to: url, options: [.atomic])
            noteIsError = false
            note = "Saved \(url.lastPathComponent)."
        } catch {
            noteIsError = true
            note = "Save failed: \(error.localizedDescription)"
        }
    }
}
