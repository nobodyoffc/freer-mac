import SwiftUI
import AppKit
import UniformTypeIdentifiers
import FCCore
import FCDomain
import FCUI

/// The Android app-signing key derived from the main FID: its
/// certificate digest, and a PKCS#12 keystore to hand Gradle or
/// `apksigner`. See ``ApkSigningKey`` for why it is derived and why the
/// certificate is byte-identical every time.
///
/// Carries the same three surprising facts as the SSH pubkey sheet —
/// derived, cannot spend, tied to the main FID — plus the one that is
/// specific to Android: an app already signed with another key needs a
/// rotation before it can switch.
struct ApkKeyToolView: View {
    let session: ActiveSession

    @State private var key: ApkSigningKey?
    @State private var error: String?
    @State private var password = ""
    @State private var confirm = ""
    @State private var savedPath: String?
    @State private var note: String?
    @State private var noteIsError = false

    private var passwordProblem: String? {
        if password.isEmpty { return nil }
        if !ApkSigningKey.isKeystorePassword(password) {
            return "Use plain ASCII — Java refuses to open a keystore whose password has any other character."
        }
        if !confirm.isEmpty, confirm != password { return "The two passwords differ." }
        return nil
    }

    private var canSave: Bool {
        !password.isEmpty && password == confirm && passwordProblem == nil
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Android signing key").font(.headline)

            if let error {
                CopyableLabel(error, systemImage: "exclamationmark.triangle")
                    .foregroundStyle(.orange)
                    .font(.callout)
            } else if let key {
                LabeledField(
                    "Certificate SHA-256",
                    hint: "What apksigner verify --print-certs, keytool and the Play Console show for this signer."
                ) {
                    CopyableText(key.fingerprint, font: .system(.caption, design: .monospaced))
                }
                LabeledField("Owner") {
                    CopyableText("CN=\(key.mainFid), O=\(ApkSigningKey.organizationName)",
                                 font: .system(.body, design: .monospaced))
                }

                Divider()
                exportSection(key)
                if let savedPath { gradleSection(savedPath) }

                explanation
            } else {
                ProgressView()
            }
        }
        .onAppear(perform: load)
    }

    // MARK: - Export

    private func exportSection(_ key: ApkSigningKey) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            LabeledField(
                "Keystore password",
                hint: passwordProblem ?? "Protects the exported file only. The key itself needs no backup — it comes back from this vault.",
                hintIsError: passwordProblem != nil
            ) {
                SecureField("Password", text: $password).fieldInputStyle()
                SecureField("Confirm", text: $confirm).fieldInputStyle()
            }

            HStack {
                Button("Save keystore…") { saveKeystore(key) }
                    .disabled(!canSave)
                Button("Save certificate…") { saveCertificate(key) }
                    .help("The public certificate as PEM — for app stores that ask for the signer up front.")
            }

            if let note {
                CopyableText(note, font: .caption, color: noteIsError ? .red : .secondary)
            }
        }
    }

    private func gradleSection(_ path: String) -> some View {
        let lines = """
        FREER_RELEASE_STORE_FILE=\(path)
        FREER_RELEASE_KEY_ALIAS=\(ApkSigningKey.defaultAlias)
        FREER_RELEASE_STORE_PASSWORD=<keystore password>
        FREER_RELEASE_KEY_PASSWORD=<keystore password>
        """
        return LabeledField(
            "~/.gradle/gradle.properties",
            hint: "Click to copy. One PKCS#12 password covers both the store and the key."
        ) {
            CopyableText(lines, font: .system(.caption, design: .monospaced))
        }
    }

    private func saveKeystore(_ key: ApkSigningKey) {
        let panel = NSSavePanel()
        panel.allowedContentTypes = [UTType(filenameExtension: "p12") ?? .data]
        panel.nameFieldStringValue = "freer-apk-signing.p12"
        panel.message = "Holds the signing prikey, encrypted with the password you chose."
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            let data = try key.keystore(password: password)
            try data.write(to: url, options: [.atomic])
            try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
            savedPath = url.path
            noteIsError = false
            note = "Saved \(url.lastPathComponent)."
            password = ""; confirm = ""
        } catch {
            noteIsError = true
            note = "Save failed: \(errorText(error))"
        }
    }

    private func saveCertificate(_ key: ApkSigningKey) {
        let panel = NSSavePanel()
        panel.allowedContentTypes = [UTType(filenameExtension: "pem") ?? .plainText]
        panel.nameFieldStringValue = "freer-apk-signing.pem"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            try Data(key.certificatePem.utf8).write(to: url, options: [.atomic])
            noteIsError = false
            note = "Saved \(url.lastPathComponent)."
        } catch {
            noteIsError = true
            note = "Save failed: \(errorText(error))"
        }
    }

    // MARK: - Notes

    private var explanation: some View {
        VStack(alignment: .leading, spacing: 10) {
            Divider()
            note(
                "checkmark.shield",
                "This key cannot spend.",
                "It is a separate P-256 key on a different curve, derived one way from your main prikey. Nothing it signs reveals anything about the key that holds your coins."
            )
            note(
                "arrow.triangle.2.circlepath",
                "Nothing to back up.",
                "The key and its certificate are re-derived byte for byte, so restoring the same main FID on another Mac gives the same signer. A lost keystore file is just exported again."
            )
            note(
                "exclamationmark.triangle",
                "It is tied to this main FID.",
                "Android pins an app to its signing certificate. Change or re-mint the main identity and apps signed here can no longer be updated by the new key."
            )
            note(
                "arrow.right.arrow.left",
                "An app already signed with another key needs a rotation first.",
                "Users of an app signed with an older keystore cannot update to a build signed with this one unless the build carries a v3 rotation proof: apksigner rotate --old-signer --ks <old> --new-signer --ks <this .p12>."
            )
        }
    }

    private func note(_ symbol: String, _ title: String, _ body: String) -> some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: symbol)
                .foregroundStyle(.secondary)
                .frame(width: 18)
            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(.callout.weight(.semibold))
                Text(body).font(.caption).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    private func load() {
        guard key == nil else { return }
        do {
            key = try session.apkSigningKey()
        } catch {
            self.error = "Could not derive the signing key — \(errorText(error))"
        }
    }
}
