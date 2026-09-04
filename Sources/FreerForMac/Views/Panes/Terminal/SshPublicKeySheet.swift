import SwiftUI
import FCCore
import FCDomain
import FCUI

/// The one thing the user has to do by hand: get this line onto the
/// server.
///
/// There is no "install for me" button in this cut, so this sheet is
/// the whole key-distribution story and has to carry the three facts
/// that are surprising about it — the key is derived, not stored; it
/// cannot spend; and it dies if the main FID changes.
struct SshPublicKeySheet: View {

    let session: ActiveSession
    let onClose: () -> Void

    @State private var key: SshEd25519Key?
    @State private var error: String?

    private var installCommand: String {
        guard let key else { return "" }
        return "mkdir -p ~/.ssh && chmod 700 ~/.ssh && echo '\(key.authorizedKeysLine())' >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys"
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header
            Divider()

            ScrollView {
                VStack(alignment: .leading, spacing: 20) {
                    if let error {
                        Label(error, systemImage: "exclamationmark.triangle")
                            .foregroundStyle(.orange)
                            .font(.callout)
                    } else if let key {
                        fingerprintSection(key)
                        lineSection(key)
                        installSection
                        explanation
                    } else {
                        ProgressView()
                    }
                }
                .padding(20)
                .frame(maxWidth: .infinity, alignment: .leading)
            }

            Divider()
            HStack {
                Spacer()
                Button("Done", action: onClose).keyboardShortcut(.defaultAction)
            }
            .padding(16)
        }
        .frame(width: 620, height: 560)
        .onAppear(perform: load)
    }

    private var header: some View {
        HStack {
            Label("SSH public key", systemImage: "key")
                .font(.title3.weight(.semibold))
            Spacer()
        }
        .padding(16)
    }

    private func fingerprintSection(_ key: SshEd25519Key) -> some View {
        LabeledField("Fingerprint") {
            CopyableText(key.fingerprint, font: .system(.body, design: .monospaced))
        }
    }

    private func lineSection(_ key: SshEd25519Key) -> some View {
        LabeledField(
            "authorized_keys line",
            hint: "Click to copy the whole line."
        ) {
            CopyableText(
                display: key.authorizedKeysLine().elidingMiddle(head: 28, tail: 24),
                copy: key.authorizedKeysLine(),
                font: .system(.body, design: .monospaced)
            )
        }
    }

    private var installSection: some View {
        LabeledField(
            "Install it",
            hint: "Log in with your password once, paste this, and the next connection needs no password."
        ) {
            CopyableText(
                display: "mkdir -p ~/.ssh && … >> ~/.ssh/authorized_keys",
                copy: installCommand,
                font: .system(.callout, design: .monospaced)
            )
        }
    }

    private var explanation: some View {
        VStack(alignment: .leading, spacing: 10) {
            Divider()
            note(
                "checkmark.shield",
                "This key cannot spend.",
                "It is a separate ed25519 key on a different curve, derived one way from your main key. Nothing it signs reveals anything about the key that holds your coins."
            )
            note(
                "arrow.triangle.2.circlepath",
                "Nothing to back up.",
                "The key is re-derived from this vault every time, so restoring the same main FID on another Mac gives you the same SSH key with nothing to export."
            )
            note(
                "exclamationmark.triangle",
                "It is tied to this main FID.",
                "Change or re-mint the main identity and this line stops working on every server you have installed it on — you would have to get in by password and paste the new one."
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
            }
        }
    }

    private func load() {
        do {
            key = try session.sshIdentity()
        } catch {
            self.error = "Could not derive the SSH key — \(error)"
        }
    }
}
