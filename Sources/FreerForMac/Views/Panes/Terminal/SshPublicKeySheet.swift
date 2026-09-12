import SwiftUI
import FCCore
import FCDomain
import FCUI

/// The key itself, and how to get its line onto a server by hand.
///
/// Install Freer key, in each server's menu, does the installing over
/// one login. This sheet is for everything that button cannot reach —
/// a box behind a console, a colleague's `authorized_keys` — and it
/// carries the three facts that are surprising about the key: it is
/// derived, not stored; it cannot spend; and it dies if the main FID
/// changes.
struct SshPublicKeySheet: View {

    let session: ActiveSession
    let onClose: () -> Void

    @State private var key: SshEd25519Key?
    @State private var error: String?

    private var installCommand: String {
        guard let key else { return "" }
        return "mkdir -p ~/.ssh && chmod 700 ~/.ssh && echo '\(key.authorizedKeysLine())' >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys"
    }

    /// The menu item's own script, so the by-hand removal is the tested
    /// one — a naive `grep -v > file` truncates before it reads.
    private var removeCommand: String {
        guard let key else { return "" }
        return (try? SshLaunch.removeKeyCommand(authorizedKeysLine: key.authorizedKeysLine())) ?? ""
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
                        removeSection
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
            hint: "Install Freer key in a server's menu does this for you. By hand: log in with your password once, paste this, and the next connection needs no password."
        ) {
            CopyableText(
                display: "mkdir -p ~/.ssh && … >> ~/.ssh/authorized_keys",
                copy: installCommand,
                font: .system(.callout, design: .monospaced)
            )
        }
    }

    private var removeSection: some View {
        LabeledField(
            "Remove it",
            hint: "Remove Freer key from server, in the same menu, does this for you. By hand: paste this on the server. It deletes every line holding this key and leaves the others."
        ) {
            CopyableText(
                display: "sh -c '… grep -vF … ~/.ssh/authorized_keys …'",
                copy: removeCommand,
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
                "Change or re-mint the main identity and this line stops working on every server you have installed it on — you would have to get in by password and paste the new one. Take it off those servers first: afterwards Freer can no longer derive it to remove it."
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
