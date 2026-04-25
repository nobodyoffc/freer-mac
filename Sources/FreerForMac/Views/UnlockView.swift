import SwiftUI
import FCDomain

/// Passphrase entry for a chosen identity. KDF runs on a background
/// task so the form stays responsive.
struct UnlockView: View {
    @Environment(AppState.self) private var appState
    let record: IdentityRecord

    @State private var passphrase: String = ""
    @State private var working: Bool = false

    var body: some View {
        VStack(spacing: 20) {
            Spacer()

            VStack(spacing: 8) {
                Image(systemName: "lock.fill")
                    .font(.system(size: 48))
                    .foregroundStyle(.secondary)
                Text(record.displayName)
                    .font(.title).bold()
                Text(record.fid)
                    .font(.caption.monospaced())
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)
            }

            VStack(spacing: 12) {
                SecureField("Passphrase", text: $passphrase)
                    .textFieldStyle(.roundedBorder)
                    .frame(width: 320)
                    .onSubmit { Task { await submit() } }
                    .disabled(working)

                if let err = appState.lastError {
                    Text(err)
                        .font(.callout)
                        .foregroundStyle(.red)
                        .multilineTextAlignment(.center)
                        .frame(maxWidth: 360)
                }

                HStack {
                    Button("Back") {
                        appState.goToChooseIdentity()
                    }
                    .disabled(working)

                    Button {
                        Task { await submit() }
                    } label: {
                        if working {
                            HStack(spacing: 6) {
                                ProgressView().controlSize(.small)
                                Text("Unlocking…")
                            }
                            .frame(width: 120)
                        } else {
                            Text("Unlock").frame(width: 120)
                        }
                    }
                    .buttonStyle(.borderedProminent)
                    .keyboardShortcut(.defaultAction)
                    .disabled(working || passphrase.isEmpty)
                }
            }

            Spacer()
        }
        .frame(minWidth: 420, minHeight: 320)
        .padding(40)
    }

    @MainActor
    private func submit() async {
        guard !working, !passphrase.isEmpty else { return }
        working = true
        defer { working = false }
        await appState.login(fid: record.fid, passphrase: passphrase)
        passphrase = ""    // wipe regardless of success
    }
}
