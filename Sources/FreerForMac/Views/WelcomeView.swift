import SwiftUI

/// Shown only when no Configures exist on this Mac. Pushes the user
/// straight into ``PasswordView`` to set their first password (which
/// becomes the unlock secret for the first Configure).
struct WelcomeView: View {
    @Environment(AppState.self) private var appState

    var body: some View {
        VStack(spacing: 24) {
            Spacer()

            Image(systemName: "key.horizontal")
                .font(.system(size: 64))
                .foregroundStyle(.secondary)

            VStack(spacing: 8) {
                Text("Welcome to Freer")
                    .font(.largeTitle).bold()
                Text("Set a password to start a new vault. The vault holds your FCH identity keys, encrypted at rest. Lose the password and the vault is unrecoverable — write it down.")
                    .font(.title3)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .frame(maxWidth: 460)
            }

            Button {
                appState.route = .password
            } label: {
                Label("Set up your first password", systemImage: "lock.shield")
                    .frame(minWidth: 240)
            }
            .controlSize(.large)
            .buttonStyle(.borderedProminent)
            .keyboardShortcut(.defaultAction)

            if let err = appState.lastError {
                Text(err)
                    .font(.callout)
                    .foregroundStyle(.red)
                    .multilineTextAlignment(.center)
                    .frame(maxWidth: 460)
            }

            Spacer()
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .padding(40)
    }
}
