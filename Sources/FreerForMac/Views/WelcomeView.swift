import SwiftUI

/// First-launch screen. Shown when ``IdentityVault`` is empty so the
/// user has no identities to log into yet.
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
                Text("A passphrase becomes your wallet, your messaging key, and your identity on FCH.")
                    .font(.title3)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .frame(maxWidth: 460)
            }

            Button {
                appState.goToCreateIdentity()
            } label: {
                Label("Create your first identity", systemImage: "plus.circle.fill")
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
