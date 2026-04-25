import SwiftUI
import FCCore
import FCDomain

/// Single password field plus two explicit actions: **Check** opens
/// an existing vault, **Create new** mints a fresh one. The view
/// shows nothing about how many vaults already exist on this Mac —
/// observable state would leak whether the device has any vaults
/// without the password.
///
/// Errors are deliberately generic ("Couldn't open" / "Couldn't
/// create") so a wrong password vs. an unknown password are
/// indistinguishable to a shoulder-surfer.
struct PasswordView: View {
    @Environment(AppState.self) private var appState

    @State private var password: String = ""
    @State private var working: Working = .none

    enum Working: Equatable { case none, checking, creating }

    var body: some View {
        VStack(spacing: 24) {
            Spacer()

            Image(systemName: "lock.shield")
                .font(.system(size: 56))
                .foregroundStyle(.secondary)

            Text("Freer")
                .font(.largeTitle).bold()

            VStack(spacing: 12) {
                SecureField("Password", text: $password)
                    .textContentType(.password)
                    .textFieldStyle(.roundedBorder)
                    .frame(width: 360)
                    .onSubmit {
                        if working == .none && !password.isEmpty {
                            Task { await runCheck() }
                        }
                    }
                    .disabled(working != .none)

                if let err = appState.lastError {
                    Text(err)
                        .font(.callout)
                        .foregroundStyle(.red)
                        .multilineTextAlignment(.center)
                        .frame(maxWidth: 400)
                }

                HStack(spacing: 12) {
                    Button {
                        Task { await runCreate() }
                    } label: {
                        if working == .creating {
                            HStack(spacing: 6) {
                                ProgressView().controlSize(.small)
                                Text("Creating…")
                            }
                            .frame(width: 150)
                        } else {
                            Text("Create new password").frame(width: 150)
                        }
                    }
                    .disabled(working != .none || password.isEmpty)

                    Button {
                        Task { await runCheck() }
                    } label: {
                        if working == .checking {
                            HStack(spacing: 6) {
                                ProgressView().controlSize(.small)
                                Text("Checking…")
                            }
                            .frame(width: 150)
                        } else {
                            Text("Check password").frame(width: 150)
                        }
                    }
                    .keyboardShortcut(.defaultAction)
                    .buttonStyle(.borderedProminent)
                    .disabled(working != .none || password.isEmpty)
                }
            }

            Spacer()
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .padding(40)
    }

    @MainActor
    private func runCheck() async {
        guard working == .none, !password.isEmpty else { return }
        working = .checking
        defer { working = .none }
        let pwd = Data(password.utf8)
        await appState.openOrCreate(
            password: pwd,
            createIfMissing: false
        )
        password = ""
    }

    @MainActor
    private func runCreate() async {
        guard working == .none, !password.isEmpty else { return }
        working = .creating
        defer { working = .none }
        let pwd = Data(password.utf8)
        await appState.openOrCreate(
            password: pwd,
            createIfMissing: true
        )
        password = ""
    }
}
