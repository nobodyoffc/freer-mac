import SwiftUI
import FCCore
import FCDomain
import FCUI

/// Single password field plus two explicit actions: **Check** opens
/// an existing vault, **Create new password** goes to
/// ``CreatePasswordView``, where a new one is typed twice. The view
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

    enum Working: Equatable { case none, checking }

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
                    .fieldInputStyle()
                    .frame(width: 360)
                    .onSubmit {
                        if working == .none && !password.isEmpty {
                            Task { await runCheck() }
                        }
                    }
                    .disabled(working != .none)

                if let err = appState.lastError {
                    CopyableText(err)
                        .font(.callout)
                        .foregroundStyle(.red)
                        .multilineTextAlignment(.center)
                        .frame(maxWidth: 400)
                } else if let notice = appState.lockNotice {
                    // Not red: the app did what the setting told it to,
                    // and nothing has gone wrong.
                    Text(notice)
                        .font(.callout)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                        .frame(maxWidth: 400)
                }

                HStack(spacing: 12) {
                    // What is typed here is not carried over: a new
                    // password is typed fresh, twice, on its own screen.
                    Button {
                        password = ""
                        appState.showCreatePassword(true)
                    } label: {
                        Text("Create new password").frame(width: 150)
                    }
                    .disabled(working != .none)

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
        await appState.open(password: pwd)
        password = ""
    }
}
