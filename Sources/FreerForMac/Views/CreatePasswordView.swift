import SwiftUI
import FCCore
import FCDomain
import FCUI

/// A new vault's password, typed twice, as on Freer for Android's
/// Create password screen.
///
/// The password is the only key to the vault: nothing stores it,
/// nothing can show it again, and a typo made once would lock the
/// vault behind a password nobody knows. So it is typed twice and the
/// two must match before anything is created.
struct CreatePasswordView: View {
    @Environment(AppState.self) private var appState

    /// Android's floor, so a vault made here opens with a password
    /// either app would have accepted.
    static let minimumLength = 4

    @State private var password: String = ""
    @State private var confirmation: String = ""
    @State private var problem: String?
    @State private var creating = false
    @FocusState private var focus: Field?

    enum Field { case password, confirmation }

    var body: some View {
        VStack(spacing: 24) {
            Spacer()

            Image(systemName: "lock.shield")
                .font(.system(size: 56))
                .foregroundStyle(.secondary)

            Text("Create new password")
                .font(.largeTitle).bold()

            VStack(spacing: 12) {
                Text("This password is the only key to the new vault. It can't be recovered or shown again, so type it twice.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .frame(maxWidth: 400)

                SecureField("Password", text: $password)
                    .textContentType(.newPassword)
                    .fieldInputStyle()
                    .frame(width: 360)
                    .focused($focus, equals: .password)
                    .onSubmit { focus = .confirmation }

                SecureField("Confirm password", text: $confirmation)
                    .textContentType(.newPassword)
                    .fieldInputStyle()
                    .frame(width: 360)
                    .focused($focus, equals: .confirmation)
                    .onSubmit { Task { await runCreate() } }

                if let message = problem ?? appState.lastError {
                    CopyableText(message)
                        .font(.callout)
                        .foregroundStyle(.red)
                        .multilineTextAlignment(.center)
                        .frame(maxWidth: 400)
                }

                HStack(spacing: 12) {
                    Button {
                        appState.showCreatePassword(false)
                    } label: {
                        Text("Cancel").frame(width: 90)
                    }
                    .keyboardShortcut(.cancelAction)

                    Button {
                        clear()
                    } label: {
                        Text("Clear").frame(width: 90)
                    }

                    Button {
                        Task { await runCreate() }
                    } label: {
                        if creating {
                            HStack(spacing: 6) {
                                ProgressView().controlSize(.small)
                                Text("Creating…")
                            }
                            .frame(width: 110)
                        } else {
                            Text("Create").frame(width: 110)
                        }
                    }
                    .keyboardShortcut(.defaultAction)
                    .buttonStyle(.borderedProminent)
                    .disabled(!canCreate)
                }
                .disabled(creating)
            }
            .disabled(creating)

            Spacer()
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .padding(40)
        .onAppear { focus = .password }
        .onChange(of: password) { problem = nil }
        .onChange(of: confirmation) { problem = nil }
    }

    private var canCreate: Bool {
        !creating && !password.isEmpty && !confirmation.isEmpty
    }

    private func clear() {
        password = ""
        confirmation = ""
        problem = nil
        appState.lastError = nil
        focus = .password
    }

    @MainActor
    private func runCreate() async {
        guard canCreate else { return }
        appState.lastError = nil
        guard password.count >= Self.minimumLength else {
            problem = String(localized: "Use at least \(String(Self.minimumLength)) characters.")
            return
        }
        guard password == confirmation else {
            problem = String(localized: "The two passwords differ.")
            focus = .confirmation
            return
        }
        creating = true
        defer { creating = false }
        await appState.create(password: Data(password.utf8))
        if appState.route != .createPassword {
            password = ""
            confirmation = ""
        }
    }
}
