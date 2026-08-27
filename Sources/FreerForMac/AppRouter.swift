import SwiftUI

/// Switches the visible screen based on ``AppState/route``. Sole top-
/// level child of the SwiftUI scene; everything else is reachable
/// from here.
struct AppRouter: View {
    @Environment(AppState.self) private var appState

    var body: some View {
        Group {
            switch appState.route {
            case .password:     PasswordView()
            case .chooseMain:   ChooseMainView()
            case .addMain:      AddMainView()
            case .home:         HomeView()
            }
        }
        .animation(.snappy, value: appState.route)
        // Hosted at the root, not per pane: a transaction can be
        // raised from inside a sheet, or by a background carve with no
        // pane on screen at all. See ``TxApprovalHost`` for why it is
        // a panel rather than a sheet.
        .background(TxApprovalHost(
            center: appState.txApprovals,
            session: appState.activeSession
        ))
    }
}
