import SwiftUI

/// Switches the visible screen based on ``AppState/route``. Sole top-
/// level child of the SwiftUI scene; everything else is reachable from
/// here.
struct AppRouter: View {
    @Environment(AppState.self) private var appState

    var body: some View {
        Group {
            switch appState.route {
            case .welcome:
                WelcomeView()
            case .chooseIdentity:
                ChooseIdentityView()
            case .createIdentity:
                CreateIdentityView()
            case .unlock(let record):
                UnlockView(record: record)
            case .home:
                HomeView()
            }
        }
        .animation(.snappy, value: appState.route)
    }
}
