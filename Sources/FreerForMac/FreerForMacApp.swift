import SwiftUI

@main
struct FreerForMacApp: App {

    @State private var appState = AppState()

    var body: some Scene {
        WindowGroup("Freer") {
            AppRouter()
                .environment(appState)
                .frame(minWidth: 720, minHeight: 480)
        }
        .windowResizability(.contentSize)
        .commands {
            CommandGroup(replacing: .appInfo) {
                Button("About Freer") {
                    NSApp.orderFrontStandardAboutPanel(nil)
                }
            }
            CommandGroup(after: .appInfo) {
                Divider()
                Button("Lock vault") {
                    appState.lockAll()
                }
                .keyboardShortcut("l", modifiers: [.command])
                .disabled(appState.configureSession == nil)
            }
        }
    }
}
