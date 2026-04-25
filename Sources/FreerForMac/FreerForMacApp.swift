import SwiftUI
import AppKit

@main
struct FreerForMacApp: App {

    /// SwiftPM-built executables ship without an Info.plist, so the
    /// process defaults to a `.prohibited` activation policy — the
    /// window draws but never becomes the focused application, and
    /// keyboard input goes nowhere. The delegate forces `.regular`
    /// + an explicit activate at launch so SecureField/TextField get
    /// first responder normally.
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate

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

final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.regular)
        NSApp.activate(ignoringOtherApps: true)
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        true
    }
}
