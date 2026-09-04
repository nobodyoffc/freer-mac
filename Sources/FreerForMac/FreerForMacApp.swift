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
                .onAppear {
                    // ⌘Q does not run `deinit`, so without this the
                    // ssh-agent's socket and runtime directory would be
                    // left behind once per launch. `$TMPDIR` is reaped
                    // eventually and a listener-less socket is inert,
                    // but leaving litter named after a dead pid is the
                    // kind of thing that later looks like a bug.
                    appDelegate.onTerminate = { [weak appState] in
                        appState?.tearDownTerminalSessions()
                        appState?.tearDownSshAgent()
                    }
                }
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
                .help("Closes the vault, and with it any open terminal sessions and the SSH agent holding your key.")
            }
        }
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate {

    /// Set by the scene once ``AppState`` exists. Used to release
    /// process-lifetime resources that outlive SwiftUI teardown — at
    /// present the ssh-agent's socket and runtime directory.
    var onTerminate: (() -> Void)?

    func applicationWillTerminate(_ notification: Notification) {
        onTerminate?()
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.regular)
        NSApp.activate(ignoringOtherApps: true)
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        true
    }
}
