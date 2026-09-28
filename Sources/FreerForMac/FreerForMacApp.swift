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
        WindowGroup("Freer", id: FreerForMacApp.mainWindow) {
            AppRouter()
                .environment(appState)
                .frame(minWidth: 720, minHeight: 480)
                .onAppear { [appState] in
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
        // Available for calls: Freer stays in the menu bar with its window closed (§11.2).
        MenuBarExtra(isInserted: Bindable(appState).availableForCalls) {
            MenuBarMenu(appState: appState)
        } label: {
            RingWatcher(appState: appState)
        }
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
                Button("Call Settings…") {
                    appState.showCallSettings = true
                }
                .disabled(appState.activeSession == nil)
            }
        }
    }
}

extension FreerForMacApp {
    static let mainWindow = "main"

    /// Bring the Freer window forward, if one is open or minimised. False if none is.
    @discardableResult
    static func showMainWindow() -> Bool {
        NSApp.activate(ignoringOtherApps: true)
        // A closed window may linger in the list with its content gone: only a shown or minimised one counts.
        guard let w = NSApp.windows.first(where: { $0.canBecomeMain && ($0.isVisible || $0.isMiniaturized) }) else {
            return false
        }
        if w.isMiniaturized { w.deminiaturize(nil) }
        w.makeKeyAndOrderFront(nil)
        return true
    }

    /// Bring the window forward, or open a new one when none is left.
    @MainActor
    static func showOrOpenMainWindow(_ openWindow: OpenWindowAction) {
        guard !showMainWindow() else { return }
        openWindow(id: mainWindow)
        NSApp.activate(ignoringOtherApps: true)
    }
}

/// The menu-bar icon's menu.
private struct MenuBarMenu: View {
    let appState: AppState
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        Button("Open Freer") { FreerForMacApp.showOrOpenMainWindow(openWindow) }
        Toggle("Available for calls", isOn: Bindable(appState).availableForCalls)
        Divider()
        Button("Quit Freer") { NSApp.terminate(nil) }
    }
}

/// The menu-bar icon, and the watch that reopens the window when something
/// rings with it closed: the icon is always on screen, so it can.
private struct RingWatcher: View {
    let appState: AppState
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        Image(systemName: "phone")
            .onChange(of: appState.somethingRinging) { _, ringing in
                if ringing { FreerForMacApp.showOrOpenMainWindow(openWindow) }
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

    /// With Available for calls on, closing the window leaves Freer in the menu bar, ringable (§11.2).
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        !UserDefaults.standard.bool(forKey: "availableForCalls")
    }
}
