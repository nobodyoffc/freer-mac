import SwiftUI
import AppKit
import SwiftTerm
import FCDomain

/// One live `ssh` session: the terminal view, the child process, and
/// whatever we can tell the user about how it ended.
///
/// **The model owns the `NSView`, not the `NSViewRepresentable`.**
/// SwiftUI creates and destroys representable structs freely, so a
/// `makeNSView` that built a view and spawned a process would fork a
/// second `ssh` on any unrelated parent re-render. The representable
/// here is a window onto a view this object already made.
@Observable
final class TerminalSessionModel {

    let server: SshServer

    /// The title the remote shell set, if it set one. Most login shells
    /// do, and it is more informative than the row label once you are
    /// three `ssh` hops deep.
    private(set) var remoteTitle: String?

    private(set) var isRunning = false

    /// Why the session is over. Nil while it is alive.
    private(set) var endedMessage: String?

    /// The exact command, shown in the scrollback before spawning so
    /// the user can see what was run on their behalf — an agent that
    /// signs invisibly is worth being loud about.
    private(set) var commandLine: String = ""

    /// Called when the child exits, however it exits — `exit` typed at
    /// the remote shell, a dropped connection, or our own ``stop()``.
    /// ``AppState`` uses it to put the ssh-agent away once no session
    /// needs it; without it a shell closed by the user would leave a
    /// signing oracle running.
    var onEnded: (() -> Void)?

    let view: LocalProcessTerminalView
    private var bridge: ProcessBridge?

    init(server: SshServer) {
        self.server = server
        self.view = LocalProcessTerminalView(
            frame: CGRect(x: 0, y: 0, width: 800, height: 480),
            font: NSFont.monospacedSystemFont(ofSize: 12, weight: .regular),
            options: TerminalOptions(termName: "xterm-256color", scrollback: 5000)
        )
        // Follows the system appearance — without this the view paints
        // its own black on white regardless of dark mode.
        view.configureNativeColors()
        // The default beeps through NSSound, so a remote `tab` on an
        // empty line makes the whole app go "bonk".
        view.bellStyle = .visual
        view.optionAsMetaKey = true
    }

    // MARK: - Lifecycle

    /// - Returns: an error string when the process could not be
    ///   started, nil on success.
    @discardableResult
    func start(credential: SshLaunch.Credential) -> String? {
        guard !isRunning else { return nil }

        // `startProcess` has no failure channel — if the fork or exec
        // fails it returns quietly and no delegate callback ever fires.
        // Checking first turns "nothing happened" into a message.
        guard SshLaunch.sshIsAvailable else {
            let message = "\(SshLaunch.executable) is missing or not executable."
            endedMessage = message
            return message
        }

        let args = SshLaunch.arguments(for: server, credential: credential)
        commandLine = (["ssh"] + args).joined(separator: " ")

        let bridge = ProcessBridge(owner: self)
        self.bridge = bridge
        view.processDelegate = bridge

        endedMessage = nil
        remoteTitle = nil

        view.feed(text: "\u{1b}[2m\(commandLine)\u{1b}[0m\r\n")

        // Set before spawning, not after. SwiftTerm arms the child's
        // exit source inside `startProcess`, and `activate()` invokes
        // the handler *synchronously* when the child has already
        // exited — so for an `ssh` that dies immediately (auth
        // refused, host unreachable) `processTerminated` lands before
        // this call returns. With the flag set after, that callback
        // would see `isRunning == false`, skip `onEnded`, and leave the
        // agent up with no session behind it.
        isRunning = true

        view.startProcess(
            executable: SshLaunch.executable,
            args: args,
            environment: SshLaunch.environment(credential: credential),
            execName: "ssh"    // so `ps` shows `ssh`, not the full path
        )

        // Two different failures, and calling them the same thing sends
        // you hunting in the wrong place:
        //
        //   - `isRunning` still true but the process is not: `forkpty`
        //     or the exec failed, and no delegate callback will ever
        //     fire. Nothing was run, so say so.
        //   - `isRunning` already false: the delegate ran while we were
        //     inside `startProcess`, meaning ssh *did* start and then
        //     exited. It has already written the real reason into the
        //     terminal and set `endedMessage`; overwriting that with
        //     "could not start" would bury the actual error.
        if !view.process.running {
            guard isRunning else { return nil }
            isRunning = false
            let message = "Could not start \(SshLaunch.executable)."
            endedMessage = message
            return message
        }

        return nil
    }

    func stop() {
        guard isRunning else { return }
        view.terminate()
        isRunning = false
        onEnded?()
    }

    // MARK: - Delegate callbacks

    fileprivate func handleTerminated(exitCode: Int32?) {
        let wasRunning = isRunning
        isRunning = false
        // A raw waitpid status, not an exit code — see SshLaunch.
        endedMessage = SshLaunch.exitDescription(rawStatus: exitCode)
        // `stop()` has already fired this; `terminate()` also lands
        // here through the delegate, and calling it twice would put the
        // agent away while another session still needs it.
        if wasRunning { onEnded?() }
    }

    fileprivate func handleTitle(_ title: String) {
        remoteTitle = title.isEmpty ? nil : title
    }
}

/// Holds SwiftTerm's `weak var processDelegate` for the model.
///
/// A separate object because the delegate reference is weak: if the
/// model were its own delegate nothing would keep the conformance
/// alive, and because `TerminalSessionModel` is `@Observable`, a
/// protocol conformance on it would drag observation machinery into
/// callbacks that fire from a dispatch queue.
///
/// Every callback here arrives on the main queue: `LocalProcess` takes
/// an optional queue and falls back to `DispatchQueue.main`, and this
/// code never passes one.
private final class ProcessBridge: LocalProcessTerminalViewDelegate {

    private weak var owner: TerminalSessionModel?

    init(owner: TerminalSessionModel) { self.owner = owner }

    func sizeChanged(source: LocalProcessTerminalView, newCols: Int, newRows: Int) {
        // SwiftTerm has already pushed the new winsize to the pty; the
        // remote side learns about it through SIGWINCH. Nothing to do.
    }

    func setTerminalTitle(source: LocalProcessTerminalView, title: String) {
        owner?.handleTitle(title)
    }

    func hostCurrentDirectoryUpdate(source: TerminalView, directory: String?) {
        // OSC 7. Only shells configured to emit it ever will, and the
        // pane has nowhere to show it.
    }

    func processTerminated(source: TerminalView, exitCode: Int32?) {
        owner?.handleTerminated(exitCode: exitCode)
    }
}
