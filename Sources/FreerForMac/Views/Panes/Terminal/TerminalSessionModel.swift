import SwiftUI
import AppKit
import Foundation
import SwiftTerm
import FCDomain

/// One live session — a shell, `sftp`, an `scp` upload, a tunnel, or
/// a one-shot key install or removal: the terminal view, the child
/// process, and whatever we can tell the user about how it ended.
///
/// **The model owns the `NSView`, not the `NSViewRepresentable`.**
/// SwiftUI creates and destroys representable structs freely, so a
/// `makeNSView` that built a view and spawned a process would fork a
/// second `ssh` on any unrelated parent re-render. The representable
/// here is a window onto a view this object already made.
@Observable
final class TerminalSessionModel {

    /// This session, not this server. A server may have several open at
    /// once and they are told apart by nothing else — same host, same
    /// user, same name in the tab until the remote shell sets a title.
    let id: String = UUID().uuidString

    let server: SshServer

    /// What this session runs. Fixed at open: a finished upload is not
    /// reopened as a shell, it is closed and a shell opened beside it.
    let kind: SshLaunch.Kind

    /// Which session this is on its server — 1, 2, 3 — fixed when it
    /// opens and never touched again.
    ///
    /// **The tab's identity, because its label is not.** Most login
    /// shells set a title and on one box every one of them sets the
    /// *same* title, so three tabs all read `liu@build: ~` and say
    /// nothing about which is which. Numbering by position in the bar
    /// instead would renumber every tab to the right of one that
    /// closed, renaming a session while the user was looking at it.
    /// ``AppState`` hands the number out.
    let ordinal: Int

    /// When this session was opened. In the tab's tooltip, because with
    /// two shells on one box "the one I started before lunch" is often
    /// the only thing anybody remembers about which is which.
    let openedAt = Date()

    /// A name the user typed for this tab, which beats anything we
    /// could infer. Nil until they type one.
    var displayName: String?

    /// What the tab shows, in order of how much it actually says: the
    /// name the user gave it, then whatever part of the shell's title
    /// is not already in the header, then the time it opened.
    ///
    /// **Never the server's name or target**, however little else there
    /// is to say. That text is the pane's heading, fixed above every
    /// tab in the bar; a chip repeating it spends its whole width on
    /// the one thing all of them have in common. When the shell's title
    /// adds nothing the clock does: two sessions on one box always
    /// started at different times.
    ///
    /// None of this is enough on its own to tell two sessions apart —
    /// that is ``ordinal``'s job, and it is why the number is drawn
    /// beside this rather than instead of it.
    var tabTitle: String {
        if let displayName, !displayName.isEmpty { return displayName }
        // Only a login shell sets a title worth reading. `sftp`, `scp`
        // and `ssh -N` never set one, and what they are is the whole of
        // what there is to say about them.
        guard kind.isShell else { return kind.tabLabel }
        if let distinct = distinctRemoteTitle { return distinct }
        return openedAt.formatted(date: .omitted, time: .shortened)
    }

    /// The shell's title with the part the header already shows taken
    /// off the front.
    ///
    /// A login shell sets `user@host: dir` and the heading above the
    /// bar is already `user@host`, so the prefix is pure repetition —
    /// and worse than idle, because it pushes the directory, the one
    /// part that differs between tabs, out to where the truncation
    /// eats it. Nil when nothing is left, which is the honest answer
    /// for a title that was only ever the header again.
    private var distinctRemoteTitle: String? {
        guard var title = remoteTitle?.trimmingCharacters(in: .whitespaces),
              !title.isEmpty
        else { return nil }

        // The port is in `target` and never in a shell's title, hence
        // the bare `user@host` beside it; the host alone is for the
        // shells that set `host: dir`.
        let known = [server.target, "\(server.user)@\(server.host)", server.host]
        let lower = title.lowercased()
        let stripped = known.first { candidate in
            guard !candidate.isEmpty, lower.hasPrefix(candidate.lowercased()) else { return false }
            // A prefix must end where a word ends, or `build` eats the
            // front of `buildbot` and leaves a tab reading `bot: ~`.
            let next = lower.dropFirst(candidate.count).first
            return next == nil || next == ":" || next == " "
        }
        if let stripped {
            title = String(title.dropFirst(stripped.count))
        } else if let colon = title.firstIndex(of: ":"), title[..<colon].contains("@") {
            // The shell names the host its own way — a short name where
            // the entry holds an FQDN, or an alias from `~/.ssh/config`
            // resolved to something else — so none of the prefixes
            // above match. Anything before the first colon carrying an
            // `@` is that same redundancy under another spelling.
            title = String(title[title.index(after: colon)...])
        }

        title = title.trimmingCharacters(in: CharacterSet(charactersIn: ": \t-·"))
        return title.isEmpty ? nil : title
    }

    /// The title the remote shell set, if it set one. Most login shells
    /// do, and it is more informative than the row label once you are
    /// three `ssh` hops deep.
    private(set) var remoteTitle: String?

    /// The directory the remote shell last reported with OSC 7.
    ///
    /// Only shells set up to send it ever will — a zsh or fish config
    /// that turns it on, or a `PROMPT_COMMAND` that prints it — so this
    /// is a suggestion the upload sheet may offer and nothing more. It
    /// is whatever the remote side says: fine for a button the user
    /// has to press, not for anything automatic.
    private(set) var remoteDirectory: String?

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

    init(server: SshServer, kind: SshLaunch.Kind, ordinal: Int) {
        self.server = server
        self.kind = kind
        self.ordinal = ordinal
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

        let invocation: SshLaunch.Invocation
        do {
            invocation = try SshLaunch.invocation(kind, server: server, credential: credential)
        } catch {
            let message = "\(error)"
            endedMessage = message
            return message
        }

        // `startProcess` has no failure channel — if the fork or exec
        // fails it returns quietly and no delegate callback ever fires.
        // Checking first turns "nothing happened" into a message.
        guard SshLaunch.isAvailable(invocation.executable) else {
            let message = "\(invocation.executable) is missing or not executable."
            endedMessage = message
            return message
        }

        commandLine = invocation.commandLine

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
            executable: invocation.executable,
            args: invocation.arguments,
            environment: SshLaunch.environment(credential: credential),
            execName: invocation.execName,    // so `ps` shows `scp`, not the full path
            currentDirectory: invocation.currentDirectory
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
            let message = "Could not start \(invocation.executable)."
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
        endedMessage = SshLaunch.exitDescription(rawStatus: exitCode, kind: kind)
        // `stop()` has already fired this; `terminate()` also lands
        // here through the delegate, and calling it twice would put the
        // agent away while another session still needs it.
        if wasRunning { onEnded?() }
    }

    fileprivate func handleTitle(_ title: String) {
        remoteTitle = title.isEmpty ? nil : title
    }

    fileprivate func handleDirectory(_ report: String?) {
        remoteDirectory = report.flatMap(SshLaunch.reportedDirectory)
    }
}

extension SshLaunch.Kind {

    var isShell: Bool {
        if case .shell = self { return true }
        return false
    }

    /// What a tab says when the program behind it sets no title.
    var tabLabel: String {
        switch self {
        case .shell:
            return "Shell"
        case .installKey:
            return "Install key"
        case .removeKey:
            return "Remove key"
        case .sftp:
            return "SFTP"
        case let .upload(paths, _):
            return paths.count == 1
                ? "Upload \((paths[0] as NSString).lastPathComponent)"
                : "Upload \(paths.count) items"
        case let .tunnel(forwards):
            return "Tunnel " + forwards.map { ":\($0.localPort)" }.joined(separator: " ")
        }
    }

    /// Drawn in front of the tab's label. None for a shell, which is
    /// what a tab in a terminal is assumed to be.
    var symbol: String? {
        switch self {
        case .shell: return nil
        case .installKey: return "key"
        case .removeKey: return "key.slash"
        case .sftp: return "folder"
        case .upload: return "arrow.up.doc"
        case .tunnel: return "point.3.connected.trianglepath.dotted"
        }
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
        // OSC 7 — offered by the upload sheet as a destination.
        owner?.handleDirectory(directory)
    }

    func processTerminated(source: TerminalView, exitCode: Int32?) {
        owner?.handleTerminated(exitCode: exitCode)
    }
}
