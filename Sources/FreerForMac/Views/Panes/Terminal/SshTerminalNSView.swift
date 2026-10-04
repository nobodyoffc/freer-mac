import SwiftUI
import AppKit
import SwiftTerm

/// Hosts the `LocalProcessTerminalView` a ``TerminalSessionModel``
/// already built.
///
/// Deliberately has no state and does no work: everything about the
/// session's lifetime belongs to the model, because a representable
/// struct is not a stable place to hang a child process.
struct SshTerminalNSView: NSViewRepresentable {

    let model: TerminalSessionModel

    func makeNSView(context: Context) -> FocusingTerminalView {
        model.view
    }

    func updateNSView(_ nsView: FocusingTerminalView, context: Context) {}
}

/// A terminal that takes the keyboard as soon as it is put on screen.
///
/// SwiftUI will not hand first responder to an embedded AppKit view,
/// so a freshly connected session would swallow every keystroke until
/// the user clicked it. Claiming focus from `updateNSView` does not
/// work: SwiftUI calls it before the view is in a window, finds no
/// window, and never calls it again. `viewDidMoveToWindow` is the
/// moment the view can actually become first responder — on connect,
/// on switching session tabs, and on coming back to the server.
///
/// It also keeps the scrollback reachable from the keyboard. SwiftTerm
/// scrolls on PageUp only while the remote has application-cursor mode
/// off, and most shells switch it on at the prompt (zsh on Debian and
/// Ubuntu, oh-my-zsh), so there PageUp went to the server and the
/// history above the screen could only be reached with the wheel.
/// Following Terminal.app, these always move the local view while the
/// normal screen is up:
///
/// - PageUp / PageDown — a page (Shift sends them to the server)
/// - ⌘↑ / ⌘↓ — a line
/// - ⌘Home / ⌘End — the top / the bottom
///
/// On the alternate screen (vim, less, tmux) there is no local
/// scrollback, so every key goes to the program as before.
final class FocusingTerminalView: LocalProcessTerminalView {

    private var keyMonitor: Any?

    deinit {
        if let keyMonitor { NSEvent.removeMonitor(keyMonitor) }
    }

    override func viewDidMoveToWindow() {
        super.viewDidMoveToWindow()
        // `keyDown` is `public`, not `open`, in SwiftTerm, so the keys
        // are caught on their way in instead. Installed only while the
        // view is on screen, and each event is checked against first
        // responder, so other sessions and other fields are untouched.
        if window == nil {
            if let keyMonitor { NSEvent.removeMonitor(keyMonitor) }
            keyMonitor = nil
            return
        }
        if keyMonitor == nil {
            keyMonitor = NSEvent.addLocalMonitorForEvents(matching: .keyDown) { [weak self] event in
                guard let self, event.window === self.window,
                      self.window?.firstResponder === self,
                      self.scrollback(for: event) else { return event }
                return nil
            }
        }
        // Deferred so it lands after SwiftUI finishes the update that
        // inserted us, which would otherwise leave focus on the button
        // or list row that triggered the connect.
        DispatchQueue.main.async { [weak self] in
            guard let self, let window = self.window,
                  window.firstResponder !== self else { return }
            window.makeFirstResponder(self)
        }
    }

    /// Moves the local view for a scrollback key.
    ///
    /// - Returns: true when the key was used here and must not reach
    ///   the server.
    private func scrollback(for event: NSEvent) -> Bool {
        // False on the alternate screen, and when nothing has scrolled
        // off yet — either way the key is the program's.
        guard canScroll,
              let key = event.charactersIgnoringModifiers?.unicodeScalars.first?.value
        else { return false }

        let flags = event.modifierFlags.intersection([.shift, .control, .option, .command])
        let rows = getTerminal().rows

        switch Int(key) {
        case NSPageUpFunctionKey where flags.isEmpty || flags == .command:
            scrollUp(lines: rows)
        case NSPageDownFunctionKey where flags.isEmpty || flags == .command:
            scrollDown(lines: rows)
        case NSUpArrowFunctionKey where flags == .command:
            scrollUp(lines: 1)
        case NSDownArrowFunctionKey where flags == .command:
            scrollDown(lines: 1)
        case NSHomeFunctionKey where flags == .command:
            scrollTo(row: 0)
        case NSEndFunctionKey where flags == .command:
            scrollDown(lines: Int.max / 2)
        default:
            return false
        }
        return true
    }
}
