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

    func makeNSView(context: Context) -> LocalProcessTerminalView {
        model.view
    }

    func updateNSView(_ nsView: LocalProcessTerminalView, context: Context) {
        // SwiftUI will not hand first responder to an embedded AppKit
        // view, so a freshly opened session would swallow every
        // keystroke until the user clicked it. Claim focus once the
        // view is actually in a window.
        guard let window = nsView.window else { return }
        if window.firstResponder !== nsView && !context.coordinator.hasFocused {
            context.coordinator.hasFocused = true
            DispatchQueue.main.async {
                window.makeFirstResponder(nsView)
            }
        }
    }

    func makeCoordinator() -> Coordinator { Coordinator() }

    final class Coordinator {
        var hasFocused = false
    }
}
