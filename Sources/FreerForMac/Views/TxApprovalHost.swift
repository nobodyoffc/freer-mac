import SwiftUI
import AppKit
import FCDomain

/// Puts ``TxConfirmSheet`` on screen for whatever ``TxApprovalCenter``
/// is currently asking about.
///
/// **Why a window and not a `.sheet`.** Most transactions are started
/// from inside a sheet — the contact editor, the mail composer, the
/// Cash pane's Send — and SwiftUI will not reliably present a second
/// sheet from an *ancestor* while a descendant's sheet is up. It fails
/// by doing nothing, which here would mean a signing request that
/// waits forever on a dialog nobody can see: the worst possible
/// outcome for the one feature whose job is to never sign silently. A
/// floating panel is above the app's sheets by construction, and works
/// the same whether the request came from a pane, from a sheet inside
/// a pane, or from a background carve with no UI at all.
///
/// The panel has no close button on purpose. The two buttons inside
/// are the only exits, so the question cannot be dismissed into
/// ambiguity — and ``TxApprovalCenter/cancelAll()`` handles the case
/// where the session disappears underneath it.
struct TxApprovalHost: View {
    let center: TxApprovalCenter
    /// Only used to put contact names on the addresses in the dialog.
    let session: ActiveSession?

    @State private var presenter = TxApprovalWindow()

    var body: some View {
        Color.clear
            .frame(width: 0, height: 0)
            .onChange(of: center.current?.id, initial: true) { _, id in
                if id == nil {
                    presenter.close()
                } else {
                    presenter.show(center: center, session: session)
                }
            }
    }
}

/// Owns the panel. Kept as a plain class in `@State` so the window
/// survives view updates — recreating it on every redraw would make
/// the dialog flicker and steal focus.
@MainActor
@Observable
final class TxApprovalWindow {
    private var window: NSWindow?

    func show(center: TxApprovalCenter, session: ActiveSession?) {
        if let window {
            window.makeKeyAndOrderFront(nil)
            NSApp.activate(ignoringOtherApps: true)
            return
        }
        let hosting = NSHostingController(
            rootView: TxApprovalWindowContent(center: center, session: session)
        )
        let panel = NSWindow(contentViewController: hosting)
        panel.title = "Approve transaction"
        // No `.closable`: answering is the only way out.
        panel.styleMask = [.titled]
        panel.level = .modalPanel
        panel.isReleasedWhenClosed = false
        panel.center()
        window = panel
        panel.makeKeyAndOrderFront(nil)
        // A carve can be raised by background work while the user is
        // in another app; a signature request they never saw is one
        // they cannot refuse.
        NSApp.activate(ignoringOtherApps: true)
    }

    func close() {
        window?.orderOut(nil)
        window = nil
    }
}

/// The panel's content. Reads the centre directly so a queued request
/// slides into the same window when the current one is answered,
/// instead of closing and reopening.
private struct TxApprovalWindowContent: View {
    let center: TxApprovalCenter
    let session: ActiveSession?

    var body: some View {
        if let request = center.current {
            TxConfirmSheet(
                preview: request.preview,
                waiting: center.waitingCount,
                session: session
            ) { approved in
                center.answer(approved)
            }
            .id(request.id)
        } else {
            Color.clear.frame(width: 560, height: 520)
        }
    }
}
