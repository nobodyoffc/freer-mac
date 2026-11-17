import SwiftUI
import FCUI

/// FCUI's QR page in a Mac sheet: the title on top, its buttons —
/// Clear, Make QR, Copy or Done, Scan — in the footer, then Cancel (or
/// Done, when nothing is waiting for the content).
struct QrPage: View {
    let title: String
    var onDone: ((String) -> Void)? = nil
    let onCancel: () -> Void

    var body: some View {
        QrCodeView(onDone: onDone) { page, buttons in
            VStack(alignment: .leading, spacing: 0) {
                Text(title)
                    .font(.title3).bold()
                    .padding(.horizontal, 16)
                    .padding(.vertical, 12)
                Divider()
                page
                Divider()
                HStack(spacing: 8) {
                    Spacer()
                    buttons
                    Button(onDone == nil ? "Done" : "Cancel", role: .cancel) { onCancel() }
                        .keyboardShortcut(.cancelAction)
                }
                .padding(.horizontal, 16)
                .padding(.vertical, 12)
            }
            .frame(minWidth: 560, minHeight: 600)
        }
    }
}

/// The QR page for a screen that wants a scanned text back: Done hands
/// it over, Cancel leaves without it.
struct QrScanSheet: View {
    var title: String = String(localized: "Scan QR code")
    let onUse: (String) -> Void
    let onCancel: () -> Void

    var body: some View {
        QrPage(title: title, onDone: onUse, onCancel: onCancel)
    }
}

/// The QR page as a modal, opened from the toolbar `qrcode` button (⌘K)
/// — Android's `QrCodeActivity`: scan with the camera or from image
/// files (each code appends, so payloads split across several codes merge
/// back together), edit the content, and render it as QR codes.
struct QrToolSheet: View {
    let onDone: () -> Void

    var body: some View {
        QrPage(title: String(localized: "QR workbench"), onCancel: onDone)
    }
}
