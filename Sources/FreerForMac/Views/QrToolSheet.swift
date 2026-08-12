import SwiftUI
import FCUI

/// The QR workbench as a modal, opened from the toolbar `qrcode`
/// button (⌘K) — the Mac counterpart of Android's `QrCodeActivity`.
/// Scan with the camera or from image files (each code appends, so
/// payloads split across several codes merge back together), edit the
/// content freely, and render it as QR codes (long content is chunked
/// across several).
struct QrToolSheet: View {
    let onDone: () -> Void

    @State private var content: String = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                Image(systemName: "qrcode").font(.title2)
                Text("QR workbench").font(.title3).bold()
                Spacer()
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 12)

            Divider()

            VStack(alignment: .leading, spacing: 10) {
                QrWorkbenchView(content: $content)

                Text("Long content is split into \(QrCoder.defaultCapacity)-byte QR codes; scanning appends each code, so multi-part payloads from the Android app reassemble here (and vice versa).")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .padding(16)

            Divider()

            HStack {
                Spacer()
                Button("Done") { onDone() }
                    .keyboardShortcut(.defaultAction)
                    .buttonStyle(.borderedProminent)
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 12)
        }
        .frame(minWidth: 560)
    }
}
