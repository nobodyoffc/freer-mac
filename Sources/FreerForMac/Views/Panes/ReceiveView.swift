import SwiftUI
import FCDomain
import FCUI

/// Receive funds screen. Shows the live FID prominently — click it to
/// copy. Phase 7.x adds a QR code (CIFilter.qrCodeGenerator).
struct ReceiveView: View {
    let session: ActiveSession

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            PaneHeader(session: session)
            Divider()

            VStack(alignment: .leading, spacing: 12) {
                Text("Your address").font(.headline)

                CopyableText(
                    session.liveFid,
                    font: .system(size: 18, weight: .medium, design: .monospaced)
                )
                .padding(.vertical, 8)

                if !session.canSign {
                    Label("Watch-only — receiving is fine, spending is not", systemImage: "eye")
                        .font(.caption)
                        .foregroundStyle(.orange)
                }
            }
            .padding(20)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Color(NSColor.controlBackgroundColor))
            .clipShape(RoundedRectangle(cornerRadius: 12))

            Spacer()

            VStack(alignment: .leading, spacing: 6) {
                Text("Coming next").font(.caption.bold()).foregroundStyle(.secondary)
                Text("Scannable QR code (`CIFilter.qrCodeGenerator`) lands in Phase 7.x along with payment-request URIs.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .padding()
        .frame(minWidth: 480)
    }
}
