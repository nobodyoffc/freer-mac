import SwiftUI
import FCDomain

/// Receive funds screen. Shows the live FID prominently with a copy
/// button. Phase 7.x adds a QR code (CIFilter.qrCodeGenerator).
struct ReceiveView: View {
    let session: ActiveSession

    @State private var copied: Bool = false

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            PaneHeader(session: session)
            Divider()

            VStack(alignment: .leading, spacing: 12) {
                Text("Your address").font(.headline)

                Text(session.liveFid)
                    .font(.system(size: 18, weight: .medium, design: .monospaced))
                    .textSelection(.enabled)
                    .padding(.vertical, 8)

                HStack(spacing: 8) {
                    Button {
                        copyToClipboard(session.liveFid)
                    } label: {
                        Label(copied ? "Copied!" : "Copy address", systemImage: copied ? "checkmark" : "doc.on.doc")
                    }
                    .disabled(copied)

                    if !session.canSign {
                        Label("Watch-only — receiving is fine, spending is not", systemImage: "eye")
                            .font(.caption)
                            .foregroundStyle(.orange)
                    }
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

    private func copyToClipboard(_ s: String) {
        let pb = NSPasteboard.general
        pb.clearContents()
        pb.setString(s, forType: .string)
        copied = true
        Task {
            try? await Task.sleep(nanoseconds: 1_500_000_000)
            await MainActor.run { copied = false }
        }
    }
}
