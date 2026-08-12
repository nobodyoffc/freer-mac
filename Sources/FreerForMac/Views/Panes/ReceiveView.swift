import SwiftUI
import AppKit
import FCDomain
import FCUI

/// Receive funds screen. Shows the live FID as a scannable QR code
/// (`CIFilter.qrCodeGenerator` via `QrCoder`) with the address text
/// below — click either to copy.
struct ReceiveView: View {
    let session: ActiveSession

    @State private var qrImage: NSImage?
    @State private var saveNote: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            PaneHeader(session: session)
            Divider()

            VStack(alignment: .leading, spacing: 12) {
                Text("Your address").font(.headline)

                HStack(alignment: .top, spacing: 20) {
                    qrCard
                    VStack(alignment: .leading, spacing: 12) {
                        CopyableText(
                            session.liveFid,
                            font: .system(size: 18, weight: .medium, design: .monospaced)
                        )
                        .padding(.vertical, 8)

                        Text("Scan the code or click the address to copy it.")
                            .font(.caption)
                            .foregroundStyle(.secondary)

                        Button {
                            saveQr()
                        } label: {
                            Label("Save QR…", systemImage: "square.and.arrow.down")
                        }
                        .disabled(qrImage == nil)

                        if let note = saveNote {
                            CopyableText(note, font: .caption)
                                .foregroundStyle(.secondary)
                        }

                        if !session.canSign {
                            Label("Watch-only — receiving is fine, spending is not", systemImage: "eye")
                                .font(.caption)
                                .foregroundStyle(.orange)
                        }
                    }
                }
            }
            .padding(20)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Color(NSColor.controlBackgroundColor))
            .clipShape(RoundedRectangle(cornerRadius: 12))

            Spacer()
        }
        .padding()
        .frame(minWidth: 480)
        .onAppear(perform: makeQr)
        .onChange(of: session.liveFid) { _, _ in makeQr() }
    }

    private var qrCard: some View {
        ZStack {
            RoundedRectangle(cornerRadius: 10, style: .continuous)
                .fill(Color.white)
            if let image = qrImage {
                Image(nsImage: image)
                    .resizable()
                    .interpolation(.none)
                    .scaledToFit()
                    .padding(8)
            } else {
                Image(systemName: "qrcode")
                    .font(.largeTitle)
                    .foregroundStyle(.secondary)
            }
        }
        .frame(width: 200, height: 200)
    }

    private func makeQr() {
        qrImage = try? QrCoder.makeImage(for: session.liveFid)
    }

    private func saveQr() {
        guard let image = qrImage, let png = QrCoder.pngData(image) else { return }
        let panel = NSSavePanel()
        panel.allowedContentTypes = [.png]
        panel.nameFieldStringValue = "\(session.liveFid).png"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            try png.write(to: url)
            saveNote = "Saved to \(url.lastPathComponent)"
        } catch {
            saveNote = "Save failed: \(error.localizedDescription)"
        }
    }
}
