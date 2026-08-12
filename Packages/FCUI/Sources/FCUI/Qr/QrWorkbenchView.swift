import SwiftUI
import AppKit
import UniformTypeIdentifiers

/// The QR workbench: an editable content area plus the Android
/// `QrCodeActivity` action set — camera **Scan**, **From images…**
/// (multi-select; every decoded code is *appended*, so a payload
/// split across several QR images merges back together), **Make QR**
/// (chunked into multiple codes when long), **Copy**, **Clear**.
///
/// Embed it in a pane (see the app's QR tool) or wrap it in
/// ``QrScanSheet`` when a flow just needs a scanned string back.
public struct QrWorkbenchView: View {
    @Binding private var content: String
    private let showsGenerate: Bool

    @StateObject private var camera = QrCameraController()
    @State private var scannedParts = 0
    @State private var statusNote: String?
    @State private var showDisplaySheet = false
    @State private var copied = false

    public init(content: Binding<String>, showsGenerate: Bool = true) {
        self._content = content
        self.showsGenerate = showsGenerate
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            editor

            if camera.isRunning {
                cameraPane
            } else if camera.permissionDenied {
                Label("Camera access denied — enable it in System Settings › Privacy & Security › Camera.",
                      systemImage: "video.slash")
                    .font(.caption)
                    .foregroundStyle(.orange)
                    .fixedSize(horizontal: false, vertical: true)
            } else if let err = camera.setupError {
                CopyableText(err, font: .caption)
                    .foregroundStyle(.red)
            }

            if let note = statusNote {
                CopyableText(note, font: .caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }

            buttons
        }
        .onAppear {
            camera.onCode = { appendScanned($0, from: "camera") }
        }
        .onDisappear { camera.stop() }
        .sheet(isPresented: $showDisplaySheet) {
            QrDisplaySheet(content: content) { showDisplaySheet = false }
        }
    }

    // MARK: - subviews

    private var editor: some View {
        TextEditor(text: $content)
            .font(.system(.body, design: .monospaced))
            .frame(minHeight: 110, maxHeight: 220)
            .padding(6)
            .background(
                RoundedRectangle(cornerRadius: 6, style: .continuous)
                    .fill(Color(nsColor: .textBackgroundColor))
            )
            .overlay(
                RoundedRectangle(cornerRadius: 6, style: .continuous)
                    .strokeBorder(Color.secondary.opacity(0.3), lineWidth: 0.5)
            )
            .dropDestination(for: URL.self) { urls, _ in
                importImages(at: urls)
                return true
            }
    }

    private var cameraPane: some View {
        ZStack(alignment: .bottom) {
            QrCameraPreview(layer: camera.previewLayer)
                .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
            Text("Point a QR code at the camera")
                .font(.caption)
                .padding(.horizontal, 10)
                .padding(.vertical, 4)
                .background(.black.opacity(0.55), in: Capsule())
                .foregroundStyle(.white)
                .padding(.bottom, 8)
        }
        .frame(height: 240)
    }

    private var buttons: some View {
        HStack(spacing: 8) {
            Button {
                if camera.isRunning {
                    camera.stop()
                } else {
                    statusNote = nil
                    camera.start()
                }
            } label: {
                Label(camera.isRunning ? "Stop" : "Scan",
                      systemImage: camera.isRunning ? "stop.circle" : "qrcode.viewfinder")
            }
            .help("Scan a QR code with the camera. Scanning pauses after each code — press Scan again for the next part.")

            Button {
                pickImages()
            } label: {
                Label("From images…", systemImage: "photo.on.rectangle")
            }
            .help("Decode QR codes from image files. Select several to merge a multi-part payload — you can also drop images onto the text area.")

            if showsGenerate {
                Button {
                    showDisplaySheet = true
                } label: {
                    Label("Make QR", systemImage: "qrcode")
                }
                .disabled(content.isEmpty)
                .help("Render the content as QR codes — long content is split across several.")
            }

            Spacer()

            Button {
                copyContent()
            } label: {
                Label(copied ? "Copied" : "Copy",
                      systemImage: copied ? "checkmark.circle.fill" : "doc.on.doc")
            }
            .foregroundStyle(copied ? .green : .primary)
            .disabled(content.isEmpty)

            Button(role: .destructive) {
                content = ""
                scannedParts = 0
                statusNote = nil
            } label: {
                Label("Clear", systemImage: "trash")
            }
            .disabled(content.isEmpty)
        }
    }

    // MARK: - actions

    /// Append a decoded code to the content — the merge behaviour
    /// multi-part payloads rely on (Android appends to its EditText
    /// the same way).
    private func appendScanned(_ code: String, from source: String) {
        content += code
        scannedParts += 1
        statusNote = scannedParts == 1
            ? "Scanned 1 code (\(source))."
            : "Scanned \(scannedParts) codes so far — parts are appended in scan order."
    }

    private func pickImages() {
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = true
        panel.allowedContentTypes = [.image]
        panel.prompt = "Decode"
        guard panel.runModal() == .OK else { return }
        importImages(at: panel.urls)
    }

    private func importImages(at urls: [URL]) {
        let images = urls.filter { url in
            (try? url.resourceValues(forKeys: [.contentTypeKey]))?
                .contentType?.conforms(to: .image) ?? true
        }
        guard !images.isEmpty else { return }

        var appended = 0
        var unreadable = 0
        for url in images {
            let payloads = (try? QrCoder.decodeImage(at: url)) ?? []
            if payloads.isEmpty {
                unreadable += 1
            } else {
                for payload in payloads {
                    content += payload
                    appended += 1
                }
            }
        }
        scannedParts += appended

        var note = "Added \(appended) code\(appended == 1 ? "" : "s") from \(images.count) image\(images.count == 1 ? "" : "s")."
        if unreadable > 0 {
            note += " \(unreadable) image\(unreadable == 1 ? " had" : "s had") no readable QR code."
        }
        statusNote = note
    }

    private func copyContent() {
        let pb = NSPasteboard.general
        pb.clearContents()
        pb.setString(content, forType: .string)
        copied = true
        Task {
            try? await Task.sleep(nanoseconds: 1_200_000_000)
            await MainActor.run { copied = false }
        }
    }
}

/// Thin modal around ``QrWorkbenchView`` for flows that need a
/// scanned string back (e.g. filling a recipient FID): scan / merge /
/// edit, then **Use content** hands the result to the caller.
public struct QrScanSheet: View {
    private let title: String
    private let onUse: (String) -> Void
    private let onCancel: () -> Void

    @State private var content = ""

    public init(
        title: String = "Scan QR code",
        onUse: @escaping (String) -> Void,
        onCancel: @escaping () -> Void
    ) {
        self.title = title
        self.onUse = onUse
        self.onCancel = onCancel
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Text(title)
                .font(.title3).bold()
                .padding(.horizontal, 16)
                .padding(.vertical, 12)

            Divider()

            QrWorkbenchView(content: $content, showsGenerate: false)
                .padding(16)

            Divider()

            HStack {
                Spacer()
                Button("Cancel", role: .cancel) { onCancel() }
                    .keyboardShortcut(.cancelAction)
                Button("Use content") {
                    onUse(content.trimmingCharacters(in: .whitespacesAndNewlines))
                }
                .keyboardShortcut(.defaultAction)
                .buttonStyle(.borderedProminent)
                .disabled(content.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 12)
        }
        .frame(minWidth: 520)
    }
}
