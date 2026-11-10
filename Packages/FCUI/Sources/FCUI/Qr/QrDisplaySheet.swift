import SwiftUI
#if os(macOS)
import AppKit
#endif
import UniformTypeIdentifiers

/// Modal that renders `content` as QR code(s) — one page per
/// ``QrCoder/defaultCapacity``-byte chunk, with a "k/N" indicator and
/// arrows when the content spans several codes. The Mac take on the
/// Android `dialog_qr_display` ViewPager. **Save…** writes PNG(s),
/// **Copy** puts the full original content on the clipboard.
public struct QrDisplaySheet: View {
    private let title: String
    private let content: String
    private let onDone: () -> Void

    @State private var images: [NSImage] = []
    @State private var page = 0
    @State private var generateError: String?
    @State private var statusNote: String?
    @State private var copied = false

    public init(
        title: String = String(localized: "QR code"),
        content: String,
        onDone: @escaping () -> Void
    ) {
        self.title = title
        self.content = content
        self.onDone = onDone
    }

    public var body: some View {
        VStack(spacing: 0) {
            HStack {
                Text(title).font(.title3).bold()
                Spacer()
                if images.count > 1 {
                    Text("\(page + 1)/\(images.count)")
                        .font(.callout.monospacedDigit())
                        .foregroundStyle(.secondary)
                }
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 12)

            Divider()

            if let err = generateError {
                CopyableText(err, font: .callout)
                    .foregroundStyle(.red)
                    .padding(24)
            } else {
                pager.padding(16)
            }

            if images.count > 1 {
                Text("This content spans \(images.count) QR codes — scan every page and the pieces merge back together.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                    .padding(.horizontal, 16)
                    .padding(.bottom, 8)
            }

            if let note = statusNote {
                CopyableText(note, font: .caption)
                    .foregroundStyle(.secondary)
                    .padding(.bottom, 8)
            }

            Divider()
            footer
        }
        #if os(macOS)
        .frame(minWidth: 420)
        #endif
        .onAppear(perform: generate)
    }

    private var pager: some View {
        HStack(spacing: 12) {
            pageButton(systemImage: "chevron.left", enabled: page > 0) {
                page -= 1
            }

            ZStack {
                RoundedRectangle(cornerRadius: 12, style: .continuous)
                    .fill(Color.white)
                if images.indices.contains(page) {
                    Image(nsImage: images[page])
                        .resizable()
                        .interpolation(.none)
                        .scaledToFit()
                        .padding(10)
                }
            }
            .frame(width: 320, height: 320)

            pageButton(systemImage: "chevron.right",
                       enabled: page < images.count - 1) {
                page += 1
            }
        }
    }

    @ViewBuilder
    private func pageButton(
        systemImage: String,
        enabled: Bool,
        action: @escaping () -> Void
    ) -> some View {
        if images.count > 1 {
            Button(action: action) {
                Image(systemName: systemImage).font(.title2)
            }
            .buttonStyle(.plain)
            .foregroundStyle(enabled ? Color.primary : Color.secondary.opacity(0.3))
            .disabled(!enabled)
        }
    }

    private var footer: some View {
        HStack(spacing: 8) {
            Button {
                save()
            } label: {
                Label(images.count > 1 ? "Save all…" : "Save…",
                      systemImage: "square.and.arrow.down")
            }
            .disabled(images.isEmpty)

            Button {
                copyContent()
            } label: {
                Label(copied ? "Copied" : "Copy content",
                      systemImage: copied ? "checkmark.circle.fill" : "doc.on.doc")
            }
            .foregroundStyle(copied ? .green : .primary)

            Spacer()

            Button("Done") { onDone() }
                .keyboardShortcut(.defaultAction)
                .buttonStyle(.borderedProminent)
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 12)
    }

    // MARK: - actions

    private func generate() {
        do {
            images = try QrCoder.makeImages(for: content)
            page = 0
        } catch {
            generateError = String(describing: error)
        }
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

    /// One image goes through NSSavePanel; several go numbered into a
    /// chosen folder (matching Android's save-all-to-gallery).
    private func save() {
        #if os(iOS)
        let images = images
        Task { @MainActor in
            // iOS exports files that already exist, so the PNGs are
            // written to a scratch folder first and copied out from there.
            let dir = FileManager.default.temporaryDirectory
                .appendingPathComponent("qr-\(UUID().uuidString)", isDirectory: true)
            try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
            defer { try? FileManager.default.removeItem(at: dir) }
            let stamp = Int(Date().timeIntervalSince1970)
            var urls: [URL] = []
            for (i, image) in images.enumerated() {
                let name = images.count == 1 ? "QR.png" : "QR_\(stamp)_\(i + 1).png"
                let url = dir.appendingPathComponent(name)
                if (try? write(image, to: url)) != nil { urls.append(url) }
            }
            guard !urls.isEmpty else {
                statusNote = String(localized: "Save failed: the images could not be written.")
                return
            }
            if await FilePanel.save(filesAt: urls) {
                statusNote = urls.count == 1 ? String(localized: "Saved QR.png") : String(localized: "Saved \(String(urls.count)) images")
            }
        }
        #else
        if images.count == 1 {
            let panel = NSSavePanel()
            panel.allowedContentTypes = [.png]
            panel.nameFieldStringValue = "QR.png"
            guard panel.runModal() == .OK, let url = panel.url else { return }
            do {
                try write(images[0], to: url)
                statusNote = String(localized: "Saved to \(url.lastPathComponent)")
            } catch {
                statusNote = String(localized: "Save failed: \(error.localizedDescription)")
            }
        } else {
            let panel = NSOpenPanel()
            panel.canChooseFiles = false
            panel.canChooseDirectories = true
            panel.canCreateDirectories = true
            panel.prompt = String(localized: "Save \(String(images.count)) images")
            guard panel.runModal() == .OK, let dir = panel.url else { return }
            let stamp = Int(Date().timeIntervalSince1970)
            var saved = 0
            for (i, image) in images.enumerated() {
                let url = dir.appendingPathComponent("QR_\(stamp)_\(i + 1).png")
                if (try? write(image, to: url)) != nil { saved += 1 }
            }
            statusNote = saved == images.count
                ? String(localized: "Saved \(String(saved)) images to \(dir.lastPathComponent)")
                : String(localized: "Saved \(String(saved)) of \(String(images.count)) images — some writes failed")
        }
        #endif
    }

    private func write(_ image: NSImage, to url: URL) throws {
        guard let png = QrCoder.pngData(image) else {
            throw QrCoder.Failure.generatorFailed
        }
        try png.write(to: url)
    }
}
