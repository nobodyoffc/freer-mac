import SwiftUI
#if os(iOS)
import PhotosUI
#else
import AppKit
#endif
import UniformTypeIdentifiers

/// The QR page — Android's `QrCodeActivity`: the camera's window on top,
/// with From images in its bottom-right corner, the content under it, and
/// Clear, Make QR, Copy (or Done) and Scan for the app to place.
///
/// Every code read is appended, so a text split across several codes —
/// what Make QR produces for long content — comes back whole.
///
/// The app frames the page: `chrome` gets the page and its buttons and
/// puts them where that app keeps a screen's title and actions — a phone's
/// bottom bar, with Scan last before Back under the thumb, or a Mac
/// sheet's footer.
///
/// With `onDone` set — another screen asked for a scan — Copy becomes
/// Done, which hands the content back (Android's Return).
public struct QrCodeView<Chrome: View>: View {
    private let onDone: ((String) -> Void)?
    private let chrome: (QrCodePage, QrCodeButtons) -> Chrome

    @StateObject private var model = QrCodeModel()

    public init(
        onDone: ((String) -> Void)? = nil,
        @ViewBuilder chrome: @escaping (_ page: QrCodePage, _ buttons: QrCodeButtons) -> Chrome
    ) {
        self.onDone = onDone
        self.chrome = chrome
    }

    public var body: some View {
        chrome(
            QrCodePage(model: model, camera: model.camera),
            QrCodeButtons(model: model, camera: model.camera, onDone: onDone)
        )
        .sheet(isPresented: $model.showQr) {
            QrDisplaySheet(content: model.content) { model.showQr = false }
        }
        #if os(iOS)
        .photosPicker(isPresented: $model.pickingImages, selection: $model.pickedImages,
                      maxSelectionCount: 0, matching: .images)
        .onChange(of: model.pickedImages) { _, items in
            guard !items.isEmpty else { return }
            model.pickedImages = []
            Task { await model.readImages(items) }
        }
        #endif
        .onAppear {
            model.camera.onCode = { [weak model] code in model?.scanned(code) }
        }
        .onDisappear { model.camera.stop() }
    }
}

// MARK: - the page

/// The camera's window and the content: what goes in the middle of the
/// screen.
public struct QrCodePage: View {
    @ObservedObject fileprivate var model: QrCodeModel
    @ObservedObject fileprivate var camera: QrCameraController
    @FocusState private var editing: Bool

    /// On a phone the keyboard needs the room: while typing — the camera
    /// is off then anyway — the window and the caption step aside, and the
    /// bar stays above the keyboard.
    private var compact: Bool {
        #if os(iOS)
        editing
        #else
        false
        #endif
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            if !compact { scanArea }
            editor
            if let note = model.note {
                Text(note)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                    .textSelection(.enabled)
            }
            if !compact {
                Text("Long content is split into \(String(QrCoder.defaultCapacity))-byte QR codes; scanning appends each code, so a text split across several codes comes back whole.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .padding(16)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
        // Typing stops the camera, as Android's text watcher does; the
        // camera starting takes the keyboard away.
        .onChange(of: editing) { _, now in if now { camera.stop() } }
        .onChange(of: camera.isRunning) { _, now in if now { editing = false } }
    }

    /// The camera's window. Off, it says how to start, and a tap there
    /// starts it too. From images sits in its corner, as on Android.
    private var scanArea: some View {
        ZStack {
            RoundedRectangle(cornerRadius: 12, style: .continuous)
                .fill(Color(nsColor: .controlBackgroundColor))
            if camera.isRunning {
                QrCameraPreview(layer: camera.previewLayer)
                    .clipShape(RoundedRectangle(cornerRadius: 12, style: .continuous))
            } else {
                VStack(spacing: 10) {
                    Image(systemName: camera.permissionDenied ? "video.slash" : "qrcode.viewfinder")
                        .font(.system(size: 44))
                        .foregroundStyle(camera.permissionDenied ? Color.orange : Color.accentColor)
                    Text(camera.permissionDenied ? Self.cameraDeniedText : Self.startText)
                        .font(.callout)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                        .fixedSize(horizontal: false, vertical: true)
                    if let error = camera.setupError {
                        Text(error).font(.caption).foregroundStyle(.red)
                    }
                }
                .padding(.horizontal, 16)
                .padding(.bottom, 40)
            }
        }
        .frame(minHeight: 180, maxHeight: .infinity)
        .contentShape(Rectangle())
        .onTapGesture { if !camera.isRunning { model.startScanning() } }
        .overlay(alignment: .bottomTrailing) {
            Button { model.pickImages() } label: {
                Image(systemName: "photo.on.rectangle")
                    .font(.title3.weight(.medium))
                    .foregroundStyle(.white)
                    .frame(width: 52, height: 52)
                    .background(Color.accentColor, in: Circle())
                    .contentShape(Circle())
            }
            .buttonStyle(.plain)
            .padding(12)
            .help(Text("Decode QR codes from images. Select several to merge a multi-part payload."))
            .accessibilityLabel(Text("From images…"))
            .accessibilityIdentifier("qr.images")
        }
        .accessibilityIdentifier("qr.scanArea")
    }

    private var editor: some View {
        TextEditor(text: $model.content)
            .font(.system(.body, design: .monospaced))
            #if os(iOS)
            .autocorrectionDisabled()
            .textInputAutocapitalization(.never)
            #endif
            .focused($editing)
            .frame(minHeight: 100, maxHeight: 200)
            .padding(6)
            .background(
                RoundedRectangle(cornerRadius: 8, style: .continuous)
                    .fill(Color(nsColor: .textBackgroundColor))
            )
            .overlay(
                RoundedRectangle(cornerRadius: 8, style: .continuous)
                    .strokeBorder(Color.secondary.opacity(0.4), lineWidth: 1)
            )
            .dropDestination(for: URL.self) { urls, _ in
                model.importImages(at: urls)
                return true
            }
            .accessibilityIdentifier("qr.content")
    }

    #if os(macOS)
    private static let startText = String(localized: "Click Scan to scan a QR code.")
    private static let cameraDeniedText = String(localized: "Camera access denied — enable it in System Settings › Privacy & Security › Camera.")
    #else
    private static let startText = String(localized: "Tap the Scan button to scan a QR code.")
    private static var cameraDeniedText: String {
        let app = Bundle.main.object(forInfoDictionaryKey: "CFBundleDisplayName") as? String
            ?? Bundle.main.object(forInfoDictionaryKey: "CFBundleName") as? String ?? ""
        return String(localized: "Camera access denied — enable it in Settings › \(app) › Camera.")
    }
    #endif
}

// MARK: - the buttons

/// Clear, Make QR, Copy (or Done), Scan — in that order, for the app's
/// bar or footer, which adds Back or Cancel after them.
public struct QrCodeButtons: View {
    @ObservedObject fileprivate var model: QrCodeModel
    @ObservedObject fileprivate var camera: QrCameraController
    fileprivate let onDone: ((String) -> Void)?

    public var body: some View {
        Button { model.clear() } label: { Label("Clear", systemImage: "xmark") }
            .disabled(model.content.isEmpty)
            .accessibilityIdentifier("qr.clear")
        Button { model.showQr = true } label: { Label("Make QR", systemImage: "qrcode") }
            .disabled(model.trimmed.isEmpty)
            .help(Text("Render the content as QR codes — long content is split across several."))
            .accessibilityIdentifier("qr.make")
        if let onDone {
            Button {
                camera.stop()
                onDone(model.trimmed)
            } label: { Label("Done", systemImage: "checkmark") }
                .keyboardShortcut(.defaultAction)
                .disabled(model.trimmed.isEmpty)
                .accessibilityIdentifier("qr.done")
        } else {
            Button { model.copy() } label: {
                Label(model.copied ? "Copied" : "Copy",
                      systemImage: model.copied ? "checkmark" : "doc.on.doc")
            }
            .tint(model.copied ? Color.green : nil)
            .disabled(model.content.isEmpty)
            .accessibilityIdentifier("qr.copy")
        }
        Button {
            if camera.isRunning { camera.stop() } else { model.startScanning() }
        } label: {
            Label(camera.isRunning ? "Stop" : "Scan",
                  systemImage: camera.isRunning ? "stop.fill" : "qrcode.viewfinder")
        }
        .help(Text("Scan a QR code with the camera. The camera stops after each code — press Scan again for the next part."))
        .accessibilityIdentifier("qr.scan")
    }
}

// MARK: - the state

@MainActor
final class QrCodeModel: ObservableObject {
    let camera = QrCameraController()

    @Published var content = ""
    @Published var note: String?
    @Published var copied = false
    @Published var showQr = false
    @Published var pickingImages = false
    #if os(iOS)
    @Published var pickedImages: [PhotosPickerItem] = []
    #endif
    private var scannedParts = 0

    var trimmed: String { content.trimmingCharacters(in: .whitespacesAndNewlines) }

    func startScanning() {
        note = nil
        camera.start()
    }

    /// One code read: appended, and the camera stops, as on Android —
    /// Scan again for the next part.
    func scanned(_ code: String) {
        content += code
        scannedParts += 1
        camera.stop()
        note = scannedParts == 1
            ? String(localized: "Scanned 1 code.")
            : String(localized: "Scanned \(String(scannedParts)) codes so far — parts are appended in scan order.")
    }

    func pickImages() {
        #if os(iOS)
        pickingImages = true
        #else
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = true
        panel.allowedContentTypes = [.image]
        panel.prompt = String(localized: "Decode")
        guard panel.runModal() == .OK else { return }
        importImages(at: panel.urls)
        #endif
    }

    #if os(iOS)
    func readImages(_ items: [PhotosPickerItem]) async {
        var images: [CGImage?] = []
        for item in items {
            let data = try? await item.loadTransferable(type: Data.self)
            images.append(data.flatMap { UIImage(data: $0)?.cgImage })
        }
        add(images)
    }
    #endif

    /// Image files: picked on the Mac, or dropped on the text.
    func importImages(at urls: [URL]) {
        let files = urls.filter { url in
            (try? url.resourceValues(forKeys: [.contentTypeKey]))?
                .contentType?.conforms(to: .image) ?? true
        }
        guard !files.isEmpty else { return }
        add(files.map { url in
            NSImage(contentsOf: url)?.cgImage(forProposedRect: nil, context: nil, hints: nil)
        })
    }

    private func add(_ images: [CGImage?]) {
        var added = 0
        var unreadable = 0
        for image in images {
            guard let image, let codes = try? QrCoder.decode(cgImage: image), !codes.isEmpty else {
                unreadable += 1
                continue
            }
            for code in codes { content += code }
            added += codes.count
        }
        scannedParts += added
        var text = String(localized: "Added \(String(added)) code(s) from \(String(images.count)) image(s).")
        if unreadable > 0 {
            text += " " + String(localized: "\(String(unreadable)) image(s) had no readable QR code.")
        }
        note = text
    }

    func clear() {
        content = ""
        scannedParts = 0
        note = nil
    }

    func copy() {
        let pb = NSPasteboard.general
        pb.clearContents()
        pb.setString(content, forType: .string)
        copied = true
        Task {
            try? await Task.sleep(nanoseconds: 1_200_000_000)
            copied = false
        }
    }
}
