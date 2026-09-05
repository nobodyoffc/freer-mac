import SwiftUI
import AppKit
import UniformTypeIdentifiers

/// The avatar, big enough to look at — and to take away.
///
/// A generated avatar is the only picture this app has of an identity,
/// and 22 points in a toolbar is not a picture. People want it as a
/// profile photo, in a message, beside a name somewhere else; all of
/// that needs the image itself, not a view of it. So this does the two
/// things that turn a rendering into a file: **Copy** puts it on the
/// pasteboard for anything that accepts an image, **Save…** writes a PNG.
///
/// **About the sizes.** The element art is drawn at 150 px, so that is
/// the real resolution and every larger option is interpolation. The
/// picker offers them anyway — a 150 px file is too small to use as an
/// avatar on most services — and says which one is native rather than
/// implying detail that is not there.
///
/// The artwork is already a circle on transparency, so no mask is
/// applied here: the file that lands on disk is exactly the image on
/// screen, alpha and all.
public struct FidAvatarSheet: View {

    private let fid: String
    private let title: String?
    private let isNobody: Bool
    private let onDone: () -> Void

    /// Export sizes. 150 is the art's own resolution; the rest are
    /// scaled up for services that reject anything smaller.
    private static let sizes = [150, 300, 600]

    @State private var pixels = 600
    @State private var copied = false
    @State private var statusNote: String?
    @State private var statusIsError = false

    /// - parameters:
    ///   - fid: whose avatar to show.
    ///   - title: an optional name to show above the FID — a CID or a
    ///     local label reads better than an address when there is one.
    ///   - isNobody: a FID whose private key is public. Flagged in
    ///     words here rather than by draining the colour: lists
    ///     desaturate so the odd one out is visible in a row of many,
    ///     while this window exists to show the artwork as it is.
    public init(
        fid: String,
        title: String? = nil,
        isNobody: Bool = false,
        onDone: @escaping () -> Void
    ) {
        self.fid = fid
        self.title = title
        self.isNobody = isNobody
        self.onDone = onDone
    }

    public var body: some View {
        VStack(spacing: 0) {
            header
            Divider()

            VStack(spacing: 14) {
                portrait
                identityLine
                if isNobody {
                    Label(
                        "Nobody FID — its private key is public, so anyone can spend from it.",
                        systemImage: "exclamationmark.triangle.fill"
                    )
                    .font(.caption)
                    .foregroundStyle(.orange)
                    .fixedSize(horizontal: false, vertical: true)
                }
                sizePicker
            }
            .padding(20)

            if let statusNote {
                Text(statusNote)
                    .font(.caption)
                    .foregroundStyle(statusIsError ? .red : .secondary)
                    .fixedSize(horizontal: false, vertical: true)
                    .padding(.horizontal, 20)
                    .padding(.bottom, 10)
            }

            Divider()
            footer
        }
        .frame(width: 380)
    }

    // MARK: - pieces

    private var header: some View {
        HStack {
            Text("Avatar").font(.title3).bold()
            Spacer()
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 12)
    }

    /// Drawn on a checkerboard-free neutral card rather than on the
    /// window: the art has transparent corners, and a plain background
    /// is the honest way to show that without pretending the file has
    /// a white square behind it.
    private var portrait: some View {
        ZStack {
            RoundedRectangle(cornerRadius: 14, style: .continuous)
                .fill(Color(NSColor.controlBackgroundColor))
            if let image = try? AvatarMaker.avatar(for: fid, pixels: 600) {
                Image(nsImage: image)
                    .resizable()
                    .interpolation(.high)
                    .scaledToFit()
                    .padding(18)
            } else {
                VStack(spacing: 6) {
                    Image(systemName: "person.crop.circle.badge.questionmark")
                        .font(.largeTitle)
                    Text("No avatar for this FID")
                        .font(.caption)
                }
                .foregroundStyle(.secondary)
            }
        }
        .frame(width: 240, height: 240)
    }

    private var identityLine: some View {
        VStack(spacing: 4) {
            if let title, !title.isEmpty {
                Text(title)
                    .font(.headline)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }
            CopyableText.elidingMiddle(
                fid, head: 10, tail: 10,
                font: .system(.caption, design: .monospaced),
                color: .secondary
            )
        }
    }

    private var sizePicker: some View {
        VStack(spacing: 5) {
            Picker("", selection: $pixels) {
                ForEach(Self.sizes, id: \.self) { size in
                    Text("\(size) px").tag(size)
                }
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .frame(width: 240)

            Text(pixels == Int(AvatarMaker.nativeSize)
                 ? "150 px is the artwork's own resolution."
                 : "Scaled up from the 150 px original — larger, not sharper.")
                .font(.caption2)
                .foregroundStyle(.secondary)
        }
    }

    private var footer: some View {
        HStack(spacing: 8) {
            Button {
                save()
            } label: {
                Label("Save…", systemImage: "square.and.arrow.down")
            }

            Button {
                copyImage()
            } label: {
                Label(copied ? "Copied" : "Copy image",
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

    /// Both the PNG bytes and an NSImage go on the pasteboard. Apps
    /// differ in which they ask for — Finder and Mail take the file
    /// data, a text field takes the image — and offering one of the two
    /// is how an avatar pastes into some places and not others.
    private func copyImage() {
        do {
            let data = try AvatarMaker.pngData(for: fid, pixels: pixels)
            let pb = NSPasteboard.general
            pb.clearContents()
            pb.setData(data, forType: .png)
            if let image = NSImage(data: data) {
                pb.writeObjects([image])
            }
            copied = true
            note("Copied at \(pixels)×\(pixels).")
            Task {
                try? await Task.sleep(nanoseconds: 1_200_000_000)
                await MainActor.run { copied = false }
            }
        } catch {
            note("Couldn't copy: \(error)", isError: true)
        }
    }

    private func save() {
        let panel = NSSavePanel()
        panel.allowedContentTypes = [.png]
        panel.nameFieldStringValue = "avatar-\(fid).png"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            try AvatarMaker.pngData(for: fid, pixels: pixels).write(to: url)
            note("Saved \(pixels)×\(pixels) to \(url.lastPathComponent)")
        } catch {
            note("Save failed: \(error.localizedDescription)", isError: true)
        }
    }

    private func note(_ text: String, isError: Bool = false) {
        statusNote = text
        statusIsError = isError
    }
}

#Preview {
    FidAvatarSheet(
        fid: "FEk41Kqjar45fLDriztUDTUkdki7mmcjWK",
        title: "no1.nrc7"
    ) {}
}
