import SwiftUI
import AppKit
import UniformTypeIdentifiers
import FCCore
import FCDomain
import FCUI

/// A Text, Sound or Video's cover (FEIP21/23/25 `cover`): the id of a
/// FEIP24 Image, never its DID, so the cover follows updates of the Image.
enum CoverChoice: Equatable {
    case none
    /// An Image record: the work's current cover, one picked from My
    /// Images, or one carved by an earlier, failed publish.
    case image(id: String)
    /// A file to publish as an Image first, in the same approval as the work.
    case newFile(URL)

    var imageId: String? {
        if case .image(let id) = self { return id }
        return nil
    }

    /// What a cover adds to a carve: `,"cover":"<64 hex>"`.
    static let carveBytes = 75
}

/// The cover row of a publish sheet.
struct CoverField: View {
    let session: ActiveSession
    @Binding var choice: CoverChoice
    /// "Cover" for a work; a token calls it its logo.
    var label = "Cover"
    /// What names the image, for the captions: "work" or "token".
    var subject = "work"
    @State private var picking = false

    var body: some View {
        LabeledField(label) {
            HStack(alignment: .top, spacing: 12) {
                thumbnail
                    .frame(width: 72, height: 72)
                    .clipShape(RoundedRectangle(cornerRadius: 6))
                VStack(alignment: .leading, spacing: 6) {
                    HStack {
                        Button("Choose Image File…", action: pickFile)
                        Button("My Images…") { picking = true }
                        if choice != .none {
                            Button("Remove \(label)") { choice = .none }
                        }
                    }
                    Text(caption).font(.caption2).foregroundStyle(.tertiary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Spacer(minLength: 0)
            }
        }
        .sheet(isPresented: $picking) {
            MyImagesPicker(session: session, title: "Choose a \(label.lowercased())") { id in
                if let id { choice = .image(id: id) }
                picking = false
            }
        }
    }

    @ViewBuilder
    private var thumbnail: some View {
        switch choice {
        case .none:
            ZStack {
                RoundedRectangle(cornerRadius: 6).fill(Color.secondary.opacity(0.12))
                Image(systemName: "photo").foregroundStyle(.tertiary)
            }
        case .newFile(let url):
            if let image = NSImage(contentsOf: url) {
                Image(nsImage: image).resizable().aspectRatio(contentMode: .fill)
            } else {
                Image(systemName: "photo")
            }
        case .image(let id):
            MediaThumbnail(session: session, kind: .image, did: (try? session.media(.image).get(id: id))?.did, side: 72)
        }
    }

    private var caption: String {
        switch choice {
        case .none:
            return "Optional. The \(label.lowercased()) is one of your Images, named by its id: update that Image later and the \(label.lowercased()) changes with it."
        case .newFile(let url):
            return "\(url.lastPathComponent) is published as an Image first, then this \(subject) names it. One approval covers both carves."
        case .image(let id):
            let title = (try? session.media(.image).get(id: id))?.title
            return "Image \(title.map { "“\($0)” " } ?? "")\(id.elidingMiddle(head: 8, tail: 6))"
        }
    }

    private func pickFile() {
        let panel = NSOpenPanel()
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = false
        panel.allowedContentTypes = [.image]
        panel.prompt = "Choose"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        choice = .newFile(url)
    }
}

/// The identity's published images, to pick one as a cover.
struct MyImagesPicker: View {
    let session: ActiveSession
    var title = "Choose a cover"
    let done: (String?) -> Void

    private var images: [MediaRecord] {
        ((try? session.media(.image).all()) ?? [])
            .filter { $0.onChain != false && !$0.isDeleted }
            .sorted { ($0.lastHeight ?? 0) > ($1.lastHeight ?? 0) }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(title).font(.title3.bold())
            let list = images
            if list.isEmpty {
                Text("You have no published images yet. Choose an image file instead: it is published as an Image with the work.")
                    .font(.callout).foregroundStyle(.secondary)
            } else {
                ScrollView {
                    LazyVGrid(columns: [GridItem(.adaptive(minimum: 120), spacing: 12)], spacing: 12) {
                        ForEach(list, id: \.id) { image in
                            Button { done(image.id) } label: {
                                VStack(spacing: 4) {
                                    MediaThumbnail(session: session, kind: .image, did: image.did, side: 120)
                                        .frame(width: 120, height: 120)
                                        .clipShape(RoundedRectangle(cornerRadius: 6))
                                    Text(image.name).font(.caption).lineLimit(1).frame(width: 120)
                                }
                            }
                            .buttonStyle(.plain)
                        }
                    }
                }
                .frame(minHeight: 280, maxHeight: 420)
            }
            HStack {
                Spacer()
                Button("Cancel") { done(nil) }.keyboardShortcut(.cancelAction)
            }
        }
        .padding(20)
        .frame(width: 560)
    }
}

/// A work's cover in its reader: the FEIP24 Image its `cover` names, as
/// that Image is now. Bytes come from this Mac or a DISK on their own; a
/// website listed in the Image's `locas` is fetched only when the reader
/// asks, and whatever arrives is shown only if it hashes to the Image's DID.
struct CoverView: View {
    let session: ActiveSession
    let imageId: String
    var title = "Cover"
    /// Given the Image's publisher, whether it may be shown at all, with
    /// the reason when not. A token's logo must be its deployer's Image.
    var refusal: ((String?) -> String?)? = nil

    @State private var image: NSImage?
    @State private var did: String?
    @State private var web: [URL] = []
    @State private var note: String?
    @State private var loading = false

    /// A cover larger than this is not one; it is not downloaded whole.
    private static let maxBytes = 20 << 20

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(title).font(.headline)
            if let image {
                Image(nsImage: image)
                    .resizable()
                    .aspectRatio(contentMode: .fit)
                    .frame(maxWidth: .infinity, maxHeight: 280, alignment: .leading)
                    .clipShape(RoundedRectangle(cornerRadius: 8))
            } else if loading {
                ProgressView().controlSize(.small)
            } else {
                if let first = web.first {
                    Button("Load Cover from \(first.host ?? "the Web")") { Task { await loadWeb() } }
                }
                if let note {
                    Text(note).font(.caption).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
        }
        .task(id: imageId) { await load() }
    }

    private func load() async {
        loading = true
        defer { loading = false }
        var record = try? session.media(.image).get(id: imageId)
        if record?.did == nil {
            record = (try? await session.publish.mediaByIds(kind: .image, [imageId]))?[imageId]
        }
        guard let record, let did = record.did, did.count == 64 else {
            note = "The cover \(imageId.elidingMiddle(head: 8, tail: 6)) is not an image on chain."
            return
        }
        guard !record.isDeleted else {
            note = "The \(title.lowercased()) image was deleted by its publisher."
            return
        }
        if let why = refusal?(record.publisher) {
            note = why
            return
        }
        self.did = did
        if let url = try? await session.publishBody.fetchURL(
            did: did, publisher: record.publisher, locas: record.locas, work: try? Hat.fromMedia(record)
        ),
           let shown = NSImage(contentsOf: url) {
            image = shown
            return
        }
        web = (record.locas ?? []).compactMap(URL.init(string:)).filter { $0.scheme == "https" }
        note = web.isEmpty
            ? "No DISK this Mac can reach holds the cover."
            : "The cover is served by a website. It is fetched only when you ask, and shown only if it matches its DID."
    }

    /// Each listed website in turn, until one serves the right bytes.
    private func loadWeb() async {
        guard let did else { return }
        loading = true
        defer { loading = false }
        var problems: [String] = []
        for url in web {
            do {
                let (data, response) = try await URLSession.shared.data(from: url)
                guard (response as? HTTPURLResponse)?.statusCode == 200 else { throw URLError(.badServerResponse) }
                guard data.count <= Self.maxBytes else { throw URLError(.dataLengthExceedsMaximum) }
                guard Hex.encode(Hash.doubleSha256(data)).lowercased() == did else {
                    problems.append("\(url.host ?? "?") served other bytes")
                    continue
                }
                if let shown = NSImage(data: data) {
                    image = shown
                    return
                }
                problems.append("\(url.host ?? "?") served no image")
            } catch {
                problems.append("\(url.host ?? "?"): \(error.localizedDescription)")
            }
        }
        note = "Not shown: " + problems.joined(separator: "; ")
    }
}
