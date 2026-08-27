import SwiftUI
import AppKit
import AVFoundation
import AVKit
import UniformTypeIdentifiers
import FCCore
import FCDomain
import FCUI

// MARK: - thumbnail

/// A row's picture, drawn **only from bytes already on this Mac**.
///
/// A shelf that fetched every row from DISK as it scrolled would turn
/// browsing into an unbounded download, on a pane whose whole premise
/// is that the bytes live somewhere else. So this shows what is local
/// and a symbol otherwise; opening a record is what fetches.
///
/// An image draws itself and a video draws its first frame. A sound has
/// nothing to draw, and a waveform glyph is more honest than a black
/// rectangle pretending to be a picture.
struct MediaThumbnail: View {
    let session: ActiveSession
    let kind: MediaKind
    let did: String?
    var side: CGFloat = 44

    @State private var image: NSImage?

    var body: some View {
        Group {
            if let image {
                Image(nsImage: image)
                    .resizable()
                    .aspectRatio(contentMode: .fill)
            } else {
                ZStack {
                    Rectangle().fill(Color.secondary.opacity(0.12))
                    Image(systemName: did == nil ? "questionmark" : kind.symbol)
                        .foregroundStyle(.tertiary)
                }
            }
        }
        .frame(width: side, height: side)
        .clipShape(RoundedRectangle(cornerRadius: 6))
        .task(id: did) { await load() }
    }

    private func load() async {
        guard kind != .sound else { return }
        guard let did, !did.isEmpty, session.publishBody.isLocal(did: did) else { return }
        guard let url = try? session.files.localURL(hatId: did) else { return }
        let side = self.side
        let kind = self.kind
        // Decoding a 40-megapixel photograph — or opening a video — to
        // fill 44 points is the one thing a list must not do on the
        // main actor.
        let loaded: NSImage? = await Task.detached(priority: .utility) {
            switch kind {
            case .image:
                guard let full = NSImage(contentsOf: url) else { return nil }
                let box = NSSize(width: side * 3, height: side * 3)
                guard full.size.width > box.width || full.size.height > box.height else { return full }
                let scaled = NSImage(size: box)
                scaled.lockFocus()
                full.draw(in: NSRect(origin: .zero, size: box),
                          from: .zero, operation: .copy, fraction: 1)
                scaled.unlockFocus()
                return scaled
            case .video:
                let generator = AVAssetImageGenerator(asset: AVURLAsset(url: url))
                generator.appliesPreferredTrackTransform = true
                generator.maximumSize = NSSize(width: side * 3, height: side * 3)
                guard let cg = try? generator.copyCGImage(
                    at: CMTime(seconds: 0, preferredTimescale: 600), actualTime: nil
                ) else { return nil }
                return NSImage(cgImage: cg, size: .zero)
            case .sound:
                return nil
            }
        }.value
        await MainActor.run { image = loaded }
    }
}

// MARK: - playback

/// Play a published sound. AVKit's `VideoPlayer` would do it, but it
/// draws a black rectangle where the picture would be, which for an
/// audio file is a broken image rather than a player.
struct AudioPlaybackView: View {
    let url: URL

    @State private var player: AVPlayer?
    @State private var playing = false
    @State private var elapsed: Double = 0
    @State private var duration: Double = 0
    @State private var observer: Any?

    var body: some View {
        HStack(spacing: 12) {
            Button {
                toggle()
            } label: {
                Image(systemName: playing ? "pause.circle.fill" : "play.circle.fill")
                    .font(.system(size: 36))
            }
            .buttonStyle(.plain)

            VStack(alignment: .leading, spacing: 4) {
                ProgressView(value: duration > 0 ? min(elapsed / duration, 1) : 0)
                Text("\(Self.time(elapsed)) / \(duration > 0 ? Self.time(duration) : "—")")
                    .font(.caption2.monospacedDigit())
                    .foregroundStyle(.secondary)
            }
        }
        .padding(.vertical, 8)
        .onAppear { prepare() }
        .onDisappear { teardown() }
    }

    private func prepare() {
        let item = AVPlayerItem(url: url)
        let player = AVPlayer(playerItem: item)
        self.player = player
        Task {
            let seconds = (try? await item.asset.load(.duration).seconds) ?? 0
            await MainActor.run { duration = seconds.isFinite ? seconds : 0 }
        }
        observer = player.addPeriodicTimeObserver(
            forInterval: CMTime(seconds: 0.2, preferredTimescale: 600), queue: .main
        ) { time in
            elapsed = time.seconds
            if duration > 0, time.seconds >= duration - 0.05 {
                playing = false
                player.seek(to: .zero)
            }
        }
    }

    private func teardown() {
        if let observer { player?.removeTimeObserver(observer) }
        observer = nil
        player?.pause()
        player = nil
    }

    private func toggle() {
        guard let player else { return }
        if playing {
            player.pause()
        } else {
            if duration > 0, elapsed >= duration - 0.05 { player.seek(to: .zero) }
            player.play()
        }
        playing.toggle()
    }

    private static func time(_ seconds: Double) -> String {
        guard seconds.isFinite, seconds >= 0 else { return "—" }
        let whole = Int(seconds.rounded())
        return String(format: "%d:%02d", whole / 60, whole % 60)
    }
}

// MARK: - compose

/// Pick a file and publish it — or save it, or publish a new edition.
///
/// **The file is referenced, never copied.** ``FileVault`` hashes it
/// where it lies and registers that path, so adding a 40 MB photograph
/// or a 400 MB video costs one hash pass rather than a duplicate in app
/// storage. The upload then streams from the user's own file.
///
/// Order of operations is a text's, and for the same reason: the bytes
/// go to DISK **before** the carve is built, so a publish that cannot
/// reach a DISK fails while it is still free.
struct PublishMediaComposer: View {
    let session: ActiveSession
    let kind: MediaKind
    let editing: MediaRecord?

    enum Result {
        case carved(MediaRecord)
        case updated(String)
        case draft
        case cancelled
    }

    let onDone: (Result) -> Void

    init(
        session: ActiveSession,
        kind: MediaKind,
        editing: MediaRecord? = nil,
        onDone: @escaping (Result) -> Void
    ) {
        self.session = session
        self.kind = kind
        self.editing = editing
        self.onDone = onDone
        _title = State(initialValue: editing?.title ?? "")
        _summary = State(initialValue: editing?.summary ?? "")
        _lang = State(initialValue: editing?.lang ?? "")
        _format = State(initialValue: editing?.format ?? "")
        _authorsText = State(initialValue: (editing?.authors ?? []).joined(separator: ", "))
    }

    @State private var title: String
    @State private var summary: String
    @State private var lang: String
    @State private var format: String
    @State private var authorsText: String

    @State private var pickedURL: URL?
    @State private var preview: NSImage?
    @State private var pickedSize: Int64?
    @State private var busy = false
    @State private var progressNote: String?
    @State private var error: String?

    private var isNewEdition: Bool { (editing?.onChain ?? false) != false && editing != nil }

    /// What the carve will point at: the new file if one was picked,
    /// otherwise whatever the record already pointed at.
    private var effectiveDid: String? { pickedURL == nil ? editing?.did : nil }

    private var authors: [String] {
        authorsText
            .split(separator: ",")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
    }

    private var remaining: Int {
        MediaFeip.remainingSummaryBytes(
            kind: kind,
            imageId: isNewEdition ? editing?.id : nil,
            title: title,
            did: String(repeating: "0", count: 64),
            lang: lang.isEmpty ? nil : lang,
            authors: authors.isEmpty ? nil : authors,
            format: format.isEmpty ? nil : format,
            summary: summary
        )
    }

    private var hasBytes: Bool { pickedURL != nil || (editing?.did?.isEmpty == false) }

    private var canPublish: Bool {
        !title.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            && hasBytes
            && remaining >= 0
            && !busy
            && session.canSign
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text(isNewEdition ? "Publish a new edition" : "Publish \(kind == .image ? "an" : "a") \(kind.noun)")
                .font(.title3.bold())

            if isNewEdition {
                Label(
                    "Every field below is re-carved, including the ones you don't touch — an update that leaves a field out clears it. The edition counter goes to v\((editing?.edition ?? 1) + 1).",
                    systemImage: "info.circle"
                )
                .font(.caption)
                .foregroundStyle(.secondary)
            }

            ScrollView {
                VStack(alignment: .leading, spacing: 12) {
                    filePicker

                    LabeledField("Title") {
                        TextField("What the work is called", text: $title)
                            .textFieldStyle(.roundedBorder)
                    }

                    LabeledField("Summary") {
                        VStack(alignment: .leading, spacing: 4) {
                            TextField("A line or two, carved on chain so a list can show it", text: $summary, axis: .vertical)
                                .lineLimit(2...5)
                                .textFieldStyle(.roundedBorder)
                            Text(remaining >= 0
                                 ? "\(remaining) bytes left in the carve"
                                 : "\(-remaining) bytes over the OP_RETURN limit")
                                .font(.caption2.monospacedDigit())
                                .foregroundStyle(remaining >= 0 ? AnyShapeStyle(.tertiary) : AnyShapeStyle(Color.red))
                        }
                    }

                    HStack(spacing: 12) {
                        LabeledField("Format") {
                            TextField(formatPlaceholder, text: $format)
                                .textFieldStyle(.roundedBorder)
                        }
                        LabeledField("Language") {
                            TextField("en, zh…", text: $lang)
                                .textFieldStyle(.roundedBorder)
                        }
                    }

                    LabeledField("Authors") {
                        VStack(alignment: .leading, spacing: 4) {
                            TextField("FIDs or names, comma separated", text: $authorsText)
                                .textFieldStyle(.roundedBorder)
                            if !authors.isEmpty {
                                HStack(spacing: 4) {
                                    ForEach(authors, id: \.self) { author in
                                        Text(author.count > 24 ? author.elidingMiddle(head: 6, tail: 6) : author)
                                            .font(.caption2)
                                            .padding(.horizontal, 6).padding(.vertical, 2)
                                            .background(Capsule().fill(Color.secondary.opacity(0.15)))
                                    }
                                }
                            }
                        }
                    }
                }
                .padding(.trailing, 4)
            }
            .frame(maxHeight: 420)

            if let n = progressNote {
                HStack(spacing: 6) {
                    ProgressView().controlSize(.small)
                    Text(n).font(.caption).foregroundStyle(.secondary)
                }
            }
            if let e = error {
                CopyableText(e, font: .caption).foregroundStyle(.red)
            }
            if !session.canSign {
                Label("This identity is watch-only — there is no key here to sign a carve with.", systemImage: "eye")
                    .font(.caption)
                    .foregroundStyle(.orange)
            }

            HStack {
                Button("Cancel") { onDone(.cancelled) }
                    .keyboardShortcut(.cancelAction)
                Spacer()
                if !isNewEdition {
                    Button("Save draft") { saveDraft() }
                        .disabled(busy || title.trimmingCharacters(in: .whitespaces).isEmpty)
                        .help("Keeps the record on this Mac. The file is registered where it lies; nothing is uploaded and nothing is carved.")
                }
                Button(isNewEdition ? "Publish edition" : "Publish") {
                    Task { await publish() }
                }
                .buttonStyle(.borderedProminent)
                .disabled(!canPublish)
            }
        }
        .padding(20)
        .frame(width: 640)
    }

    private var formatPlaceholder: String {
        switch kind {
        case .image: return "image/png…"
        case .sound: return "audio/mpeg…"
        case .video: return "video/mp4…"
        }
    }

    private var contentTypes: [UTType] {
        switch kind {
        case .image: return [.image]
        case .sound: return [.audio]
        case .video: return [.movie]
        }
    }

    // MARK: - the file

    @ViewBuilder
    private var filePicker: some View {
        LabeledField("The \(kind.noun)") {
            HStack(alignment: .top, spacing: 12) {
                Group {
                    if let preview {
                        Image(nsImage: preview)
                            .resizable()
                            .aspectRatio(contentMode: .fit)
                    } else if pickedURL != nil {
                        ZStack {
                            RoundedRectangle(cornerRadius: 8).fill(Color.secondary.opacity(0.12))
                            Image(systemName: kind.symbol).font(.title).foregroundStyle(.secondary)
                        }
                    } else if editing?.did != nil {
                        MediaThumbnail(session: session, kind: kind, did: editing?.did, side: 120)
                    } else {
                        ZStack {
                            RoundedRectangle(cornerRadius: 8).fill(Color.secondary.opacity(0.12))
                            Image(systemName: kind.symbol).font(.title).foregroundStyle(.tertiary)
                        }
                    }
                }
                .frame(width: 120, height: 120)
                .clipShape(RoundedRectangle(cornerRadius: 8))

                VStack(alignment: .leading, spacing: 6) {
                    Button(hasBytes ? "Choose a different file…" : "Choose a file…") { pick() }
                    if let url = pickedURL {
                        Text(url.lastPathComponent).font(.caption).lineLimit(1).truncationMode(.middle)
                        if let size = pickedSize {
                            Text(ByteCountFormatter.string(fromByteCount: size, countStyle: .file))
                                .font(.caption2).foregroundStyle(.tertiary)
                        }
                        Text("Uploaded to DISK on publish. The file stays where it is — it is referenced, not copied.")
                            .font(.caption2).foregroundStyle(.tertiary)
                    } else if let did = editing?.did {
                        Text("Currently: \(did.elidingMiddle(head: 8, tail: 8))")
                            .font(.system(.caption2, design: .monospaced))
                            .foregroundStyle(.secondary)
                        Text("Leave it alone to keep this file and change only the details.")
                            .font(.caption2).foregroundStyle(.tertiary)
                    } else {
                        Text("The bytes go to DISK; the chain gets their hash.")
                            .font(.caption2).foregroundStyle(.tertiary)
                    }
                }
                Spacer(minLength: 0)
            }
        }
    }

    private func pick() {
        let panel = NSOpenPanel()
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = false
        panel.allowedContentTypes = contentTypes
        panel.prompt = "Choose"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        pickedURL = url
        pickedSize = (try? FileManager.default.attributesOfItem(atPath: url.path)[.size] as? NSNumber)??.int64Value
        preview = kind == .image ? NSImage(contentsOf: url) : nil
        if title.isEmpty {
            title = url.deletingPathExtension().lastPathComponent
        }
        // The format hint is free and exact here, and a guess later.
        if let type = UTType(filenameExtension: url.pathExtension),
           let mime = type.preferredMIMEType {
            format = mime
        }
    }

    // MARK: - actions

    private func saveDraft() {
        do {
            var did = effectiveDid
            if let url = pickedURL {
                did = try session.publishBody.storeFileLocally(at: url)
            }
            var draft = MediaRecord.createLocal(
                kind: kind,
                title: title,
                did: did,
                lang: lang.isEmpty ? nil : lang,
                authors: authors.isEmpty ? nil : authors,
                format: format.isEmpty ? nil : format,
                summary: summary.isEmpty ? nil : summary,
                publisher: session.liveFid
            )
            let store = session.media(kind)
            if let editing, editing.onChain == false, editing.id != draft.id {
                _ = try? store.remove(id: editing.id)
            }
            draft.addedAt = editing?.addedAt ?? Date()
            try store.upsert(draft)
            onDone(.draft)
        } catch {
            self.error = String(describing: error)
        }
    }

    private func publish() async {
        busy = true
        defer { busy = false }
        error = nil
        do {
            var did = effectiveDid
            if let url = pickedURL {
                progressNote = "Uploading the \(kind.noun) to DISK…"
                did = try await session.publishBody.storeFile(at: url)
            }

            progressNote = "Carving the record…"
            if isNewEdition, let record = editing {
                let txid = try await session.carveMediaUpdateOnChain(
                    kind: kind,
                    mediaId: record.id,
                    title: title,
                    did: did,
                    lang: lang.isEmpty ? nil : lang,
                    authors: authors.isEmpty ? nil : authors,
                    format: format.isEmpty ? nil : format,
                    summary: summary.isEmpty ? nil : summary
                )
                progressNote = nil
                onDone(.updated(txid))
            } else {
                let record = try await session.carveMediaPublishOnChain(
                    kind: kind,
                    title: title,
                    did: did,
                    lang: lang.isEmpty ? nil : lang,
                    authors: authors.isEmpty ? nil : authors,
                    format: format.isEmpty ? nil : format,
                    summary: summary.isEmpty ? nil : summary,
                    draftId: editing?.onChain == false ? editing?.id : nil
                )
                progressNote = nil
                onDone(.carved(record))
            }
        } catch {
            progressNote = nil
            self.error = String(describing: error)
        }
    }
}

// MARK: - view

/// Look at — or listen to — a published work, and the remarks anchored
/// to it.
///
/// The file is fetched the same way a text's body is, through
/// ``PublishBody/fetchURL(did:publisher:progress:)``: this Mac, then
/// our DISK, then the publisher's, hashed before anything is shown. So
/// what plays is the file the publisher committed to, or nothing.
struct MediaViewerSheet: View {
    let session: ActiveSession
    let kind: MediaKind
    let record: MediaRecord
    let name: (String) -> String?
    let onClose: () -> Void

    @State private var localURL: URL?
    @State private var image: NSImage?
    @State private var loading = true
    @State private var loadError: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            header
            Divider()

            ScrollView {
                VStack(alignment: .leading, spacing: 18) {
                    presentation
                    Divider()
                    RemarkThreadView(session: session, targetId: record.id, name: name)
                }
                .padding(.trailing, 4)
            }

            HStack {
                if localURL != nil {
                    Button("Save a copy…") { saveCopy() }
                    Button("Reveal in Finder") {
                        if let url = localURL { NSWorkspace.shared.activateFileViewerSelecting([url]) }
                    }
                }
                Spacer()
                Button("Close") { onClose() }
                    .keyboardShortcut(.cancelAction)
            }
        }
        .padding(20)
        .frame(width: 720, height: 760)
        .onAppear { load() }
    }

    // MARK: - header

    private var header: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 8) {
                Text(record.title?.isEmpty == false ? record.title! : "Untitled")
                    .font(.title3.bold())
                if record.isDeleted {
                    Text("Deleted")
                        .font(.caption2.bold())
                        .padding(.horizontal, 6).padding(.vertical, 2)
                        .background(Capsule().fill(Color.red.opacity(0.15)))
                        .foregroundStyle(.red)
                }
                Spacer()
                if let rate = record.tRate {
                    Text(String(format: "★ %.1f", rate))
                        .font(.callout)
                        .foregroundStyle(.orange)
                        .help("CDD-weighted over \(record.tCdd ?? 0) coin-days")
                }
            }

            HStack(spacing: 10) {
                FidAvatarView(fid: record.publisher ?? "", size: 22)
                CopyableText(
                    display: record.publisher.map { name($0) ?? $0.elidingMiddle(head: 8, tail: 8) } ?? "—",
                    copy: record.publisher ?? "",
                    font: .caption
                )
                if let ver = record.ver {
                    Text("edition \(ver)").font(.caption).foregroundStyle(.secondary)
                } else {
                    Text("edition —")
                        .font(.caption)
                        .foregroundStyle(.tertiary)
                        .help("This record was indexed before the server set an edition counter, so it has none. It is not a first edition; it is an unknown one.")
                }
                if let f = record.format, !f.isEmpty {
                    Text(f).font(.caption).foregroundStyle(.secondary)
                }
                if let t = record.lastTime {
                    Text(Date(timeIntervalSince1970: TimeInterval(t)).formatted(date: .abbreviated, time: .shortened))
                        .font(.caption).foregroundStyle(.secondary)
                }
            }

            if let summary = record.summary, !summary.isEmpty {
                Text(summary).font(.callout).foregroundStyle(.secondary)
            }

            HStack(spacing: 12) {
                idLine("Record", record.id)
                if let did = record.did { idLine("Document", did) }
            }
        }
    }

    private func idLine(_ label: String, _ value: String) -> some View {
        HStack(spacing: 3) {
            Text(label).font(.caption2).foregroundStyle(.tertiary)
            CopyableText(
                display: value.elidingMiddle(head: 8, tail: 8),
                copy: value,
                font: .system(.caption2, design: .monospaced)
            )
            .foregroundStyle(.secondary)
        }
    }

    // MARK: - the work itself

    @ViewBuilder
    private var presentation: some View {
        if loading {
            HStack(spacing: 8) {
                ProgressView().controlSize(.small)
                Text("Fetching the \(kind.noun)…").font(.callout).foregroundStyle(.secondary)
            }
        } else if let url = localURL {
            switch kind {
            case .image:
                if let image {
                    Image(nsImage: image)
                        .resizable()
                        .aspectRatio(contentMode: .fit)
                        .frame(maxWidth: .infinity, maxHeight: 400)
                        .clipShape(RoundedRectangle(cornerRadius: 8))
                } else {
                    undecodable
                }
            case .sound:
                AudioPlaybackView(url: url)
            case .video:
                VideoPlayer(player: AVPlayer(url: url))
                    .frame(height: 380)
                    .clipShape(RoundedRectangle(cornerRadius: 8))
            }
        } else if record.did == nil {
            Label("This record has no \(kind.noun)", systemImage: "questionmark.folder")
                .font(.callout)
                .foregroundStyle(.secondary)
        } else {
            VStack(alignment: .leading, spacing: 6) {
                Label("The \(kind.noun) could not be fetched", systemImage: "exclamationmark.triangle")
                    .font(.callout)
                    .foregroundStyle(.orange)
                if let e = loadError {
                    CopyableText(e, font: .caption).foregroundStyle(.secondary)
                }
                Button("Try again") { load() }
                    .controlSize(.small)
            }
        }
    }

    /// Bytes that hash correctly but nothing can open are the right
    /// file for the wrong kind of record — the media counterpart of
    /// ``PublishBody/Failure/notUtf8(did:)``.
    private var undecodable: some View {
        VStack(alignment: .leading, spacing: 6) {
            Label("Fetched, but not something macOS can show", systemImage: "questionmark.square")
                .font(.callout)
                .foregroundStyle(.orange)
            Text("The bytes hash to the carved document ID, so this is the right file — it is simply not \(kind == .image ? "an image" : "a \(kind.noun)") this Mac can decode. Save a copy and open it elsewhere.")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
    }

    private func load() {
        guard let did = record.did, !did.isEmpty else {
            loading = false
            return
        }
        loading = true
        loadError = nil
        Task {
            do {
                let url = try await session.publishBody.fetchURL(did: did, publisher: record.publisher)
                let decoded = kind == .image ? NSImage(contentsOf: url) : nil
                await MainActor.run {
                    localURL = url
                    image = decoded
                    loading = false
                }
            } catch {
                await MainActor.run {
                    loadError = String(describing: error)
                    loading = false
                }
            }
        }
    }

    private func saveCopy() {
        guard let source = localURL else { return }
        let fallback: String
        switch kind {
        case .image: fallback = "png"
        case .sound: fallback = "m4a"
        case .video: fallback = "mp4"
        }
        let panel = NSSavePanel()
        panel.nameFieldStringValue = (record.title?.isEmpty == false ? record.title! : kind.noun)
            + "." + (source.pathExtension.isEmpty ? fallback : source.pathExtension)
        guard panel.runModal() == .OK, let target = panel.url else { return }
        try? FileManager.default.removeItem(at: target)
        try? FileManager.default.copyItem(at: source, to: target)
    }
}
