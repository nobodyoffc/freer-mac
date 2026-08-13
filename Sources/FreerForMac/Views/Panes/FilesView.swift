import SwiftUI
import UniformTypeIdentifiers
import AppKit
import FCCore
import FCDomain
import FCUI

/// Files pane — the Mac port of Android's `DataActivity` + `HatFileOpener`.
///
/// Lists the raw HATs (cipher HATs are an implementation detail of the
/// upload path and stay hidden), and drives the whole file lifecycle:
/// register, open, upload to DISK, download, and remove.
///
/// **Registering references, it does not copy.** Adding a file records
/// its path, so the row you see points at the user's own file in place.
/// That is why rows can go stale — moved, deleted, or edited behind the
/// app's back — and why every row shows where its bytes actually are.
struct FilesView: View {
    let session: ActiveSession

    @State private var rows: [Hat] = []
    @State private var statuses: [String: RowStatus] = [:]
    @State private var loadError: String?
    @State private var search = ""

    @State private var busy: [String: BusyKind] = [:]
    @State private var progressText: [String: String] = [:]
    @State private var banner: Banner?

    @State private var detailHat: Hat?
    @State private var pendingDelete: Hat?
    @State private var pendingUpload: Hat?
    @State private var showImport = false
    @State private var exportHat: Hat?
    @State private var isDropTargeted = false

    /// Where a row's bytes live right now — recomputed on load, and
    /// after anything that could move them.
    private enum RowStatus: Equatable {
        case localOnly
        case bothPlaces
        case remoteOnly
        case staleReference
        case missing

        var label: String {
            switch self {
            case .localOnly:       return "On this Mac"
            case .bothPlaces:      return "Local + DISK"
            case .remoteOnly:      return "On DISK"
            case .staleReference:  return "File changed"
            case .missing:         return "No copy"
            }
        }

        var color: Color {
            switch self {
            case .localOnly:      return .blue
            case .bothPlaces:     return .green
            case .remoteOnly:     return .purple
            case .staleReference: return .orange
            case .missing:        return .gray
            }
        }

        var help: String {
            switch self {
            case .localOnly:
                return "The file is on this Mac but not backed up to a DISK service."
            case .bothPlaces:
                return "Available locally and stored (encrypted) on a DISK service."
            case .remoteOnly:
                return "Stored on DISK. Opening it will download a copy first."
            case .staleReference:
                return "The original file was edited, so it no longer matches this record. Add it again to keep the new version."
            case .missing:
                return "No local file and nothing on DISK — only the record remains."
            }
        }
    }

    private enum BusyKind: Equatable {
        case uploading, downloading, opening
    }

    private struct Banner: Identifiable {
        enum Kind { case info, success, failure }
        let id = UUID()
        let kind: Kind
        let text: String
        /// Copying the DID/txid matters more than the sentence around it.
        var copyValue: String?
    }

    // MARK: - body

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            PaneHeader(session: session)
            Divider()
            toolbar
            if let banner { bannerView(banner) }
            if let loadError {
                card {
                    Label("Couldn't load files", systemImage: "exclamationmark.triangle")
                        .foregroundStyle(.red)
                    CopyableText(loadError, font: .callout).foregroundStyle(.red)
                }
            } else {
                list
            }
            Spacer(minLength: 0)
        }
        .padding()
        .frame(minWidth: 560)
        .onAppear(perform: reload)
        .onDrop(of: [.fileURL], isTargeted: $isDropTargeted) { providers in
            handleDrop(providers)
            return true
        }
        .overlay {
            if isDropTargeted {
                RoundedRectangle(cornerRadius: 12)
                    .strokeBorder(Color.accentColor, style: StrokeStyle(lineWidth: 2, dash: [6]))
                    .padding(4)
                    .allowsHitTesting(false)
            }
        }
        .sheet(item: $detailHat) { hat in
            HatDetailSheet(session: session, hat: hat) { detailHat = nil; reload() }
        }
        .sheet(item: $exportHat) { hat in
            HatExportSheet(hat: hat) { exportHat = nil }
        }
        .sheet(isPresented: $showImport) {
            HatImportSheet(session: session) { imported in
                showImport = false
                if let imported {
                    banner = Banner(kind: .success,
                                    text: "Imported \(imported) file record(s). Use Download to fetch their contents.")
                }
                reload()
            }
        }
        .alert(deleteTitle, isPresented: deleteBinding) {
            Button("Cancel", role: .cancel) { pendingDelete = nil }
            Button("Remove local copy", role: .destructive) {
                if let hat = pendingDelete { removeLocal(hat) }
                pendingDelete = nil
            }
            Button("Delete record", role: .destructive) {
                if let hat = pendingDelete { deleteRecord(hat) }
                pendingDelete = nil
            }
        } message: {
            Text("""
            “Remove local copy” frees space: it deletes copies this app made and forgets where the file was, keeping the record so you can download it again.

            “Delete record” removes the entry entirely. Neither option ever deletes your own file — the app only references it.
            """)
        }
        .alert("Upload \(pendingUpload?.displayName ?? "file") to DISK?", isPresented: uploadBinding) {
            Button("Cancel", role: .cancel) { pendingUpload = nil }
            Button("Store for now") {
                if let hat = pendingUpload { Task { await upload(hat, permanent: false) } }
                pendingUpload = nil
            }
            Button("Store permanently") {
                if let hat = pendingUpload { Task { await upload(hat, permanent: true) } }
                pendingUpload = nil
            }
        } message: {
            Text("""
            The file is encrypted with a fresh key before it leaves this Mac; only your key can unlock it.

            “Store for now” keeps it for a limited time and costs less. “Store permanently” pays once to keep it indefinitely.
            """)
        }
    }

    // MARK: - toolbar

    private var toolbar: some View {
        HStack(spacing: 12) {
            TextField("Search name, description, type, location…", text: $search)
                .textFieldStyle(.roundedBorder)
                .frame(maxWidth: 320)

            Spacer()

            Button {
                showImport = true
            } label: {
                Label("Import record", systemImage: "square.and.arrow.down.on.square")
            }
            .help("Paste or open a HAT record shared from another device")

            Button(action: addFiles) {
                Label("Add files", systemImage: "plus")
            }
            .buttonStyle(.borderedProminent)
            .help("Reference files on this Mac — they are not copied")
        }
    }

    @ViewBuilder
    private func bannerView(_ banner: Banner) -> some View {
        HStack(spacing: 6) {
            Image(systemName: {
                switch banner.kind {
                case .info:    return "info.circle"
                case .success: return "checkmark.seal"
                case .failure: return "exclamationmark.triangle"
                }
            }())
            if let copyValue = banner.copyValue {
                CopyableText(display: banner.text, copy: copyValue, font: .caption)
            } else {
                CopyableText(banner.text, font: .caption)
            }
            Spacer(minLength: 0)
            Button {
                self.banner = nil
            } label: {
                Image(systemName: "xmark.circle.fill")
            }
            .buttonStyle(.borderless)
        }
        .foregroundStyle({
            switch banner.kind {
            case .info:    return Color.secondary
            case .success: return Color.green
            case .failure: return Color.orange
            }
        }())
    }

    // MARK: - list

    private var visibleRows: [Hat] {
        let needle = search.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !needle.isEmpty else { return rows }
        return rows.filter { $0.matches(query: needle) }
    }

    @ViewBuilder
    private var list: some View {
        if rows.isEmpty {
            card {
                Label("No files yet", systemImage: "folder")
                    .foregroundStyle(.secondary)
                Text("Drag files here, or use Add files. Files stay where they are — Freer records where to find them and can back them up, encrypted, to a DISK service.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        } else if visibleRows.isEmpty {
            card {
                Label("Nothing matches “\(search)”", systemImage: "magnifyingglass")
                    .foregroundStyle(.secondary)
            }
        } else {
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 0) {
                    ForEach(visibleRows, id: \.id) { hat in
                        row(hat)
                            .padding(.vertical, 10)
                            .padding(.horizontal, 16)
                        Divider()
                    }
                }
                .background(Color(NSColor.controlBackgroundColor))
                .clipShape(RoundedRectangle(cornerRadius: 12))
            }
        }
    }

    @ViewBuilder
    private func row(_ hat: Hat) -> some View {
        let id = hat.id ?? ""
        let status = statuses[id] ?? .missing

        HStack(alignment: .top, spacing: 12) {
            Image(systemName: Self.icon(for: hat))
                .font(.title3)
                .foregroundStyle(.secondary)
                .frame(width: 40, height: 40)
                .background(Circle().fill(Color.secondary.opacity(0.1)))

            VStack(alignment: .leading, spacing: 4) {
                HStack(spacing: 6) {
                    Text(hat.displayName)
                        .font(.body.bold())
                        .lineLimit(1)
                        .truncationMode(.middle)
                    chip(status.label, color: status.color).help(status.help)
                }

                HStack(spacing: 8) {
                    if let size = hat.size {
                        Text(Self.formatBytes(size))
                    }
                    if let type = hat.mimeType {
                        Text(type)
                    }
                    if let last = hat.last {
                        Text(Self.formatDate(last))
                    }
                }
                .font(.caption)
                .foregroundStyle(.tertiary)

                CopyableText(
                    display: id.elidingMiddle(head: 10, tail: 8),
                    copy: id,
                    font: .system(.caption2, design: .monospaced)
                )
                .foregroundStyle(.tertiary)

                if let note = progressText[id] {
                    Text(note).font(.caption).foregroundStyle(.secondary)
                }
            }

            Spacer(minLength: 8)

            rowActions(hat, status: status)
        }
    }

    @ViewBuilder
    private func rowActions(_ hat: Hat, status: RowStatus) -> some View {
        let id = hat.id ?? ""
        HStack(spacing: 4) {
            if busy[id] != nil {
                ProgressView().controlSize(.small)
            } else {
                Button { detailHat = hat } label: { Image(systemName: "info.circle") }
                    .buttonStyle(.borderless)
                    .help("Show every field of this record")

                if status != .missing {
                    Button { Task { await open(hat) } } label: {
                        Image(systemName: "arrow.up.forward.app")
                    }
                    .buttonStyle(.borderless)
                    .help(status == .remoteOnly
                          ? "Download a copy and open it"
                          : "Open in the default app")
                }

                if status == .localOnly || status == .bothPlaces {
                    Button { revealInFinder(hat) } label: { Image(systemName: "folder") }
                        .buttonStyle(.borderless)
                        .help("Reveal in Finder")
                }

                if status == .localOnly || status == .bothPlaces {
                    Button { pendingUpload = hat } label: { Image(systemName: "icloud.and.arrow.up") }
                        .buttonStyle(.borderless)
                        .disabled(!session.canSign)
                        .help(session.canSign
                              ? "Encrypt and back up to a DISK service"
                              : "Watch-only identity — no key to encrypt with")
                }

                if status == .remoteOnly || status == .missing, hat.hasDiskSource {
                    Button { Task { await download(hat) } } label: {
                        Image(systemName: "icloud.and.arrow.down")
                    }
                    .buttonStyle(.borderless)
                    .help("Fetch a copy from DISK")
                }

                Button { exportHat = hat } label: { Image(systemName: "square.and.arrow.up") }
                    .buttonStyle(.borderless)
                    .help("Share this record — the JSON another device needs to fetch the file")

                Button(role: .destructive) { pendingDelete = hat } label: {
                    Image(systemName: "trash")
                }
                .buttonStyle(.borderless)
                .help("Remove the local copy, or delete the record")
            }
        }
        .foregroundStyle(.secondary)
    }

    // MARK: - loading

    private func reload() {
        do {
            rows = try session.hats.sortedByLastDesc()
            loadError = nil
            refreshStatuses()
        } catch {
            loadError = String(describing: error)
        }
    }

    /// Recompute where each row's bytes are. `resolve` heals the record
    /// as a side effect (pruning dead paths, detaching edited files),
    /// so this doubles as the pane's self-repair pass.
    private func refreshStatuses() {
        var next: [String: RowStatus] = [:]
        for hat in rows {
            guard let id = hat.id else { continue }
            let remote = hat.hasDiskSource
            do {
                switch try session.files.resolve(hatId: id) {
                case .available:
                    next[id] = remote ? .bothPlaces : .localOnly
                case .modified:
                    next[id] = .staleReference
                case .unavailable:
                    next[id] = remote ? .remoteOnly : .missing
                }
            } catch {
                next[id] = remote ? .remoteOnly : .missing
            }
        }
        statuses = next
    }

    // MARK: - registering

    private func addFiles() {
        let panel = NSOpenPanel()
        panel.allowsMultipleSelection = true
        panel.canChooseDirectories = false
        panel.canChooseFiles = true
        panel.message = "Files stay where they are — Freer records where to find them."
        panel.prompt = "Add"
        guard panel.runModal() == .OK else { return }
        register(urls: panel.urls)
    }

    private func handleDrop(_ providers: [NSItemProvider]) {
        Task {
            var urls: [URL] = []
            for provider in providers {
                if let url = try? await provider.loadFileURL() { urls.append(url) }
            }
            await MainActor.run { register(urls: urls) }
        }
    }

    private func register(urls: [URL]) {
        guard !urls.isEmpty else { return }
        var added = 0
        var failures: [String] = []
        for url in urls {
            do {
                try session.files.registerFile(at: url)
                added += 1
            } catch {
                failures.append("\(url.lastPathComponent): \(String(describing: error))")
            }
        }
        if failures.isEmpty {
            banner = Banner(kind: .success, text: "Added \(added) file\(added == 1 ? "" : "s").")
        } else {
            banner = Banner(
                kind: added > 0 ? .info : .failure,
                text: "Added \(added); couldn't add \(failures.count) — \(failures.joined(separator: "; "))"
            )
        }
        reload()
    }

    // MARK: - row actions

    private func open(_ hat: Hat) async {
        guard let id = hat.id else { return }
        if let url = try? session.files.localURL(hatId: id) {
            NSWorkspace.shared.open(url)
            return
        }
        // Remote-only: fetch first, then open — Android's HatFileOpener
        // does the same rather than telling the user to download twice.
        busy[id] = .opening
        progressText[id] = "Downloading…"
        defer { busy[id] = nil; progressText[id] = nil }
        do {
            let url = try await performDownload(hat)
            NSWorkspace.shared.open(url)
            reload()
        } catch {
            banner = Banner(kind: .failure, text: "Couldn't open \(hat.displayName): \(describe(error))")
        }
    }

    private func revealInFinder(_ hat: Hat) {
        guard let id = hat.id, let url = try? session.files.localURL(hatId: id) else { return }
        NSWorkspace.shared.activateFileViewerSelecting([url])
    }

    private func upload(_ hat: Hat, permanent: Bool) async {
        guard let id = hat.id else { return }
        guard let pubkey = session.liveKeyInfo.pubkey else {
            banner = Banner(kind: .failure, text: "This identity has no public key, so the file key can't be sealed.")
            return
        }
        busy[id] = .uploading
        progressText[id] = "Encrypting…"
        defer { busy[id] = nil; progressText[id] = nil }
        do {
            let result = try await session.hatSync.upload(
                hatId: id,
                permanent: permanent,
                ownPubkey: pubkey,
                progress: { sent, total in
                    Task { @MainActor in
                        progressText[id] = total > 0
                            ? "Uploading \(Self.formatBytes(sent)) of \(Self.formatBytes(total))…"
                            : "Uploading…"
                    }
                }
            )
            banner = Banner(
                kind: .success,
                text: "Backed up \(hat.displayName) — encrypted copy \(result.cipherHat.id?.elidingMiddle(head: 8, tail: 6) ?? "")",
                copyValue: result.cipherHat.id
            )
            reload()
        } catch {
            banner = Banner(kind: .failure, text: "Upload failed for \(hat.displayName): \(describe(error))")
        }
    }

    private func download(_ hat: Hat) async {
        guard let id = hat.id else { return }
        busy[id] = .downloading
        progressText[id] = "Downloading…"
        defer { busy[id] = nil; progressText[id] = nil }
        do {
            _ = try await performDownload(hat)
            banner = Banner(kind: .success, text: "Downloaded \(hat.displayName).")
            reload()
        } catch {
            banner = Banner(kind: .failure, text: "Download failed for \(hat.displayName): \(describe(error))")
        }
    }

    private func performDownload(_ hat: Hat) async throws -> URL {
        guard let id = hat.id else { throw HatSyncService.Failure.hatNotFound("") }
        // A HAT carrying a plaintext key (one shared with us) needs no
        // private key at all; otherwise we decrypt with our own.
        let privkey: Data? = session.canSign ? try? session.livePrikey() : nil
        return try await session.hatSync.download(
            hatId: id,
            privkey: privkey,
            progress: { received in
                Task { @MainActor in
                    progressText[id] = "Downloading \(Self.formatBytes(received))…"
                }
            }
        )
    }

    private func removeLocal(_ hat: Hat) {
        guard let id = hat.id else { return }
        do {
            try session.files.removeLocalData(hatId: id)
            banner = Banner(kind: .info, text: "Removed local copies of \(hat.displayName). Your own file was not touched.")
            reload()
        } catch {
            banner = Banner(kind: .failure, text: "Couldn't remove local data: \(describe(error))")
        }
    }

    private func deleteRecord(_ hat: Hat) {
        guard let id = hat.id else { return }
        do {
            try session.files.delete(hatId: id)
            banner = Banner(kind: .info, text: "Deleted the record for \(hat.displayName). Your own file was not touched.")
            reload()
        } catch {
            banner = Banner(kind: .failure, text: "Couldn't delete: \(describe(error))")
        }
    }

    // MARK: - alert bindings

    private var deleteTitle: String {
        "Remove \(pendingDelete?.displayName ?? "file")?"
    }

    private var deleteBinding: Binding<Bool> {
        Binding(get: { pendingDelete != nil }, set: { if !$0 { pendingDelete = nil } })
    }

    private var uploadBinding: Binding<Bool> {
        Binding(get: { pendingUpload != nil }, set: { if !$0 { pendingUpload = nil } })
    }

    // MARK: - small helpers

    private func card(@ViewBuilder _ content: () -> some View) -> some View {
        VStack(alignment: .leading, spacing: 8, content: content)
            .padding(20)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Color(NSColor.controlBackgroundColor))
            .clipShape(RoundedRectangle(cornerRadius: 12))
    }

    private func chip(_ text: String, color: Color) -> some View {
        Text(text)
            .font(.caption2.bold())
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .background(Capsule().fill(color.opacity(0.15)))
            .foregroundStyle(color)
    }

    private func describe(_ error: Error) -> String {
        if let e = error as? HatSyncService.Failure { return e.description }
        if let e = error as? DiskService.Failure { return e.description }
        if let e = error as? FileVault.Failure { return e.description }
        return String(describing: error)
    }

    static func icon(for hat: Hat) -> String {
        guard let mime = hat.mimeType?.lowercased() else { return "doc" }
        if mime.hasPrefix("image/") { return "photo" }
        if mime.hasPrefix("video/") { return "film" }
        if mime.hasPrefix("audio/") { return "music.note" }
        if mime.contains("pdf") { return "doc.richtext" }
        if mime.hasPrefix("text/") { return "doc.text" }
        if mime.contains("zip") || mime.contains("compressed") { return "archivebox" }
        return "doc"
    }

    static func formatBytes(_ bytes: Int64) -> String {
        ByteCountFormatter.string(fromByteCount: bytes, countStyle: .file)
    }

    static func formatDate(_ epochMs: Int64) -> String {
        let date = Date(timeIntervalSince1970: Double(epochMs) / 1000)
        let f = DateFormatter()
        f.dateStyle = .medium
        f.timeStyle = .short
        return f.string(from: date)
    }
}

// MARK: - drag & drop helper

private extension NSItemProvider {
    /// Bridge the callback-based file-URL load into async/await.
    func loadFileURL() async throws -> URL? {
        try await withCheckedThrowingContinuation { continuation in
            _ = loadObject(ofClass: URL.self) { url, error in
                if let error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume(returning: url)
                }
            }
        }
    }
}
