import SwiftUI
import AppKit
import FCCore
import FCDomain
import FCUI

/// A team's consensus document: read it, or write one.
///
/// **The consensus is the only part of a team that is prose**, and the
/// only part a member is asked to *agree* to rather than simply observe.
/// It is also the part with no field on the chain: what is carved is a
/// hash, and the bytes it names live on the team's DISK. So this sheet
/// is the whole of the document's user interface — there is nowhere else
/// the text appears.
///
/// **Reading follows the same order everywhere: this Mac, then each
/// candidate DISK.** The candidates are plural on purpose. A team
/// midway through moving has its document on one server or the other,
/// and the reader has no way to tell which, so an update form offers
/// both the team's current DISK and the one typed into the box. Bytes
/// are hashed and refused unless they match the id, because a DISK is a
/// service, not an authority.
///
/// **A consensus is not always prose, and this sheet does not pretend
/// otherwise.** Nothing on the chain and nothing in the convention says
/// the bytes behind an id are text; owners on other clients carve PDFs
/// and word-processor files. Those arrive here fetched, hashed and
/// stored exactly like any other document — the only thing missing is a
/// text box that can show them — so the sheet names the file and hands
/// it over rather than reporting an encoding error about a document it
/// is holding.
///
/// **Saving stores locally and nothing else.** The id is the hash of the
/// text, so editing one word makes a different document with a different
/// id — and the caller is handed that new id rather than a bare success,
/// which is the whole point of saving. Uploading is deliberately not
/// here: the document goes to the *team's* DISK, which the settings
/// sheet knows about and this one does not, and it happens as part of
/// paying for the carve rather than quietly on a Save button.
struct ConsensusDocumentSheet: View {

    let session: ActiveSession
    /// What the sheet is about — "This team's consensus", "A new
    /// consensus". Not a document title: the document has none.
    let title: String
    /// The document to open. Empty means the team names none: writing
    /// starts from ``TeamConsensus/template``, which is how a new team
    /// gets one, and reading says there is nothing carved rather than
    /// showing the template as though it were the team's own words.
    let consensusId: String
    /// Where to look, in order, after this Mac. Usually the team's DISK
    /// and whatever a form has typed in it.
    let diskSids: [String]
    let editable: Bool
    /// Handed the id of a document that was **saved**, which is a new id
    /// whenever the text changed. Never called for a read.
    let onSaved: (String) -> Void
    let onClose: () -> Void

    @State private var text = ""
    @State private var loadedText = ""
    @State private var loading = true
    @State private var saving = false
    @State private var error: String?
    @State private var note: String?
    /// Set when the fetched bytes turned out not to be text. The
    /// document is *here* — verified, and on this Mac — so this drives
    /// a panel that offers the file rather than an error about it.
    @State private var file: FetchedFile?

    private struct FetchedFile {
        let url: URL
        let byteCount: Int64
        let kind: TeamConsensus.FileKind?
    }

    /// True once the text differs from what was loaded — and therefore
    /// once saving would produce a *different* id. Comparing the text
    /// rather than tracking edits is not laziness: the id is the hash,
    /// so text typed and untyped again really is the same document.
    private var isChanged: Bool { text != loadedText }

    private var currentId: String { TeamConsensus.id(for: text) }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 8) {
                Image(systemName: "doc.text").foregroundStyle(.teal)
                Text(title).font(.title3.bold())
                Spacer()
            }

            if !consensusId.isEmpty {
                CopyableText(
                    display: consensusId.elidingMiddle(head: 12, tail: 12),
                    copy: consensusId,
                    font: .caption
                )
                .foregroundStyle(.tertiary)
            }

            if loading {
                HStack(spacing: 8) {
                    ProgressView().controlSize(.small)
                    Text("Looking for the document…").font(.caption).foregroundStyle(.secondary)
                }
                .frame(maxWidth: .infinity, minHeight: 260)
            } else if let file {
                fileBody(file)
            } else if editable {
                TextEditor(text: $text)
                    .font(.system(.body, design: .monospaced))
                    .fieldEditorStyle(minHeight: 300)
            } else {
                ScrollView {
                    Text(text)
                        .font(.system(.body, design: .monospaced))
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(8)
                }
                .frame(minHeight: 300)
                .overlay(
                    RoundedRectangle(cornerRadius: 6)
                        .stroke(Color.secondary.opacity(0.3))
                )
            }

            if editable, !loading, file == nil {
                // The id the text currently hashes to, shown live. It is
                // what Save would hand back, and seeing it change as
                // words change is the clearest statement this app can
                // make about what content-addressing means.
                HStack(spacing: 6) {
                    Text(isChanged ? "Would save as" : "Saved as")
                        .font(.caption2).foregroundStyle(.tertiary)
                    CopyableText(
                        display: currentId.elidingMiddle(head: 8, tail: 8),
                        copy: currentId,
                        font: .caption2
                    )
                    .foregroundStyle(.tertiary)
                }
            }

            if let note {
                Text(note).font(.caption).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if let error {
                CopyableText(error, font: .caption).foregroundStyle(.red)
                    .fixedSize(horizontal: false, vertical: true)
            }

            HStack {
                Spacer()
                Button(editable ? "Cancel" : "Close", role: .cancel) { onClose() }
                if editable {
                    Button(saving ? "Saving…" : "Save") { save() }
                        .buttonStyle(.borderedProminent)
                        .keyboardShortcut(.defaultAction)
                        .disabled(saving || loading || text.isEmpty)
                }
            }
        }
        .padding(20)
        .frame(width: 640)
        .task(load)
    }

    // MARK: - a document that is not prose

    /// The document arrived, its hash matches the id, and it is not
    /// text.
    ///
    /// Deliberately not phrased as a failure, because nothing failed:
    /// the id names these bytes and the hash proves it. The one thing
    /// this Mac cannot do is render them, so the panel says what they
    /// are and hands them over — the app that opens a PDF is not this
    /// one.
    private func fileBody(_ file: FetchedFile) -> some View {
        VStack(spacing: 10) {
            Image(systemName: "doc.richtext")
                .font(.system(size: 36))
                .foregroundStyle(.teal)
            Text(file.kind.map { "This consensus is \($0.label), not text." }
                 ?? "This consensus is not text.")
                .font(.headline)
                .multilineTextAlignment(.center)
            Text("It downloaded and its bytes hash to the id above, so this is the document the team carved — \(ByteCountFormatter.string(fromByteCount: file.byteCount, countStyle: .file)) of it. Open it in something that reads \(file.kind?.fileExtension.uppercased() ?? "this kind of file").")
                .font(.caption)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .fixedSize(horizontal: false, vertical: true)
                .padding(.horizontal, 24)

            HStack(spacing: 8) {
                Button {
                    saveCopy(file)
                } label: {
                    Label("Save a copy…", systemImage: "square.and.arrow.down")
                }
                .buttonStyle(.borderedProminent)
                // Saving is the prominent action rather than opening
                // because this Mac's copy is named by the hash and has
                // no extension: the Finder has nothing to go on, and
                // the save panel is where the name gets fixed.
                .help("Write the bytes out under a name the Finder can open")

                Button {
                    NSWorkspace.shared.activateFileViewerSelecting([file.url])
                } label: {
                    Label("Show this Mac's copy", systemImage: "folder")
                }
                .help("The stored copy is named by the document's id, so it carries no file extension")
            }

            if editable {
                Divider().padding(.vertical, 4)
                Text("This sheet only writes text. Replacing \(file.kind?.label ?? "a document like this") means writing a new one in prose — and that is a different document with a different id, not an edit of this one.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .fixedSize(horizontal: false, vertical: true)
                    .padding(.horizontal, 24)
                Button("Write a text replacement") {
                    self.file = nil
                    text = TeamConsensus.template
                    loadedText = ""
                    note = "Starting from the template. Saving this makes a new document with a new id, and the team keeps the file it names now until a carve says otherwise."
                }
            }
        }
        .frame(maxWidth: .infinity, minHeight: 300)
        .overlay(
            RoundedRectangle(cornerRadius: 6)
                .stroke(Color.secondary.opacity(0.3))
        )
    }

    /// Write the bytes out where the user can open them.
    ///
    /// A copy rather than a move or a reveal: the stored file is
    /// content-addressed and the next read depends on it still being
    /// there under its own hash.
    private func saveCopy(_ file: FetchedFile) {
        let panel = NSSavePanel()
        panel.nameFieldStringValue = "team-consensus.\(file.kind?.fileExtension ?? "bin")"
        panel.canCreateDirectories = true
        guard panel.runModal() == .OK, let destination = panel.url else { return }
        do {
            if FileManager.default.fileExists(atPath: destination.path) {
                try FileManager.default.removeItem(at: destination)
            }
            try FileManager.default.copyItem(at: file.url, to: destination)
            error = nil
            note = "Saved to \(destination.path)."
        } catch {
            self.error = "Couldn't save a copy: \(String(describing: error))"
        }
    }

    // MARK: - actions

    @Sendable private func load() async {
        guard !consensusId.isEmpty else {
            await MainActor.run {
                loading = false
                loadedText = ""
                guard editable else {
                    // Nothing was carved, and the template is not an
                    // answer to that: putting it on screen would show a
                    // reader words their team never agreed to, in the
                    // one place the team's own words are supposed to
                    // be. Say the team names no document instead.
                    text = ""
                    note = "This team names no consensus document — there is nothing carved to read. Only the owner can put one there, by carving it in the team's settings."
                    return
                }
                // A team being created has no document yet, so it is offered
                // the questions rather than a blank box. See
                // ``TeamConsensus/template``.
                text = TeamConsensus.template
                note = "This is a starting point, not a consensus. Answer what applies, delete what does not, and rewrite anything that reads like a form."
            }
            return
        }
        do {
            let document = try await session.teamConsensus.read(
                consensusId: consensusId, diskSids: diskSids
            )
            await MainActor.run {
                loading = false
                guard let body = document.text else {
                    // Fetched, hashed and stored — just not prose. The
                    // panel takes it from here.
                    file = FetchedFile(
                        url: document.url,
                        byteCount: document.byteCount,
                        kind: document.kind
                    )
                    return
                }
                text = body
                loadedText = body
            }
        } catch {
            await MainActor.run {
                loading = false
                self.error = readFailure(error)
                if editable {
                    // An owner who cannot fetch the old text can still
                    // write a replacement, which is more useful than a
                    // locked box — but the sheet must not pretend the
                    // template is what the team currently runs on.
                    text = TeamConsensus.template
                    loadedText = ""
                    note = "Starting from the template instead. Saving this makes a new document with a new id — it does not recover the one above."
                }
            }
        }
    }

    /// Say which step actually failed.
    ///
    /// "Failed to download" when there was no DISK to try at all names a
    /// step that never ran, and sends the reader looking for a network
    /// problem that is not there. ``TeamConsensus/Failure/notHere(consensusId:)``
    /// is the case that matters: not on this device, and nowhere to ask.
    private func readFailure(_ error: Error) -> String {
        if let failure = error as? TeamConsensus.Failure {
            switch failure {
            case .notHere:
                return "This document is not on this Mac, and there is no DISK to read it from — the team publishes none, so nobody can fetch it. Setting the team's DISK is what fixes that."
            default:
                return String(describing: failure)
            }
        }
        return String(describing: error)
    }

    private func save() {
        saving = true
        error = nil
        do {
            let id = try session.teamConsensus.storeText(text, name: "team-consensus.txt")
            saving = false
            onSaved(id)
        } catch {
            saving = false
            self.error = String(describing: error)
        }
    }
}
