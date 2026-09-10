import SwiftUI
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
    /// The document to open. Empty starts from
    /// ``TeamConsensus/template``, which is how a new team gets one.
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
            } else if editable {
                TextEditor(text: $text)
                    .font(.system(.body, design: .monospaced))
                    .frame(minHeight: 300)
                    .overlay(
                        RoundedRectangle(cornerRadius: 6)
                            .stroke(Color.secondary.opacity(0.3))
                    )
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

            if editable, !loading {
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

    // MARK: - actions

    @Sendable private func load() async {
        guard !consensusId.isEmpty else {
            // A team being created has no document yet, so it is offered
            // the questions rather than a blank box. See
            // ``TeamConsensus/template``.
            await MainActor.run {
                text = TeamConsensus.template
                loadedText = ""
                loading = false
                note = "This is a starting point, not a consensus. Answer what applies, delete what does not, and rewrite anything that reads like a form."
            }
            return
        }
        do {
            let body = try await session.teamConsensus.readText(
                consensusId: consensusId, diskSids: diskSids
            )
            await MainActor.run {
                text = body
                loadedText = body
                loading = false
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
                    note = "Starting from the template instead. Saving this makes a **new** document with a new id — it does not recover the one above."
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
