import SwiftUI
import FCDomain
import FCUI

/// Release Sync's review page for one text, image, sound or video carve.
///
/// The file and its DID come from the release and are locked; the
/// metadata can be edited, and edits are written back to the work's entry
/// in `freeverse-release.json`. The locations are built from the release
/// and the manifest's mirrors, so they are shown, not edited here.
struct WorkReviewSheet: View {
    let review: ReleaseReview<WorkCarve>

    @State private var title: String
    @State private var type: String
    @State private var lang: String
    @State private var authors: String
    @State private var format: String
    @State private var summary: String

    init(review: ReleaseReview<WorkCarve>) {
        self.review = review
        let c = review.original
        _title = State(initialValue: c.title)
        _type = State(initialValue: c.type ?? "")
        _lang = State(initialValue: c.lang ?? "")
        _authors = State(initialValue: (c.authors ?? []).joined(separator: ", "))
        _format = State(initialValue: c.format ?? "")
        _summary = State(initialValue: c.summary ?? "")
    }

    private var edited: WorkCarve {
        var c = review.original
        func value(_ s: String) -> String? {
            let t = s.trimmingCharacters(in: .whitespacesAndNewlines)
            return t.isEmpty ? nil : t
        }
        c.title = title.trimmingCharacters(in: .whitespacesAndNewlines)
        c.type = c.kind == .text ? value(type) : nil
        c.lang = value(lang)
        let list = authors.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
        c.authors = list.isEmpty ? nil : list
        c.format = value(format)
        c.summary = value(summary)
        return c
    }

    /// The carve's size, or why it cannot go out.
    private var check: (bytes: Int?, error: String?) {
        do { return (try edited.json().utf8.count, nil) } catch { return (nil, String(describing: error)) }
    }

    var body: some View {
        let c = review.original
        VStack(alignment: .leading, spacing: 12) {
            ReleaseReviewNote(status: review.status,
                              text: "From the release: the file and its DID are locked. Edits are written back to freeverse-release.json.")
            Text("\(c.targetId == nil ? "Publish" : "Update") \(c.kind.label)").font(.headline)
            Form {
                TextField("Title", text: $title)
                if c.kind == .text { TextField("Type", text: $type) }
                TextField("Language", text: $lang)
                TextField("Authors", text: $authors, prompt: Text("FIDs or names, comma-separated"))
                TextField("Format", text: $format)
                TextField("Summary", text: $summary, axis: .vertical).lineLimit(3...8)
                LabeledContent("DID") {
                    CopyableText(display: c.did.elidingMiddle(head: 12, tail: 8), copy: c.did,
                                 font: .system(.caption, design: .monospaced))
                }
                if let id = c.targetId {
                    LabeledContent("Record") {
                        CopyableText(display: id.elidingMiddle(head: 12, tail: 8), copy: id,
                                     font: .system(.caption, design: .monospaced))
                    }
                }
                LabeledContent("Locations") {
                    VStack(alignment: .leading, spacing: 2) {
                        if c.disk { Text("This DISK, once the file is stored").font(.caption) }
                        ForEach(c.locas ?? [], id: \.self) { Text($0).font(.caption).textSelection(.enabled) }
                    }
                }
            }
            if let error = check.error {
                Text(error).font(.caption).foregroundStyle(.red)
            } else if let bytes = check.bytes {
                Text("OP_RETURN, \(bytes) bytes").font(.caption).foregroundStyle(.secondary)
            }
            ReleaseReviewButtons(
                canCarve: check.error == nil && !edited.title.isEmpty,
                stop: { review.decide(.stop) },
                skip: { review.decide(.skip) },
                carve: { review.decide(.carve(edited)) }
            )
        }
        .padding(20)
        .frame(width: 620)
    }
}
