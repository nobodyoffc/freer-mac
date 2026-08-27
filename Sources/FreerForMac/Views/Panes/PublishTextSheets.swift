import SwiftUI
import AppKit
import FCCore
import FCDomain
import FCUI

// MARK: - compose

/// Write a text and publish it — or save it, or publish a new edition
/// of one already on chain.
///
/// **Two things are paid for and they are paid for in that order.** The
/// body goes to DISK first and the metadata is carved second, because a
/// carve naming bytes nobody can fetch is a permanent dead link that
/// cost a fee. If the upload fails, nothing has been carved and nothing
/// is lost; if the carve fails, the bytes are on DISK and the same
/// Publish will reuse them, because the DID of unchanged text is the
/// same DID.
///
/// **The byte budget is on the metadata, not the work.** Only the
/// title, summary, authors and the 64-character `did` ride in the
/// OP_RETURN, so a novel and a note cost the same to publish. What can
/// still overflow is the summary and a long author list, which is what
/// the live counter watches.
struct PublishTextComposer: View {
    let session: ActiveSession

    /// The record being revised — a draft, or a carved record getting a
    /// new edition. Nil composes a new one.
    let editing: TextRecord?

    enum Result {
        case carved(TextRecord)
        case updated(String)
        case draft
        case cancelled
    }

    let onDone: (Result) -> Void

    init(session: ActiveSession, editing: TextRecord? = nil, onDone: @escaping (Result) -> Void) {
        self.session = session
        self.editing = editing
        self.onDone = onDone
        _title = State(initialValue: editing?.title ?? "")
        _summary = State(initialValue: editing?.summary ?? "")
        _type = State(initialValue: editing?.type ?? "")
        _lang = State(initialValue: editing?.lang ?? "")
        _format = State(initialValue: editing?.format ?? "markdown")
        _authorsText = State(initialValue: (editing?.authors ?? []).joined(separator: ", "))
    }

    @State private var title: String
    @State private var summary: String
    @State private var type: String
    @State private var lang: String
    @State private var format: String
    @State private var authorsText: String
    @State private var body_: String = ""

    @State private var loadingBody = false
    @State private var bodyError: String?
    @State private var busy = false
    @State private var progressNote: String?
    @State private var error: String?

    /// True once this record exists on chain — the editor is then
    /// producing an *edition*, not a first publish.
    private var isNewEdition: Bool { (editing?.onChain ?? false) != false && editing != nil }

    private var authors: [String] {
        authorsText
            .split(separator: ",")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
    }

    private var remaining: Int {
        TextFeip.remainingSummaryBytes(
            textId: isNewEdition ? editing?.id : nil,
            title: title,
            type: type.isEmpty ? nil : type,
            // The did is always 64 hex characters, so its cost is known
            // before the body exists. Measuring with a placeholder keeps
            // the budget honest for a draft that has not uploaded yet.
            did: String(repeating: "0", count: 64),
            lang: lang.isEmpty ? nil : lang,
            authors: authors.isEmpty ? nil : authors,
            format: format.isEmpty ? nil : format,
            summary: summary
        )
    }

    private var canPublish: Bool {
        !title.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            && !body_.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            && remaining >= 0
            && !busy
            && session.canSign
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text(isNewEdition ? "Publish a new edition" : "Write a text")
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
                    LabeledField("Title") {
                        TextField("What the work is called", text: $title)
                            .textFieldStyle(.roundedBorder)
                    }

                    LabeledField("The work") {
                        VStack(alignment: .leading, spacing: 4) {
                            if loadingBody {
                                HStack(spacing: 6) {
                                    ProgressView().controlSize(.small)
                                    Text("Fetching the body…").font(.caption).foregroundStyle(.secondary)
                                }
                            }
                            TextEditor(text: $body_)
                                .font(.body)
                                .frame(minHeight: 200)
                                .overlay(
                                    RoundedRectangle(cornerRadius: 6)
                                        .stroke(Color(NSColor.separatorColor))
                                )
                            HStack(spacing: 8) {
                                Text("\(Data(body_.utf8).count) bytes — stored on DISK, not on the chain")
                                    .font(.caption2)
                                    .foregroundStyle(.tertiary)
                                if let e = bodyError {
                                    CopyableText(e, font: .caption2).foregroundStyle(.orange)
                                }
                            }
                        }
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
                        LabeledField("Type") {
                            TextField("essay, note, article…", text: $type)
                                .textFieldStyle(.roundedBorder)
                        }
                        LabeledField("Language") {
                            TextField("en, zh…", text: $lang)
                                .textFieldStyle(.roundedBorder)
                        }
                        LabeledField("Format") {
                            TextField("markdown, plain…", text: $format)
                                .textFieldStyle(.roundedBorder)
                        }
                    }

                    LabeledField("Authors") {
                        VStack(alignment: .leading, spacing: 4) {
                            TextField("FIDs or names, comma separated", text: $authorsText)
                                .textFieldStyle(.roundedBorder)
                            if !authors.isEmpty {
                                // Echo the parse back, so what will be
                                // carved is never a guess the writer
                                // cannot see.
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
                        .help("Keeps the work on this Mac. Nothing is uploaded and nothing is carved.")
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
        .onAppear { loadBody() }
    }

    // MARK: - body

    /// A draft keeps its text in the HAT store under the DID it will be
    /// published as, so reopening one is a local read. A carved record
    /// being revised fetches its current body the same way the reader
    /// does — including from the publisher's DISK, since the reviser is
    /// the publisher.
    private func loadBody() {
        guard let did = editing?.did, !did.isEmpty, body_.isEmpty else { return }
        loadingBody = true
        Task {
            do {
                let text = try await session.publishBody.read(
                    did: did, publisher: editing?.publisher
                )
                await MainActor.run {
                    body_ = text
                    loadingBody = false
                }
            } catch {
                await MainActor.run {
                    bodyError = "Couldn't load the existing body — \(error). Publishing an edition with an empty body would replace the pointer, so write it again or cancel."
                    loadingBody = false
                }
            }
        }
    }

    // MARK: - actions

    private func saveDraft() {
        do {
            // The body is written and registered but not uploaded: a
            // draft costs nothing until somebody chooses to pay.
            let did = body_.isEmpty ? nil : try session.publishBody.storeLocally(body_, name: "\(title).txt")
            var draft = TextRecord.createLocal(
                title: title,
                type: type.isEmpty ? nil : type,
                did: did,
                lang: lang.isEmpty ? nil : lang,
                authors: authors.isEmpty ? nil : authors,
                format: format.isEmpty ? nil : format,
                summary: summary.isEmpty ? nil : summary,
                publisher: session.liveFid
            )
            // Re-saving an existing draft replaces it rather than
            // leaving a second row: the id is a digest of the content,
            // so an edit produces a new key and the old one has to go.
            if let editing, editing.onChain == false, editing.id != draft.id {
                _ = try? session.texts.remove(id: editing.id)
            }
            draft.addedAt = editing?.addedAt ?? Date()
            try session.texts.upsert(draft)
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
            progressNote = "Uploading the body to DISK…"
            let did = try await session.publishBody.store(body_, name: "\(title).txt")

            progressNote = "Carving the record…"
            if isNewEdition, let record = editing {
                let txid = try await session.carveTextUpdateOnChain(
                    textId: record.id,
                    title: title,
                    type: type.isEmpty ? nil : type,
                    did: did,
                    lang: lang.isEmpty ? nil : lang,
                    authors: authors.isEmpty ? nil : authors,
                    format: format.isEmpty ? nil : format,
                    summary: summary.isEmpty ? nil : summary
                )
                progressNote = nil
                onDone(.updated(txid))
            } else {
                let record = try await session.carveTextPublishOnChain(
                    title: title,
                    type: type.isEmpty ? nil : type,
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

// MARK: - read

/// Read a published text, and the remarks anchored to it.
///
/// **The body is fetched, not carried.** What the chain holds is a
/// hash; this sheet asks ``PublishBody`` for the bytes behind it, which
/// tries this Mac, then our own DISK, then the publisher's. Every one
/// of those verifies the hash before showing a word, so what is on
/// screen is the work the publisher committed to or nothing at all.
struct TextReaderSheet: View {
    let session: ActiveSession
    let record: TextRecord
    let name: (String) -> String?
    let onClose: () -> Void

    @State private var body_: String?
    @State private var loadingBody = true
    @State private var bodyError: String?


    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            header
            Divider()

            ScrollView {
                VStack(alignment: .leading, spacing: 18) {
                    bodySection
                    Divider()
                    RemarkThreadView(session: session, targetId: record.id, name: name)
                }
                .padding(.trailing, 4)
            }

            HStack {
                Spacer()
                Button("Close") { onClose() }
                    .keyboardShortcut(.cancelAction)
            }
        }
        .padding(20)
        .frame(width: 680, height: 680)
        .onAppear { loadBody() }
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

    // MARK: - body

    @ViewBuilder
    private var bodySection: some View {
        if loadingBody {
            HStack(spacing: 8) {
                ProgressView().controlSize(.small)
                Text("Fetching the work…").font(.callout).foregroundStyle(.secondary)
            }
        } else if let text = body_ {
            Text(text)
                .font(.body)
                .textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading)
        } else if record.did == nil {
            Label("This record has no body", systemImage: "doc")
                .font(.callout)
                .foregroundStyle(.secondary)
        } else {
            VStack(alignment: .leading, spacing: 6) {
                Label("The work could not be fetched", systemImage: "exclamationmark.triangle")
                    .font(.callout)
                    .foregroundStyle(.orange)
                if let e = bodyError {
                    CopyableText(e, font: .caption).foregroundStyle(.secondary)
                }
                Button("Try again") { loadBody() }
                    .controlSize(.small)
            }
        }
    }

    private func loadBody() {
        guard let did = record.did, !did.isEmpty else {
            loadingBody = false
            return
        }
        loadingBody = true
        bodyError = nil
        Task {
            do {
                let text = try await session.publishBody.read(did: did, publisher: record.publisher)
                await MainActor.run {
                    body_ = text
                    loadingBody = false
                }
            } catch {
                await MainActor.run {
                    bodyError = String(describing: error)
                    loadingBody = false
                }
            }
        }
    }
}
