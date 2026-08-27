import SwiftUI
import AppKit
import FCCore
import FCDomain
import FCUI

// MARK: - compose

/// Write a statement and carve it.
///
/// **This sheet's job is to make sure nobody does this by accident.**
/// Every other publish in this app can be revised or retired; a
/// statement cannot. FEIP8 builds that into the protocol — the payload
/// must carry an exact confirmation sentence, and a parser that does
/// not find it byte for byte ignores the record — so the sentence is
/// shown here in full and has to be ticked by hand. It is never
/// pre-ticked, never remembered between statements, and re-arms the
/// moment the text changes: a confirmation that survives an edit is
/// confirming something the person did not read.
///
/// **The byte budget is a real constraint here, not a formality.** A
/// statement's text goes into the OP_RETURN uncompressed, so the
/// 4096-byte ceiling is reached by ordinary prose — roughly a page. The
/// remaining bytes are counted off the *encoded* envelope, because JSON
/// escaping makes a character count wrong by an unpredictable margin,
/// and Carve turns off before anyone can pay for a transaction that
/// cannot relay.
struct ComposeStatementSheet: View {
    let session: ActiveSession

    /// The draft being edited, or nil for a new statement. Only a draft
    /// can be edited — that is the entire difference this record has.
    let editing: Statement?

    enum Result {
        case carved(Statement)
        case draft
        case cancelled
    }

    let onDone: (Result) -> Void

    init(session: ActiveSession, editing: Statement? = nil, onDone: @escaping (Result) -> Void) {
        self.session = session
        self.editing = editing
        self.onDone = onDone
        _title = State(initialValue: editing?.title ?? "")
        _content = State(initialValue: editing?.content ?? "")
    }

    @State private var title: String
    @State private var content: String
    @State private var confirmed = false
    @State private var busy = false
    @State private var error: String?

    private var remaining: Int {
        StatementFeip.remainingContentBytes(
            title: title.isEmpty ? nil : title, content: content
        )
    }

    /// FEIP8 wants one of the two, not both.
    private var hasSomethingToSay: Bool {
        !title.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            || !content.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }

    private var canCarve: Bool {
        hasSomethingToSay && remaining >= 0 && confirmed && !busy && session.canSign
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Make a statement")
                .font(.title3.bold())

            Label(
                "A statement cannot be edited, deleted or recovered. Once a block confirms it, it is on the chain under your FID for as long as the chain exists.",
                systemImage: "exclamationmark.triangle"
            )
            .font(.caption)
            .foregroundStyle(.orange)

            ScrollView {
                VStack(alignment: .leading, spacing: 12) {
                    LabeledField("Title") {
                        VStack(alignment: .leading, spacing: 2) {
                            TextField("Optional — what the statement is about", text: $title)
                                .textFieldStyle(.roundedBorder)
                            Text("Carved on chain, like everything else here.")
                                .font(.caption2).foregroundStyle(.tertiary)
                        }
                    }

                    LabeledField("Statement") {
                        VStack(alignment: .leading, spacing: 4) {
                            TextEditor(text: $content)
                                .font(.body)
                                .frame(minHeight: 220)
                                .overlay(
                                    RoundedRectangle(cornerRadius: 6)
                                        .stroke(Color(NSColor.separatorColor))
                                )
                            HStack {
                                Text(remaining >= 0
                                     ? "\(remaining) bytes left in the carve"
                                     : "\(-remaining) bytes over the OP_RETURN limit")
                                    .font(.caption2.monospacedDigit())
                                    .foregroundStyle(remaining >= 0 ? AnyShapeStyle(.tertiary) : AnyShapeStyle(Color.red))
                                Spacer()
                                Text("The text goes into the transaction itself — not to DISK.")
                                    .font(.caption2).foregroundStyle(.tertiary)
                            }
                            if remaining < 0 {
                                Text("A statement is carved in full and is neither compressed nor stored off-chain. If it needs to be longer than this, publish it as a Text instead — that keeps the body on DISK and carves a hash of it.")
                                    .font(.caption2)
                                    .foregroundStyle(.orange)
                            }
                            if !hasSomethingToSay {
                                Text("FEIP8 needs at least one of a title and a statement.")
                                    .font(.caption2).foregroundStyle(.tertiary)
                            }
                        }
                    }
                }
                .padding(.trailing, 4)
            }
            .frame(maxHeight: 380)

            confirmation

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
                Button("Save draft") { saveDraft() }
                    .disabled(busy || !hasSomethingToSay)
                    .help("Keeps it on this Mac. A draft is the only form of a statement you can still change.")
                Button("Carve statement") { Task { await carve() } }
                    .buttonStyle(.borderedProminent)
                    .disabled(!canCarve)
                if busy { ProgressView().controlSize(.small) }
            }
        }
        .padding(20)
        .frame(width: 640)
        // Editing after confirming means the confirmation was for
        // different words. Re-arm rather than carry it forward.
        .onChange(of: content) { _, _ in confirmed = false }
        .onChange(of: title) { _, _ in confirmed = false }
    }

    /// The exact sentence FEIP8 puts in the payload, shown rather than
    /// paraphrased — what is ticked here is what is carved.
    private var confirmation: some View {
        Toggle(isOn: $confirmed) {
            VStack(alignment: .leading, spacing: 2) {
                Text("“\(StatementFeip.confirmPhrase)”")
                    .font(.callout.italic())
                Text("This sentence is carved with the statement. The protocol requires it, byte for byte, as proof that whoever signed knew it could never be taken back.")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }
        }
        .toggleStyle(.checkbox)
        .padding(10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(NSColor.controlBackgroundColor))
        .clipShape(RoundedRectangle(cornerRadius: 8))
    }

    // MARK: - actions

    private func saveDraft() {
        do {
            var draft = Statement.createLocal(
                title: title.isEmpty ? nil : title,
                content: content.isEmpty ? nil : content,
                publisher: session.liveFid
            )
            // The id is a digest of the payload, so an edited draft is a
            // new key and the old row has to go.
            if let editing, editing.onChain == false, editing.id != draft.id {
                _ = try? session.statements.remove(id: editing.id)
            }
            draft.addedAt = editing?.addedAt ?? Date()
            try session.statements.upsert(draft)
            onDone(.draft)
        } catch {
            self.error = String(describing: error)
        }
    }

    private func carve() async {
        busy = true
        defer { busy = false }
        error = nil
        do {
            let statement = try await session.carveStatementOnChain(
                title: title.isEmpty ? nil : title,
                content: content.isEmpty ? nil : content,
                draftId: editing?.onChain == false ? editing?.id : nil
            )
            onDone(.carved(statement))
        } catch {
            self.error = String(describing: error)
        }
    }
}

// MARK: - read

/// Read a statement. There is nothing to do to one, so there is nothing
/// on this sheet but the statement — no remark thread, no rating, no
/// edition, and no actions.
struct StatementReaderSheet: View {
    let session: ActiveSession
    let statement: Statement
    let name: (String) -> String?
    let onClose: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            VStack(alignment: .leading, spacing: 6) {
                if let title = statement.title, !title.isEmpty {
                    Text(title).font(.title3.bold())
                } else {
                    Text("Untitled statement")
                        .font(.title3.bold())
                        .foregroundStyle(.secondary)
                }

                HStack(spacing: 10) {
                    FidAvatarView(fid: statement.publisher ?? "", size: 22)
                    CopyableText(
                        display: statement.publisher.map {
                            name($0) ?? $0.elidingMiddle(head: 8, tail: 8)
                        } ?? "—",
                        copy: statement.publisher ?? "",
                        font: .caption
                    )
                    if let t = statement.birthTime {
                        Text(Date(timeIntervalSince1970: TimeInterval(t))
                            .formatted(date: .abbreviated, time: .shortened))
                            .font(.caption).foregroundStyle(.secondary)
                    }
                    if let h = statement.birthHeight, h != StatementsStore.unconfirmedHeight {
                        Text("block \(h)").font(.caption).foregroundStyle(.secondary)
                    } else if statement.onChain == nil {
                        Text("awaiting a block")
                            .font(.caption).foregroundStyle(.orange)
                    }
                }

                HStack(spacing: 3) {
                    Text("Record").font(.caption2).foregroundStyle(.tertiary)
                    CopyableText(
                        display: statement.id.elidingMiddle(head: 8, tail: 8),
                        copy: statement.id,
                        font: .system(.caption2, design: .monospaced)
                    )
                    .foregroundStyle(.secondary)
                }
            }

            Divider()

            ScrollView {
                Text(statement.content ?? "")
                    .font(.body)
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }

            Label(
                "Carved in full on the chain, and irrevocable. Nothing can edit or remove it.",
                systemImage: "lock"
            )
            .font(.caption)
            .foregroundStyle(.secondary)

            HStack {
                Button("Copy statement") {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(
                        [statement.title, statement.content]
                            .compactMap { $0 }.joined(separator: "\n\n"),
                        forType: .string
                    )
                }
                Spacer()
                Button("Close") { onClose() }
                    .keyboardShortcut(.cancelAction)
            }
        }
        .padding(20)
        .frame(width: 640, height: 560)
    }
}
