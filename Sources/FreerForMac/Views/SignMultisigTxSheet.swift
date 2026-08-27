import SwiftUI
import UniformTypeIdentifiers
import FCCore
import FCDomain
import FCUI

/// The co-sign surface — propose a spend from a group, sign one, or
/// merge what other members send back. The Mac answer to Android's
/// `BuildMultisigTxActivity` + `SignMultisigTxActivity` +
/// `MultisigTxDetailFragment`, as one sheet because they are three
/// views of a single document.
///
/// **The document is the unit of work.** A multisig spend is a
/// conversation: somebody proposes, members sign wherever they are,
/// and the partials are merged until the threshold is met. What moves
/// between them is a `RawTxInfo` — the same cold-sign JSON the
/// watch-only Send path exports — carrying the signatures gathered so
/// far. This sheet loads one, shows what it does and who has signed,
/// and offers the next step.
///
/// **Every signature commits to the whole transaction**, so the
/// document that goes out must be the one that comes back. Editing the
/// amount after a member has signed voids their signature; the merge
/// refuses to combine documents that disagree rather than producing a
/// transaction that fails at the node.
struct SignMultisigTxSheet: View {
    let session: ActiveSession
    /// The group this sheet was opened for. A loaded document must
    /// match it — signing for the wrong group is a mistake worth
    /// catching here, not at broadcast.
    let groupFid: String
    let onDone: (String) -> Void
    let onCancel: () -> Void

    @State private var document: RawTxInfo?
    @State private var status: MultisigCosign.Status?
    @State private var busy = false
    @State private var error: String?
    @State private var note: String?

    // proposal inputs
    @State private var recipient = ""
    @State private var amountText = ""
    @State private var pick: FidPickerRequest?

    // import
    @State private var importText = ""
    @State private var showImport = false

    private var group: Multisig? { session.multisigGroup(for: groupFid) }

    private var amountSats: Int64? {
        let t = amountText.trimmingCharacters(in: .whitespaces)
        guard !t.isEmpty, let v = Int64(t), v > 0 else { return nil }
        return v
    }

    private var canPropose: Bool {
        !busy && amountSats != nil && (try? FchAddress(fid: recipient)) != nil
    }

    /// Whether this Setting's main FID still owes a signature.
    private var weCanSign: Bool {
        guard let status else { return false }
        return status.group.contains(session.mainFid)
            && !status.signed.contains(session.mainFid)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header
            Divider()
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    if document == nil {
                        proposePanel
                        importPanel
                    } else {
                        documentPanel
                        signersPanel
                        exportPanel
                    }
                    if let error {
                        Label(error, systemImage: "xmark.octagon.fill")
                            .font(.callout)
                            .foregroundStyle(.red)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    if let note {
                        Label(note, systemImage: "info.circle")
                            .font(.callout)
                            .foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
                .padding(16)
            }
            Divider()
            footer
        }
        .frame(minWidth: 620, minHeight: 620)
        .sheet(item: $pick) { request in
            FidPickerSheet(session: session, request: request) { picked in
                pick = nil
                if let one = picked.first { recipient = one.fid }
            } onCancel: {
                pick = nil
            }
        }
    }

    // MARK: - panels

    private var header: some View {
        HStack(spacing: 12) {
            Image(systemName: "signature")
                .font(.title2)
                .foregroundStyle(.secondary)
            VStack(alignment: .leading, spacing: 2) {
                Text("Multisig transaction")
                    .font(.title2).bold()
                HStack(spacing: 6) {
                    if let g = group, let m = g.m, let n = g.n {
                        Text("\(m)-of-\(n)")
                            .font(.caption.bold())
                    }
                    CopyableText(
                        display: groupFid.elidingMiddle(head: 10, tail: 10),
                        copy: groupFid,
                        font: .caption.monospaced()
                    )
                    .foregroundStyle(.secondary)
                }
            }
            Spacer()
            if document != nil {
                Button("Start over") { reset() }
                    .buttonStyle(.link)
            }
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 12)
    }

    private var proposePanel: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Propose a spend")
                .font(.caption.bold()).textCase(.uppercase)
                .foregroundStyle(.secondary)

            LabeledField("Pay to", hint: nil) {
                HStack(spacing: 8) {
                    TextField("", text: $recipient, prompt: Text("F…"))
                        .font(.system(.body, design: .monospaced))
                        .fieldInputStyle()
                    Button {
                        pick = .one(
                            title: "Pay whom?",
                            subtitle: "Where this group's coins go.",
                            initialQuery: recipient
                        )
                    } label: {
                        Label("Find…", systemImage: "person.text.rectangle")
                    }
                }
            }
            LabeledField("Amount", hint: "In satoshis.") {
                TextField("", text: $amountText, prompt: Text("10000"))
                    .font(.system(.body, design: .monospaced))
                    .fieldInputStyle()
            }
            HStack {
                Spacer()
                Button {
                    Task { await propose() }
                } label: {
                    if busy {
                        HStack(spacing: 6) {
                            ProgressView().controlSize(.small)
                            Text("Building…")
                        }
                    } else {
                        Text("Build proposal")
                    }
                }
                .buttonStyle(.borderedProminent)
                .disabled(!canPropose)
            }
            Text("Builds the transaction and signs it as you. Send the result to the other members.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    private var importPanel: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Or open one you were sent")
                .font(.caption.bold()).textCase(.uppercase)
                .foregroundStyle(.secondary)
            TextEditor(text: $importText)
                .font(.system(.caption, design: .monospaced))
                .frame(minHeight: 90)
                .overlay(
                    RoundedRectangle(cornerRadius: 5)
                        .stroke(Color.secondary.opacity(0.3))
                )
            HStack {
                Text("Paste the JSON a member sent you.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Spacer()
                Button("Open") { load(importText) }
                    .disabled(importText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            }
        }
    }

    @ViewBuilder
    private var documentPanel: some View {
        if let doc = document {
            VStack(alignment: .leading, spacing: 6) {
                Text("This transaction")
                    .font(.caption.bold()).textCase(.uppercase)
                    .foregroundStyle(.secondary)
                ForEach(Array((doc.outputs ?? []).enumerated()), id: \.offset) { _, out in
                    HStack(spacing: 6) {
                        Image(systemName: "arrow.right")
                            .font(.caption).foregroundStyle(.secondary)
                        Text("\(out.value ?? 0) sat")
                            .font(.body.monospaced())
                        Text("to").foregroundStyle(.secondary)
                        CopyableText(
                            display: (out.owner ?? "?").elidingMiddle(head: 8, tail: 8),
                            copy: out.owner ?? "",
                            font: .body.monospaced()
                        )
                    }
                }
                Text("\((doc.inputs ?? []).count) input(s) · \(doc.totalIn) sat in · \(doc.totalIn - doc.totalOut) sat to fee and change")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                if let op = doc.opReturn, !op.isEmpty {
                    Text("op_return: \(op.elidingMiddle(head: 16, tail: 16))")
                        .font(.caption.monospaced())
                        .foregroundStyle(.secondary)
                }
            }
            .padding(10)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(
                RoundedRectangle(cornerRadius: 6, style: .continuous)
                    .fill(Color.secondary.opacity(0.08))
            )
        }
    }

    @ViewBuilder
    private var signersPanel: some View {
        if let status {
            VStack(alignment: .leading, spacing: 8) {
                HStack(spacing: 8) {
                    Text(status.isComplete
                         ? "Ready to broadcast"
                         : "\(status.remaining) more signature\(status.remaining == 1 ? "" : "s") needed")
                        .font(.headline)
                        .foregroundStyle(status.isComplete ? .green : .primary)
                    Spacer()
                    Text("\(status.signed.count) of \(status.group.m) required · \(status.group.n) members")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                ForEach(status.group.fids, id: \.self) { fid in
                    let signed = status.signed.contains(fid)
                    HStack(spacing: 8) {
                        Image(systemName: signed ? "checkmark.circle.fill" : "circle.dashed")
                            .foregroundStyle(signed ? .green : .secondary)
                        FidAvatarView(fid: fid, size: 22)
                        CopyableText(
                            display: fid.elidingMiddle(head: 10, tail: 10),
                            copy: fid,
                            font: .caption.monospaced()
                        )
                        if fid == session.mainFid {
                            Text("you").font(.caption2)
                                .padding(.horizontal, 5).padding(.vertical, 1)
                                .background(Capsule().fill(Color.accentColor.opacity(0.18)))
                        }
                        Spacer()
                        Text(signed ? "signed" : "waiting")
                            .font(.caption)
                            .foregroundStyle(signed ? AnyShapeStyle(.green) : AnyShapeStyle(.tertiary))
                    }
                }
            }
        }
    }

    @ViewBuilder
    private var exportPanel: some View {
        if let doc = document, let json = exportJson(doc) {
            VStack(alignment: .leading, spacing: 8) {
                Text("Pass it on")
                    .font(.caption.bold()).textCase(.uppercase)
                    .foregroundStyle(.secondary)
                HStack(spacing: 8) {
                    Button {
                        NSPasteboard.general.clearContents()
                        NSPasteboard.general.setString(json, forType: .string)
                        note = "Copied. Send it to the members who have not signed."
                    } label: {
                        Label("Copy document", systemImage: "doc.on.doc")
                    }
                    Button { save(json) } label: {
                        Label("Save…", systemImage: "square.and.arrow.down")
                    }
                    Spacer()
                }
                Text("The group is not included — every member rebuilds it from the inputs, so the document reveals no membership to whoever carries it.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)

                Divider().padding(.vertical, 2)

                Text("Merge a reply")
                    .font(.caption.bold()).textCase(.uppercase)
                    .foregroundStyle(.secondary)
                TextEditor(text: $importText)
                    .font(.system(.caption, design: .monospaced))
                    .frame(minHeight: 70)
                    .overlay(
                        RoundedRectangle(cornerRadius: 5)
                            .stroke(Color.secondary.opacity(0.3))
                    )
                HStack {
                    Spacer()
                    Button("Merge") { merge(importText) }
                        .disabled(importText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                }
            }
        }
    }

    private var footer: some View {
        HStack {
            Spacer()
            Button("Close", role: .cancel) { onCancel() }
                .keyboardShortcut(.cancelAction)
            if weCanSign {
                Button("Sign as me") { sign() }
                    .disabled(busy)
            }
            if let status, status.isComplete {
                Button {
                    Task { await broadcast() }
                } label: {
                    if busy {
                        HStack(spacing: 6) {
                            ProgressView().controlSize(.small)
                            Text("Broadcasting…")
                        }
                    } else {
                        Text("Broadcast")
                    }
                }
                .buttonStyle(.borderedProminent)
                .disabled(busy)
            }
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 12)
    }

    // MARK: - actions

    private func reset() {
        document = nil
        status = nil
        importText = ""
        error = nil
        note = nil
    }

    /// Recompute the status panel. Also the one place a document is
    /// checked against the group this sheet is for — a mismatch here
    /// means somebody pasted the wrong conversation.
    private func refreshStatus() {
        guard let doc = document else {
            status = nil
            return
        }
        do {
            let s = try MultisigCosign.status(doc)
            guard s.group.fid == groupFid else {
                status = nil
                error = "That document spends from \(s.group.fid.elidingMiddle(head: 8, tail: 8)), not this group."
                document = nil
                return
            }
            status = s
        } catch {
            status = nil
            self.error = String(describing: error)
            document = nil
        }
    }

    @MainActor
    private func propose() async {
        guard let amount = amountSats else { return }
        busy = true
        error = nil
        note = nil
        defer { busy = false }
        do {
            let proposed = try await session.proposeMultisigSpend(
                groupFid: groupFid,
                to: recipient.trimmingCharacters(in: .whitespaces),
                amount: amount
            )
            // Sign it as ourselves straight away: a proposal nobody has
            // signed is one more round trip for no reason, and the
            // proposer is nearly always a member.
            document = (try? session.signMultisigDocument(proposed)) ?? proposed
            refreshStatus()
        } catch {
            self.error = String(describing: error)
        }
    }

    private func sign() {
        guard let doc = document else { return }
        error = nil
        do {
            document = try session.signMultisigDocument(doc)
            refreshStatus()
            note = "Signed. Send the document to the remaining members."
        } catch {
            self.error = String(describing: error)
        }
    }

    private func load(_ text: String) {
        error = nil
        note = nil
        guard let doc = decode(text) else { return }
        document = doc
        importText = ""
        refreshStatus()
    }

    private func merge(_ text: String) {
        guard let mine = document, let theirs = decode(text) else { return }
        error = nil
        do {
            document = try MultisigCosign.merge([mine, theirs])
            importText = ""
            refreshStatus()
            note = "Merged."
        } catch {
            self.error = String(describing: error)
        }
    }

    private func decode(_ text: String) -> RawTxInfo? {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let data = trimmed.data(using: .utf8) else {
            error = "That is not text this can read."
            return nil
        }
        do {
            return try JSONDecoder().decode(RawTxInfo.self, from: data)
        } catch {
            self.error = "Not a transaction document — \(error)"
            return nil
        }
    }

    private func exportJson(_ doc: RawTxInfo) -> String? {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        guard let data = try? encoder.encode(doc) else { return nil }
        return String(data: data, encoding: .utf8)
    }

    private func save(_ json: String) {
        let panel = NSSavePanel()
        panel.allowedContentTypes = [.json]
        panel.nameFieldStringValue = "multisig-tx.json"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            try json.write(to: url, atomically: true, encoding: .utf8)
            note = "Saved to \(url.lastPathComponent)."
        } catch {
            self.error = String(describing: error)
        }
    }

    @MainActor
    private func broadcast() async {
        guard let doc = document else { return }
        busy = true
        error = nil
        defer { busy = false }
        do {
            let txid = try await session.broadcastMultisigDocument(doc)
            onDone(txid)
        } catch {
            self.error = String(describing: error)
        }
    }
}
