import SwiftUI
import AppKit
import FCCore
import FCDomain
import FCUI

// MARK: - issue

/// Write and carve a proof — the Mac port of Android's
/// `IssueProofActivity`.
///
/// **The byte budget is the whole design.** A proof's text goes into an
/// OP_RETURN uncompressed and unencrypted, so the 4096-byte ceiling is
/// reached by ordinary prose, not by pathological input. Android has no
/// check at all: you write your agreement, press Carve, and the
/// transaction fails at broadcast with a message about script size.
/// Here the remaining bytes are counted live off the *encoded* envelope
/// — JSON escaping makes a character count wrong by an unpredictable
/// margin — and the Carve button turns off before the user can pay for
/// a transaction that cannot relay.
struct IssueProofSheet: View {
    let session: ActiveSession

    /// The draft being edited, or nil to compose a new proof. Only a
    /// draft is editable: once carved, a proof's text is what the chain
    /// says it is, which is the entire point of having one.
    let editing: Proof?

    enum Result {
        case carved(Proof)
        case draft
        case cancelled
    }

    let onDone: (Result) -> Void

    init(session: ActiveSession, editing: Proof? = nil, onDone: @escaping (Result) -> Void) {
        self.session = session
        self.editing = editing
        self.onDone = onDone
        _title = State(initialValue: editing?.title ?? "")
        _content = State(initialValue: editing?.content ?? "")
        _cosigners = State(initialValue: editing?.cosignersInvited ?? [])
        _transferable = State(initialValue: editing?.transferable ?? false)
        _allSignsRequired = State(initialValue: editing?.allSignsRequired ?? false)
    }

    @State private var title: String
    @State private var content: String
    @State private var cosigners: [String]
    @State private var names: [String: String] = [:]
    @State private var transferable: Bool
    @State private var allSignsRequired: Bool

    @State private var pick: FidPickerRequest?
    @State private var busy = false
    @State private var error: String?

    private var remaining: Int {
        ProofFeip.remainingContentBytes(
            title: title, content: content,
            cosigners: cosigners.isEmpty ? nil : cosigners,
            transferable: transferable,
            allSignsRequired: cosigners.isEmpty ? nil : allSignsRequired
        )
    }

    private var canCarve: Bool {
        !title.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            && !content.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            && remaining >= 0
            && session.canSign
            && !busy
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text(editing == nil ? "Issue a proof" : "Edit draft")
                .font(.title3.bold())

            Text("Everything below goes onto the chain in the clear, signed by \(session.liveFid.elidingMiddle(head: 8, tail: 8)). Anyone can read it; nobody can change it — which is why this is the last point at which it can be edited.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            field("Title") {
                TextField("What this proof is", text: $title)
                    .textFieldStyle(.roundedBorder)
            }

            field("Content") {
                VStack(alignment: .leading, spacing: 4) {
                    TextEditor(text: $content)
                        .font(.body)
                        .frame(minHeight: 120, maxHeight: 200)
                        .overlay(
                            RoundedRectangle(cornerRadius: 6)
                                .stroke(Color(NSColor.separatorColor))
                        )
                    HStack {
                        Text(remaining >= 0
                             ? "\(remaining) bytes left"
                             : "\(-remaining) bytes over the limit")
                            .font(.caption.monospacedDigit())
                            .foregroundStyle(remaining < 0 ? .red : (remaining < 256 ? .orange : .secondary))
                        Spacer()
                        Text("A proof is stored whole in one transaction — \(ProofFeip.maxOpReturnSize) bytes for everything.")
                            .font(.caption2)
                            .foregroundStyle(.tertiary)
                    }
                }
            }

            field("Cosigners") {
                VStack(alignment: .leading, spacing: 6) {
                    if cosigners.isEmpty {
                        Text("Nobody — the proof stands on your signature alone.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    } else {
                        ForEach(cosigners, id: \.self) { fid in
                            HStack(spacing: 6) {
                                FidAvatarView(fid: fid, size: 20)
                                CopyableText(
                                    display: names[fid] ?? fid.elidingMiddle(head: 8, tail: 8),
                                    copy: fid,
                                    font: .system(.caption, design: .monospaced)
                                )
                                Button {
                                    cosigners.removeAll { $0 == fid }
                                } label: {
                                    Image(systemName: "xmark.circle.fill")
                                        .foregroundStyle(.secondary)
                                }
                                .buttonStyle(.plain)
                                Spacer()
                            }
                        }
                    }
                    Button {
                        pick = .many(
                            title: "Invite cosigners",
                            subtitle: "They will be asked to countersign this proof on chain.",
                            excluded: Set(cosigners).union([session.liveFid])
                        )
                    } label: {
                        Label("Add cosigners", systemImage: "person.badge.plus")
                    }
                    .controlSize(.small)
                }
            }

            Toggle("Transferable — ownership can be handed to someone else", isOn: $transferable)
                .help("Fixed at issue. There is no op to make a proof transferable afterwards.")

            Toggle("All invited signatures required before it takes force", isOn: $allSignsRequired)
                .disabled(cosigners.isEmpty)
                .help(cosigners.isEmpty
                      ? "Only means something once you have invited cosigners"
                      : "Until the last invited cosigner signs, the chain will not mark this proof active")

            if let error {
                CopyableText(error, font: .caption).foregroundStyle(.red)
            }

            if !session.canSign {
                Text("This identity is watch-only, so it cannot sign a carve. You can still save a draft and carve it later from an identity that holds the key.")
                    .font(.caption)
                    .foregroundStyle(.orange)
                    .fixedSize(horizontal: false, vertical: true)
            }

            HStack {
                Button("Cancel") { onDone(.cancelled) }
                Spacer()
                if busy { ProgressView().controlSize(.small) }
                Button(editing == nil ? "Save draft" : "Save changes") { saveDraft() }
                    .disabled(busy || title.trimmingCharacters(in: .whitespaces).isEmpty)
                Button("Issue on chain") { Task { await carve() } }
                    .keyboardShortcut(.defaultAction)
                    .disabled(!canCarve)
            }
        }
        .padding(20)
        .frame(width: 560)
        .sheet(item: $pick) { request in
            FidPickerSheet(session: session, request: request) { picked in
                for p in picked where !cosigners.contains(p.fid) {
                    cosigners.append(p.fid)
                    if let cid = p.cid, !cid.isEmpty { names[p.fid] = cid }
                }
                pick = nil
            } onCancel: { pick = nil }
        }
    }

    /// Persist the draft, and return it.
    ///
    /// **Editing moves the row's key.** A draft's id is a digest of the
    /// text it will carve, so changing a word changes the id — that is
    /// what makes an unchanged draft's id stable across a reload. The
    /// old key is therefore deleted rather than updated in place;
    /// `addedAt` is carried over so "when did I start this" survives the
    /// move.
    @discardableResult
    private func persistDraft() throws -> Proof {
        var draft = Proof.createLocal(
            title: title.trimmingCharacters(in: .whitespacesAndNewlines),
            content: content,
            cosigners: cosigners,
            transferable: transferable,
            allSignsRequired: allSignsRequired,
            issuer: session.liveFid
        )
        if let editing {
            draft.addedAt = editing.addedAt
            if editing.id != draft.id {
                try session.proofs.remove(id: editing.id)
            }
        }
        try session.proofs.upsert(draft)
        return draft
    }

    private func saveDraft() {
        error = nil
        do {
            try persistDraft()
            onDone(.draft)
        } catch {
            self.error = "Couldn't save the draft: \(error)"
        }
    }

    private func carve() async {
        busy = true
        defer { busy = false }
        error = nil
        do {
            // Write the edits down before spending anything. The carve
            // rekeys the stored draft to the txid, so the stored row has
            // to be the one being carved — and if the broadcast fails,
            // the user's edits are on disk rather than lost with the
            // sheet.
            let draftId = editing == nil ? nil : try persistDraft().id
            let proof = try await session.carveProofIssueOnChain(
                title: title.trimmingCharacters(in: .whitespacesAndNewlines),
                content: content,
                cosigners: cosigners,
                transferable: transferable,
                allSignsRequired: allSignsRequired,
                draftId: draftId
            )
            onDone(.carved(proof))
        } catch {
            self.error = "Couldn't issue: \(error)"
        }
    }

    @ViewBuilder
    private func field(_ label: String, @ViewBuilder value: () -> some View) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(label).font(.caption).foregroundStyle(.secondary)
            value()
        }
    }
}

// MARK: - detail

/// Every field of one proof, untruncated and copyable — the Mac
/// analogue of Android's proof detail activity.
struct ProofDetailSheet: View {
    let session: ActiveSession
    let proof: Proof
    let name: (String) -> String?
    let onClose: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(spacing: 8) {
                Text(proof.title?.isEmpty == false ? proof.title! : "Untitled proof")
                    .font(.title3.bold())
                    .lineLimit(2)
                    .truncationMode(.middle)
                Spacer()
                stateChip
            }

            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    if let content = proof.content, !content.isEmpty {
                        field("Content") {
                            CopyableText(content, font: .body)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                    }

                    HStack(alignment: .top, spacing: 24) {
                        field("Issuer") { fidValue(proof.issuer) }
                        field("Owner") { fidValue(proof.owner) }
                    }

                    field("Cosigners") {
                        if let invited = proof.cosignersInvited, !invited.isEmpty {
                            VStack(alignment: .leading, spacing: 5) {
                                ForEach(invited, id: \.self) { fid in
                                    let signed = (proof.cosignersSigned ?? []).contains(fid)
                                    HStack(spacing: 6) {
                                        Image(systemName: signed ? "checkmark.seal.fill" : "clock")
                                            .foregroundStyle(signed ? .green : .orange)
                                        CopyableText(
                                            display: name(fid) ?? fid.elidingMiddle(head: 10, tail: 10),
                                            copy: fid,
                                            font: .system(.caption, design: .monospaced)
                                        )
                                        Text(signed ? "signed" : "pending")
                                            .font(.caption2)
                                            .foregroundStyle(signed ? .green : .orange)
                                    }
                                }
                            }
                        } else {
                            Text("None invited — the issuer's signature is the whole of it.")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    }

                    HStack(spacing: 24) {
                        field("Transferable") {
                            Text(proof.transferable == true ? "Yes" : "No").font(.caption)
                        }
                        field("In force") {
                            Text(proof.active == true ? "Yes"
                                 : (proof.active == false ? "Not yet" : "—"))
                                .font(.caption)
                        }
                        field("Destroyed") {
                            Text(proof.destroyed == true ? "Yes" : "No").font(.caption)
                        }
                    }

                    field("Proof ID") {
                        CopyableText.elidingMiddle(
                            proof.id, head: 12, tail: 12,
                            font: .system(.caption, design: .monospaced)
                        )
                    }

                    if let txid = proof.lastTxId, !txid.isEmpty, txid != proof.id {
                        field("Last transaction") {
                            CopyableText.elidingMiddle(
                                txid, head: 12, tail: 12,
                                font: .system(.caption, design: .monospaced)
                            )
                        }
                    }

                    HStack(spacing: 24) {
                        if let t = proof.birthTime {
                            field("Issued") {
                                Text(Date(timeIntervalSince1970: TimeInterval(t)),
                                     format: .dateTime.year().month().day().hour().minute())
                                    .font(.caption)
                            }
                        }
                        if let t = proof.lastTime {
                            field("Last change") {
                                Text(Date(timeIntervalSince1970: TimeInterval(t)),
                                     format: .dateTime.year().month().day().hour().minute())
                                    .font(.caption)
                            }
                        }
                        if let h = proof.lastHeight, h != ProofsStore.unconfirmedHeight {
                            field("Height") {
                                Text("\(h)").font(.caption.monospacedDigit())
                            }
                        }
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }

            HStack {
                Spacer()
                Button("Done", action: onClose)
                    .keyboardShortcut(.defaultAction)
            }
        }
        .padding(20)
        .frame(width: 520)
        .frame(minHeight: 340, maxHeight: 620)
    }

    @ViewBuilder
    private var stateChip: some View {
        if proof.destroyed == true {
            chip("Destroyed", color: .red)
        } else if proof.onChain == false {
            chip("Draft", color: .gray)
        } else if proof.onChain == nil {
            chip("Broadcast, unconfirmed", color: .orange)
        } else {
            chip("On chain", color: .blue)
        }
    }

    @ViewBuilder
    private func fidValue(_ fid: String?) -> some View {
        if let fid, !fid.isEmpty {
            HStack(spacing: 6) {
                FidAvatarView(fid: fid, size: 22)
                CopyableText(
                    display: name(fid) ?? fid.elidingMiddle(head: 10, tail: 10),
                    copy: fid,
                    font: .system(.caption, design: .monospaced)
                )
            }
        } else {
            Text("—").font(.caption).foregroundStyle(.tertiary)
        }
    }

    @ViewBuilder
    private func field(_ label: String, @ViewBuilder value: () -> some View) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(label).font(.caption).foregroundStyle(.secondary)
            value()
        }
    }

    private func chip(_ text: String, color: Color) -> some View {
        Text(text)
            .font(.caption2.bold())
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .background(Capsule().fill(color.opacity(0.15)))
            .foregroundStyle(color)
    }
}

// MARK: - transfer

/// Hand a proof to someone else.
///
/// Its own sheet rather than a row button straight into the FID picker,
/// because a transfer is irreversible and pays the recipient: the user
/// should see who they picked, and what it costs, before the carve goes
/// out. Android goes from the pay icon to the picker to the broadcast
/// with nothing in between.
struct TransferProofSheet: View {
    let session: ActiveSession
    let proof: Proof
    let onDone: (String?) -> Void

    @State private var recipient: PickedFid?
    @State private var pick: FidPickerRequest?
    @State private var busy = false
    @State private var error: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Transfer this proof")
                .font(.title3.bold())

            Text(proof.title?.isEmpty == false ? proof.title! : "Untitled proof")
                .font(.body.bold())
                .lineLimit(2)

            Text("Ownership moves to whoever the carve pays — that payment is how the protocol addresses the transfer, not a courtesy. You will remain its issuer forever; you will no longer be able to transfer or destroy it.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            VStack(alignment: .leading, spacing: 4) {
                Text("New owner").font(.caption).foregroundStyle(.secondary)
                if let recipient {
                    HStack(spacing: 8) {
                        FidAvatarView(fid: recipient.fid, size: 28)
                        VStack(alignment: .leading, spacing: 2) {
                            if let cid = recipient.cid, !cid.isEmpty {
                                Text(cid).font(.body)
                            }
                            CopyableText.elidingMiddle(
                                recipient.fid, head: 10, tail: 10,
                                font: .system(.caption, design: .monospaced)
                            )
                        }
                        Spacer()
                        Button("Change") { openPicker() }
                            .controlSize(.small)
                    }
                } else {
                    Button {
                        openPicker()
                    } label: {
                        Label("Choose someone", systemImage: "person.crop.circle.badge.plus")
                    }
                }
            }

            Text("The carve pays them \(NoticeFee.coinString(satoshis: ActiveSession.proofTransferSats)) F, plus the miner fee.")
                .font(.caption)
                .foregroundStyle(.tertiary)

            if let error {
                CopyableText(error, font: .caption).foregroundStyle(.red)
            }

            HStack {
                Button("Cancel") { onDone(nil) }
                Spacer()
                if busy { ProgressView().controlSize(.small) }
                Button("Transfer") { Task { await transfer() } }
                    .keyboardShortcut(.defaultAction)
                    .disabled(recipient == nil || busy || !session.canSign)
            }
        }
        .padding(20)
        .frame(width: 460)
        .sheet(item: $pick) { request in
            FidPickerSheet(session: session, request: request) { picked in
                recipient = picked.first
                pick = nil
            } onCancel: { pick = nil }
        }
    }

    private func openPicker() {
        pick = .one(
            title: "Transfer to",
            subtitle: "They become the owner of this proof once the carve confirms.",
            excluded: [session.liveFid]
        )
    }

    private func transfer() async {
        guard let recipient else { return }
        busy = true
        defer { busy = false }
        error = nil
        do {
            let txid = try await session.carveProofTransferOnChain(
                proofId: proof.id, to: recipient.fid
            )
            onDone(txid)
        } catch {
            self.error = "Couldn't transfer: \(error)"
        }
    }
}
