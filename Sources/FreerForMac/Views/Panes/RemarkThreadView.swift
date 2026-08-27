import SwiftUI
import AppKit
import FCCore
import FCDomain
import FCUI

/// The remarks anchored to one published record, and the composer that
/// adds another — FEIP22, as a strip that sits under whatever it is
/// remarking on.
///
/// **One view for the whole Publish family.** A remark's target is
/// `onDid`, which this app fills with the target's *record id*, and a
/// record id is a record id whether the thing it names is a text, an
/// image, a sound, a video or another remark. So this takes an id and
/// nothing else about what it belongs to: the reader sheets differ in
/// how they show a work, not in how they carry a conversation, and a
/// second copy of this is where the two would start disagreeing about
/// what `onDid` means.
struct RemarkThreadView: View {
    let session: ActiveSession
    /// The record being remarked on — its publish txid.
    let targetId: String
    /// FID → display name, resolved by whoever owns the surrounding
    /// pane; a thread has no directory of its own.
    let name: (String) -> String?

    @State private var remarks: [Remark] = []
    @State private var loadingRemarks = false
    @State private var remarkError: String?

    @State private var remarkTitle = ""
    @State private var remarkNote = ""
    @State private var remarkBody = ""
    @State private var showRemarkComposer = false
    @State private var posting = false
    @State private var actionNote: String?

    // MARK: - remarks

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Text("Remarks").font(.headline)
                if loadingRemarks { ProgressView().controlSize(.small) }
                Spacer()
                Button(showRemarkComposer ? "Cancel" : "Add a remark") {
                    showRemarkComposer.toggle()
                }
                .controlSize(.small)
                .disabled(!session.canSign)
                .help(session.canSign
                      ? "Anchor a remark to this record"
                      : "Watch-only identity — no key to sign a carve with")
            }

            if showRemarkComposer { remarkComposer }

            if let e = remarkError {
                CopyableText(e, font: .caption).foregroundStyle(.red)
            }
            if let n = actionNote {
                CopyableText(n, font: .caption).foregroundStyle(.green)
            }

            if remarks.isEmpty && !loadingRemarks {
                Text("Nobody has remarked on this. A remark is its own on-chain record anchored to this one — it costs a carve, which is what keeps a thread from being free to flood.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            } else {
                ForEach(remarks) { remark in
                    remarkRow(remark)
                    Divider()
                }
            }
        }
        .onAppear {
            guard remarks.isEmpty, !loadingRemarks else { return }
            Task { await loadRemarks() }
        }
    }

    private var remarkComposer: some View {
        VStack(alignment: .leading, spacing: 10) {
            // Each field says what it is *and* where it lands. The two
            // are different questions and a placeholder that answers
            // only the second reads as a description of the field above
            // it — which is exactly how "A line, carved on chain" got
            // mistaken for the title.
            LabeledField("Title") {
                VStack(alignment: .leading, spacing: 2) {
                    TextField("What this remark says, in a few words", text: $remarkTitle)
                        .textFieldStyle(.roundedBorder)
                    Text("Required by the protocol, and carved on chain. This is what the thread shows.")
                        .font(.caption2)
                        .foregroundStyle(.tertiary)
                }
            }

            LabeledField("Summary") {
                VStack(alignment: .leading, spacing: 2) {
                    TextField("Optional — a line under the title", text: $remarkNote, axis: .vertical)
                        .lineLimit(1...3)
                        .textFieldStyle(.roundedBorder)
                    Text("Also carved on chain, so a thread can show it without fetching anything.")
                        .font(.caption2)
                        .foregroundStyle(.tertiary)
                }
            }

            DisclosureGroup("The remark itself — optional, stored on DISK, not on the chain") {
                TextEditor(text: $remarkBody)
                    .font(.callout)
                    .frame(height: 90)
                    .overlay(
                        RoundedRectangle(cornerRadius: 6)
                            .stroke(Color(NSColor.separatorColor))
                    )
                    .padding(.top, 4)
            }
            .font(.caption)

            HStack {
                Text(remarkRemaining >= 0
                     ? "\(remarkRemaining) bytes left in the carve"
                     : "\(-remarkRemaining) bytes over the limit")
                    .font(.caption2.monospacedDigit())
                    .foregroundStyle(remarkRemaining >= 0 ? AnyShapeStyle(.tertiary) : AnyShapeStyle(Color.red))
                Spacer()
                Button("Publish remark") { Task { await postRemark() } }
                    .buttonStyle(.borderedProminent)
                    .controlSize(.small)
                    .disabled(
                        posting
                        || remarkTitle.trimmingCharacters(in: .whitespaces).isEmpty
                        || remarkRemaining < 0
                        || !session.canSign
                    )
                if posting { ProgressView().controlSize(.small) }
            }
        }
        .padding(10)
        .background(Color(NSColor.controlBackgroundColor))
        .clipShape(RoundedRectangle(cornerRadius: 8))
    }

    private var remarkRemaining: Int {
        RemarkFeip.remainingSummaryBytes(
            title: remarkTitle,
            onDid: targetId,
            did: remarkBody.isEmpty ? nil : String(repeating: "0", count: 64),
            summary: remarkNote
        )
    }

    @ViewBuilder
    private func remarkRow(_ remark: Remark) -> some View {
        HStack(alignment: .top, spacing: 10) {
            FidAvatarView(fid: remark.publisher ?? "", size: 26)
            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 6) {
                    Text(remark.title ?? "Untitled remark").font(.callout.bold())
                    if remark.publisher == session.liveFid {
                        Text("You")
                            .font(.caption2.bold())
                            .padding(.horizontal, 5).padding(.vertical, 1)
                            .background(Capsule().fill(Color.blue.opacity(0.15)))
                            .foregroundStyle(.blue)
                    }
                    if remark.onChain == nil {
                        Text("Broadcast")
                            .font(.caption2.bold())
                            .padding(.horizontal, 5).padding(.vertical, 1)
                            .background(Capsule().fill(Color.orange.opacity(0.15)))
                            .foregroundStyle(.orange)
                    }
                    Spacer()
                    if let t = remark.birthTime ?? remark.lastTime {
                        Text(Date(timeIntervalSince1970: TimeInterval(t))
                            .formatted(date: .abbreviated, time: .shortened))
                            .font(.caption2).foregroundStyle(.tertiary)
                    }
                }
                if let summary = remark.summary, !summary.isEmpty {
                    Text(summary).font(.caption).foregroundStyle(.secondary)
                }
                HStack(spacing: 8) {
                    CopyableText(
                        display: remark.publisher.map { name($0) ?? $0.elidingMiddle(head: 6, tail: 6) } ?? "—",
                        copy: remark.publisher ?? "",
                        font: .system(.caption2, design: .monospaced)
                    )
                    .foregroundStyle(.tertiary)
                    if remark.did != nil {
                        Text("has a longer text")
                            .font(.caption2)
                            .foregroundStyle(.tertiary)
                    }
                    if remark.canDelete(as: session.liveFid) && session.canSign {
                        Button("Delete", role: .destructive) {
                            Task { await deleteRemark(remark) }
                        }
                        .font(.caption2)
                        .buttonStyle(.link)
                    }
                }
            }
        }
        .padding(.vertical, 4)
    }

    private func loadRemarks() async {
        loadingRemarks = true
        defer { loadingRemarks = false }
        do {
            let page = try await session.publish.fetchRemarks(on: targetId)
            remarks = page.rows
            _ = try? session.remarks.mergeChainRows(page.rows)
            remarkError = nil
        } catch {
            // The cached thread is better than none, and says so by
            // being there next to the error.
            remarks = (try? session.remarks.all(on: targetId)) ?? []
            remarkError = String(describing: error)
        }
    }

    private func postRemark() async {
        posting = true
        defer { posting = false }
        do {
            var did: String?
            if !remarkBody.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                did = try await session.publishBody.store(remarkBody, name: "\(remarkTitle).txt")
            }
            let remark = try await session.carveRemarkPublishOnChain(
                title: remarkTitle,
                onDid: targetId,
                did: did,
                summary: remarkNote.isEmpty ? nil : remarkNote
            )
            remarks.append(remark)
            remarkTitle = ""
            remarkNote = ""
            remarkBody = ""
            showRemarkComposer = false
            remarkError = nil
            actionNote = "Remark carved — tx \(remark.id.elidingMiddle(head: 8, tail: 8))."
        } catch {
            remarkError = String(describing: error)
        }
    }

    private func deleteRemark(_ remark: Remark) async {
        do {
            let txid = try await session.carveRemarkDeleteOnChain(remarkIds: [remark.id])
            actionNote = "Remark deleted — tx \(txid.elidingMiddle(head: 8, tail: 8))."
            remarks.removeAll { $0.id == remark.id }
        } catch {
            remarkError = String(describing: error)
        }
    }

}
