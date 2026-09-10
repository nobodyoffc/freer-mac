import SwiftUI
import FCCore
import FCDomain
import FCUI

/// The teams whose consensus changed under you, and the three answers
/// available: agree, put it off, or leave.
///
/// **Nobody sent you this.** An owner who replaces a team's consensus
/// document carves an update and nothing else; the indexer refills
/// ``Team/notAgreeMembers`` with every non-owner member, and that public
/// list is the whole of the notification. So this sheet is driven off
/// the chain — written by the team sync, on every refresh — which is
/// what makes it survive being offline, reinstalling, or a message that
/// never arrived, and what makes it **clear itself** when the signature
/// came from another device or the owner dismissed you.
///
/// **Both documents, side by side, because that is the actual question.**
/// The chain holds one consensus id: the current one. The previous one
/// exists on this Mac only because the sync captured it in the instant
/// before overwriting the cached team — see
/// ``ConsensusSignatureRequest/previousConsensusId`` — and without it a
/// member is being asked to sign a replacement with no way to see what
/// it replaced. It is legitimately missing when this device had never
/// seen the team before, and the sheet says so rather than hiding the
/// button.
///
/// **Postpone is a real answer, not a snooze.** Agreeing is a
/// transaction the member pays for; "not now" deserves somewhere to go
/// that is neither signing nor leaving. A postponed row stays in the
/// store and out of the prompt, and comes back the moment the owner
/// changes the consensus again.
struct ConsensusSignatureSheet: View {

    let session: ActiveSession
    let onClose: () -> Void
    /// Called after anything that changes the team list.
    let onChanged: () -> Void

    @State private var requests: [ConsensusSignatureRequest] = []
    @State private var selectedId: String?
    @State private var working = false
    @State private var error: String?
    @State private var note: String?
    @State private var document: DocumentRequest?
    @State private var confirmingLeave = false

    private struct DocumentRequest: Identifiable {
        let id = UUID()
        let consensusId: String
        let title: String
        let diskSids: [String]
    }

    private var selected: ConsensusSignatureRequest? {
        requests.first { $0.id == selectedId } ?? requests.first
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack {
                Text("Teams awaiting your agreement").font(.title3.bold())
                Spacer()
                Button("Done", action: onClose).keyboardShortcut(.defaultAction)
            }

            Text("The chain lists you as not having agreed to these teams' current consensus documents. Nothing was sent to tell you — this is read from the teams themselves, so it is true whichever device you are on, and it goes away on its own once your agreement is carved.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            if requests.isEmpty {
                Spacer()
                Text("Nothing is waiting on you.")
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity)
                Spacer()
            } else {
                HStack(alignment: .top, spacing: 12) {
                    list.frame(width: 200)
                    Divider()
                    detail
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
        }
        .padding(20)
        .frame(width: 640, height: 480)
        .onAppear(perform: load)
        .sheet(item: $document) { request in
            ConsensusDocumentSheet(
                session: session,
                title: request.title,
                consensusId: request.consensusId,
                diskSids: request.diskSids,
                editable: false,
                onSaved: { _ in document = nil },
                onClose: { document = nil }
            )
        }
        .confirmationDialog(
            "Leave this team?",
            isPresented: $confirmingLeave,
            titleVisibility: .visible
        ) {
            Button("Leave the team", role: .destructive) { leave() }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("Leaving is a transaction and it is public. The transcript stays on this Mac, but you stop receiving anything new, and rejoining needs a fresh invitation from the owner.")
        }
    }

    private var list: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 0) {
                ForEach(requests) { request in
                    Button {
                        selectedId = request.id
                        note = nil
                        error = nil
                    } label: {
                        HStack(spacing: 6) {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(request.teamName ?? request.id.elidingMiddle(head: 6, tail: 6))
                                    .font(.callout)
                                    .lineLimit(1)
                                if request.isPostponed {
                                    Text("put off").font(.caption2).foregroundStyle(.tertiary)
                                }
                            }
                            Spacer()
                        }
                        .padding(.vertical, 6)
                        .padding(.horizontal, 8)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .background(
                            RoundedRectangle(cornerRadius: 6)
                                .fill(request.id == selected?.id
                                      ? Color.accentColor.opacity(0.15) : .clear)
                        )
                    }
                    .buttonStyle(.plain)
                }
            }
        }
    }

    @ViewBuilder
    private var detail: some View {
        if let request = selected {
            VStack(alignment: .leading, spacing: 12) {
                Text(request.teamName ?? "This team").font(.headline)
                CopyableText(
                    display: request.id.elidingMiddle(head: 10, tail: 10),
                    copy: request.id,
                    font: .caption
                )
                .foregroundStyle(.tertiary)

                documentRow(
                    label: "New consensus",
                    id: request.consensusId,
                    title: "The new consensus",
                    diskSids: diskSids(for: request, previous: false),
                    missingNote: "The team names no consensus document."
                )

                documentRow(
                    label: "What you agreed to",
                    id: request.previousConsensusId,
                    title: "The consensus you signed",
                    diskSids: diskSids(for: request, previous: true),
                    // Not a fault and not a loss: the previous id only
                    // ever existed in the moment before this device
                    // overwrote its cached copy of the team, and a
                    // device that had not yet seen the team never had it.
                    missingNote: "This Mac never saw this team's previous consensus, so there is nothing to compare against. The owner can tell you what changed."
                )

                Spacer()

                Text("Agreeing is a transaction: it costs a miner fee and is public. It quotes the team's consensus id as it stands the moment you sign, so if the owner has changed it again since, that is what gets signed.")
                    .font(.caption)
                    .foregroundStyle(.tertiary)
                    .fixedSize(horizontal: false, vertical: true)

                HStack {
                    Button(working ? "Carving…" : "Agree") { agree(request) }
                        .buttonStyle(.borderedProminent)
                        .disabled(working || !session.canSign)
                    if !request.isPostponed {
                        Button("Not now") { postpone(request) }
                            .disabled(working)
                            .help("Keeps it here and stops it prompting. It comes back if the owner changes the consensus again.")
                    }
                    Spacer()
                    Button("Leave the team", role: .destructive) { confirmingLeave = true }
                        .disabled(working || !session.canSign)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        } else {
            Spacer()
        }
    }

    private func documentRow(
        label: String,
        id: String?,
        title: String,
        diskSids: [String],
        missingNote: String
    ) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(label)
                .font(.caption).fontWeight(.semibold)
                .textCase(.uppercase).tracking(0.5)
                .foregroundStyle(.secondary)
            if let id, !id.isEmpty {
                HStack(spacing: 8) {
                    CopyableText(
                        display: id.elidingMiddle(head: 8, tail: 8),
                        copy: id,
                        font: .system(.caption, design: .monospaced)
                    )
                    Button("Read…") {
                        document = DocumentRequest(
                            consensusId: id, title: title, diskSids: diskSids
                        )
                    }
                    .buttonStyle(.borderless)
                    .font(.caption)
                }
            } else {
                Text(missingNote)
                    .font(.caption2)
                    .foregroundStyle(.tertiary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    /// Where to look for one of the two documents.
    ///
    /// The team's current DISK for the new one; for the previous one,
    /// the DISK the team published *then* as well, because a team that
    /// moved its DISK left the old document behind on the old server.
    private func diskSids(for request: ConsensusSignatureRequest, previous: Bool) -> [String] {
        let team = try? session.teams.get(id: request.id)
        let current = TeamConsensus.diskSid(of: team)
        guard previous else { return [current].compactMap { $0 } }
        return [request.previousDiskSid, current].compactMap { $0 }
    }

    // MARK: - actions

    private func load() {
        do {
            requests = try session.consensusSignatures.all()
            if selectedId == nil || !requests.contains(where: { $0.id == selectedId }) {
                selectedId = requests.first?.id
            }
            error = nil
        } catch {
            self.error = String(describing: error)
        }
    }

    /// Carve the agreement.
    ///
    /// The id is **not** taken from this row: ``ActiveSession/carveTeamAgreeConsensusOnChain(teamId:feePerByte:timeoutMs:)``
    /// re-reads the team from the chain and signs whatever it says now.
    /// A further change may have landed while the member was deciding,
    /// and the parser refuses an agreement naming anything but the
    /// current id — which would cost the fee and agree to nothing.
    private func agree(_ request: ConsensusSignatureRequest) {
        working = true
        error = nil
        note = nil
        Task {
            do {
                let txid = try await session.carveTeamAgreeConsensusOnChain(teamId: request.id)
                await MainActor.run {
                    working = false
                    note = "Broadcast — tx \(txid.elidingMiddle(head: 8, tail: 8)). This clears itself from here on the next refresh, once the chain stops listing you."
                    onChanged()
                }
            } catch {
                await MainActor.run {
                    working = false
                    self.error = String(describing: error)
                    // A refusal for "nothing to sign" means the chain has
                    // already moved on, so the row is stale rather than
                    // wrong — drop it instead of leaving a dead prompt.
                    if Self.isNothingToSign(error) {
                        _ = try? session.consensusSignatures.remove(teamId: request.id)
                        load()
                        onChanged()
                    }
                }
            }
        }
    }

    /// Whether the carve was refused because the chain no longer asks
    /// this identity for a signature. Unwrapped through
    /// ``ActiveSession/Failure/underlying(_:)``, which is the one shape
    /// the session wraps a domain refusal in.
    private static func isNothingToSign(_ error: Error) -> Bool {
        guard let failure = error as? ActiveSession.Failure,
              case .underlying(let inner) = failure,
              let team = inner as? TeamConsensusFailure,
              case .nothingToSign = team
        else { return false }
        return true
    }

    private func postpone(_ request: ConsensusSignatureRequest) {
        do {
            try session.consensusSignatures.postpone(teamId: request.id)
            load()
            note = "Put off. It stays here and stops prompting; if the owner changes the consensus again it comes back."
            onChanged()
        } catch {
            self.error = String(describing: error)
        }
    }

    private func leave() {
        guard let request = selected else { return }
        working = true
        error = nil
        note = nil
        Task {
            do {
                let txid = try await session.carveTeamLeaveOnChain(teamIds: [request.id])
                await MainActor.run {
                    working = false
                    // The obligation is gone either way — the chain will
                    // stop listing us — so the row goes now rather than
                    // asking again before the carve confirms.
                    _ = try? session.consensusSignatures.remove(teamId: request.id)
                    load()
                    note = "Leaving — tx \(txid.elidingMiddle(head: 8, tail: 8)). The thread stays on this Mac and stops receiving once the carve confirms."
                    onChanged()
                }
            } catch {
                await MainActor.run {
                    working = false
                    self.error = String(describing: error)
                }
            }
        }
    }
}
