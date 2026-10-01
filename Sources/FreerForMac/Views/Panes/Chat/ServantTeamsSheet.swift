import SwiftUI
import FCCore
import FCDomain
import FCUI

/// Teams owned by this FID's servants — the ones it may hand over as
/// their master (FEIP18 rule 16).
///
/// **Why this is its own list.** A master acting for a servant who lost
/// their prikey is usually not in the servant's teams, so none of them
/// is a conversation here and the per-team menu never offers anything.
/// This asks the chain instead: which FIDs name the live FID as master,
/// and which active teams do they own.
///
/// Handing a team over here is the same carve the owner makes; the
/// master normally hands it to itself and then takes it over from Team
/// invitations.
struct ServantTeamsSheet: View {

    @Environment(\.inspectFid) private var inspectFid

    let session: ActiveSession
    let onClose: () -> Void
    /// A line for the pane's summary once something was broadcast.
    let onDone: (String) -> Void

    @State private var teams: [Team]?
    @State private var loading = false
    @State private var error: String?
    @State private var transferring: TeamRef?

    private struct TeamRef: Identifiable {
        let id: String
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text("Servants' teams").font(.title3.bold())
                Spacer()
                Button {
                    Task { await load() }
                } label: {
                    if loading {
                        ProgressView().controlSize(.small)
                    } else {
                        Label("Check the chain", systemImage: "arrow.clockwise")
                    }
                }
                .disabled(loading)
                Button("Done", action: onClose).keyboardShortcut(.defaultAction)
            }

            Text("Teams owned by FIDs that name you as their master. The chain lets an owner's master hand a team over, so a team outlives its owner losing their prikey — that is the only thing a master can do for it here.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            if let teams, !teams.isEmpty {
                ScrollView {
                    VStack(alignment: .leading, spacing: 0) {
                        ForEach(teams, id: \.id) { team in
                            row(team)
                            Divider()
                        }
                    }
                }
            } else {
                VStack {
                    Spacer()
                    Text(teams == nil ? "Checking…" : "None of your servants owns a team.")
                        .foregroundStyle(.secondary)
                    Spacer()
                }
                .frame(maxWidth: .infinity)
            }

            if let error {
                CopyableText(error, font: .caption).foregroundStyle(.red)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .padding(20)
        .frame(width: 600, height: 460)
        .fidDetailsHost(session: session)
        .task { await load() }
        .sheet(item: $transferring) { ref in
            TeamTransferSheet(
                session: session,
                teamId: ref.id,
                onClose: { transferring = nil },
                onDone: { summary in
                    transferring = nil
                    onDone(summary)
                }
            )
        }
    }

    private func row(_ team: Team) -> some View {
        HStack(spacing: 8) {
            VStack(alignment: .leading, spacing: 3) {
                Text(team.displayName ?? "Unnamed team").font(.callout.weight(.semibold))
                HStack(spacing: 4) {
                    Text("Owner").font(.caption).foregroundStyle(.secondary)
                    if let owner = team.owner {
                        Button { inspectFid(owner) } label: {
                            FidAvatarView(fid: owner, size: 16)
                        }
                        .buttonStyle(.plain)
                        FidBadge(owner, font: .caption)
                    }
                    if let count = team.memberNum ?? team.members.map({ Int64($0.count) }) {
                        Text("· \(count) member\(count == 1 ? "" : "s")")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                }
                if let transferee = team.transferee, !transferee.isEmpty {
                    HStack(spacing: 4) {
                        ChatChip(transferee == session.liveFid ? "on offer to you" : "on offer", color: .orange)
                        if transferee != session.liveFid {
                            FidBadge(transferee, font: .caption)
                        }
                    }
                }
            }
            Spacer()
            Button("Hand over…") {
                if let id = team.id { transferring = TeamRef(id: id) }
            }
            .disabled(!session.canSign)
        }
        .padding(.vertical, 8)
    }

    private func load() async {
        loading = true
        error = nil
        defer { loading = false }
        do {
            teams = try await session.servantTeams()
        } catch {
            if teams == nil { teams = [] }
            self.error = String(describing: error)
        }
    }
}
