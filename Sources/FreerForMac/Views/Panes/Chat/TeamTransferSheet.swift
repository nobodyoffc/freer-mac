import SwiftUI
import FCCore
import FCDomain
import FCUI

/// Offer a team you own to somebody else — Android's "Transfer team" in
/// the owner menu — or withdraw an offer already out.
///
/// **An offer, not a hand-over.** The carve only names who may take the
/// team; you stay owner until they carve a take-over of their own, and
/// until then the offer can be withdrawn. What does happen at once, when
/// they take it, is total: they become owner and **sole** manager, so
/// everyone you appointed loses the role.
///
/// The person offered is sent the same `[TEAM_TRANSFER]` notice Android
/// sends, so they have a reason to look. It is only a hint: their client
/// checks the chain before letting them act.
struct TeamTransferSheet: View {

    let session: ActiveSession
    let teamId: String
    let onClose: () -> Void
    /// A line for the pane's summary once something was broadcast.
    let onDone: (String) -> Void

    @State private var team: Team?
    @State private var chosen: PickedFid?
    @State private var pick: FidPickerRequest?
    @State private var working = false
    @State private var error: String?

    private var pending: String? {
        guard let transferee = team?.transferee, !transferee.isEmpty else { return nil }
        return transferee
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack {
                Text("Hand over \(team?.displayName ?? "this team")").font(.title3.bold())
                Spacer()
            }

            Text("The person you name may take the team over. Nothing changes until they do, and until then you can withdraw the offer. When they take it they become the owner and the only manager — everyone you appointed loses the role — and they sign their agreement to the team's consensus.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            if let pending {
                VStack(alignment: .leading, spacing: 6) {
                    Text("On offer now")
                        .font(.caption).fontWeight(.semibold)
                        .textCase(.uppercase).tracking(0.5)
                        .foregroundStyle(.secondary)
                    HStack(spacing: 8) {
                        FidAvatarView(fid: pending, size: 22)
                        NobodyChip(fid: pending)
                        FidBadge(pending, font: .callout)
                        Spacer()
                        Button("Withdraw the offer (carve)") { withdraw() }
                            .disabled(working || !session.canSign)
                    }
                }
                .padding(10)
                .background(RoundedRectangle(cornerRadius: 8).fill(Color.orange.opacity(0.12)))
            }

            VStack(alignment: .leading, spacing: 6) {
                Text(pending == nil ? "New owner" : "Offer it to somebody else instead")
                    .font(.caption).fontWeight(.semibold)
                    .textCase(.uppercase).tracking(0.5)
                    .foregroundStyle(.secondary)
                HStack(spacing: 8) {
                    if let chosen {
                        FidAvatarView(fid: chosen.fid, size: 22)
                        NobodyChip(fid: chosen.fid)
                        Text(chosen.cid ?? chosen.fid.elidingMiddle(head: 8, tail: 8))
                            .font(.callout)
                        if chosen.cid != nil {
                            FidBadge(chosen.fid)
                        }
                    } else {
                        Text("Nobody chosen").foregroundStyle(.secondary)
                    }
                    Spacer()
                    Button {
                        pick = .one(
                            title: "Hand the team to…",
                            subtitle: "They may take the team over; nothing changes until they do.",
                            excluded: [session.liveFid]
                        )
                    } label: {
                        Label("Choose…", systemImage: "person.crop.circle.badge.checkmark")
                    }
                }
                if let chosen {
                    NobodyBanner(fid: chosen.fid, message: NobodyConsequence.teamOwner.text)
                }
            }

            Spacer(minLength: 0)

            if let error {
                CopyableText(error, font: .caption).foregroundStyle(.red)
                    .fixedSize(horizontal: false, vertical: true)
            }

            HStack {
                Spacer()
                Button("Cancel", role: .cancel, action: onClose)
                Button(working ? "Carving…" : "Offer the team (carve)") { offer() }
                    .buttonStyle(.borderedProminent)
                    .disabled(working || chosen == nil || !session.canSign)
            }
        }
        .padding(20)
        .frame(width: 520, height: 400)
        .onAppear { team = try? session.teams.get(id: teamId) }
        .task {
            // The offer on screen should be the chain's, not the cache's:
            // it may have been taken or withdrawn from another device.
            if let fresh = try? await session.freshTeam(id: teamId) {
                await MainActor.run { team = fresh }
            }
        }
        .sheet(item: $pick) { request in
            FidPickerSheet(session: session, request: request) { picked in
                chosen = picked.first
                pick = nil
            } onCancel: {
                pick = nil
            }
        }
    }

    private func offer() {
        guard let fid = chosen?.fid else { return }
        working = true
        error = nil
        Task {
            // A team owned by a nobody can be run by anyone.
            guard await NobodyGate.confirm([fid], .teamOwner, session: session) else {
                await MainActor.run { working = false }
                return
            }
            do {
                let txid = try await session.carveTeamTransferOnChain(teamId: teamId, transferee: fid)
                let told = try? await session.queueTeamNotices(
                    .transfer, teamId: teamId, teamName: team?.displayName, to: [fid]
                )
                _ = try? await session.courier.drainOutbox(as: session.liveFid)
                let notice = (told?.queued.isEmpty ?? true)
                    ? " They could not be told — they have never published a public key — so let them know yourself."
                    : " They have been sent a notice."
                await MainActor.run {
                    working = false
                    onDone("Offer broadcast — tx \(txid.elidingMiddle(head: 8, tail: 8)). The team is theirs once they take it over.\(notice)")
                }
            } catch {
                await MainActor.run {
                    working = false
                    self.error = String(describing: error)
                }
            }
        }
    }

    private func withdraw() {
        working = true
        error = nil
        Task {
            do {
                let txid = try await session.carveTeamCancelTransferOnChain(teamId: teamId)
                await MainActor.run {
                    working = false
                    onDone("Withdrawal broadcast — tx \(txid.elidingMiddle(head: 8, tail: 8)). The offer stands until it confirms, so it can still be taken until then.")
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
