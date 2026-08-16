import SwiftUI
import FCCore
import FCDomain
import FCUI

/// Ask specific people for something — Android's `AskSymkeyActivity` and
/// `AskRoomInfoActivity`, which are one screen with two payloads.
///
/// **Who you ask is a choice, not a broadcast.** Asking everyone tells
/// the whole group that this device lost the key, and in a room that
/// list is exactly the people whose opinion of you it affects. It also
/// costs a message each, on somebody's DOCK, paid for by us. So the
/// members are listed and the user picks.
///
/// The answers arrive on a later receive, through ``SignalRouter``, and
/// several answers are harmless: ``SymkeyStore`` refuses to overwrite a
/// version it already holds unless the sender owns the entity, so the
/// second reply is a no-op rather than a race.
struct AskMembersSheet: View {

    /// What is being asked for. The two differ in what comes back and in
    /// whose answer counts, which is why the sheet says both.
    enum Ask: Identifiable, Hashable {
        var id: Self { self }

        case symkey
        case roomInfo

        var title: String {
            switch self {
            case .symkey:   return "Ask for the key"
            case .roomInfo: return "Ask for this room's details"
            }
        }

        var requestType: RequestType {
            switch self {
            case .symkey:   return .symkey
            case .roomInfo: return .roomInfo
            }
        }
    }

    let session: ActiveSession
    let style: ChatModeStyle
    let conversation: Conversation
    let ask: Ask
    let onClose: () -> Void
    let onSent: (String) -> Void

    @State private var members: [String] = []
    @State private var owner: String?
    @State private var chosen: Set<String> = []
    @State private var error: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack {
                Text(ask.title).font(.title3.bold())
                Spacer()
                Button("Cancel", role: .cancel, action: onClose)
            }

            Text(explanation)
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            if members.isEmpty {
                Text("This \(style.noun) lists no other member on this device, so there is nobody to ask. Refresh it first.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, alignment: .leading)
            } else {
                HStack {
                    Button(chosen.count == members.count ? "Select none" : "Select all") {
                        chosen = chosen.count == members.count ? [] : Set(members)
                    }
                    .buttonStyle(.borderless)
                    .font(.caption)
                    Spacer()
                    Text("\(chosen.count) of \(members.count) selected")
                        .font(.caption)
                        .foregroundStyle(.tertiary)
                }
                list
            }

            if let error {
                CopyableText(error, font: .caption).foregroundStyle(.red)
            }

            HStack {
                Spacer()
                Button("Send request\(chosen.count == 1 ? "" : "s")") { send() }
                    .buttonStyle(.borderedProminent)
                    .disabled(chosen.isEmpty)
            }
        }
        .padding(20)
        .frame(width: 480, height: 420)
        .onAppear(perform: load)
    }

    /// Whose answer can actually be applied — the part that decides who
    /// to tick, and the part a user has no way of guessing.
    private var explanation: String {
        switch ask {
        case .symkey where style.mode == .team:
            return "Any member who holds the team's key can send it. It arrives on a later receive and is stored sealed to this identity."
        case .symkey:
            return "Any member who holds the room's key can send it. Only the owner's copy can replace a version this device already has."
        case .roomInfo:
            return "Only the **owner's** answer can rewrite who is in this room — a member's answer still carries the name and the key, which is usually the part that was missing. The owner is ticked for you."
        }
    }

    private var list: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 0) {
                ForEach(members, id: \.self) { fid in
                    Button {
                        if chosen.contains(fid) { chosen.remove(fid) } else { chosen.insert(fid) }
                    } label: {
                        HStack(spacing: 8) {
                            Image(systemName: chosen.contains(fid) ? "checkmark.square.fill" : "square")
                                .foregroundStyle(chosen.contains(fid) ? style.tint : .secondary)
                            FidAvatarView(fid: fid, size: 22)
                            Text(fid.elidingMiddle(head: 8, tail: 8))
                                .font(.callout)
                            if fid == owner { ChatChip("owner", color: style.tint) }
                            Spacer(minLength: 0)
                        }
                        .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                    .padding(.vertical, 5)
                    Divider()
                }
            }
        }
    }

    // MARK: - actions

    private func load() {
        do {
            switch style.mode {
            case .room:
                let room = try session.rooms.get(id: conversation.targetId)
                owner = room?.owner
                members = (room?.members ?? []).filter { $0 != session.liveFid }
            case .team:
                let team = try session.teams.get(id: conversation.targetId)
                owner = team?.owner
                members = (team?.members ?? []).filter { $0 != session.liveFid }
            case .square, .p2p:
                // Neither has a key, so neither reaches this sheet.
                members = []
            }
            // The owner is the answer that counts most in both cases, so
            // it starts ticked; everything else is the user's call.
            if let owner, members.contains(owner) { chosen = [owner] }
            error = nil
        } catch {
            self.error = String(describing: error)
        }
    }

    private func send() {
        do {
            let outbound = KeyExchange.requests(
                entityId: conversation.targetId,
                kind: ask.requestType,
                from: session.liveFid,
                to: Array(chosen)
            )
            for message in outbound {
                guard let to = message.targetId else { continue }
                try session.outbox.enqueue(message, in: Conversation.id(type: .p2p, targetId: to))
            }
            Task { _ = try? await session.courier.drainOutbox(as: session.liveFid) }
            onSent("Asked \(outbound.count) member\(outbound.count == 1 ? "" : "s"). The answer arrives on a later receive.")
            onClose()
        } catch {
            self.error = String(describing: error)
        }
    }
}
