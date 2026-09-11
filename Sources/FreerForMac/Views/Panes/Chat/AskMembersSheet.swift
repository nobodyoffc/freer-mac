import SwiftUI
import FCCore
import FCDomain
import FCUI

/// Ask specific people for something — Android's `AskSymkeyActivity` and
/// `AskRoomInfoActivity`, which are one screen with two payloads — or,
/// for a room's owner, send its details to chosen members (Android's
/// "Share room info" and "Share symkey", which pick recipients the same
/// way).
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
        /// Not a question: the owner sends the room's details, current
        /// key included, to the members picked.
        case shareRoomInfo

        var title: String {
            switch self {
            case .symkey:        return "Ask for the key"
            case .roomInfo:      return "Ask for this room's details"
            case .shareRoomInfo: return "Share this room's details"
            }
        }

        var requestType: RequestType {
            switch self {
            case .symkey:                  return .symkey
            case .roomInfo, .shareRoomInfo: return .roomInfo
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
    /// Whether we already hold a key for this entity. Only a caption —
    /// asking again is legitimate (a rotation we missed, a room whose
    /// membership drifted), so it informs rather than disables.
    @State private var alreadyHeld = false

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
                Text("This \(style.noun) lists nobody to ask on this device — not even you. Refresh it first.")
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
                Button(ask == .shareRoomInfo
                       ? "Send to \(chosen.count) member\(chosen.count == 1 ? "" : "s")"
                       : "Send request\(chosen.count == 1 ? "" : "s")") { send() }
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
        case .shareRoomInfo:
            return "Each member picked gets the room's membership, name, DOCK and current key, sealed to them — the same message an invitation is. Nothing is rotated. A member with no published DOCK has nowhere to receive it and is skipped."
        }
    }

    private var list: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 0) {
                ForEach(members, id: \.self) { fid in
                    Button {
                        if chosen.contains(fid) { chosen.remove(fid) } else { chosen.insert(fid) }
                    } label: {
                        VStack(alignment: .leading, spacing: 2) {
                            HStack(spacing: 8) {
                                Image(systemName: chosen.contains(fid) ? "checkmark.square.fill" : "square")
                                    .foregroundStyle(chosen.contains(fid) ? style.tint : .secondary)
                                FidAvatarView(fid: fid, size: 22)
                                Text(fid.elidingMiddle(head: 8, tail: 8))
                                    .font(.callout)
                                if fid == owner { ChatChip("owner", color: style.tint) }
                                if fid == session.liveFid { ChatChip("your other devices", color: style.tint) }
                                Spacer(minLength: 0)
                            }
                            if fid == session.liveFid, ask != .shareRoomInfo {
                                Text(ownRowHint)
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                                    .fixedSize(horizontal: false, vertical: true)
                                    .padding(.leading, 26)
                            }
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

    /// What ticking our own FID actually does — the one row whose
    /// meaning is not obvious, because on the face of it it reads as
    /// asking yourself a question you already know you cannot answer.
    ///
    /// It is not. The request goes out on the ordinary P2P route
    /// addressed to this identity, and **every device signed in as this
    /// identity collects it** — so the one that still holds the key
    /// answers, and this one does not (a device with no key has nothing
    /// to reply with, so its own copy is a silent no-op). It is the only
    /// thing to tick for a re-installed **owner**, whose other device is
    /// the only copy of the key that exists.
    private var ownRowHint: String {
        alreadyHeld
            ? "Your other devices signed in as this identity. This device already holds a key — an answer can still bring a newer version."
            : "Your other devices signed in as this identity. Whichever one still holds the key answers; this one stays quiet."
    }

    // MARK: - actions

    private func load() {
        do {
            let me = session.liveFid
            switch style.mode {
            case .room:
                let room = try session.rooms.get(id: conversation.targetId)
                owner = room?.owner
                members = ask == .shareRoomInfo
                    // An owner telling the room: there is nobody to tell
                    // but the others.
                    ? (room?.others(than: me) ?? [])
                    : roster(all: room?.members, owner: room?.owner, me: me)
            case .team:
                let team = try session.teams.get(id: conversation.targetId)
                owner = team?.owner
                members = roster(all: team?.members, owner: team?.owner, me: me)
            case .square, .p2p:
                // Neither has a key, so neither reaches this sheet.
                members = []
            }
            alreadyHeld = (try? session.symkeys.has(entityId: conversation.targetId)) ?? false
            // The owner is the answer that counts most in both cases, so
            // it starts ticked; everything else is the user's call —
            // except when the owner *is* us, where the only useful tick
            // is our own row, and pre-ticking it is what makes the
            // re-installed owner's one path out of this the default.
            if ask == .shareRoomInfo { chosen = Set(members) }
            else if let owner, members.contains(owner) { chosen = [owner] }
            else if members.contains(me) { chosen = [me] }
            error = nil
        } catch {
            self.error = String(describing: error)
        }
    }

    /// Who to offer, our own FID **first**.
    ///
    /// It used to be filtered out, on the reading that asking yourself
    /// is a no-op. It is not: an identity is not a device, and a second
    /// Mac signed in as this FID has the identity and none of the keys.
    /// The request travels the ordinary P2P route to this FID, and the
    /// device that still holds the key answers it like any member's —
    /// see ``KeyExchange/requests(entityId:kind:from:to:now:)``. Leaving
    /// it out left a re-installed owner, whose other device is the only
    /// holder in existence, with nobody to ask.
    ///
    /// It leads because it is the one row the user cannot reconstruct
    /// for themselves, and the owner keeps its chip wherever it lands.
    private func roster(all: [String]?, owner: String?, me: String) -> [String] {
        let listed = all ?? []
        let others = listed.filter { $0 != me }
        // Only if we are actually in the entity — the sheet is reachable
        // for a room whose membership has drifted past us, and offering
        // to ask ourselves about one we are not in would be a request
        // every responder is right to ignore.
        guard listed.contains(me) || owner == me else { return others }
        return [me] + others
    }

    private func share() {
        do {
            let (outbound, unreachable) = try session.roomService.shareInfo(
                conversation.targetId,
                to: Array(chosen),
                as: session.liveFid,
                pubkeys: { fid in try session.knownPubkey(of: fid) },
                homes: { fid in try session.knownHome(of: fid) }
            )
            for message in outbound {
                guard let to = message.targetId else { continue }
                try session.outbox.enqueue(message, in: Conversation.id(type: .p2p, targetId: to))
            }
            Task { _ = try? await session.courier.drainOutbox(as: session.liveFid) }
            onSent(unreachable.isEmpty
                   ? "\(outbound.count) update(s) queued."
                   : "\(outbound.count) update(s) queued. \(unreachable.count) member(s) publish no DOCK, so there is nowhere to leave one for them.")
            onClose()
        } catch {
            self.error = String(describing: error)
        }
    }

    private func send() {
        if ask == .shareRoomInfo { return share() }
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
