import SwiftUI
import FCCore
import FCDomain
import FCUI

/// Starting a conversation — the Mac port of Android's
/// `NewTalkActivity` / `CreateRoomActivity` / `JoinTeamActivity` /
/// `JoinSquareActivity`, gathered into one sheet because they are one
/// question with three answers.
///
/// The three differ in **what it costs to say yes**, and the sheet says
/// so rather than making all three look like the same button:
///
/// - A **chat** with one person costs nothing and asks nobody. It opens
///   a thread locally; the other end learns of it when a message
///   arrives.
/// - A **room** costs nothing either, because a room is local — but its
///   invitations have to reach people, and until the transport lands
///   (9.2.4b) they sit in the outbox.
/// - **Joining a team or a square is a transaction.** It is carved,
///   costs a miner fee, and is public. That is not a detail to bury in a
///   confirmation dialog.
struct NewChatSheet: View {
    let session: ActiveSession
    /// Called with the conversation id to select.
    let onOpened: (String) -> Void
    let onCancel: () -> Void

    private enum Kind: String, CaseIterable, Identifiable {
        case chat = "Chat"
        case room = "Room"
        case join = "Join"
        var id: String { rawValue }
    }

    @State private var kind: Kind = .chat

    // Chat
    @State private var contactFid = ""
    @State private var contacts: [Contact] = []

    // Room
    @State private var roomName = ""
    @State private var roomDesc = ""
    @State private var roomMembers = ""

    // Join
    @State private var joinType: ImType = .team
    @State private var joinId = ""

    @State private var working = false
    @State private var error: String?
    @State private var note: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("New conversation").font(.title3.bold())

            Picker("", selection: $kind) {
                ForEach(Kind.allCases) { Text($0.rawValue).tag($0) }
            }
            .pickerStyle(.segmented)
            .labelsHidden()

            switch kind {
            case .chat: chatForm
            case .room: roomForm
            case .join: joinForm
            }

            if let error {
                CopyableText(error, font: .callout).foregroundStyle(.red)
            }
            if let note {
                Text(note).font(.caption).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }

            HStack {
                Spacer()
                Button("Cancel", role: .cancel) { onCancel() }
                Button(primaryTitle) { commit() }
                    .buttonStyle(.borderedProminent)
                    .disabled(working || !canCommit)
            }
        }
        .padding(20)
        .frame(width: 480)
        .onAppear { contacts = (try? session.contacts.all()) ?? [] }
    }

    // MARK: - forms

    private var chatForm: some View {
        VStack(alignment: .leading, spacing: 8) {
            TextField("FID", text: $contactFid, prompt: Text("F…"))
                .font(.system(.body, design: .monospaced))

            if !contacts.isEmpty {
                Text("Contacts").font(.caption).foregroundStyle(.secondary)
                ScrollView {
                    VStack(alignment: .leading, spacing: 0) {
                        ForEach(contacts, id: \.id) { contact in
                            Button {
                                contactFid = contact.id
                            } label: {
                                HStack(spacing: 8) {
                                    FidAvatarView(fid: contact.id, size: 22)
                                    Text(contact.name)
                                        .lineLimit(1)
                                    Spacer()
                                }
                                .contentShape(Rectangle())
                            }
                            .buttonStyle(.borderless)
                            .padding(.vertical, 4)
                        }
                    }
                }
                .frame(maxHeight: 160)
            }

            Text("Opens a thread on this device. Messages to them are encrypted so that both of you can reopen them.")
                .font(.caption)
                .foregroundStyle(.tertiary)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    private var roomForm: some View {
        VStack(alignment: .leading, spacing: 8) {
            TextField("Name", text: $roomName, prompt: Text("The Usual Place"))
            TextField("Description", text: $roomDesc, prompt: Text("optional"))
            TextField("Invite (one FID per line)", text: $roomMembers, axis: .vertical)
                .lineLimit(2...5)
                .font(.system(.body, design: .monospaced))

            Text("A room is local: nothing about it is on the chain, and you decide who is in it. Each invitation carries the room's key, sealed to that person — anyone whose public key we can't find is invited without one and has to ask for it.")
                .font(.caption)
                .foregroundStyle(.tertiary)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    private var joinForm: some View {
        VStack(alignment: .leading, spacing: 8) {
            Picker("Kind", selection: $joinType) {
                Text("Team").tag(ImType.team)
                Text("Square").tag(ImType.square)
            }
            .pickerStyle(.segmented)

            TextField(joinType == .team ? "Team id" : "Square id", text: $joinId)
                .font(.system(.body, design: .monospaced))

            Text(joinType == .team
                 ? "Joining a team is a transaction: it is carved on chain, costs a miner fee, and is public. The carve also quotes the team's consensus document — joining is a signed statement that you agree to it."
                 : "Joining a square is a transaction: it is carved on chain, costs a miner fee, and is public. Squares are open and unencrypted.")
                .font(.caption)
                .foregroundStyle(.tertiary)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    private var primaryTitle: String {
        switch kind {
        case .chat: return "Open chat"
        case .room: return "Create room"
        case .join: return working ? "Carving…" : "Join on-chain"
        }
    }

    private var canCommit: Bool {
        switch kind {
        case .chat: return !contactFid.trimmingCharacters(in: .whitespaces).isEmpty
        case .room: return !roomName.trimmingCharacters(in: .whitespaces).isEmpty && session.canSign
        case .join: return !joinId.trimmingCharacters(in: .whitespaces).isEmpty && session.canSign
        }
    }

    // MARK: - actions

    private func commit() {
        error = nil
        switch kind {
        case .chat: openChat()
        case .room: createRoom()
        case .join: Task { await joinOnChain() }
        }
    }

    /// A P2P thread is opened locally. There is nothing to tell the
    /// other end yet — they learn of it when the first message lands.
    private func openChat() {
        let fid = contactFid.trimmingCharacters(in: .whitespaces)
        guard (try? FchAddress(fid: fid)) != nil else {
            error = "That is not a valid FID."
            return
        }
        do {
            let id = Conversation.id(type: .p2p, targetId: fid)
            if try session.conversations.get(id: id) == nil {
                var conversation = Conversation(id: id, targetId: fid, type: .p2p)
                conversation.unreadCount = 0
                conversation.displayName = try session.contacts.get(fid: fid)?.cid
                try session.conversations.upsert(conversation)
            }
            onOpened(id)
        } catch {
            self.error = String(describing: error)
        }
    }

    private func createRoom() {
        do {
            let members = roomMembers
                .split(whereSeparator: \.isNewline)
                .map { $0.trimmingCharacters(in: .whitespaces) }
                .filter { !$0.isEmpty }

            let service = try session.roomService
            let (room, invitations) = try service.create(
                name: roomName.trimmingCharacters(in: .whitespaces),
                desc: roomDesc.isEmpty ? nil : roomDesc,
                owner: session.liveFid,
                invite: members,
                pubkeys: { fid in try session.contacts.get(fid: fid)?.pubkey }
            )
            guard let roomId = room.id else { return }

            let conversationId = Conversation.id(type: .room, targetId: roomId)
            var conversation = Conversation(id: conversationId, targetId: roomId, type: .room)
            conversation.displayName = room.name
            conversation.memberNum = Int64(room.memberCount)
            conversation.unreadCount = 0
            conversation.hasSymkey = true
            conversation.symkeyVersion = room.symkeyVersion
            try session.conversations.upsert(conversation)

            // The invitations are P2P control messages, so they queue
            // like anything else and go out when the transport does.
            for invitation in invitations {
                guard let to = invitation.targetId else { continue }
                try session.outbox.enqueue(
                    invitation, in: Conversation.id(type: .p2p, targetId: to)
                )
            }
            note = invitations.isEmpty
                ? nil
                : "\(invitations.count) invitation(s) queued — they go out with the transport (9.2.4b)."
            onOpened(conversationId)
        } catch {
            self.error = String(describing: error)
        }
    }

    private func joinOnChain() async {
        await MainActor.run { working = true }
        let id = joinId.trimmingCharacters(in: .whitespaces)
        do {
            let txid: String
            if joinType == .team {
                // Read the consensus id from the team record rather than
                // a cached copy: the carve is a signed statement about
                // *which* document was agreed to.
                let consensusId = try session.teams.get(id: id)?.consensusId
                txid = try await session.carveTeamJoinOnChain(teamId: id, consensusId: consensusId)
            } else {
                txid = try await session.carveSquareJoinOnChain(squareId: id)
            }
            await MainActor.run {
                working = false
                note = "Broadcast — tx \(txid.elidingMiddle(head: 8, tail: 8)). The thread appears after the carve confirms and you refresh."
            }
        } catch {
            await MainActor.run {
                working = false
                self.error = String(describing: error)
            }
        }
    }
}
