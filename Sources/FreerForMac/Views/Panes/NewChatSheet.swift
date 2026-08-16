import SwiftUI
import FCCore
import FCDomain
import FCUI

/// Starting a conversation — the Mac port of Android's
/// `NewTalkActivity` / `CreateRoomActivity` / `JoinTeamActivity` /
/// `CreateTeamActivity` / `JoinSquareActivity` / `CreateSquareActivity`.
///
/// **The flavour is decided by the tab you came from, not in here.**
/// This sheet used to open on a three-way picker — Chat / Room / Join —
/// which meant the mode was chosen twice and the second choice could
/// contradict the first: pressing "New" in the Squares tab and getting a
/// room. Now the caller states the mode and the sheet only asks what is
/// genuinely still open.
///
/// For a chat and a room, nothing is: one form, one button. For a team
/// and a square there are two real answers, and they are wildly
/// different in cost and in consequence, so those two get a picker:
///
/// - **Join** an existing one by id. A transaction, a miner fee, public
///   — and for a team, a signed statement of agreement to its consensus
///   document.
/// - **Create** a new one. Also a transaction, and the id you get is the
///   carve's own txid, so there is nothing to show until it confirms.
///
/// A room is the odd one out and the sheet says so: it costs nothing and
/// exists nowhere but on the devices that hold it.
struct NewChatSheet: View {

    let session: ActiveSession
    /// Which flavour is being made. Authoritative — the sheet never
    /// crosses from one to another.
    var mode: ImType = .p2p
    /// Called with the conversation id to select.
    let onOpened: (String) -> Void
    let onCancel: () -> Void

    /// The one question a team and a square still leave open.
    private enum GroupAction: String, CaseIterable, Identifiable {
        case join = "Join one"
        case create = "Create one"
        var id: String { rawValue }
    }

    @State private var groupAction: GroupAction = .join

    // Chat
    @State private var contactFid = ""
    @State private var contacts: [Contact] = []

    // Room
    @State private var roomName = ""
    @State private var roomDesc = ""
    @State private var roomMembers = ""

    // Join a team or a square
    @State private var joinId = ""

    // Create a team or a square
    @State private var groupName = ""
    @State private var groupDesc = ""
    @State private var consensusId = ""

    @State private var working = false
    @State private var error: String?
    @State private var note: String?

    private var style: ChatModeStyle { .of(mode) }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack(spacing: 8) {
                Image(systemName: style.systemImage).foregroundStyle(style.tint)
                Text(title).font(.title3.bold())
            }

            Text(style.summary)
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            if style.syncsFromChain {
                Picker("", selection: $groupAction) {
                    ForEach(GroupAction.allCases) { Text($0.rawValue).tag($0) }
                }
                .pickerStyle(.segmented)
                .labelsHidden()
            }

            form

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

    private var title: String {
        switch mode {
        case .p2p:    return "New chat"
        case .room:   return "New room"
        case .team:   return groupAction == .join ? "Join a team" : "Create a team"
        case .square: return groupAction == .join ? "Join a square" : "Create a square"
        }
    }

    // MARK: - forms

    @ViewBuilder
    private var form: some View {
        switch mode {
        case .p2p:  chatForm
        case .room: roomForm
        case .team, .square:
            if groupAction == .join { joinForm } else { createGroupForm }
        }
    }

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

            Text("Costs nothing and asks nobody: a room exists only on the devices that hold it. Each invitation carries the room's key sealed to that person — anyone whose public key we can't find is invited without one and has to ask.")
                .font(.caption)
                .foregroundStyle(.tertiary)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    private var joinForm: some View {
        VStack(alignment: .leading, spacing: 8) {
            TextField(mode == .team ? "Team id" : "Square id", text: $joinId)
                .font(.system(.body, design: .monospaced))

            Text(mode == .team
                 ? "Joining a team is a transaction: carved on chain, costs a miner fee, and is public. The carve quotes the team's consensus document, so joining is a signed statement that you agree to it."
                 : "Joining a square is a transaction: carved on chain, costs a miner fee, and is public. A square is open and unencrypted.")
                .font(.caption)
                .foregroundStyle(.tertiary)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    private var createGroupForm: some View {
        VStack(alignment: .leading, spacing: 8) {
            TextField("Name", text: $groupName, prompt: Text(mode == .team ? "The Standard Name" : "The Square"))
            TextField("Description", text: $groupDesc, prompt: Text("optional"))

            if mode == .team {
                TextField("Consensus document id", text: $consensusId, prompt: Text("optional, but see below"))
                    .font(.system(.body, design: .monospaced))
                Text("The consensus document is what members agree to when they join — their carve quotes it, which is what makes agreement a public, signed act rather than a checkbox. A team created without one has nothing for its members to agree to.")
                    .font(.caption)
                    .foregroundStyle(.tertiary)
                    .fixedSize(horizontal: false, vertical: true)
            }

            Text("Creating is a transaction: it costs a miner fee and is public. **The id is the carve's own txid**, so nothing appears here until it confirms and you refresh — you are its first member either way.")
                .font(.caption)
                .foregroundStyle(.tertiary)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    private var primaryTitle: String {
        if working { return "Carving…" }
        switch mode {
        case .p2p:  return "Open chat"
        case .room: return "Create room"
        case .team, .square:
            return groupAction == .join ? "Join on-chain" : "Create on-chain"
        }
    }

    private var canCommit: Bool {
        func filled(_ s: String) -> Bool { !s.trimmingCharacters(in: .whitespaces).isEmpty }
        switch mode {
        case .p2p:  return filled(contactFid)
        case .room: return filled(roomName) && session.canSign
        case .team, .square:
            guard session.canSign else { return false }
            return groupAction == .join ? filled(joinId) : filled(groupName)
        }
    }

    // MARK: - actions

    private func commit() {
        error = nil
        switch mode {
        case .p2p:  openChat()
        case .room: createRoom()
        case .team, .square:
            Task { groupAction == .join ? await joinOnChain() : await createGroupOnChain() }
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
            // Opening a thread with somebody is consent to hear from
            // them: without this their reply would come back through the
            // stranger gate and be held as a request, which would be an
            // absurd thing to do to a conversation the user just started.
            try session.contactPolicy.mutate(liveFid: session.liveFid) { $0.allow(fid) }
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
            // like anything else and go out on the next send.
            for invitation in invitations {
                guard let to = invitation.targetId else { continue }
                try session.outbox.enqueue(
                    invitation, in: Conversation.id(type: .p2p, targetId: to)
                )
            }
            note = invitations.isEmpty ? nil : "\(invitations.count) invitation(s) queued."
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
            if mode == .team {
                // Read the consensus id from the team record rather than
                // a cached copy: the carve is a signed statement about
                // *which* document was agreed to.
                let consensus = try session.teams.get(id: id)?.consensusId
                txid = try await session.carveTeamJoinOnChain(teamId: id, consensusId: consensus)
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

    /// Create a team or a square.
    ///
    /// Nothing is written locally, and that is not laziness: the id is
    /// the carve's txid, so until the transaction confirms there is no
    /// entity to make a row for. The group sync finds it.
    private func createGroupOnChain() async {
        await MainActor.run { working = true }
        let name = groupName.trimmingCharacters(in: .whitespaces)
        let desc = groupDesc.trimmingCharacters(in: .whitespaces)
        do {
            let txid: String
            if mode == .team {
                let consensus = consensusId.trimmingCharacters(in: .whitespaces)
                txid = try await session.carveTeamCreateOnChain(
                    stdName: name,
                    desc: desc.isEmpty ? nil : desc,
                    consensusId: consensus.isEmpty ? nil : consensus
                )
            } else {
                txid = try await session.carveSquareCreateOnChain(
                    name: name, desc: desc.isEmpty ? nil : desc
                )
            }
            await MainActor.run {
                working = false
                note = "Broadcast — tx \(txid.elidingMiddle(head: 8, tail: 8)). That txid is the \(style.noun)'s id. It appears here once the carve confirms and you refresh."
            }
        } catch {
            await MainActor.run {
                working = false
                self.error = String(describing: error)
            }
        }
    }
}
