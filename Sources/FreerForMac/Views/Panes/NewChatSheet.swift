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
    /// Called with the conversation id to select, and anything the user
    /// still needs told. The sheet closes on this, so a note it left on
    /// its own screen would never be read — creating a room is the case
    /// that has something to say (members with no DOCK were not written
    /// to), and it has to survive the sheet.
    let onOpened: (String, String?) -> Void
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
    @State private var chatParty: PickedFid?

    // Room
    @State private var roomName = ""
    @State private var roomDesc = ""
    /// The room's DOCK, as a service id or a direct address. Android's
    /// `room_dock_input`.
    @State private var roomDock = ""
    @State private var roomInvitees: [PickedFid] = []
    @State private var pickingDock = false

    /// Which pick the open picker is for. One sheet, two jobs — the
    /// request says which.
    @State private var pick: FidPickerRequest?

    // Join a team or a square
    @State private var joinId = ""

    // Create a team or a square
    @State private var groupName = ""
    @State private var groupDesc = ""
    @State private var consensusId = ""
    /// The group's DOCK. Android asks for one on both create screens,
    /// and it is not optional in practice: a team or a square with no
    /// DOCK is one whose members have nowhere to leave a message, so it
    /// can be carved and then never spoken in.
    @State private var groupDock = ""
    /// The team's DISK — where the consensus document is published, and
    /// therefore the only route any member has to reading it. Carved
    /// with the team, in plaintext, because a peer holding no key at all
    /// has to be able to resolve it.
    @State private var groupDisk = ""
    @State private var pickingDisk = false
    @State private var document: DocumentRequest?

    @State private var working = false
    @State private var error: String?
    @State private var note: String?

    /// An open consensus-document sheet. Identifiable so a fresh id
    /// re-opens it after a save rather than reusing stale text.
    private struct DocumentRequest: Identifiable {
        let id = UUID()
        let consensusId: String
        let editable: Bool
    }

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
        .sheet(item: $pick) { request in
            FidPickerSheet(session: session, request: request) { picked in
                receive(picked)
                pick = nil
            } onCancel: {
                pick = nil
            }
        }
        .sheet(isPresented: $pickingDock) {
            ServicePickerSheet(
                session: session,
                component: ServiceName.dock,
                title: "Choose this \(style.noun)'s DOCK",
                subtitle: "The \(style.noun)'s messages rest here until each member collects them. Everyone reads from the same one, so it is set once for the whole \(style.noun).",
                initialQuery: mode == .room ? roomDock : groupDock
            ) { service in
                // The service id, not the address: the server can move,
                // and every member re-resolves the id through the chain.
                if mode == .room { roomDock = service.sid } else { groupDock = service.sid }
                pickingDock = false
            } onCancel: {
                pickingDock = false
            }
        }
        .sheet(isPresented: $pickingDisk) {
            ServicePickerSheet(
                session: session,
                component: ServiceName.disk,
                title: "Choose this team's DISK",
                subtitle: "The consensus document is stored here. Its id is the hash of its contents, so anyone can check that what they downloaded is what was carved.",
                initialQuery: groupDisk
            ) { service in
                groupDisk = service.sid
                pickingDisk = false
            } onCancel: {
                pickingDisk = false
            }
        }
        .sheet(item: $document) { request in
            ConsensusDocumentSheet(
                session: session,
                title: "This team's consensus",
                consensusId: request.consensusId,
                // Nothing is on chain yet, so the only DISK worth trying
                // is the one being chosen for the team.
                diskSids: [groupDisk],
                editable: request.editable,
                onSaved: { newId in
                    consensusId = newId
                    document = nil
                },
                onClose: { document = nil }
            )
        }
    }

    private func pickConsensusFile() {
        let panel = NSOpenPanel()
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = false
        panel.message = "Choose the document this team's members will agree to."
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            consensusId = try session.teamConsensus.importFile(at: url)
            error = nil
        } catch {
            self.error = String(describing: error)
        }
    }

    /// Route a pick back to whichever form asked for it. The mode is
    /// fixed by the caller, so there is no third possibility.
    private func receive(_ picked: [PickedFid]) {
        switch mode {
        case .p2p:
            guard let one = picked.first else { return }
            chatParty = one
            contactFid = one.fid
        case .room:
            let known = Set(roomInvitees.map(\.fid))
            roomInvitees.append(contentsOf: picked.filter { !known.contains($0.fid) })
        case .team, .square:
            break
        }
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
            LabeledField("FID") {
                HStack(spacing: 8) {
                    TextField("", text: $contactFid, prompt: Text("F…"))
                        .font(.system(.body, design: .monospaced))
                        .fieldInputStyle()
                        .onChange(of: contactFid) { _, new in
                            // Typing over a pick drops what came with it.
                            if chatParty?.fid != new { chatParty = nil }
                        }
                    Button {
                        pick = .one(
                            title: "Who is this chat with?",
                            subtitle: "Search your contacts, or look up a FID or CID on chain."
                        )
                    } label: {
                        Label("Find…", systemImage: "person.text.rectangle")
                    }
                    .help("Search contacts and the chain for the person to chat with.")
                }
            }

            if let party = chatParty {
                HStack(spacing: 8) {
                    FidAvatarView(fid: party.fid, size: 24)
                    Text(party.name).font(.callout).lineLimit(1)
                    if party.pubkey == nil {
                        Label("no published key", systemImage: "lock.open")
                            .font(.caption)
                            .foregroundStyle(.orange)
                            .help("They haven't published a public key, so messages to them can't be encrypted until they do.")
                    }
                    Spacer()
                }
            }

            Text("Opens a thread on this device. Messages to them are encrypted so that both of you can reopen them.")
                .font(.caption)
                .foregroundStyle(.tertiary)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    private var roomForm: some View {
        VStack(alignment: .leading, spacing: 4) {
            LabeledField("Room name") {
                TextField("", text: $roomName, prompt: Text("The Usual Place"))
                    .fieldInputStyle()
            }
            LabeledField("Description") {
                TextField("", text: $roomDesc, prompt: Text("optional"))
                    .fieldInputStyle()
            }

            LabeledField(
                "DOCK",
                hint: "Where this room's messages rest until each member collects them. Without one there is nowhere for them to wait, so the room can be created but nothing can be said in it until you set one."
            ) {
                HStack(spacing: 8) {
                    TextField("", text: $roomDock, prompt: Text("service id, or host:port"))
                        .font(.system(.body, design: .monospaced))
                        .fieldInputStyle()
                    Button {
                        pickingDock = true
                    } label: {
                        Label("Find…", systemImage: "server.rack")
                    }
                    .help("Search the chain for a server that offers DOCK.")
                }
            }

            HStack(spacing: 8) {
                Text("Invite")
                    .font(.caption)
                    .fontWeight(.semibold)
                    .textCase(.uppercase)
                    .tracking(0.5)
                    .foregroundStyle(.secondary)
                Button {
                    pick = .many(
                        title: "Invite to this room",
                        subtitle: "Everyone picked gets the room's key sealed to their public key, when we know it.",
                        confirmTitle: "Invite",
                        preselected: roomInvitees,
                        excluded: [session.liveFid]
                    )
                } label: {
                    Label("Add people…", systemImage: "person.crop.circle.badge.plus")
                }
                Spacer()
                if !roomInvitees.isEmpty {
                    Button("Clear") { roomInvitees = [] }
                        .buttonStyle(.borderless)
                        .font(.caption)
                }
            }

            if !roomInvitees.isEmpty {
                ScrollView(.horizontal, showsIndicators: false) {
                    HStack(spacing: 6) {
                        ForEach(roomInvitees) { invitee in
                            HStack(spacing: 5) {
                                FidAvatarView(fid: invitee.fid, size: 18)
                                Text(invitee.cid ?? invitee.fid.elidingMiddle(head: 6, tail: 6))
                                    .font(.caption)
                                if invitee.pubkey == nil {
                                    Image(systemName: "lock.open")
                                        .font(.caption2)
                                        .foregroundStyle(.orange)
                                        .help("No published key — they'll be invited without the room key and have to ask for it.")
                                }
                                Button {
                                    roomInvitees.removeAll { $0.fid == invitee.fid }
                                } label: {
                                    Image(systemName: "xmark.circle.fill")
                                        .font(.caption)
                                        .foregroundStyle(.secondary)
                                }
                                .buttonStyle(.plain)
                            }
                            .padding(.horizontal, 7)
                            .padding(.vertical, 4)
                            .background(Capsule().fill(Color.accentColor.opacity(0.14)))
                        }
                    }
                    .padding(.vertical, 2)
                }
            }

            Text("Costs nothing and asks nobody: a room exists only on the devices that hold it. Each invitation carries the room's key sealed to that person — anyone whose public key we can't find is invited without one and has to ask.")
                .font(.caption)
                .foregroundStyle(.tertiary)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    private var joinForm: some View {
        VStack(alignment: .leading, spacing: 8) {
            LabeledField(mode == .team ? "Team id" : "Square id") {
                TextField("", text: $joinId, prompt: Text("the create carve's txid"))
                    .font(.system(.body, design: .monospaced))
                    .fieldInputStyle()
            }

            Text(mode == .team
                 ? "Joining a team is a transaction: carved on chain, costs a miner fee, and is public. The carve quotes the team's consensus document, so joining is a signed statement that you agree to it."
                 : "Joining a square is a transaction: carved on chain, costs a miner fee, and is public. A square is open and unencrypted.")
                .font(.caption)
                .foregroundStyle(.tertiary)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    private var createGroupForm: some View {
        VStack(alignment: .leading, spacing: 4) {
            LabeledField(mode == .team ? "Team name" : "Square name") {
                TextField(
                    "", text: $groupName,
                    prompt: Text(mode == .team ? "The Standard Name" : "The Square")
                )
                .fieldInputStyle()
            }
            LabeledField("Description") {
                TextField("", text: $groupDesc, prompt: Text("optional"))
                    .fieldInputStyle()
            }

            if mode == .team {
                LabeledField(
                    "Consensus document",
                    hint: "What members agree to when they join — their carve quotes its id, which is what makes agreement a public, signed act rather than a checkbox. The id is the hash of the text, so it is written after the document is, not before."
                ) {
                    VStack(alignment: .leading, spacing: 6) {
                        TextField("", text: $consensusId, prompt: Text("required"))
                            .font(.system(.body, design: .monospaced))
                            .fieldInputStyle()
                        HStack(spacing: 8) {
                            Button {
                                document = DocumentRequest(
                                    consensusId: consensusId.trimmingCharacters(in: .whitespaces),
                                    editable: true
                                )
                            } label: {
                                Label(consensusId.isEmpty ? "Write one…" : "Edit…",
                                      systemImage: "square.and.pencil")
                            }
                            .help("Start from a template that asks the questions a consensus has to answer, and edit it into yours.")
                            Button { pickConsensusFile() } label: {
                                Label("Choose file…", systemImage: "doc.badge.plus")
                            }
                            .help("Use a document already on this Mac.")
                        }
                        .buttonStyle(.borderless)
                        .font(.caption)
                    }
                }

                LabeledField(
                    "DISK",
                    hint: "Where the consensus document is stored, unencrypted and permanently, so anyone weighing up joining can read it. The id is published in the team's home in plain text, which is the whole of how a member finds the document."
                ) {
                    HStack(spacing: 8) {
                        TextField("", text: $groupDisk, prompt: Text("service id"))
                            .font(.system(.body, design: .monospaced))
                            .fieldInputStyle()
                        Button { pickingDisk = true } label: {
                            Label("Find…", systemImage: "externaldrive")
                        }
                        .help("Search the chain for a server that offers DISK.")
                    }
                }
            }

            LabeledField(
                "DOCK",
                hint: "Where this \(style.noun)'s messages rest until each member collects them. It is carved with the \(style.noun), and a \(style.noun) created without one cannot be spoken in until a later update sets it — which is another transaction."
            ) {
                HStack(spacing: 8) {
                    TextField("", text: $groupDock, prompt: Text("service id, or host:port"))
                        .font(.system(.body, design: .monospaced))
                        .fieldInputStyle()
                    Button {
                        pickingDock = true
                    } label: {
                        Label("Find…", systemImage: "server.rack")
                    }
                    .help("Search the chain for a server that offers DOCK.")
                }
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
            if groupAction == .join { return filled(joinId) }
            guard filled(groupName) else { return false }
            // A team is refused without both halves of its consensus:
            // the document, and somewhere members can read it. Stated by
            // the button rather than discovered at carve time.
            if mode == .team { return filled(consensusId) && filled(groupDisk) }
            return true
        }
    }

    // MARK: - actions

    private func commit() {
        error = nil
        switch mode {
        case .p2p:
            // A nobody's side of a chat is anyone's to read and write.
            // The request board explains itself and is not asked about.
            let fid = contactFid.trimmingCharacters(in: .whitespaces)
            Task {
                if !NobodyBoard.isDefaultNobody(fid) {
                    guard await NobodyGate.confirm([fid], .chat, session: session) else { return }
                }
                openChat()
            }
        case .room:
            Task {
                guard await NobodyGate.confirm(roomInvitees.map(\.fid), .room, session: session) else { return }
                createRoom()
            }
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
                conversation.displayName = try chatParty.flatMap { $0.fid == fid ? $0.cid : nil }
                    ?? session.contacts.get(fid: fid)?.cid
                try session.conversations.upsert(conversation)
            }
            // Opening a thread with somebody is consent to hear from
            // them: without this their reply would come back through the
            // stranger gate and be held as a request, which would be an
            // absurd thing to do to a conversation the user just started.
            try session.contactPolicy.mutate(liveFid: session.liveFid) { $0.allow(fid) }
            onOpened(id, nil)
        } catch {
            self.error = String(describing: error)
        }
    }

    private func createRoom() {
        do {
            let members = roomInvitees.map(\.fid)
            // The picker looks each pick up as it is chosen, so the key
            // an invitation is sealed to is the one the chain published
            // moments ago — fresher than whatever the local contact row
            // happens to hold. Contacts remain the fallback for a pick
            // the directory couldn't answer for.
            let pickedPubkeys = Dictionary(
                roomInvitees.compactMap { p in p.pubkey.map { (p.fid, $0) } },
                uniquingKeysWith: { first, _ in first }
            )

            // Same argument for the home map: the picker's on-chain
            // record is fresher than the contact row, and a member whose
            // record we have never fetched reads as "no DOCK" — which is
            // the honest answer and the one that keeps an undeliverable
            // invitation out of the outbox.
            let pickedHomes = Dictionary(
                roomInvitees.compactMap { p in p.freer?.home.map { (p.fid, $0) } },
                uniquingKeysWith: { first, _ in first }
            )

            let dock = roomDock.trimmingCharacters(in: .whitespaces)
            let service = try session.roomService
            let created = try service.create(
                name: roomName.trimmingCharacters(in: .whitespaces),
                desc: roomDesc.isEmpty ? nil : roomDesc,
                owner: session.liveFid,
                invite: members,
                home: dock.isEmpty ? nil : [ServiceName.dock: dock],
                pubkeys: { fid in
                    try pickedPubkeys[fid] ?? session.contacts.get(fid: fid)?.pubkey
                },
                homes: { fid in
                    try pickedHomes[fid] ?? session.knownHome(of: fid)
                }
            )
            let room = created.room
            let invitations = created.invitations
            guard let roomId = room.id else { return }

            let conversationId = Conversation.id(type: .room, targetId: roomId)
            try session.roomConversations.sync(roomId)

            // The invitations are P2P control messages, so they queue
            // like anything else and go out on the next send.
            for invitation in invitations {
                guard let to = invitation.targetId else { continue }
                try session.outbox.enqueue(
                    invitation, in: Conversation.id(type: .p2p, targetId: to)
                )
            }
            var lines: [String] = []
            if !invitations.isEmpty { lines.append("\(invitations.count) invitation(s) queued.") }
            if !created.unreachable.isEmpty {
                lines.append(
                    "\(created.unreachable.count) invited member(s) publish no DOCK, so there is nowhere to leave an invitation for them — they are in the room, and you can share its details again once they have a server."
                )
            }
            if dock.isEmpty {
                lines.append("No DOCK set: nothing can be said here until you set one.")
            }
            onOpened(conversationId, lines.isEmpty ? nil : lines.joined(separator: " "))
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
                // **Read from the chain, not the cache.** The carve is a
                // signed statement about *which* document was agreed to,
                // and the parser refuses a join whose id is not the
                // team's current one — so a stale cached copy costs the
                // fee and joins nothing. This is also the only way a
                // team we have never synced can be joined at all.
                let fresh = try await session.freshTeam(id: id)
                // A team owned by a nobody can be run by anyone.
                let owner = try fresh?.owner ?? session.teams.get(id: id)?.owner
                guard await NobodyGate.confirm([owner], .teamOwner, session: session) else {
                    await MainActor.run { working = false }
                    return
                }
                let consensus = try fresh?.consensusId
                    ?? session.teams.get(id: id)?.consensusId
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
    ///
    /// **A team's consensus document is uploaded first, and the carve is
    /// abandoned if that fails.** The id carved on chain is a hash and
    /// nothing else — the indexer never resolves it, so a team whose
    /// consensus points at bytes no DISK holds looks perfectly valid and
    /// is unreadable forever. Failing here costs nothing; failing after
    /// the carve costs the fee and leaves a permanent dead pointer that
    /// every joiner signs their agreement to.
    private func createGroupOnChain() async {
        await MainActor.run { working = true }
        let name = groupName.trimmingCharacters(in: .whitespaces)
        let desc = groupDesc.trimmingCharacters(in: .whitespaces)
        let dock = groupDock.trimmingCharacters(in: .whitespaces)
        let diskSid = groupDisk.trimmingCharacters(in: .whitespaces)
        let consensus = consensusId.trimmingCharacters(in: .whitespaces)

        // The service ids go on the chain, not the addresses they
        // currently resolve to — the same reasoning as a room's DOCK,
        // except that here they are public and everyone reads them from
        // the same record. `(sid)`-prefixed, which is the shape the rest
        // of the family writes.
        let home = GroupHome.merged(over: nil, changing: [
            ServiceName.dock: dock.isEmpty ? nil : dock,
            ServiceName.disk: mode == .team && !diskSid.isEmpty ? diskSid : nil,
        ])
        do {
            let txid: String
            if mode == .team {
                try await publishConsensus(consensus, toDiskSid: diskSid)
                txid = try await session.carveTeamCreateOnChain(
                    stdName: name,
                    desc: desc.isEmpty ? nil : desc,
                    consensusId: consensus.isEmpty ? nil : consensus,
                    home: home
                )
            } else {
                txid = try await session.carveSquareCreateOnChain(
                    name: name, desc: desc.isEmpty ? nil : desc, home: home
                )
            }
            await MainActor.run {
                working = false
                var lines = ["Broadcast — tx \(txid.elidingMiddle(head: 8, tail: 8)). That txid is the \(style.noun)'s id. It appears here once the carve confirms and you refresh."]
                if dock.isEmpty {
                    lines.append("No DOCK was carved, so nothing can be said here until you set one — which is another transaction.")
                }
                note = lines.joined(separator: " ")
            }
        } catch {
            await MainActor.run {
                working = false
                self.error = String(describing: error)
            }
        }
    }

    /// Put the consensus document on the team's DISK before the team
    /// exists. Refuses rather than carving an id with nothing behind it.
    private func publishConsensus(_ consensus: String, toDiskSid diskSid: String) async throws {
        guard !consensus.isEmpty else { throw CreateRefusal.noConsensus }
        guard !diskSid.isEmpty else { throw CreateRefusal.noDisk }
        await MainActor.run { note = "Uploading the consensus document…" }
        let placement = try await session.teamConsensus.place(
            consensusId: consensus,
            onDiskSid: diskSid,
            // A team being created is not moving from anywhere.
            fallbackDiskSid: nil
        )
        if case .unavailable = placement { throw CreateRefusal.documentMissing }
    }

    private enum CreateRefusal: Error, CustomStringConvertible {
        case noConsensus
        case noDisk
        case documentMissing

        var description: String {
            switch self {
            case .noConsensus:
                return "A team needs a consensus document: it is what every member signs their agreement to when they join, and a team without one has nothing for that signature to mean. Write one, or choose a file."
            case .noDisk:
                return "A team needs a DISK. The consensus id carved on chain is only a hash — without a server publishing the bytes, nobody can read what they are agreeing to."
            case .documentMissing:
                return "That consensus id names no document this Mac holds, so there is nothing to upload. Nothing was carved. Write the document or choose its file, and the id follows from its contents."
            }
        }
    }
}
