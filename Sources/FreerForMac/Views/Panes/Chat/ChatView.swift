import SwiftUI
import FCCore
import FCDomain
import FCUI

/// The chat pane — the Mac port of Android's `TalkActivity`,
/// `RoomActivity`, `TeamActivity` and `SquareActivity`, plus the
/// `ChatActivity` they all open.
///
/// **Four flavours, four lists.** Phase 9.2.7a put all four in one list
/// on the grounds that everything separating them had been settled
/// below the view. That was true of *sealing* and of nothing else. A
/// square is public and unencrypted, a room is sealed to a membership
/// only its owner knows, a team is sealed to a membership the chain
/// publishes, and a P2P chat is sealed to one person — four security
/// models, four sets of things that can go wrong, and one list in which
/// they differed by a small coloured chip. Android never merges them,
/// and the reason is the one that matters: the defence against sending
/// a private message into a public square is that the two never look
/// alike and are never one mis-click apart.
///
/// So: a tab per flavour, each with its own list, its own selection, its
/// own draft and its own colour; ``ChatModeStyle`` is the single place
/// that colour and wording are decided.
///
/// **What you may send is a decision, not a view condition.** The pane
/// used to check whether we had left the group and let everything else
/// fail at send time. ``ChatGate`` now answers it in advance —
/// membership, the group's DOCK, and whether we hold the key — and this
/// view renders the verdict.
///
/// **Delivery is store-and-forward.** Sending seals a message, files it
/// and queues it; the courier parks it at the recipient's DOCK, where it
/// waits until they next collect. "Sent" means the DOCK took it and
/// nothing more.
struct ChatView: View {
    let session: ActiveSession

    /// The shell owns the poller. This pane only tells it two things:
    /// that a chat is on screen (so it polls faster), and which DOCK
    /// the open conversation lives on (so that one is polled fastest).
    @Environment(AppState.self) private var appState

    /// Which flavour's tab is showing. Everything below is scoped to it.
    @State private var mode: ImType = .p2p

    /// Threads per flavour. Kept apart rather than filtered out of one
    /// array so that nothing — a stale index, a sort, a search — can put
    /// a square in front of someone who thinks they are in a P2P list.
    @State private var threads: [ImType: [Conversation]] = [:]
    /// The open thread **per flavour**: switching tabs must not carry a
    /// selection across a security boundary.
    @State private var selection: [ImType: String] = [:]
    /// Unsent text, per conversation. A draft typed for one thread
    /// following you into another is the same class of mistake this
    /// whole pane exists to prevent.
    @State private var drafts: [String: String] = [:]

    @State private var page: MessagesStore.Page = .init(messages: [], olderCursor: nil)
    @State private var search = ""

    /// Senders this identity has not agreed to hear from, and how many
    /// messages each is holding. Only ever non-empty on the Chats tab —
    /// group traffic does not go through the stranger gate.
    @State private var requests: [MessageRequest] = []

    @State private var loadError: String?
    @State private var sendError: String?
    @State private var showNewChat = false
    @State private var showDetails = false
    @State private var showRequests = false
    @State private var showPolicy = false
    @State private var showMembers = false
    /// Which "ask somebody for something" sheet is open, if any. Nil is
    /// closed — the sheet needs to know *what* is being asked for, so a
    /// bare Bool could not say it.
    @State private var asking: AskMembersSheet.Ask?
    /// Room invitations waiting for an answer. Rooms tab only — a team
    /// or a square is joined by carving, not by being invited here.
    @State private var invites: [RoomInvite] = []
    @State private var confirmLeave = false
    @State private var syncing = false
    @State private var syncSummary: String?
    @State private var delivering = false
    @State private var attaching = false
    @State private var attachProgress: (sent: Int64, total: Int64)?

    /// One recorder and one player for the whole pane. The player is
    /// shared on purpose — see ``VoicePlayer``: two notes talking over
    /// each other is never what a click meant.
    @State private var recorder = VoiceRecorder()
    @State private var player = VoicePlayer()
    @State private var sendingVoice = false

    /// Resolved once per recipient, then reused: a P2P send needs the
    /// other party's pubkey and it never changes.
    @State private var pubkeys: [String: Data] = [:]

    // MARK: - derived

    private var style: ChatModeStyle { .of(mode) }

    private var conversations: [Conversation] { threads[mode] ?? [] }

    private var filtered: [Conversation] {
        let needle = search.trimmingCharacters(in: .whitespaces)
        guard !needle.isEmpty else { return conversations }
        return conversations.filter { $0.matches(query: needle) }
    }

    private var selectedId: Binding<String?> {
        Binding(
            get: { selection[mode] },
            set: { selection[mode] = $0 }
        )
    }

    private var selected: Conversation? {
        guard let id = selection[mode] else { return nil }
        return conversations.first { $0.id == id }
    }

    /// What the composer may do here, decided before it is drawn.
    private var verdict: ChatGate.Verdict {
        guard let selected else { return .open }
        return ChatGate.decide(session.chatGateFacts(for: selected))
    }

    private var draft: Binding<String> {
        Binding(
            get: { selection[mode].map { drafts[$0] ?? "" } ?? "" },
            set: { if let id = selection[mode] { drafts[id] = $0 } }
        )
    }

    private var leaveTitle: String { "Leave this \(style.noun)?" }

    private var leaveConfirmTitle: String {
        style.syncsFromChain ? "Leave (broadcast a carve)" : "Leave"
    }

    /// What leaving actually costs, said before it is done. The two
    /// on-chain flavours cost money and are public; a room is neither,
    /// but rejoining needs a fresh invitation.
    private var leaveMessage: String {
        switch mode {
        case .team, .square:
            return "Leaving is a transaction: it costs a miner fee and is public on the chain. You are still in until it confirms. The transcript stays on this Mac."
        case .room:
            return "The owner is told, and only they can let you back in. The transcript stays on this Mac."
        case .p2p:
            return ""
        }
    }

    private func unread(_ type: ImType) -> Int {
        (threads[type] ?? []).reduce(0) { $0 + ($1.unreadCount ?? 0) }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            PaneHeader(session: session)
            Divider()
            modeTabs
            toolbar

            if mode == .p2p, !requests.isEmpty {
                requestsBanner
            }
            if mode == .room, !invites.isEmpty {
                invitesBanner
            }

            if let err = loadError {
                card {
                    Label("Couldn't load chats", systemImage: "exclamationmark.triangle")
                        .foregroundStyle(.red)
                    CopyableText(err, font: .callout).foregroundStyle(.red)
                }
            } else if conversations.isEmpty {
                emptyCard
            } else {
                HStack(alignment: .top, spacing: 12) {
                    ConversationListView(
                        style: style,
                        conversations: filtered,
                        selectedId: selectedId
                    )
                    .frame(width: 260)
                    Divider()
                    transcript
                }
            }

            Spacer(minLength: 0)
        }
        .padding()
        .frame(minWidth: 720)
        .onAppear {
            reload()
            if selection[mode] == nil { selection[mode] = conversations.first?.id }
            openSelected()
            appState.setChatOpen(true)
            appState.fetchInboxNow()
            updatePriorityDock()
        }
        .onDisappear {
            appState.setChatOpen(false)
            appState.setPriorityDock(nil)
            // The microphone does not keep running behind a pane that
            // is not on screen, and an unsent recording is not a draft.
            recorder.cancel()
            player.stop()
        }
        // A flavour change is at least as sharp a context switch as a
        // thread change: a note recorded for a room must not be sendable
        // into a square, and the search box belongs to the list that was
        // being searched.
        .onChange(of: mode) { _, _ in
            recorder.cancel()
            player.stop()
            search = ""
            if selection[mode] == nil { selection[mode] = conversations.first?.id }
            openSelected()
            updatePriorityDock()
        }
        .onChange(of: selection[mode]) { _, _ in
            recorder.cancel()
            player.stop()
            openSelected()
            updatePriorityDock()
        }
        // The poller files straight into the stores, behind this view's
        // back. Without this the transcript would sit stale until the
        // user touched something.
        .onChange(of: appState.inboxRevision) { _, _ in
            reload()
            openSelected()
        }
        .sheet(isPresented: $showDetails) {
            if let conversation = selected {
                ChatPartyDetailSheet(
                    session: session,
                    conversation: conversation,
                    onClose: { showDetails = false }
                )
            }
        }
        .sheet(item: $asking) { ask in
            if let conversation = selected {
                AskMembersSheet(
                    session: session,
                    style: style,
                    conversation: conversation,
                    ask: ask,
                    onClose: { asking = nil },
                    onSent: { summary in syncSummary = summary }
                )
            }
        }
        .sheet(isPresented: $showMembers) {
            if let conversation = selected {
                MemberListSheet(
                    session: session,
                    style: style,
                    conversation: conversation,
                    onClose: { showMembers = false },
                    onChanged: { reload() }
                )
            }
        }
        .confirmationDialog(
            leaveTitle,
            isPresented: $confirmLeave,
            titleVisibility: .visible
        ) {
            if let conversation = selected {
                Button(leaveConfirmTitle, role: .destructive) { leave(conversation) }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text(leaveMessage)
        }
        .sheet(isPresented: $showRequests) {
            MessageRequestsSheet(
                session: session,
                onClose: { showRequests = false },
                onChanged: {
                    reload()
                    openSelected()
                }
            )
        }
        .sheet(isPresented: $showPolicy) {
            StrangerPolicySheet(session: session, onClose: { showPolicy = false })
        }
        .sheet(isPresented: $showNewChat) {
            NewChatSheet(
                session: session,
                mode: mode,
                onOpened: { id in
                    showNewChat = false
                    reload()
                    if let opened = try? session.conversations.get(id: id) {
                        mode = opened.type
                    }
                    selection[mode] = id
                },
                onCancel: { showNewChat = false }
            )
        }
    }

    // MARK: - chrome

    /// The four flavours, as tabs rather than as rows in one list.
    private var modeTabs: some View {
        HStack(spacing: 6) {
            ForEach(ChatModeStyle.all) { candidate in
                let count = unread(candidate.mode)
                Button {
                    mode = candidate.mode
                } label: {
                    HStack(spacing: 5) {
                        Image(systemName: candidate.systemImage)
                        Text(candidate.title)
                        if count > 0 {
                            Text("\(count)")
                                .font(.caption2.bold())
                                .padding(.horizontal, 5)
                                .padding(.vertical, 1)
                                .background(Capsule().fill(candidate.tint))
                                .foregroundStyle(.white)
                        }
                    }
                    .padding(.horizontal, 10)
                    .padding(.vertical, 5)
                    .background(
                        RoundedRectangle(cornerRadius: 7)
                            .fill(candidate.mode == mode
                                  ? candidate.tint.opacity(0.18)
                                  : Color(NSColor.controlBackgroundColor))
                    )
                    .overlay(
                        RoundedRectangle(cornerRadius: 7)
                            .stroke(candidate.mode == mode ? candidate.tint : .clear, lineWidth: 1)
                    )
                    .foregroundStyle(candidate.mode == mode ? AnyShapeStyle(candidate.tint) : AnyShapeStyle(.primary))
                }
                .buttonStyle(.plain)
                .help(candidate.summary)
            }
            Spacer(minLength: 0)
        }
    }

    private var toolbar: some View {
        HStack(spacing: 12) {
            Text(style.title)
                .font(.headline)
                .foregroundStyle(style.isPublic ? AnyShapeStyle(style.tint) : AnyShapeStyle(.primary))

            Spacer()

            SearchField("Search \(style.title.lowercased())…", text: $search, minWidth: 140)
                .help("Matches the name, the id, and the last message shown")

            // Only the on-chain flavours have anything to refresh: a
            // team's and a square's membership is the chain's answer,
            // while a room and a P2P chat are made here.
            if style.syncsFromChain {
                Button {
                    Task { await syncGroups() }
                } label: {
                    if syncing {
                        ProgressView().controlSize(.small)
                    } else {
                        Label("Refresh", systemImage: "arrow.clockwise")
                    }
                }
                .disabled(syncing)
                .help("Pull the \(style.title.lowercased()) this FID belongs to from the chain")
            }

            Button {
                Task { await exchange() }
            } label: {
                if delivering {
                    ProgressView().controlSize(.small)
                } else {
                    Label("Send & receive", systemImage: "arrow.up.arrow.down")
                }
            }
            .disabled(delivering || !session.canSign)
            .help("Park queued messages at their recipients' DOCKs, and collect whatever ours is holding for us")

            Button {
                showNewChat = true
            } label: {
                Label(style.newActionTitle, systemImage: "square.and.pencil")
            }
            .buttonStyle(.borderedProminent)

            tabMenu
        }
    }

    /// The tab's own menu — what Android puts behind the ⋮ on each of
    /// its four list screens, and it is different on each of them
    /// because the four flavours are governed in four different ways.
    @ViewBuilder
    private var tabMenu: some View {
        Menu {
            switch mode {
            case .p2p:
                Button("Message requests…") { showRequests = true }
                Button("Who can message me…") { showPolicy = true }
            case .room, .team, .square:
                // The per-flavour membership actions land with the rest
                // of the group menus; until then there is nothing here
                // that would be true.
                Text("Nothing here yet")
            }
        } label: {
            Image(systemName: "ellipsis.circle")
        }
        .menuStyle(.borderlessButton)
        .fixedSize()
    }

    /// Held messages have to be visible somewhere or holding them would
    /// be no better than dropping them — but they are deliberately *not*
    /// in the thread list, since being in that list is exactly the thing
    /// a stranger has not been granted.
    private var requestsBanner: some View {
        let senders = requests.count
        let messages = requests.reduce(0) { $0 + $1.count }
        return Button {
            showRequests = true
        } label: {
            HStack(spacing: 8) {
                Image(systemName: "tray.full")
                Text("\(messages) message\(messages == 1 ? "" : "s") from \(senders) sender\(senders == 1 ? "" : "s") you haven't accepted")
                Spacer()
                Text("Review").font(.caption.bold())
            }
            .font(.callout)
            .padding(10)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(RoundedRectangle(cornerRadius: 8).fill(Color.orange.opacity(0.14)))
        }
        .buttonStyle(.plain)
        .help("These are stored on this Mac and appear nowhere else until you accept them")
    }

    /// Room invitations, with the two facts that decide the answer:
    /// who says so, and that nothing about the claim can be checked.
    private var invitesBanner: some View {
        VStack(alignment: .leading, spacing: 8) {
            ForEach(invites) { invite in
                HStack(spacing: 8) {
                    Image(systemName: "envelope.open")
                    VStack(alignment: .leading, spacing: 1) {
                        Text("\(invite.name ?? "A room") — invitation from \(invite.from.elidingMiddle(head: 6, tail: 6))")
                        Text("Nothing about a room is on the chain, so this claim cannot be checked against anything. Accept only if you expected it.")
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                    }
                    Spacer()
                    Button("Accept") { accept(invite) }
                        .buttonStyle(.borderedProminent)
                    Button("Decline") { decline(invite) }
                }
                .font(.callout)
                .padding(10)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(RoundedRectangle(cornerRadius: 8).fill(style.tint.opacity(0.12)))
            }
        }
    }

    @ViewBuilder
    private var emptyCard: some View {
        card {
            Label(style.emptyTitle, systemImage: style.systemImage)
                .foregroundStyle(style.isPublic ? AnyShapeStyle(style.tint) : AnyShapeStyle(.secondary))
            Text(style.summary)
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            Text(style.syncsFromChain
                 ? "Refresh to pull the \(style.title.lowercased()) this FID already belongs to, or join one by id."
                 : "Start one with the button above.")
                .font(.caption)
                .foregroundStyle(.tertiary)
            if let summary = syncSummary {
                Text(summary).font(.caption).foregroundStyle(.tertiary)
            }
        }
    }

    // MARK: - transcript

    @ViewBuilder
    private var transcript: some View {
        if let conversation = selected {
            VStack(alignment: .leading, spacing: 10) {
                transcriptHeader(conversation)
                Divider()

                TranscriptView(
                    session: session,
                    style: style,
                    conversation: conversation,
                    page: page,
                    player: player,
                    onLoadOlder: loadOlder,
                    onDownload: download
                )

                MessageComposerView(
                    style: style,
                    verdict: verdict,
                    draft: draft,
                    recorder: recorder,
                    attaching: attaching,
                    sendingVoice: sendingVoice,
                    attachProgress: attachProgress,
                    errorText: sendError ?? player.failure,
                    onSend: { send(in: conversation) },
                    onAttach: { attach(in: conversation) },
                    onStartRecording: { Task { await recorder.start(in: voiceDirectory) } },
                    onSendVoice: { sendVoice(in: conversation) },
                    onCancelRecording: { recorder.cancel() },
                    onGenerateKey: { generateKey(for: conversation) }
                )
            }
        } else {
            card {
                Text("Pick a \(style.noun) on the left.")
                    .foregroundStyle(.secondary)
            }
        }
    }

    /// The header wears the flavour's colour as a band, so which kind of
    /// conversation is open is answerable without reading anything.
    private func transcriptHeader(_ conversation: Conversation) -> some View {
        HStack(spacing: 8) {
            Rectangle().fill(style.tint).frame(width: 3, height: 22)

            Text(ChatFormat.title(of: conversation)).font(.title3.bold()).lineLimit(1)
            if conversation.leftGroup == true {
                ChatChip("left", color: .secondary)
            }
            if style.isPublic {
                ChatChip("public", color: style.tint)
            }
            if let members = conversation.memberNum, members > 0 {
                Text("\(members) members").font(.caption).foregroundStyle(.secondary)
            }
            Spacer()
            CopyableText(
                display: conversation.targetId.elidingMiddle(head: 8, tail: 8),
                copy: conversation.targetId,
                font: .caption
            )
            .foregroundStyle(.tertiary)

            Button {
                showDetails = true
            } label: {
                Image(systemName: "info.circle")
            }
            .buttonStyle(.borderless)
            .help("Who this is, where their messages rest, and whether that server is reachable")

            conversationMenu(conversation)
        }
    }

    /// What you can *do* to this conversation — and the four flavours
    /// differ here more than anywhere else, which is why Android has
    /// four separate menus and this switches rather than showing a
    /// superset with half of it greyed out.
    @ViewBuilder
    private func conversationMenu(_ conversation: Conversation) -> some View {
        let facts = session.chatGateFacts(for: conversation)
        Menu {
            switch conversation.type {
            case .p2p:
                Button("Block this FID") { block(conversation) }
                Button("Remove this thread", role: .destructive) { removeThread(conversation) }

            case .room:
                Button("Members…") { showMembers = true }
                Button("Ask for the key…") { asking = .symkey }
                Button("Ask for this room's details…") { asking = .roomInfo }
                if facts.isOwner {
                    Divider()
                    Button("Share the room's details") { shareRoomInfo(conversation) }
                    Button("Reset the key") { generateKey(for: conversation) }
                    Button("Close this room", role: .destructive) { disband(conversation) }
                } else {
                    Button("Leave this room", role: .destructive) { confirmLeave = true }
                }

            case .team:
                Button("Members…") { showMembers = true }
                Button("Ask for the key…") { asking = .symkey }
                if facts.isOwner {
                    Button("Reset the key") { generateKey(for: conversation) }
                }
                Divider()
                Button("Leave this team (carve)…", role: .destructive) { confirmLeave = true }

            case .square:
                // **No "ask for the key".** A square has no key, and an
                // item offering to fetch one would advertise a privacy
                // the flavour does not have. Android ships exactly that
                // item in `popup_group_chat_menu.xml` — with no click
                // listener bound, so it does nothing at all.
                Button("Members…") { showMembers = true }
                Divider()
                Button("Leave this square (carve)…", role: .destructive) { confirmLeave = true }
            }
        } label: {
            Image(systemName: "ellipsis.circle")
        }
        .menuStyle(.borderlessButton)
        .fixedSize()
    }

    /// Where recordings live. The session's own directory rather than a
    /// temp one, because a note too long to travel inline is *shared by
    /// reference* — ``FileVault`` registers the path, so bytes the
    /// system might sweep are not somewhere to leave a shared file.
    private var voiceDirectory: URL {
        session.dataDirectory.appendingPathComponent("voice", isDirectory: true)
    }

    // MARK: - actions

    private func reload() {
        do {
            var rebuilt: [ImType: [Conversation]] = [:]
            for style in ChatModeStyle.all {
                rebuilt[style.mode] = try session.conversations.visible(type: style.mode)
            }
            threads = rebuilt
            requests = try session.messageRequests.pending()
            invites = try session.roomInvites.all()
            loadError = nil
        } catch {
            loadError = String(describing: error)
        }
    }

    private func openSelected() {
        guard let id = selection[mode] else {
            page = .init(messages: [], olderCursor: nil)
            return
        }
        do {
            page = try session.chat.page(id)
            let nowRead = try session.chat.markRead(id)
            reload()
            acknowledgeRead(nowRead)
        } catch {
            loadError = String(describing: error)
        }
    }

    /// Tell the senders we read their messages.
    ///
    /// Opening a thread is the only moment a `read` status can be
    /// honestly reported, and without this the sender never advances past
    /// `delivered`. Fire-and-forget on purpose: a receipt that cannot be
    /// sent is a status the sender does not see, not an error for the
    /// reader to deal with, so nothing here touches `loadError`.
    private func acknowledgeRead(_ messages: [ImMessage]) {
        let theirs = messages.filter { $0.senderId != session.liveFid && $0.type == .p2p }
        guard !theirs.isEmpty else { return }
        Task {
            for message in theirs {
                guard let senderId = message.senderId else { continue }
                let conversationId = Conversation.id(type: .p2p, targetId: senderId)
                guard let conversation = try? session.conversations.get(id: conversationId),
                      let keys = try? await sendKeys(for: conversation)
                else { continue }
                _ = try? session.chat.acknowledge(message, kind: .read, as: session.liveFid, keys: keys)
            }
            _ = try? await session.courier.drainOutbox(as: session.liveFid)
        }
    }

    private func loadOlder() {
        guard let id = selection[mode], let cursor = page.olderCursor else { return }
        do {
            let older = try session.chat.page(id, before: cursor)
            page = .init(
                messages: older.messages + page.messages,
                olderCursor: older.olderCursor
            )
        } catch {
            loadError = String(describing: error)
        }
    }

    private func send(in conversation: Conversation) {
        let text = draft.wrappedValue.trimmingCharacters(in: .whitespacesAndNewlines)
        guard verdict.canSend, !text.isEmpty else { return }
        sendError = nil
        Task {
            do {
                let keys = try await sendKeys(for: conversation)
                _ = try session.chat.sendText(
                    text, in: conversation.id, as: session.liveFid, keys: keys
                )
                await MainActor.run { drafts[conversation.id] = "" }
                // Try to move it straight away; if that fails it stays
                // queued and the next send-and-receive picks it up.
                _ = try? await session.courier.drainOutbox(as: session.liveFid)
                await MainActor.run { openSelected() }
            } catch {
                await MainActor.run { sendError = String(describing: error) }
            }
        }
    }

    /// Stop recording and send what was captured.
    ///
    /// **Which way it travels is decided here, by size.** The DOCK's
    /// per-item ceiling is 64 KB by default and each operator may
    /// advertise less, so a note that fits goes inside the message and
    /// one that does not takes the same DISK-and-HAT road a shared file
    /// takes. Asking the courier for the destination's real budget is
    /// the point: an app-side constant asserting a server limit it never
    /// read is exactly the bug the wire-format work was cleaning up.
    ///
    /// The temp file is deleted only on the inline path. The HAT path
    /// shares it *by reference*, so those bytes have to stay.
    private func sendVoice(in conversation: Conversation) {
        guard let recording = recorder.finish() else { return }
        sendError = nil
        sendingVoice = true
        Task {
            do {
                let keys = try await sendKeys(for: conversation)
                let budget = await session.courier.itemBudget(
                    forTarget: conversation.targetId, type: conversation.type
                )
                let inline = VoiceNote.fitsInline(audioBytes: recording.data.count, budget: budget)
                let message: ImMessage
                if inline {
                    message = VoiceNote.message(
                        type: conversation.type,
                        from: session.liveFid,
                        to: conversation.targetId,
                        audio: recording.data,
                        durationMs: recording.durationMs,
                        sampleRate: recording.sampleRate
                    )
                } else {
                    let pubkey = try Secp256k1.publicKey(fromPrivateKey: try session.livePrikey())
                    message = try await session.fileShare.share(
                        fileAt: recording.url,
                        in: conversation,
                        as: session.liveFid,
                        ownPubkey: pubkey,
                        desc: "Voice note, \(VoiceNote.formatDuration(recording.durationMs))",
                        progress: { sent, total in
                            Task { @MainActor in attachProgress = (sent, total) }
                        }
                    )
                }
                _ = try session.chat.send(
                    message, in: conversation, as: session.liveFid, keys: keys
                )
                if inline { try? FileManager.default.removeItem(at: recording.url) }
                _ = try? await session.courier.drainOutbox(as: session.liveFid)
                await MainActor.run {
                    sendingVoice = false
                    attachProgress = nil
                    openSelected()
                }
            } catch {
                await MainActor.run {
                    sendingVoice = false
                    attachProgress = nil
                    sendError = String(describing: error)
                }
            }
        }
    }

    /// P2P needs our privkey and their pubkey; a group needs neither,
    /// because its key is in ``SymkeyStore``.
    private func sendKeys(for conversation: Conversation) async throws -> ChatService.Keys {
        guard conversation.type == .p2p else { return .none }
        let privkey = try session.livePrikey()
        if let cached = pubkeys[conversation.targetId] {
            return .init(privkey: privkey, recipientPubkey: cached)
        }
        let quote = try await session.quoteMail(to: conversation.targetId)
        guard let pubkey = quote.recipientPubkey else {
            throw ChatService.Failure.noRecipientKey(conversation.targetId)
        }
        await MainActor.run { pubkeys[conversation.targetId] = pubkey }
        return .init(privkey: privkey, recipientPubkey: pubkey)
    }

    /// Pick a file, upload it, and send the reference.
    ///
    /// The upload happens *before* the send, so a failed upload leaves
    /// nothing queued — the alternative is a message pointing at bytes
    /// that never arrived.
    private func attach(in conversation: Conversation) {
        let panel = NSOpenPanel()
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = false
        guard panel.runModal() == .OK, let url = panel.url else { return }

        attaching = true
        sendError = nil
        Task {
            do {
                let pubkey = try Secp256k1.publicKey(fromPrivateKey: try session.livePrikey())
                let message = try await session.fileShare.share(
                    fileAt: url,
                    in: conversation,
                    as: session.liveFid,
                    ownPubkey: pubkey,
                    progress: { sent, total in
                        Task { @MainActor in attachProgress = (sent, total) }
                    }
                )
                let keys = try await sendKeys(for: conversation)
                _ = try session.chat.send(
                    message, in: conversation, as: session.liveFid, keys: keys
                )
                _ = try? await session.courier.drainOutbox(as: session.liveFid)
                await MainActor.run {
                    attaching = false
                    attachProgress = nil
                    openSelected()
                }
            } catch {
                await MainActor.run {
                    attaching = false
                    attachProgress = nil
                    sendError = String(describing: error)
                }
            }
        }
    }

    private func download(_ message: ImMessage) {
        sendError = nil
        Task {
            do {
                _ = try await session.fileShare.download(message)
                await MainActor.run { openSelected() }
            } catch {
                await MainActor.run { sendError = String(describing: error) }
            }
        }
    }

    /// The owner's way out of ``ChatGate/Verdict/ownerNeedsKey``: make a
    /// key and give it to the members.
    ///
    /// **Rotating rather than generating a first key** is deliberate and
    /// costs nothing: ``SymkeyStore/rotate(for:now:)`` takes the next
    /// version up, which is version 1 when there is nothing there. An
    /// owner reaching this button on a room that *did* have a key — one
    /// this device lost, say — must not reuse that version number, since
    /// two different keys under one version is the one state the store
    /// cannot represent.
    ///
    /// A room's members get the new key in a `ROOM_INFO`, which is the
    /// envelope that already carries a membership and a key together. A
    /// team's get a plain SYMKEY message, because a team's membership
    /// comes from the chain and is not ours to announce.
    private func generateKey(for conversation: Conversation) {
        sendError = nil
        do {
            let outbound: [ImMessage]
            switch conversation.type {
            case .room:
                let service = try session.roomService
                outbound = try service.resetSymkey(
                    conversation.targetId,
                    as: session.liveFid,
                    pubkeys: { fid in try session.contacts.get(fid: fid)?.pubkey }
                ).outbound

            case .team:
                let team = try session.teams.get(id: conversation.targetId)
                let rotated = try session.symkeys.rotate(for: conversation.targetId)
                outbound = try KeyExchange.shareWithAll(
                    entityId: conversation.targetId,
                    version: rotated.version,
                    members: team?.members ?? [],
                    from: session.liveFid,
                    symkeys: session.symkeys,
                    pubkeys: { fid in try session.contacts.get(fid: fid)?.pubkey }
                )

            case .p2p, .square:
                // Neither has a group key: a P2P body is sealed to the
                // person, and a square has no membership to keep anyone
                // out of. `ChatGate` never asks for one here.
                return
            }

            // Key traffic is P2P, so it queues into each recipient's own
            // thread and travels like any other message.
            for message in outbound {
                guard let to = message.targetId else { continue }
                try session.outbox.enqueue(message, in: Conversation.id(type: .p2p, targetId: to))
            }
            reload()
            openSelected()
            syncSummary = outbound.isEmpty
                ? "Key created. No member could be sealed to — share it from the members list once their pubkeys are known."
                : "Key created; \(outbound.count) share(s) queued."
            Task { _ = try? await session.courier.drainOutbox(as: session.liveFid) }
        } catch {
            sendError = String(describing: error)
        }
    }

    // MARK: - menu actions

    /// Re-send the room's details — membership and current key — to
    /// every member. The owner's answer to "I can't read anything".
    private func shareRoomInfo(_ conversation: Conversation) {
        sendError = nil
        do {
            let service = try session.roomService
            guard let room = try session.rooms.get(id: conversation.targetId) else { return }
            let outbound = try room.others(than: session.liveFid).map { fid in
                try service.invitation(
                    for: room, to: fid, from: session.liveFid,
                    pubkeys: { f in try session.contacts.get(fid: f)?.pubkey }
                )
            }
            try queue(outbound)
            syncSummary = "\(outbound.count) update(s) queued."
        } catch {
            sendError = String(describing: error)
        }
    }

    /// Close a room we own. The keys are **kept**: this ends the
    /// conversation, it does not burn the transcript.
    private func disband(_ conversation: Conversation) {
        sendError = nil
        do {
            let outbound = try session.roomService.disband(
                conversation.targetId, as: session.liveFid
            )
            try queue(outbound)
            _ = try session.conversations.mutate(id: conversation.id) { $0.leftGroup = true }
            reload()
            openSelected()
        } catch {
            sendError = String(describing: error)
        }
    }

    /// Leave. A room is local and takes effect at once; a team or a
    /// square is a carve, and until it confirms the chain still says we
    /// are in it.
    private func leave(_ conversation: Conversation) {
        sendError = nil
        Task {
            do {
                switch conversation.type {
                case .room:
                    if let notice = try session.roomService.leave(
                        conversation.targetId, as: session.liveFid
                    ) {
                        try queue([notice])
                    }
                    await MainActor.run { syncSummary = "Left. The owner is told on the next send." }
                case .team:
                    let txid = try await session.carveTeamLeaveOnChain(
                        teamIds: [conversation.targetId]
                    )
                    await MainActor.run {
                        syncSummary = "Broadcast — tx \(txid.elidingMiddle(head: 8, tail: 8)). You are out once it confirms."
                    }
                case .square:
                    let txid = try await session.carveSquareLeaveOnChain(
                        squareIds: [conversation.targetId]
                    )
                    await MainActor.run {
                        syncSummary = "Broadcast — tx \(txid.elidingMiddle(head: 8, tail: 8)). You are out once it confirms."
                    }
                case .p2p:
                    return
                }
                await MainActor.run {
                    // The transcript stays either way: we were there,
                    // and the history is ours.
                    _ = try? session.conversations.mutate(id: conversation.id) { $0.leftGroup = true }
                    reload()
                    openSelected()
                }
            } catch {
                await MainActor.run { sendError = String(describing: error) }
            }
        }
    }

    /// Block a P2P correspondent: nothing more from them is kept, and
    /// the thread they had goes with it.
    private func block(_ conversation: Conversation) {
        sendError = nil
        do {
            try session.contactPolicy.mutate(liveFid: session.liveFid) {
                $0.block(conversation.targetId)
            }
            removeThread(conversation)
        } catch {
            sendError = String(describing: error)
        }
    }

    /// Forget a thread on this device. The messages go with it — there
    /// is no copy anywhere else, which the alert on the way in has to
    /// say and this comment records for whoever writes it.
    private func removeThread(_ conversation: Conversation) {
        sendError = nil
        do {
            _ = try session.messages.deleteConversation(conversation.id)
            _ = try session.conversations.remove(id: conversation.id)
            selection[mode] = nil
            reload()
            openSelected()
        } catch {
            sendError = String(describing: error)
        }
    }

    private func accept(_ invite: RoomInvite) {
        sendError = nil
        do {
            let (_, reply) = try session.roomService.acceptInvite(
                roomInfoJson: invite.roomInfoJson, as: session.liveFid
            )
            if let reply { try queue([reply]) }
            _ = try session.roomInvites.remove(roomId: invite.roomId)
            reload()
            selection[.room] = Conversation.id(type: .room, targetId: invite.roomId)
            openSelected()
        } catch {
            sendError = String(describing: error)
        }
    }

    private func decline(_ invite: RoomInvite) {
        sendError = nil
        do {
            if let reply = try session.roomService.rejectInvite(
                roomInfoJson: invite.roomInfoJson, as: session.liveFid
            ) {
                try queue([reply])
            }
            _ = try session.roomInvites.remove(roomId: invite.roomId)
            reload()
        } catch {
            sendError = String(describing: error)
        }
    }

    /// Room control traffic is P2P, so it queues into each recipient's
    /// own thread — an invitation has to reach someone not yet in the
    /// room, and a removal someone no longer in it.
    private func queue(_ outbound: [ImMessage]) throws {
        for message in outbound {
            guard let to = message.targetId else { continue }
            try session.outbox.enqueue(message, in: Conversation.id(type: .p2p, targetId: to))
        }
        Task { _ = try? await session.courier.drainOutbox(as: session.liveFid) }
    }

    /// Put the open conversation's DOCK on the poller's fast lane.
    ///
    /// A P2P thread resolves to our *own* server — their messages to us
    /// rest there, not on theirs — so switching between P2P threads
    /// keeps the same fast lane rather than churning it.
    private func updatePriorityDock() {
        guard let conversation = selected else {
            appState.setPriorityDock(nil)
            return
        }
        Task {
            let url = await session.dockRegistry.dockUrl(
                forTarget: conversation.targetId, type: conversation.type
            )
            await MainActor.run { appState.setPriorityDock(url) }
        }
    }

    /// One round of delivery in both directions.
    private func exchange() async {
        await MainActor.run { delivering = true; sendError = nil }
        var parts: [String] = []
        do {
            // Which DOCK each group sits on can have changed since the
            // last pass — a group joined, left, or moved — and the
            // registry is what the collect polls.
            await session.refreshDockRegistry()
            let sent = try await session.courier.drainOutbox(as: session.liveFid)
            let received = try await session.courier.collect(
                as: session.liveFid,
                privkey: try? session.livePrikey()
            )
            if sent.attempted > 0 {
                parts.append("sent \(sent.sent)/\(sent.attempted)")
            }
            if sent.failed > 0 { parts.append("\(sent.failed) failed") }
            parts.append("received \(received.filed)")
            if received.sealed > 0 { parts.append("\(received.sealed) need a key") }
        } catch {
            await MainActor.run { sendError = String(describing: error) }
        }
        await MainActor.run {
            delivering = false
            syncSummary = parts.isEmpty ? nil : parts.joined(separator: " · ")
            reload()
            openSelected()
        }
    }

    private func syncGroups() async {
        await MainActor.run { syncing = true; syncSummary = nil }
        var parts: [String] = []
        do {
            let teams = try await session.groups.syncTeams(
                fid: session.liveFid, into: session.teams, conversations: session.conversations
            )
            let squares = try await session.groups.syncSquares(
                fid: session.liveFid, into: session.squares, conversations: session.conversations
            )
            parts.append("\(teams.total) team(s), \(squares.total) square(s)")
            if teams.joined + squares.joined > 0 {
                parts.append("\(teams.joined + squares.joined) new")
            }
            if teams.left + squares.left > 0 {
                parts.append("\(teams.left + squares.left) left")
            }
        } catch {
            parts = ["sync failed: \(error)"]
        }
        // A group we just joined lives on its own DOCK, and until the
        // registry knows about it nothing that group says is collected.
        await session.refreshDockRegistry()
        await MainActor.run {
            syncing = false
            syncSummary = parts.joined(separator: " · ")
            reload()
        }
    }

    // MARK: - chrome helpers

    private func card(@ViewBuilder _ content: () -> some View) -> some View {
        VStack(alignment: .leading, spacing: 8, content: content)
            .padding(20)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Color(NSColor.controlBackgroundColor))
            .clipShape(RoundedRectangle(cornerRadius: 12))
    }
}
