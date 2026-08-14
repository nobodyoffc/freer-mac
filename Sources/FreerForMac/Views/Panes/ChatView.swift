import SwiftUI
import FCCore
import FCDomain
import FCUI

/// The chat pane — the Mac port of Android's `ChatActivity` /
/// `TalkActivity` / `RoomActivity` / `TeamActivity` / `SquareActivity`,
/// which are one screen here because they are one screen's worth of
/// difference: a thread list on the left, a transcript on the right, and
/// a composer under it.
///
/// **Four flavours, one transcript.** A P2P chat, a room, a team and a
/// square differ in who may join and how a message is sealed, and both
/// of those are settled below this view — in ``RoomService``,
/// ``GroupService`` and ``ChatService``. What reaches the pane is a
/// ``Conversation`` and a page of ``ImMessage``, and the only place the
/// flavour shows through is a badge and what the header offers to do.
///
/// **Delivery is store-and-forward.** Sending seals a message, files it
/// and queues it; the courier then parks it at the recipient's DOCK,
/// where it waits until they next collect. So "Sent" here means *the
/// DOCK took it*, and nothing more — a checkmark that claimed the
/// recipient had it would be a claim this route cannot make.
struct ChatView: View {
    let session: ActiveSession

    @State private var conversations: [Conversation] = []
    @State private var selectedId: String?
    @State private var page: MessagesStore.Page = .init(messages: [], olderCursor: nil)
    @State private var draft = ""
    @State private var search = ""

    @State private var loadError: String?
    @State private var sendError: String?
    @State private var showNewChat = false
    @State private var syncing = false
    @State private var syncSummary: String?
    @State private var delivering = false

    /// Resolved once per recipient, then reused: a P2P send needs the
    /// other party's pubkey and it never changes.
    @State private var pubkeys: [String: Data] = [:]

    // MARK: - derived

    private var selected: Conversation? {
        guard let selectedId else { return nil }
        return conversations.first { $0.id == selectedId }
    }

    private var filtered: [Conversation] {
        let needle = search.trimmingCharacters(in: .whitespaces)
        guard !needle.isEmpty else { return conversations }
        return conversations.filter { $0.matches(query: needle) }
    }

    private var totalUnread: Int {
        conversations.reduce(0) { $0 + ($1.unreadCount ?? 0) }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            PaneHeader(session: session)
            Divider()
            toolbar

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
                    threadList
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
            if selectedId == nil { selectedId = conversations.first?.id }
            openSelected()
        }
        .onChange(of: selectedId) { _, _ in openSelected() }
        .sheet(isPresented: $showNewChat) {
            NewChatSheet(
                session: session,
                onOpened: { id in
                    showNewChat = false
                    reload()
                    selectedId = id
                },
                onCancel: { showNewChat = false }
            )
        }
    }

    // MARK: - chrome

    private var toolbar: some View {
        HStack(spacing: 12) {
            Text(totalUnread > 0 ? "Chats (\(totalUnread))" : "Chats")
                .font(.headline)

            Spacer()

            SearchField("Search chats…", text: $search, minWidth: 140)
                .help("Matches the name, the FID or group id, and the last message shown")

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
            .help("Pull the teams and squares this FID belongs to from the chain")

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
                Label("New", systemImage: "square.and.pencil")
            }
            .buttonStyle(.borderedProminent)
            .help("Start a chat, or make a room")
        }
    }

    @ViewBuilder
    private var emptyCard: some View {
        card {
            Label("No chats yet", systemImage: "bubble.left.and.bubble.right")
                .foregroundStyle(.secondary)
            Text("Start a chat with a contact, make a room, or refresh to pull the teams and squares this FID is already a member of.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            if let summary = syncSummary {
                Text(summary).font(.caption).foregroundStyle(.tertiary)
            }
        }
    }

    // MARK: - thread list

    private var threadList: some View {
        ScrollView {
            LazyVStack(alignment: .leading, spacing: 0) {
                ForEach(filtered) { conversation in
                    threadRow(conversation)
                        .padding(.vertical, 8)
                        .padding(.horizontal, 10)
                        .background(
                            conversation.id == selectedId
                                ? Color.accentColor.opacity(0.12)
                                : Color.clear
                        )
                        .contentShape(Rectangle())
                        .onTapGesture { selectedId = conversation.id }
                    Divider()
                }
            }
        }
        .background(Color(NSColor.controlBackgroundColor))
        .clipShape(RoundedRectangle(cornerRadius: 10))
    }

    private func threadRow(_ conversation: Conversation) -> some View {
        HStack(alignment: .top, spacing: 8) {
            FidAvatarView(fid: conversation.targetId, size: 32)

            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 4) {
                    Text(title(of: conversation))
                        .font(.callout.bold())
                        .lineLimit(1)
                    flavourBadge(conversation.type)
                    if conversation.leftGroup == true {
                        chip("left", color: .secondary)
                    }
                }
                Text(conversation.lastMessageContent ?? "No messages yet")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }

            Spacer(minLength: 0)

            VStack(alignment: .trailing, spacing: 4) {
                if let time = conversation.lastActiveAt {
                    Text(Self.shortTime.string(from: Date(timeIntervalSince1970: Double(time) / 1000)))
                        .font(.caption2)
                        .foregroundStyle(.tertiary)
                }
                if let unread = conversation.unreadCount, unread > 0 {
                    Text("\(unread)")
                        .font(.caption2.bold())
                        .padding(.horizontal, 6)
                        .padding(.vertical, 2)
                        .background(Capsule().fill(Color.accentColor))
                        .foregroundStyle(.white)
                }
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

                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 10) {
                        if page.hasOlder {
                            Button("Load earlier messages") { loadOlder() }
                                .buttonStyle(.borderless)
                                .font(.caption)
                        }
                        ForEach(page.messages) { message in
                            bubble(message, in: conversation)
                        }
                        if page.messages.isEmpty {
                            Text("Nothing said here yet.")
                                .font(.caption)
                                .foregroundStyle(.tertiary)
                                .padding(.vertical, 20)
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(12)
                }
                .background(Color(NSColor.textBackgroundColor))
                .clipShape(RoundedRectangle(cornerRadius: 10))

                composer(conversation)
            }
        } else {
            card {
                Text("Pick a chat on the left.")
                    .foregroundStyle(.secondary)
            }
        }
    }

    private func transcriptHeader(_ conversation: Conversation) -> some View {
        HStack(spacing: 8) {
            Text(title(of: conversation)).font(.title3.bold()).lineLimit(1)
            flavourBadge(conversation.type)
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
        }
    }

    private func bubble(_ message: ImMessage, in conversation: Conversation) -> some View {
        let mine = message.isOutgoing(from: session.liveFid)
        return HStack {
            if mine { Spacer(minLength: 40) }
            VStack(alignment: mine ? .trailing : .leading, spacing: 3) {
                if !mine, conversation.type != .p2p {
                    Text((message.senderName ?? message.senderId ?? "").elidingMiddle(head: 6, tail: 6))
                        .font(.caption2)
                        .foregroundStyle(.tertiary)
                }
                body(of: message)
                    .padding(.horizontal, 10)
                    .padding(.vertical, 7)
                    .background(
                        RoundedRectangle(cornerRadius: 12)
                            .fill(mine ? Color.accentColor.opacity(0.18)
                                       : Color(NSColor.controlBackgroundColor))
                    )
                HStack(spacing: 4) {
                    if let time = message.timestamp {
                        Text(Self.shortTime.string(from: Date(timeIntervalSince1970: Double(time) / 1000)))
                    }
                    if mine { statusLabel(message) }
                }
                .font(.caption2)
                .foregroundStyle(.tertiary)
            }
            if !mine { Spacer(minLength: 40) }
        }
    }

    @ViewBuilder
    private func body(of message: ImMessage) -> some View {
        if let content = message.content {
            Text(content).textSelection(.enabled)
        } else if message.isSealed {
            HStack(spacing: 4) {
                Image(systemName: "lock.slash")
                Text(message.symkeyVersion.map { "Sealed with key v\($0) — not held here" }
                     ?? "Sealed to a key this identity doesn't hold")
            }
            .font(.caption)
            .foregroundStyle(.secondary)
        } else {
            Text(Conversation.preview(for: message) ?? "")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
    }

    /// The delivery state, told straight. Until 9.2.4b there is no
    /// transport, so an outgoing message stays `pending` — and saying
    /// "Sent" here would be a lie the user cannot check.
    @ViewBuilder
    private func statusLabel(_ message: ImMessage) -> some View {
        switch message.status {
        case .pending, .none:
            Label("Queued", systemImage: "clock")
                .help("Sealed and waiting in the outbox. It goes out on the next send.")
        case .sent:
            Label("Sent", systemImage: "checkmark")
                .help("Parked at their DOCK. They have it when they next collect.")
        case .delivered:
            Label("Delivered", systemImage: "checkmark.circle")
        case .read:
            Label("Read", systemImage: "checkmark.circle.fill")
        case .failed:
            Label("Failed", systemImage: "exclamationmark.triangle").foregroundStyle(.orange)
        case .quarantined:
            Label("Held", systemImage: "hand.raised")
        case .imported:
            Label("Imported", systemImage: "tray.and.arrow.down")
        }
    }

    // MARK: - composer

    private func composer(_ conversation: Conversation) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            if let err = sendError {
                CopyableText(err, font: .caption).foregroundStyle(.orange)
            }
            if conversation.leftGroup == true {
                Text("You are not a member of this \(conversation.type.rawValue.lowercased()) any more. The transcript stays; sending does not.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            HStack(spacing: 8) {
                TextField("Message", text: $draft, axis: .vertical)
                    .lineLimit(1...5)
                    .textFieldStyle(.roundedBorder)
                    .onSubmit { send(in: conversation) }

                Button {
                    send(in: conversation)
                } label: {
                    Label("Send", systemImage: "paperplane.fill")
                }
                .buttonStyle(.borderedProminent)
                .disabled(!canSend(in: conversation))
            }
            Text(sealingNote(for: conversation))
                .font(.caption2)
                .foregroundStyle(.tertiary)
        }
    }

    private func canSend(in conversation: Conversation) -> Bool {
        guard session.canSign, conversation.leftGroup != true else { return false }
        return !draft.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }

    /// What sealing this conversation gets, said plainly. A square is
    /// the one that needs saying: it is *not* encrypted, and a padlock
    /// the user assumed was there is worse than none.
    private func sealingNote(for conversation: Conversation) -> String {
        switch conversation.type {
        case .p2p:
            return "Encrypted to you and them — both of you can reopen it."
        case .room:
            return "Encrypted with this room's key. Members who join later cannot read this."
        case .team:
            return "Encrypted with this team's key."
        case .square:
            return "Squares are public — anyone may join, so nothing here is encrypted."
        }
    }

    // MARK: - actions

    private func reload() {
        do {
            conversations = try session.conversations.visible()
            loadError = nil
        } catch {
            loadError = String(describing: error)
        }
    }

    private func openSelected() {
        guard let id = selectedId else {
            page = .init(messages: [], olderCursor: nil)
            return
        }
        do {
            page = try session.chat.page(id)
            _ = try session.chat.markRead(id)
            reload()
        } catch {
            loadError = String(describing: error)
        }
    }

    private func loadOlder() {
        guard let id = selectedId, let cursor = page.olderCursor else { return }
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
        guard canSend(in: conversation) else { return }
        let text = draft
        sendError = nil
        Task {
            do {
                let keys = try await sendKeys(for: conversation)
                _ = try session.chat.sendText(
                    text, in: conversation.id, as: session.liveFid, keys: keys
                )
                await MainActor.run { draft = "" }
                // Try to move it straight away; if that fails it stays
                // queued and the next send-and-receive picks it up.
                _ = try? await session.courier.drainOutbox(
                    as: session.liveFid, ownDockUrl: nil
                )
                await MainActor.run { openSelected() }
            } catch {
                await MainActor.run { sendError = String(describing: error) }
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

    /// One round of delivery in both directions.
    private func exchange() async {
        await MainActor.run { delivering = true; sendError = nil }
        var parts: [String] = []
        do {
            let sent = try await session.courier.drainOutbox(
                as: session.liveFid, ownDockUrl: nil
            )
            let received = try await session.courier.collect(
                as: session.liveFid,
                recipientIds: try session.dockRecipientIds(),
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
        await MainActor.run {
            syncing = false
            syncSummary = parts.joined(separator: " · ")
            reload()
        }
    }

    // MARK: - chrome helpers

    private func title(of conversation: Conversation) -> String {
        conversation.displayName ?? conversation.targetId.elidingMiddle(head: 8, tail: 6)
    }

    @ViewBuilder
    private func flavourBadge(_ type: ImType) -> some View {
        switch type {
        case .p2p:    EmptyView()
        case .room:   chip("room", color: .purple)
        case .team:   chip("team", color: .blue)
        case .square: chip("square", color: .green)
        }
    }

    private func chip(_ text: String, color: Color) -> some View {
        Text(text)
            .font(.caption2.bold())
            .padding(.horizontal, 5)
            .padding(.vertical, 1)
            .background(Capsule().fill(color.opacity(0.15)))
            .foregroundStyle(color)
    }

    private func card(@ViewBuilder _ content: () -> some View) -> some View {
        VStack(alignment: .leading, spacing: 8, content: content)
            .padding(20)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Color(NSColor.controlBackgroundColor))
            .clipShape(RoundedRectangle(cornerRadius: 12))
    }

    private static let shortTime: DateFormatter = {
        let f = DateFormatter()
        f.dateStyle = .short
        f.timeStyle = .short
        return f
    }()
}
