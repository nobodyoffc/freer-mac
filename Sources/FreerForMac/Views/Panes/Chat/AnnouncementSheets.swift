import SwiftUI
import FCDomain
import FCUI

/// A team's or a room's announcements: posting one, reading and confirming
/// those not yet confirmed, and the group's history of them.
///
/// The rules — what an announcement is, who may post one — are FCDomain's
/// ``Announcements``. An announcement is a message too, so it is also in
/// the transcript, drawn as a card.

/// Write an announcement and send it to every member. Offered only to a
/// team's owner and managers and a room's owner; a member's device reads
/// one from anybody else as a plain message, so the menu is not the guard.
struct AnnouncementComposeSheet: View {

    let session: ActiveSession
    let conversation: Conversation
    let onClose: () -> Void
    let onPosted: () -> Void

    @State private var text = ""
    @State private var working = false
    @State private var error: String?

    private var style: ChatModeStyle { ChatModeStyle.of(conversation.type) }
    private var trimmed: String { text.trimmingCharacters(in: .whitespacesAndNewlines) }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(spacing: 8) {
                Image(systemName: "megaphone").foregroundStyle(style.tint)
                Text("New announcement").font(.title3.bold())
                Spacer()
            }
            Text("Every member is asked to open it and confirm. Once they have, it leaves their list and stays in the announcement history.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            TextEditor(text: $text)
                .fieldEditorStyle(minHeight: 160, maxHeight: 260)

            if let error {
                CopyableText(error, font: .caption).foregroundStyle(.red)
            }

            HStack {
                Spacer()
                Button("Cancel", role: .cancel) { onClose() }
                    .keyboardShortcut(.cancelAction)
                Button(working ? "Posting…" : "Post to everyone") { post() }
                    .buttonStyle(.borderedProminent)
                    .keyboardShortcut(.defaultAction)
                    .disabled(working || trimmed.isEmpty)
            }
        }
        .padding(20)
        .frame(width: 480)
    }

    private func post() {
        guard !trimmed.isEmpty else { return }
        working = true
        error = nil
        do {
            _ = try session.chat.sendText(
                Announcements.text(trimmed), in: conversation.id, as: session.liveFid
            )
            Task { _ = try? await session.courier.drainOutbox(as: session.liveFid) }
            working = false
            onPosted()
        } catch {
            working = false
            self.error = String(describing: error)
        }
    }
}

/// One announcement, as a card: who posted it, when, and what it says.
struct AnnouncementCard: View {

    let announcement: GroupAnnouncement
    let names: ChatNameBook
    /// The group's name above the words, where announcements from several
    /// groups are read one after another.
    var showsGroup = false

    private var style: ChatModeStyle { ChatModeStyle.of(announcement.conversation.type) }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            if showsGroup {
                Text(ChatFormat.title(of: announcement.conversation))
                    .font(.caption.bold())
                    .foregroundStyle(style.tint)
            }
            HStack(spacing: 6) {
                Image(systemName: "megaphone.fill").foregroundStyle(style.tint)
                if let sender = announcement.message.senderId {
                    Text(names.cid(of: sender) ?? sender.elidingMiddle())
                        .font(.callout.bold())
                        .lineLimit(1)
                }
                Spacer(minLength: 4)
                if let time = announcement.message.timestamp {
                    Text(Date(timeIntervalSince1970: Double(time) / 1000).formatted(date: .abbreviated, time: .shortened))
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            Text(announcement.body)
                .textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(12)
        .background(RoundedRectangle(cornerRadius: 10).fill(style.tint.opacity(0.10)))
        .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(style.tint.opacity(0.35)))
    }
}

/// The announcements waiting for this identity's confirmation, one at a
/// time, oldest first. Confirming one moves to the next; the sheet closes
/// on the last.
struct AnnouncementReadSheet: View {

    let session: ActiveSession
    let names: ChatNameBook
    /// The ones to go through, oldest first.
    let announcements: [GroupAnnouncement]
    let onClose: () -> Void
    let onChanged: () -> Void

    @State private var index = 0

    private var current: GroupAnnouncement? {
        announcements.indices.contains(index) ? announcements[index] : nil
    }
    private var groups: Set<String> { Set(announcements.map(\.conversation.id)) }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(spacing: 8) {
                Image(systemName: "megaphone")
                Text("Announcement").font(.title3.bold())
                Spacer()
                if announcements.count > 1 {
                    Text("\(String(index + 1)) of \(String(announcements.count))")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            ScrollView {
                if let current {
                    AnnouncementCard(announcement: current, names: names, showsGroup: groups.count > 1)
                }
            }
            .frame(minHeight: 120, maxHeight: 360)

            HStack {
                Spacer()
                Button("Later", role: .cancel) { onClose() }
                    .keyboardShortcut(.cancelAction)
                Button("Confirm") { confirm() }
                    .buttonStyle(.borderedProminent)
                    .keyboardShortcut(.defaultAction)
                    .disabled(current == nil)
                    .help("You have read it: it leaves your list and stays in the announcement history")
            }
        }
        .padding(20)
        .frame(width: 500)
        .task(id: announcements.compactMap(\.message.senderId)) {
            names.resolve(announcements.compactMap(\.message.senderId), session: session)
        }
    }

    private func confirm() {
        guard let current else { return }
        session.confirmAnnouncement(current)
        onChanged()
        if index + 1 < announcements.count {
            index += 1
        } else {
            onClose()
        }
    }
}

/// Every announcement a group has had, newest first, confirmed or not —
/// one still waiting can be confirmed from its row.
struct AnnouncementHistorySheet: View {

    let session: ActiveSession
    let conversation: Conversation
    let names: ChatNameBook
    let onClose: () -> Void
    let onChanged: () -> Void
    /// Set for the owner, and a team's managers.
    var onPost: (() -> Void)?

    @State private var items: [GroupAnnouncement] = []
    @State private var loaded = false

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(spacing: 8) {
                Image(systemName: "megaphone")
                    .foregroundStyle(ChatModeStyle.of(conversation.type).tint)
                Text("Announcement history").font(.title3.bold())
                Spacer()
            }
            if loaded && items.isEmpty {
                Spacer()
                Label("No announcements yet", systemImage: "megaphone")
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity)
                Spacer()
            } else {
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 10) {
                        ForEach(items) { item in
                            VStack(alignment: .trailing, spacing: 6) {
                                AnnouncementCard(announcement: item, names: names)
                                if !item.isConfirmed {
                                    Button("Confirm") { confirm(item) }
                                }
                            }
                        }
                    }
                }
                .frame(minHeight: 200, maxHeight: 480)
            }

            HStack {
                if let onPost {
                    Button { onPost() } label: {
                        Label("New announcement…", systemImage: "plus")
                    }
                }
                Spacer()
                Button("Done") { onClose() }
                    .keyboardShortcut(.defaultAction)
            }
        }
        .padding(20)
        .frame(width: 520)
        .onAppear(perform: load)
        .task(id: items.compactMap(\.message.senderId)) {
            names.resolve(items.compactMap(\.message.senderId), session: session)
        }
    }

    private func load() {
        // A history may hold announcements this device never indexed —
        // ones that came in a shared history file — so the transcript is
        // read once here.
        session.indexAnnouncements(in: conversation)
        items = session.announcements(in: conversation)
        loaded = true
    }

    private func confirm(_ item: GroupAnnouncement) {
        session.confirmAnnouncement(item)
        items = session.announcements(in: conversation)
        onChanged()
    }
}
