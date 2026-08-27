import SwiftUI
import FCCore
import FCDomain
import FCUI

/// The thread list for **one** flavour.
///
/// It takes a ``ChatModeStyle`` rather than reading a conversation's
/// `type`, because the list it is drawing holds one flavour and only
/// one: the pane never mixes them. That is the whole point of the split
/// — a square and a P2P thread can no longer be adjacent rows differing
/// by a chip, so there is no row here that could be the other kind.
struct ConversationListView: View {

    let style: ChatModeStyle
    let conversations: [Conversation]
    @Binding var selectedId: String?
    /// Asked for by the row's context menu. The list does not delete
    /// anything itself — it has no stores and no way to warn — so it
    /// says which row and lets the pane confirm.
    var onDelete: ((Conversation) -> Void)?

    var body: some View {
        ScrollView {
            LazyVStack(alignment: .leading, spacing: 0) {
                ForEach(conversations) { conversation in
                    row(conversation)
                        .padding(.vertical, 8)
                        .padding(.horizontal, 10)
                        .background(
                            conversation.id == selectedId
                                ? style.tint.opacity(0.14)
                                : Color.clear
                        )
                        .overlay(alignment: .leading) {
                            // The selected row wears the flavour's colour
                            // as a spine, so which list you are in is
                            // visible from the transcript side too.
                            if conversation.id == selectedId {
                                Rectangle().fill(style.tint).frame(width: 3)
                            }
                        }
                        .contentShape(Rectangle())
                        .onTapGesture { selectedId = conversation.id }
                        .contextMenu {
                            if let onDelete {
                                Button("Delete", role: .destructive) { onDelete(conversation) }
                            }
                        }
                    Divider()
                }
            }
        }
        .background(Color(NSColor.controlBackgroundColor))
        .clipShape(RoundedRectangle(cornerRadius: 10))
    }

    private func row(_ conversation: Conversation) -> some View {
        HStack(alignment: .top, spacing: 8) {
            // A P2P thread's target *is* a FID, so it gets the person's
            // circle. A group's target is a room id or a txid, which
            // ``AvatarMaker`` cannot read and must never be handed —
            // it would either fail or composite a face out of a
            // transaction id. Groups get the square tile instead.
            if conversation.type == .p2p {
                FidAvatarView(fid: conversation.targetId, size: 32)
            } else {
                GroupAvatarView(
                    groupId: conversation.targetId,
                    ownerFid: conversation.avatarDid,
                    size: 32
                )
            }

            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 4) {
                    Text(ChatFormat.title(of: conversation))
                        .font(.callout.bold())
                        .lineLimit(1)
                    if conversation.leftGroup == true {
                        ChatChip("left", color: .secondary)
                    }
                    // Only the square is labelled in the list, and only
                    // because its label is a warning. The others are
                    // already named by the tab you are standing in.
                    if style.isPublic {
                        ChatChip("public", color: style.tint)
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
                    Text(ChatFormat.shortTime.string(from: Date(timeIntervalSince1970: Double(time) / 1000)))
                        .font(.caption2)
                        .foregroundStyle(.tertiary)
                }
                if let unread = conversation.unreadCount, unread > 0 {
                    Text("\(unread)")
                        .font(.caption2.bold())
                        .padding(.horizontal, 6)
                        .padding(.vertical, 2)
                        .background(Capsule().fill(style.tint))
                        .foregroundStyle(.white)
                }
            }
        }
    }
}

/// The small pill used for a flag on a row or in a header.
struct ChatChip: View {
    let text: String
    let color: Color

    init(_ text: String, color: Color) {
        self.text = text
        self.color = color
    }

    var body: some View {
        Text(text)
            .font(.caption2.bold())
            .padding(.horizontal, 5)
            .padding(.vertical, 1)
            .background(Capsule().fill(color.opacity(0.15)))
            .foregroundStyle(color)
    }
}

/// Formatting shared by the list, the transcript and the headers.
enum ChatFormat {

    static func title(of conversation: Conversation) -> String {
        conversation.displayName ?? conversation.targetId.elidingMiddle(head: 8, tail: 6)
    }

    static let shortTime: DateFormatter = {
        let f = DateFormatter()
        f.dateStyle = .short
        f.timeStyle = .short
        return f
    }()
}
