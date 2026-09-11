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
    @Environment(\.inspectFid) private var inspectFid

    let style: ChatModeStyle
    let conversations: [Conversation]
    /// Who the P2P rows are. A chat opened by an incoming message has
    /// no `displayName` — nothing on the wire carries one — so without
    /// this the list would name half its rows and show the other half
    /// as digits.
    let names: ChatNameBook
    @Binding var selectedId: String?
    /// Asked for by the row's context menu. The list does not delete
    /// anything itself — it has no stores and no way to warn — so it
    /// says which row and lets the pane confirm.
    var onDelete: ((Conversation) -> Void)?
    /// Groups whose DOCK refused us last time — Android's red dot. Their
    /// messages are not arriving, and a quiet thread would otherwise read
    /// as a quiet group.
    var unreachable: Set<String> = []
    /// Non-nil while the pane is choosing several threads to act on
    /// together (Android's long-press selection). A tap then ticks a row
    /// instead of opening it.
    var checked: Binding<Set<String>>? = nil

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
                        .onTapGesture {
                            if let checked {
                                if checked.wrappedValue.contains(conversation.id) {
                                    checked.wrappedValue.remove(conversation.id)
                                } else {
                                    checked.wrappedValue.insert(conversation.id)
                                }
                            } else {
                                selectedId = conversation.id
                            }
                        }
                        .contextMenu {
                            // Only a person has a `Freer` behind them —
                            // a team, square or room id looks like a FID
                            // and is not one.
                            if conversation.type == .p2p {
                                Button("Show FID details") {
                                    inspectFid(conversation.targetId)
                                }
                            }
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

    /// A group is named by the flavour it belongs to; a person is not.
    /// Colouring a CID would say something about the person rather than
    /// about the kind of thread, and the tab already says which list
    /// this is.
    private var nameColor: Color {
        style.mode == .p2p ? .primary : style.tint
    }

    /// What to call this thread.
    ///
    /// A group carries its own name. A P2P thread's name is the other
    /// person's CID, and the chain is the only place that knows one —
    /// so the book is asked before falling back to whatever was stored
    /// when the thread was opened, and to the elided FID after that.
    private func title(of conversation: Conversation) -> String {
        guard conversation.type == .p2p else { return ChatFormat.title(of: conversation) }
        if let cid = names.cid(of: conversation.targetId) { return cid }
        return ChatFormat.title(of: conversation)
    }

    private func row(_ conversation: Conversation) -> some View {
        HStack(alignment: .top, spacing: 8) {
            if let checked {
                Image(systemName: checked.wrappedValue.contains(conversation.id)
                      ? "checkmark.circle.fill" : "circle")
                    .foregroundStyle(checked.wrappedValue.contains(conversation.id)
                                     ? AnyShapeStyle(style.tint) : AnyShapeStyle(.tertiary))
                    .padding(.top, 8)
            }
            // A P2P thread's target *is* a FID, so it gets the person's
            // circle. A group's target is a room id or a txid, which
            // ``AvatarMaker`` cannot read and must never be handed —
            // it would either fail or composite a face out of a
            // transaction id. Groups get the square tile instead.
            if conversation.type == .p2p {
                FidAvatarView(
                    fid: conversation.targetId,
                    size: 32,
                    isNobody: names.isNobody(conversation.targetId)
                )
            } else {
                GroupAvatarView(
                    groupId: conversation.targetId,
                    ownerFid: conversation.avatarDid,
                    size: 32
                )
            }

            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 4) {
                    if conversation.type == .p2p {
                        NobodyChip(fid: conversation.targetId)
                    }
                    // **The name is the loudest thing in the row.** A
                    // thread list is scanned, not read: the eye is
                    // looking for one name among twenty, and it was
                    // competing with a preview line of the same weight
                    // one size down. So the name goes up a size, gains
                    // the flavour's colour where the flavour has one to
                    // give, and the preview drops back to being the
                    // quiet second line it always meant to be.
                    Text(title(of: conversation))
                        .font(.body.weight(.bold))
                        .foregroundStyle(nameColor)
                        .lineLimit(1)
                    if conversation.leftGroup == true {
                        // A room ends the same way whether its owner
                        // closed it, removed us, or we left: nobody here
                        // can speak in it again.
                        ChatChip(conversation.type == .room ? "closed" : "left", color: .secondary)
                    } else if unreachable.contains(conversation.targetId) {
                        ChatChip("DOCK down", color: .red)
                            .help("This group's DOCK refused the last connection, so nothing new is arriving. It is retried whenever this list opens.")
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
