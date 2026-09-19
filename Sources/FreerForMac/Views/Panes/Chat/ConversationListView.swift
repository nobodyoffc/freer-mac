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

    /// Whether the second line has an id worth printing.
    ///
    /// A thread with no name of its own is *already* titled by its
    /// elided id — printing it again underneath would be the same
    /// string twice, one size down.
    private func showsId(_ conversation: Conversation) -> Bool {
        title(of: conversation) != conversation.targetId.elidingMiddle(head: 8, tail: 6)
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
                // **The name is the loudest thing in the row**, and it
                // gets the whole first line. A thread list is scanned,
                // not read: the eye is looking for one name among
                // twenty, and sharing the line with an id and two flags
                // left it a third of the row to truncate into.
                HStack(spacing: 4) {
                    if conversation.type == .p2p {
                        NobodyChip(fid: conversation.targetId)
                    }
                    Text(title(of: conversation))
                        .font(.body.weight(.bold))
                        .foregroundStyle(nameColor)
                        .lineLimit(1)
                    // The time belongs to the first line and only to
                    // the first line. Standing in a column beside all
                    // three, it was narrowing the id and the preview by
                    // its own width — and a long date is wide.
                    Spacer(minLength: 8)
                    if let time = conversation.lastActiveAt {
                        Text(ChatFormat.shortTime.string(from: Date(timeIntervalSince1970: Double(time) / 1000)))
                            .font(.caption2)
                            .foregroundStyle(.tertiary)
                            .fixedSize()
                    }
                }
                // The id and the flags share the second line. The id is
                // what you compare against a link someone sent you, so
                // it is elided in the middle and copies whole on a
                // click; the flags are short enough to sit beside it.
                HStack(spacing: 4) {
                    if showsId(conversation) {
                        CopyableText.elidingMiddle(
                            conversation.targetId,
                            head: 8,
                            tail: 6,
                            font: .caption2.monospaced(),
                            color: .secondary,
                            help: conversation.type == .p2p
                                ? "Copy this Freer's FID"
                                : "Copy this \(style.noun)'s id"
                        )
                    }
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
                // The unread count rides the last line, where it is
                // out of the name's way and still on the edge the eye
                // runs down.
                HStack(spacing: 4) {
                    Text(conversation.lastMessageContent ?? "No messages yet")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                    Spacer(minLength: 8)
                    if let unread = conversation.unreadCount, unread > 0 {
                        Text("\(unread)")
                            .font(.caption2.bold())
                            .padding(.horizontal, 6)
                            .padding(.vertical, 2)
                            .background(Capsule().fill(style.tint))
                            .foregroundStyle(.white)
                            .fixedSize()
                    }
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
            // A chip is a label, not a paragraph. Left compressible it
            // breaks mid-word into a two-letter column — "DO CK do wn" —
            // the moment the row it sits in runs short of width. It keeps
            // its natural size instead, and the name beside it truncates.
            .lineLimit(1)
            .fixedSize()
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
