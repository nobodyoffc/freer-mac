import SwiftUI

/// A small emoji palette for the chat composer — the Mac counterpart of
/// Android's `emoji/EmojiAdapter` + `EmojiData`.
///
/// **Deliberately a short list, not a full picker.** macOS already has
/// a complete emoji browser on ⌃⌘Space that every text field opens, so
/// reimplementing one here would be a worse copy of something the user
/// already has. What the system palette is *not* good at is being one
/// click away while typing, which is all this is: the handful people
/// actually send, grouped, in a popover.
struct EmojiPicker: View {

    let onPick: (String) -> Void

    private static let groups: [(String, [String])] = [
        ("Faces", [
            "😀", "😂", "🙂", "😉", "😍", "🤔", "😐", "🙄",
            "😢", "😭", "😅", "😬", "😴", "🤯", "😎", "🥳",
        ]),
        ("Gestures", [
            "👍", "👎", "👌", "🙏", "👏", "🤝", "✋", "💪",
        ]),
        ("Marks", [
            "❤️", "🔥", "✅", "❌", "⚠️", "❓", "❗", "💡",
            "⭐️", "🎉", "🚀", "⏰", "📌", "🔒", "🔑", "📎",
        ]),
    ]

    private let columns = Array(repeating: GridItem(.fixed(30), spacing: 2), count: 8)

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            ForEach(Self.groups, id: \.0) { group in
                VStack(alignment: .leading, spacing: 4) {
                    Text(group.0)
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                    LazyVGrid(columns: columns, spacing: 2) {
                        ForEach(group.1, id: \.self) { emoji in
                            Button {
                                onPick(emoji)
                            } label: {
                                Text(emoji).font(.title3)
                            }
                            .buttonStyle(.borderless)
                        }
                    }
                }
            }

            Divider()
            Text("⌃⌘Space opens the full palette.")
                .font(.caption2)
                .foregroundStyle(.tertiary)
        }
        .padding(12)
        .frame(width: 280)
    }
}
