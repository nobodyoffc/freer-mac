import SwiftUI

/// The app's one search box — a magnifier, a plain text field, and a
/// clear button that appears only once there's something to clear.
///
/// Panes filter lists in memory as the user types (see
/// `Hat.matches(query:)` / `Secret.matches(query:)`), so this is a
/// pure binding with no debounce or submit action; it exists to keep
/// every list pane's search looking and behaving the same.
///
/// ```
/// SearchField("Search title, type, memo…", text: $search)
/// ```
public struct SearchField: View {

    private let prompt: String
    @Binding private var text: String
    private let minWidth: CGFloat
    private let maxWidth: CGFloat

    public init(
        _ prompt: String,
        text: Binding<String>,
        minWidth: CGFloat = 180,
        maxWidth: CGFloat = 280
    ) {
        self.prompt = prompt
        self._text = text
        self.minWidth = minWidth
        self.maxWidth = maxWidth
    }

    @FocusState private var focused: Bool
    @State private var hovering = false

    public var body: some View {
        HStack(spacing: 6) {
            Image(systemName: "magnifyingglass")
                .foregroundStyle(focused ? Color.accentColor : .secondary)
            TextField("", text: $text, prompt: Text(prompt))
                .textFieldStyle(.plain)
                .focused($focused)
                .frame(minWidth: minWidth, maxWidth: maxWidth)
            if !text.isEmpty {
                Button {
                    text = ""
                } label: {
                    Image(systemName: "xmark.circle.fill").foregroundStyle(.secondary)
                }
                .buttonStyle(.plain)
                .help("Clear the search")
            }
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 5)
        .background(FieldChrome.background)
        .overlay(FieldChrome.border(focused: focused, hovering: hovering))
        // The magnifier and the whitespace around the field are the
        // part of a search box people actually aim at.
        .contentShape(FieldChrome.shape)
        .onTapGesture { focused = true }
        .onHover { hovering = $0 }
        .animation(.easeOut(duration: 0.12), value: focused)
        .animation(.easeOut(duration: 0.12), value: hovering)
    }
}
