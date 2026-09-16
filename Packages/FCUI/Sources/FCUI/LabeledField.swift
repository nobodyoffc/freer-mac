import SwiftUI

/// A form row with a clearly-tagged label above a clearly-bordered
/// input area. Solves the macOS-Form problem where
/// `TextField("Label", text:)` renders the label and the input in the
/// same body font with no separator, so users can't tell where the
/// label ends and the input begins.
///
/// Wrap the actual input (TextField, SecureField, Picker, anything)
/// in the trailing `content` closure. Apply `.fieldInputStyle()` to
/// text/secure fields to give them the bordered appearance that
/// pairs with this label.
///
/// ```
/// LabeledField("Host", hint: "Plain hostname or IP, no scheme.") {
///     TextField("", text: $host, prompt: Text("localhost"))
///         .fieldInputStyle()
/// }
/// ```
public struct LabeledField<Content: View>: View {

    private let label: String
    private let hint: String?
    private let hintIsError: Bool
    private let content: () -> Content

    public init(
        _ label: String,
        hint: String? = nil,
        hintIsError: Bool = false,
        @ViewBuilder content: @escaping () -> Content
    ) {
        self.label = label
        self.hint = hint
        self.hintIsError = hintIsError
        self.content = content
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(label)
                .font(.caption)
                .fontWeight(.semibold)
                .textCase(.uppercase)
                .tracking(0.5)
                .foregroundStyle(.secondary)

            content()

            if let hint, !hint.isEmpty {
                Text(hint)
                    .font(.caption)
                    .foregroundStyle(hintIsError ? .red : .secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .padding(.vertical, 4)
    }
}

public extension View {
    /// Give a TextField / SecureField a clearly-bordered "input box"
    /// appearance — solid background, visible stroke, padded interior,
    /// and a focus ring that says which box the keys are going into.
    /// Pair with `LabeledField` so the label tag sits above a visibly
    /// distinct input area.
    func fieldInputStyle() -> some View {
        modifier(FieldInputStyle())
    }

    /// The same box, sized for a multi-line `TextEditor`.
    ///
    /// A TextEditor paints its own backing over anything you put
    /// behind it, so the `.scrollContentBackground(.hidden)` here is
    /// load-bearing — it is why the hand-rolled editor chrome around
    /// the app looks like its background fill did nothing.
    func fieldEditorStyle(
        minHeight: CGFloat = 90,
        maxHeight: CGFloat? = nil,
        isError: Bool = false
    ) -> some View {
        modifier(FieldEditorStyle(minHeight: minHeight, maxHeight: maxHeight, isError: isError))
    }
}

/// The one description of what an editable box looks like.
///
/// Every colour and measurement the app's input surfaces share lives
/// here so they cannot drift apart again — the hand-rolled copies had
/// managed three different corner radii and two different stroke
/// colours between them.
public enum FieldChrome {
    public static let cornerRadius: CGFloat = 6

    public static var shape: RoundedRectangle {
        RoundedRectangle(cornerRadius: cornerRadius, style: .continuous)
    }

    public static var background: some View { shape.fill(Color(nsColor: .textBackgroundColor)) }

    /// The resting border was `secondary.opacity(0.3)` at half a point,
    /// which against a grouped Form is very nearly invisible — the
    /// reason people could not tell where a field began. A full point
    /// at 0.5 reads as an edge without shouting, hover confirms the box
    /// is live, and focus takes the accent colour so the field holding
    /// the caret is obvious from across the window.
    /// An invalid box is red whether or not it has the caret — a field
    /// you are still typing into is exactly the one that needs to say
    /// it has gone over a limit.
    public static func stroke(focused: Bool, hovering: Bool, isError: Bool = false) -> Color {
        if isError { return .red }
        if focused { return .accentColor }
        return .secondary.opacity(hovering ? 0.75 : 0.5)
    }

    public static func border(focused: Bool, hovering: Bool = false, isError: Bool = false) -> some View {
        shape.strokeBorder(
            stroke(focused: focused, hovering: hovering, isError: isError),
            lineWidth: (focused || isError) ? 2 : 1
        )
    }
}

private struct FieldInputStyle: ViewModifier {
    @FocusState private var focused: Bool
    @State private var hovering = false

    func body(content: Content) -> some View {
        content
            .textFieldStyle(.plain)
            .focused($focused)
            .padding(.horizontal, 10)
            .padding(.vertical, 8)
            .background(FieldChrome.background)
            .overlay(FieldChrome.border(focused: focused, hovering: hovering))
            // The padding is part of the box as far as the user is
            // concerned, so a click that lands on it has to arrive
            // somewhere. Without this it hits nothing and the field
            // the user aimed at stays unfocused.
            .contentShape(FieldChrome.shape)
            .onTapGesture { focused = true }
            .onHover { hovering = $0 }
            .animation(.easeOut(duration: 0.12), value: focused)
            .animation(.easeOut(duration: 0.12), value: hovering)
    }
}

private struct FieldEditorStyle: ViewModifier {
    let minHeight: CGFloat
    let maxHeight: CGFloat?
    let isError: Bool

    @FocusState private var focused: Bool
    @State private var hovering = false

    func body(content: Content) -> some View {
        content
            .scrollContentBackground(.hidden)
            .focused($focused)
            .padding(6)
            .frame(minHeight: minHeight, maxHeight: maxHeight)
            .background(FieldChrome.background)
            .overlay(FieldChrome.border(focused: focused, hovering: hovering, isError: isError))
            .onHover { hovering = $0 }
            .animation(.easeOut(duration: 0.12), value: focused)
            .animation(.easeOut(duration: 0.12), value: hovering)
    }
}
