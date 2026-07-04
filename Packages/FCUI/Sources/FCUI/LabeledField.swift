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
    /// appearance — solid background, subtle stroke, padded interior.
    /// Pair with `LabeledField` so the label tag sits above a visibly
    /// distinct input area.
    func fieldInputStyle() -> some View {
        modifier(FieldInputStyle())
    }
}

private struct FieldInputStyle: ViewModifier {
    func body(content: Content) -> some View {
        content
            .textFieldStyle(.plain)
            .padding(.horizontal, 10)
            .padding(.vertical, 8)
            .background(
                RoundedRectangle(cornerRadius: 6, style: .continuous)
                    .fill(Color(nsColor: .textBackgroundColor))
            )
            .overlay(
                RoundedRectangle(cornerRadius: 6, style: .continuous)
                    .strokeBorder(Color.secondary.opacity(0.3), lineWidth: 0.5)
            )
    }
}
