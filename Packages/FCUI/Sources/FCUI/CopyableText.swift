import SwiftUI
import AppKit

extension String {
    /// Truncate by removing the middle, keeping the first `head` and
    /// last `tail` characters joined by "…". Returns `self` unchanged
    /// when it already fits in `head + tail + 1`. The trailing
    /// characters of an ID are usually the discriminating ones a
    /// user verifies against — never hide them with `prefix(N)`.
    public func elidingMiddle(head: Int = 8, tail: Int = 8) -> String {
        guard count > head + tail + 1 else { return self }
        let h = self.prefix(head)
        let t = self.suffix(tail)
        return "\(h)…\(t)"
    }
}

/// Text that copies its full string to the system clipboard on a
/// single click. Briefly flashes a checkmark + tint so the click
/// registers visibly. The display string can be a truncated /
/// formatted version of the underlying value (e.g. show
/// "FA1B…cdef" while copying the full FID).
///
/// The `pointing-hand` cursor on hover signals the affordance.
///
/// **The resting colour is inherited** unless `color` is given, so an
/// outer `.foregroundStyle(.orange)` on a warning reaches the text.
/// It used to default to `.primary`, set on the inner `Text`, where it
/// beat every outer style — warnings and errors rendered in the body
/// colour.
public struct CopyableText: View {

    private let display: String
    private let copyValue: String
    private let font: Font?
    private let color: Color?
    /// What the hover tip says while nothing has been copied yet. Nil
    /// gets the generic wording, which is right whenever the display
    /// string *is* the copied string. Set it when the two differ — a
    /// row showing a CID and copying the FID behind it has to say so,
    /// or the click looks like it copied the name.
    private let help: String?

    @State private var copied = false

    /// - parameters:
    ///   - text: the value displayed AND copied. Use this when the
    ///     visible string is exactly what the user wants on the
    ///     clipboard.
    ///   - font: optional explicit font; nil inherits.
    ///   - color: resting text colour; nil inherits the surrounding
    ///     foreground style.
    public init(
        _ text: String, font: Font? = nil, color: Color? = nil, help: String? = nil
    ) {
        self.display = text
        self.copyValue = text
        self.font = font
        self.color = color
        self.help = help
    }

    /// - parameters:
    ///   - display: what the user sees (may be truncated / formatted).
    ///   - copy: what gets put on the clipboard (the full value).
    ///   - font: optional explicit font; nil inherits.
    public init(
        display: String,
        copy: String,
        font: Font? = nil,
        color: Color? = nil,
        help: String? = nil
    ) {
        self.display = display
        self.copyValue = copy
        self.font = font
        self.color = color
        self.help = help
    }

    /// Display `value` with its middle elided (`head + "…" + tail`)
    /// while the full string lands on the clipboard. The standard
    /// way to render any ID (FID, txid, cashId, pubkey) in the UI.
    public static func elidingMiddle(
        _ value: String,
        head: Int = 8,
        tail: Int = 8,
        font: Font? = nil,
        color: Color? = nil,
        help: String? = nil
    ) -> CopyableText {
        CopyableText(
            display: value.elidingMiddle(head: head, tail: tail),
            copy: value,
            font: font,
            color: color,
            help: help
        )
    }

    public var body: some View {
        Text(display)
            .font(font)
            .foregroundStyle(restingStyle)
            .copiesOnClick(copyValue, help: help, copied: $copied)
    }

    private var restingStyle: AnyShapeStyle {
        if copied { return AnyShapeStyle(Color.green) }
        if let color { return AnyShapeStyle(color) }
        // `.primary` as a hierarchical style is the first level of the
        // *current* content style, not the fixed label colour.
        return AnyShapeStyle(HierarchicalShapeStyle.primary)
    }
}

/// A `Label` — icon and sentence — that copies its sentence on a
/// single click. For warnings and errors: whatever the app says went
/// wrong is something the user will want to paste somewhere.
public struct CopyableLabel: View {
    private let text: String
    private let systemImage: String
    private let help: String?

    public init(_ text: String, systemImage: String, help: String? = nil) {
        self.text = text
        self.systemImage = systemImage
        self.help = help
    }

    public var body: some View {
        Label(text, systemImage: systemImage)
            .copiesOnClick(text, help: help)
    }
}

public extension View {
    /// A single click anywhere on this view puts `value` on the
    /// clipboard, with the same hand cursor and checkmark flash as
    /// ``CopyableText``. For a composite — an icon beside a sentence —
    /// where the copied string is the sentence alone.
    func copiesOnClick(_ value: String, help: String? = nil) -> some View {
        modifier(CopyOnClick(value: value, help: help, external: nil))
    }

    fileprivate func copiesOnClick(
        _ value: String, help: String?, copied: Binding<Bool>
    ) -> some View {
        modifier(CopyOnClick(value: value, help: help, external: copied))
    }
}

private struct CopyOnClick: ViewModifier {
    let value: String
    let help: String?
    /// The owner's flag when it tints on copy (``CopyableText``); nil
    /// keeps the flag here.
    let external: Binding<Bool>?

    @State private var local = false

    private var copied: Binding<Bool> { external ?? $local }

    func body(content: Content) -> some View {
        content
            .contentShape(Rectangle())
            .onTapGesture { copy() }
            .pointingHand()
            .help(copied.wrappedValue ? "Copied!" : (help ?? "Click to copy"))
            .overlay(alignment: .trailing) {
                if copied.wrappedValue {
                    Image(systemName: "checkmark.circle.fill")
                        .foregroundStyle(.green)
                        .padding(.trailing, -18)
                        .transition(.opacity)
                }
            }
            .animation(.easeInOut(duration: 0.15), value: copied.wrappedValue)
    }

    private func copy() {
        let pb = NSPasteboard.general
        pb.clearContents()
        pb.setString(value, forType: .string)
        copied.wrappedValue = true
        let flag = copied
        Task {
            try? await Task.sleep(nanoseconds: 1_200_000_000)
            await MainActor.run { flag.wrappedValue = false }
        }
    }
}

/// The pointing-hand cursor on hover — the signal that something is
/// clickable when it does not look like a button.
///
/// Push/pop rather than `NSCursor.set()`: a cursor set on enter and
/// never popped outlives the view under it, and the user is left with
/// a hand over the whole window.
public extension View {
    func pointingHand() -> some View {
        onHover { hovering in
            if hovering { NSCursor.pointingHand.push() } else { NSCursor.pop() }
        }
    }
}
