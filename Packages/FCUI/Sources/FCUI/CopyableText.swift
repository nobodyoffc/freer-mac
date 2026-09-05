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
public struct CopyableText: View {

    private let display: String
    private let copyValue: String
    private let font: Font?
    private let color: Color
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
    ///   - color: resting text colour. Set explicitly rather than with
    ///     an outer `.foregroundStyle` — this view sets its own so the
    ///     copied-flash can turn green, and the inner modifier wins.
    public init(
        _ text: String, font: Font? = nil, color: Color = .primary, help: String? = nil
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
        color: Color = .primary,
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
        color: Color = .primary,
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
            .foregroundStyle(copied ? Color.green : color)
            .contentShape(Rectangle())
            .onTapGesture { copy() }
            .onHover { hovering in
                if hovering {
                    NSCursor.pointingHand.push()
                } else {
                    NSCursor.pop()
                }
            }
            .help(copied ? "Copied!" : (help ?? "Click to copy"))
            .overlay(alignment: .trailing) {
                if copied {
                    Image(systemName: "checkmark.circle.fill")
                        .foregroundStyle(.green)
                        .padding(.trailing, -18)
                        .transition(.opacity)
                }
            }
            .animation(.easeInOut(duration: 0.15), value: copied)
    }

    private func copy() {
        let pb = NSPasteboard.general
        pb.clearContents()
        pb.setString(copyValue, forType: .string)
        copied = true
        Task {
            try? await Task.sleep(nanoseconds: 1_200_000_000)
            await MainActor.run { copied = false }
        }
    }
}
