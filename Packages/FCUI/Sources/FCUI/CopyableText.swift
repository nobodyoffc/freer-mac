import SwiftUI
import AppKit

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

    @State private var copied = false

    /// - parameters:
    ///   - text: the value displayed AND copied. Use this when the
    ///     visible string is exactly what the user wants on the
    ///     clipboard.
    ///   - font: optional explicit font; nil inherits.
    public init(_ text: String, font: Font? = nil) {
        self.display = text
        self.copyValue = text
        self.font = font
    }

    /// - parameters:
    ///   - display: what the user sees (may be truncated / formatted).
    ///   - copy: what gets put on the clipboard (the full value).
    ///   - font: optional explicit font; nil inherits.
    public init(display: String, copy: String, font: Font? = nil) {
        self.display = display
        self.copyValue = copy
        self.font = font
    }

    public var body: some View {
        Text(display)
            .font(font)
            .foregroundStyle(copied ? Color.green : Color.primary)
            .contentShape(Rectangle())
            .onTapGesture { copy() }
            .onHover { hovering in
                if hovering {
                    NSCursor.pointingHand.push()
                } else {
                    NSCursor.pop()
                }
            }
            .help(copied ? "Copied!" : "Click to copy")
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
