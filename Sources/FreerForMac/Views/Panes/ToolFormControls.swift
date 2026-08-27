import SwiftUI
import AppKit
import FCUI

/// Form controls shared by the two workbench panes, ``ToolsView`` and
/// ``ConvertView``. Both are the same shape of screen — paste something
/// in, press a button, read something out — so they share the input
/// editor, the error rendering, and the labelled result row.

/// Multiline monospaced editor with a subtle border — for ciphers,
/// signature JSON, scripts, and long messages.
struct ToolTextEditor: View {
    let placeholder: String
    @Binding var text: String
    var minHeight: CGFloat = 64

    var body: some View {
        ZStack(alignment: .topLeading) {
            TextEditor(text: $text)
                .font(.system(.body, design: .monospaced))
                .scrollContentBackground(.hidden)
                .padding(4)
            if text.isEmpty {
                Text(placeholder)
                    .foregroundStyle(.tertiary)
                    .font(.system(.body, design: .monospaced))
                    .padding(.top, 8)
                    .padding(.leading, 9)
                    .allowsHitTesting(false)
            }
        }
        .frame(minHeight: minHeight)
        .background(Color(NSColor.textBackgroundColor))
        .clipShape(RoundedRectangle(cornerRadius: 6))
        .overlay(
            RoundedRectangle(cornerRadius: 6)
                .strokeBorder(Color(NSColor.separatorColor))
        )
    }
}

/// One `label: value` line of a multi-part result — the address table,
/// the public-key forms, the encodings of a string.
///
/// The value wraps rather than scrolling: these are 130-character
/// public keys and 42-character addresses that users read across, and
/// **a click anywhere on the value copies the whole of it**.
///
/// Note the absence of `.textSelection(.enabled)`. It looks like a free
/// addition and is not: selectable text takes the mouse for
/// drag-to-select, so the tap never reaches `CopyableText` and the
/// click-to-copy this app relies on everywhere silently stops working.
/// One-click copy beats hand-selecting a 130-character key anyway.
///
/// The QR button is Android's per-result `makeQrIcon`, and it sits on
/// the label line rather than beside the value so it can never steal a
/// click meant for the copy.
struct ToolResultRow: View {
    let label: String
    let value: String

    @State private var showQr = false

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            HStack(spacing: 6) {
                Text(label)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Button {
                    showQr = true
                } label: {
                    Image(systemName: "qrcode")
                        .font(.caption)
                }
                .buttonStyle(.borderless)
                .foregroundStyle(.secondary)
                .help("Show “\(label)” as a QR code")
                Spacer(minLength: 0)
            }
            CopyableText(value, font: .system(.body, design: .monospaced))
                .fixedSize(horizontal: false, vertical: true)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .sheet(isPresented: $showQr) {
            // QrDisplaySheet chunks anything past one code's capacity,
            // so a pretty-printed JSON blob paginates instead of failing.
            QrDisplaySheet(title: label, content: value) { showQr = false }
        }
    }
}

/// A block of ``ToolResultRow``s on the standard result background.
struct ToolResultTable: View {
    let rows: [(String, String)]

    var body: some View {
        if !rows.isEmpty {
            VStack(alignment: .leading, spacing: 10) {
                ForEach(rows, id: \.0) { row in
                    ToolResultRow(label: row.0, value: row.1)
                }
            }
            .padding(10)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Color(NSColor.textBackgroundColor))
            .clipShape(RoundedRectangle(cornerRadius: 6))
        }
    }
}

/// Copy and QR buttons for a value that lives in an *editable* field,
/// where the click-to-copy used everywhere else cannot apply — clicking
/// an editable field has to place the caret. Used by the Time
/// converter, whose five fields are all inputs and all outputs.
struct ToolValueActions: View {
    let label: String
    let value: String

    @State private var showQr = false
    @State private var copied = false

    var body: some View {
        HStack(spacing: 6) {
            Button {
                let pasteboard = NSPasteboard.general
                pasteboard.clearContents()
                pasteboard.setString(value, forType: .string)
                copied = true
                Task {
                    try? await Task.sleep(nanoseconds: 1_200_000_000)
                    await MainActor.run { copied = false }
                }
            } label: {
                Image(systemName: copied ? "checkmark.circle.fill" : "doc.on.doc")
                    .font(.caption)
            }
            .buttonStyle(.borderless)
            .foregroundStyle(copied ? Color.green : Color.secondary)
            .help(copied ? "Copied!" : "Copy “\(label)”")
            .animation(.easeInOut(duration: 0.15), value: copied)

            Button {
                showQr = true
            } label: {
                Image(systemName: "qrcode").font(.caption)
            }
            .buttonStyle(.borderless)
            .foregroundStyle(.secondary)
            .help("Show “\(label)” as a QR code")
        }
        .disabled(value.isEmpty)
        .opacity(value.isEmpty ? 0 : 1)
        .sheet(isPresented: $showQr) {
            QrDisplaySheet(title: label, content: value) { showQr = false }
        }
    }
}

/// Our `Failure` enums are `CustomStringConvertible`, so
/// `String(describing:)` surfaces their message. Foreign `NSError`s
/// read acceptably too.
func errorText(_ error: Error) -> String {
    String(describing: error)
}
