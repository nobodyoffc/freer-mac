import SwiftUI
import AppKit
import FCDomain
import FCUI

/// Export modal for a freshly-built unsigned transaction (the
/// watch-only Send fallback). Shows the coin-selection summary and
/// the `RawTxInfo` JSON — Android `CreateTxActivity`'s import format
/// — with three ways out: **Copy JSON**, **Save…** to a file, and
/// **Show QR** (long documents chunk across multiple codes, which
/// the Android side merges back on scan).
struct UnsignedTxSheet: View {
    let result: WalletService.UnsignedSendResult
    let onDone: () -> Void

    @State private var json: String = ""
    @State private var encodeError: String?
    @State private var copied = false
    @State private var saveNote: String?
    @State private var showQr = false

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 10) {
                Image(systemName: "signature").font(.title2)
                Text("Unsigned transaction").font(.title3).bold()
                Spacer()
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 12)

            Divider()

            VStack(alignment: .leading, spacing: 10) {
                summary

                if let err = encodeError {
                    CopyableText(err, font: .caption)
                        .foregroundStyle(.red)
                        .fixedSize(horizontal: false, vertical: true)
                } else {
                    jsonPane
                }

                if let note = saveNote {
                    CopyableText(note, font: .caption)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }

                Text("Sign it where the key lives: the Android app imports this document in Create Tx (paste or QR scan), signs, and broadcasts.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .padding(16)

            Divider()

            HStack(spacing: 8) {
                Button {
                    copyJson()
                } label: {
                    Label(copied ? "Copied" : "Copy JSON",
                          systemImage: copied ? "checkmark.circle.fill" : "doc.on.doc")
                }
                .foregroundStyle(copied ? .green : .primary)

                Button {
                    saveJson()
                } label: {
                    Label("Save…", systemImage: "square.and.arrow.down")
                }

                Button {
                    showQr = true
                } label: {
                    Label("Show QR", systemImage: "qrcode")
                }
                .help("Render the document as QR codes — long content is split across several; scan them all on the signer to merge.")

                Spacer()

                Button("Done") { onDone() }
                    .keyboardShortcut(.defaultAction)
                    .buttonStyle(.borderedProminent)
            }
            .disabled(json.isEmpty && encodeError == nil)
            .padding(.horizontal, 16)
            .padding(.vertical, 12)
        }
        .frame(minWidth: 560)
        .onAppear { encode() }
        .sheet(isPresented: $showQr) {
            QrDisplaySheet(content: json) { showQr = false }
        }
    }

    private var summary: some View {
        let p = result.plan
        let text = "\(p.selected.count) input(s) · \(p.totalIn) sat in · fee \(p.fee) sat · \(p.estimatedSize) B" +
            (p.hasChange ? " · change \(p.change) sat" : " · no change")
        return CopyableText(text, font: .caption.monospaced())
            .foregroundStyle(.secondary)
    }

    private var jsonPane: some View {
        ScrollView {
            Text(json)
                .font(.system(.caption, design: .monospaced))
                .textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(8)
        }
        .frame(minHeight: 160, maxHeight: 280)
        .background(
            RoundedRectangle(cornerRadius: 6, style: .continuous)
                .fill(Color(nsColor: .textBackgroundColor))
        )
        .overlay(
            RoundedRectangle(cornerRadius: 6, style: .continuous)
                .strokeBorder(Color.secondary.opacity(0.3), lineWidth: 0.5)
        )
    }

    private func encode() {
        do {
            json = try result.info.exportJson()
        } catch {
            encodeError = String(describing: error)
        }
    }

    private func copyJson() {
        let pb = NSPasteboard.general
        pb.clearContents()
        pb.setString(json, forType: .string)
        copied = true
        Task {
            try? await Task.sleep(nanoseconds: 1_200_000_000)
            await MainActor.run { copied = false }
        }
    }

    private func saveJson() {
        let panel = NSSavePanel()
        panel.nameFieldStringValue =
            "unsignedTx_\(Int(Date().timeIntervalSince1970)).json"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            try Data(json.utf8).write(to: url)
            saveNote = "Saved to \(url.path)"
        } catch {
            saveNote = "Save failed: \(error.localizedDescription)"
        }
    }
}
