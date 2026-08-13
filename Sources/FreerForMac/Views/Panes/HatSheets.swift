import SwiftUI
import AppKit
import FCCore
import FCDomain
import FCUI

// MARK: - detail

/// Every field of one HAT, plus its locations. The Mac equivalent of
/// Android's `HatDetailActivity`.
struct HatDetailSheet: View {
    let session: ActiveSession
    let hat: Hat
    let onDone: () -> Void

    @State private var record: HatRecord?
    @State private var error: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack(spacing: 8) {
                Image(systemName: FilesView.icon(for: hat))
                    .font(.title2)
                    .foregroundStyle(.secondary)
                Text(hat.displayName)
                    .font(.title3.bold())
                    .lineLimit(2)
                    .truncationMode(.middle)
                if hat.isCipherHat {
                    chip("Encrypted copy", color: .purple)
                }
                Spacer()
            }

            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    field("Data id (DID)") {
                        CopyableText(hat.id ?? "—", font: .system(.callout, design: .monospaced))
                            .lineLimit(1)
                            .truncationMode(.middle)
                    }

                    if let size = hat.size {
                        field("Size") { Text(FilesView.formatBytes(size)) }
                    }
                    if let desc = hat.desc, !desc.isEmpty {
                        field("Description") { CopyableText(desc, font: .body) }
                    }
                    if let types = hat.types, !types.isEmpty {
                        field("Types") { Text(types.joined(separator: ", ")) }
                    }
                    if let born = hat.born {
                        field("Added") { Text(FilesView.formatDate(born)) }
                    }
                    if let last = hat.last {
                        field("Last used") { Text(FilesView.formatDate(last)) }
                    }

                    locationsSection

                    if let cipherIds = hat.cipherIds, !cipherIds.isEmpty {
                        field("Encrypted copies on DISK") {
                            VStack(alignment: .leading, spacing: 4) {
                                ForEach(cipherIds, id: \.self) { id in
                                    CopyableText(
                                        display: id.elidingMiddle(head: 10, tail: 8),
                                        copy: id,
                                        font: .system(.caption, design: .monospaced)
                                    )
                                }
                            }
                        }
                    }

                    if hat.key != nil {
                        field("Sharing key") {
                            Label(
                                "This record carries a plaintext key, so anyone it is shared with can open the file.",
                                systemImage: "exclamationmark.triangle"
                            )
                            .font(.caption)
                            .foregroundStyle(.orange)
                        }
                    }

                    if let srcDid = hat.srcDid, !srcDid.isEmpty {
                        field("First version") {
                            CopyableText(
                                display: srcDid.elidingMiddle(head: 10, tail: 8),
                                copy: srcDid,
                                font: .system(.caption, design: .monospaced))
                        }
                    }
                    if let preDid = hat.preDid, !preDid.isEmpty {
                        field("Previous version") {
                            CopyableText(
                                display: preDid.elidingMiddle(head: 10, tail: 8),
                                copy: preDid,
                                font: .system(.caption, design: .monospaced))
                        }
                    }

                    if let error {
                        Text(error).font(.caption).foregroundStyle(.red)
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }

            HStack {
                Spacer()
                Button("Done", action: onDone).keyboardShortcut(.defaultAction)
            }
        }
        .padding(20)
        .frame(width: 560, height: 520)
        .onAppear {
            record = try? session.hats.record(id: hat.id ?? "")
        }
    }

    @ViewBuilder
    private var locationsSection: some View {
        field("Where it is") {
            VStack(alignment: .leading, spacing: 6) {
                let locas = hat.locas ?? []
                if locas.isEmpty {
                    Text("No locations recorded.").font(.caption).foregroundStyle(.secondary)
                }
                ForEach(locas, id: \.self) { loca in
                    HStack(spacing: 6) {
                        Image(systemName: loca.hasPrefix(Hat.localLocationPrefix)
                              ? "internaldrive" : "externaldrive.connected.to.line.below")
                            .foregroundStyle(.secondary)
                        CopyableText(loca, font: .system(.caption, design: .monospaced))
                            .lineLimit(1)
                            .truncationMode(.middle)
                        if loca.hasPrefix(Hat.localLocationPrefix) {
                            let path = String(loca.dropFirst(Hat.localLocationPrefix.count))
                            if !FileManager.default.fileExists(atPath: path) {
                                chip("Missing", color: .orange)
                            } else if record?.local.stamps[path] == nil {
                                chip("Unverified", color: .gray)
                            }
                        }
                    }
                }
            }
        }
    }

    @ViewBuilder
    private func field(_ label: String, @ViewBuilder _ content: () -> some View) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(label).font(.caption).foregroundStyle(.secondary)
            content()
        }
    }

    private func chip(_ text: String, color: Color) -> some View {
        Text(text)
            .font(.caption2.bold())
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .background(Capsule().fill(color.opacity(0.15)))
            .foregroundStyle(color)
    }
}

// MARK: - export

/// Hands out the HAT's JSON — the record another device needs in order
/// to fetch this file. Android's `ExportHatActivity`.
struct HatExportSheet: View {
    let hat: Hat
    let onDone: () -> Void

    @State private var includeKey = false
    @State private var saved: String?

    private var json: String {
        var copy = hat
        if !includeKey { copy.key = nil }
        return copy.wireJson()
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Share “\(hat.displayName)”").font(.title3.bold())

            Text("This record tells another device where the file is stored and how to verify it. The file itself must already be on a DISK service for them to fetch it.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            if hat.key != nil {
                Toggle(isOn: $includeKey) {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Include the decryption key")
                        Text("Required for them to open it — but anyone who gets this text can then read the file.")
                            .font(.caption)
                            .foregroundStyle(includeKey ? .orange : .secondary)
                    }
                }
            }

            ScrollView {
                Text(json)
                    .font(.system(.caption, design: .monospaced))
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(8)
            }
            .frame(height: 200)
            .background(Color(NSColor.textBackgroundColor))
            .clipShape(RoundedRectangle(cornerRadius: 8))

            if let saved {
                Label(saved, systemImage: "checkmark.seal")
                    .font(.caption)
                    .foregroundStyle(.green)
            }

            HStack {
                Button {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(json, forType: .string)
                    saved = "Copied to the clipboard."
                } label: {
                    Label("Copy", systemImage: "doc.on.doc")
                }

                Button(action: saveToFile) {
                    Label("Save…", systemImage: "square.and.arrow.down")
                }

                Spacer()
                Button("Done", action: onDone).keyboardShortcut(.defaultAction)
            }
        }
        .padding(20)
        .frame(width: 560)
    }

    private func saveToFile() {
        let panel = NSSavePanel()
        panel.nameFieldStringValue = "\(hat.displayName).hat.json"
        panel.allowedContentTypes = [.json]
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            try Data(json.utf8).write(to: url)
            saved = "Saved to \(url.lastPathComponent)."
        } catch {
            saved = "Couldn't save: \(String(describing: error))"
        }
    }
}

// MARK: - import

/// Takes HAT JSON produced by another device (or by Android) and stores
/// the records. Android's `ImportHatActivity`.
struct HatImportSheet: View {
    let session: ActiveSession
    /// Passes the number imported, or nil when cancelled.
    let onDone: (Int?) -> Void

    @State private var text = ""
    @State private var error: String?
    @State private var preview: [Hat] = []

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Import file records").font(.title3.bold())

            Text("Paste the record someone shared, or open a .hat.json file. One record, or a list of them.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            TextEditor(text: $text)
                .font(.system(.caption, design: .monospaced))
                .frame(height: 180)
                .overlay(RoundedRectangle(cornerRadius: 8).stroke(Color.secondary.opacity(0.3)))
                .onChange(of: text) { _, _ in parse() }

            if !preview.isEmpty {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Found \(preview.count) record\(preview.count == 1 ? "" : "s"):")
                        .font(.caption).foregroundStyle(.secondary)
                    ForEach(Array(preview.enumerated()), id: \.offset) { _, hat in
                        HStack(spacing: 6) {
                            Image(systemName: FilesView.icon(for: hat))
                            Text(hat.displayName).font(.caption).lineLimit(1)
                            if hat.key != nil { Text("· includes key").font(.caption2).foregroundStyle(.orange) }
                        }
                    }
                }
            }

            if let error {
                Label(error, systemImage: "exclamationmark.triangle")
                    .font(.caption)
                    .foregroundStyle(.orange)
                    .fixedSize(horizontal: false, vertical: true)
            }

            HStack {
                Button(action: openFile) {
                    Label("Open file…", systemImage: "folder")
                }
                Spacer()
                Button("Cancel") { onDone(nil) }
                Button("Import") { importRecords() }
                    .buttonStyle(.borderedProminent)
                    .disabled(preview.isEmpty)
                    .keyboardShortcut(.defaultAction)
            }
        }
        .padding(20)
        .frame(width: 560)
    }

    private func parse() {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { preview = []; error = nil; return }
        let data = Data(trimmed.utf8)
        // Accept a single object or an array, the two shapes an export
        // can produce.
        if let one = try? JSONDecoder().decode(Hat.self, from: data) {
            preview = [one]
            error = nil
        } else if let many = try? JSONDecoder().decode([Hat].self, from: data) {
            preview = many
            error = nil
        } else {
            preview = []
            error = "That doesn't look like a file record."
        }
    }

    private func openFile() {
        let panel = NSOpenPanel()
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = false
        guard panel.runModal() == .OK, let url = panel.url,
              let contents = try? String(contentsOf: url, encoding: .utf8) else { return }
        text = contents
    }

    private func importRecords() {
        var imported = 0
        var failures: [String] = []
        for hat in preview {
            do {
                // An id-less record gets the DID Android would derive,
                // so the same import lands on the same id on both.
                try session.hats.upsert(hat, touch: false)
                imported += 1
            } catch {
                failures.append(String(describing: error))
            }
        }
        if failures.isEmpty {
            onDone(imported)
        } else {
            error = "Imported \(imported); \(failures.count) failed — \(failures.joined(separator: "; "))"
        }
    }
}
