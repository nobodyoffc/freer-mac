import SwiftUI
import AppKit
import PDFKit
import UniformTypeIdentifiers
import FCCore
import FCDomain
import FCUI

/// The kinds of file a published text can be, and how this app shows
/// each one.
///
/// **A text work is a file now, not something typed into the sheet.**
/// FEIP21 only carves a pointer — `did`, the sha256x2 of the bytes — so
/// the body can be any document a reader can open: plain text,
/// Markdown, RTF, Word, OpenDocument or PDF. The composer uploads the
/// file and carves its DID; the reader fetches the bytes, verifies them
/// against the DID, and picks a view by looking at the bytes
/// themselves, since `format` is the publisher's claim and the bytes
/// are what arrived.
///
/// **HTML is deliberately not on the list.** AppKit's HTML importer
/// runs WebKit and can fetch remote resources named in the file, so
/// opening a stranger's HTML would tell their server who is reading.
enum PublishDocument {

    enum Kind: Equatable {
        case plain
        case markdown
        case pdf
        /// RTF, Word (.doc / .docx) and OpenDocument text — formats
        /// AppKit's attributed-string importer reads without a network.
        case richText(NSAttributedString.DocumentType)
        /// Bytes this app cannot draw. Still verified, still openable in
        /// another app or savable.
        case other

        static func == (lhs: Kind, rhs: Kind) -> Bool {
            switch (lhs, rhs) {
            case (.plain, .plain), (.markdown, .markdown), (.pdf, .pdf), (.other, .other): return true
            case let (.richText(a), .richText(b)): return a == b
            default: return false
            }
        }
    }

    /// What the file picker accepts.
    static var contentTypes: [UTType] {
        let byExtension = ["txt", "md", "markdown", "rtf", "doc", "docx", "odt", "pdf"]
            .compactMap { UTType(filenameExtension: $0) }
        let named = ["net.daringfireball.markdown", "com.microsoft.word.doc",
                     "org.openxmlformats.wordprocessingml.document",
                     "org.oasis-open.opendocument.text"]
            .compactMap { UTType($0) }
        var seen = Set<String>()
        return ([.plainText, .rtf, .pdf] + byExtension + named).filter { seen.insert($0.identifier).inserted }
    }

    /// MIME types by extension, written out because UTType has no MIME
    /// type for Markdown on every macOS and calls RTF `text/rtf`.
    private static let mimeByExtension: [String: String] = [
        "txt": "text/plain",
        "md": "text/markdown",
        "markdown": "text/markdown",
        "rtf": "application/rtf",
        "doc": "application/msword",
        "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "odt": "application/vnd.oasis.opendocument.text",
        "pdf": "application/pdf"
    ]

    /// The `format` to carve for a picked file.
    static func mimeType(for url: URL) -> String? {
        let ext = url.pathExtension.lowercased()
        if let mime = mimeByExtension[ext] { return mime }
        return UTType(filenameExtension: ext)?.preferredMIMEType
    }

    /// A filename extension for bytes of this kind and claimed format —
    /// what a copy handed to another app or saved by the user needs, since
    /// the vault names a fetched body by its DID alone.
    static func fileExtension(kind: Kind, format: String?) -> String {
        switch kind {
        case .pdf: return "pdf"
        case .markdown: return "md"
        case .plain: return "txt"
        case .richText(let type):
            switch type {
            case .rtf: return "rtf"
            case .docFormat: return "doc"
            case .officeOpenXML: return "docx"
            case .openDocument: return "odt"
            default: return "rtf"
            }
        case .other:
            if let format, let ext = mimeByExtension.first(where: { $0.value == format })?.key { return ext }
            if let format, let ext = UTType(mimeType: format)?.preferredFilenameExtension { return ext }
            return "bin"
        }
    }

    /// Decide what the bytes are. Magic numbers first, then the claimed
    /// `format` to tell Markdown from plain text and `.docx` from any
    /// other ZIP, then UTF-8 as the last resort.
    static func kind(of data: Data, format: String?) -> Kind {
        let head = [UInt8](data.prefix(8))
        let claim = (format ?? "").lowercased()
        if head.starts(with: Array("%PDF".utf8)) { return .pdf }
        if head.starts(with: Array("{\\rtf".utf8)) { return .richText(.rtf) }
        if head.starts(with: [0xD0, 0xCF, 0x11, 0xE0]) { return .richText(.docFormat) }
        if head.starts(with: [0x50, 0x4B, 0x03, 0x04]) {
            if claim.contains("opendocument") { return .richText(.openDocument) }
            if claim.contains("wordprocessingml") || claim.contains("officedocument") || claim.isEmpty {
                return .richText(.officeOpenXML)
            }
            return .other
        }
        guard String(data: data, encoding: .utf8) != nil else { return .other }
        if claim.contains("markdown") || claim == "md" { return .markdown }
        return .plain
    }
}

// MARK: - reader

/// A fetched, verified text body, drawn according to what it is.
struct PublishDocumentView: View {
    let url: URL
    let format: String?
    let title: String

    @State private var kind: PublishDocument.Kind?
    @State private var text: String?
    @State private var attributed: AttributedString?
    @State private var note: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            content
            actions
        }
        .task(id: url) { await load() }
    }

    @ViewBuilder
    private var content: some View {
        switch kind {
        case .none:
            ProgressView().controlSize(.small)
        case .pdf:
            PDFDocumentView(url: url)
                .frame(minHeight: 420)
                .clipShape(RoundedRectangle(cornerRadius: 6))
        case .markdown, .plain, .richText:
            if let attributed {
                Text(attributed)
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
            } else if let text {
                Text(text)
                    .font(.body)
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
        case .other:
            Label("This app can't display this kind of file. It was fetched and matches its Document id, so you can open it in another app or save a copy.", systemImage: "doc")
                .font(.callout)
                .foregroundStyle(.secondary)
        }
        if let note {
            CopyableText(note, font: .caption).foregroundStyle(.secondary)
        }
    }

    private var actions: some View {
        HStack(spacing: 10) {
            Button("Open in default app") { openExternally() }
                .controlSize(.small)
            Button("Save a copy…") { saveCopy() }
                .controlSize(.small)
        }
    }

    private func load() async {
        let url = self.url
        let format = self.format
        let loaded: (PublishDocument.Kind, String?, AttributedString?, String?) = await Task.detached(priority: .userInitiated) {
            guard let data = try? Data(contentsOf: url) else {
                return (.other, nil, nil, "The fetched file could not be read back from this Mac.")
            }
            let kind = PublishDocument.kind(of: data, format: format)
            switch kind {
            case .plain:
                return (kind, String(data: data, encoding: .utf8), nil, nil)
            case .markdown:
                let source = String(data: data, encoding: .utf8) ?? ""
                // Inline Markdown only — headings and lists keep their
                // marks, but nothing is lost and no link is followed.
                let rendered = try? AttributedString(
                    markdown: source,
                    options: .init(interpretedSyntax: .inlineOnlyPreservingWhitespace)
                )
                return (kind, source, rendered, nil)
            case .richText(let type):
                do {
                    let ns = try NSAttributedString(
                        data: data,
                        options: [.documentType: type],
                        documentAttributes: nil
                    )
                    return (kind, ns.string, AttributedString(ns), nil)
                } catch {
                    return (.other, nil, nil, "The document could not be read: \(error.localizedDescription)")
                }
            case .pdf, .other:
                return (kind, nil, nil, nil)
            }
        }.value
        kind = loaded.0
        text = loaded.1
        attributed = loaded.2
        note = loaded.3
    }

    /// A copy under a real filename, so the receiving app knows what it
    /// is: the vault names the body by its DID with no extension.
    private func namedCopy() throws -> URL {
        let ext = PublishDocument.fileExtension(kind: kind ?? .other, format: format)
        let base = title.isEmpty ? "document" : title.replacingOccurrences(of: "/", with: "-")
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("FreerPublished-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let dest = dir.appendingPathComponent(base).appendingPathExtension(ext)
        try FileManager.default.copyItem(at: url, to: dest)
        return dest
    }

    private func openExternally() {
        do {
            NSWorkspace.shared.open(try namedCopy())
        } catch {
            note = "Couldn't hand the file to another app: \(error.localizedDescription)"
        }
    }

    private func saveCopy() {
        let panel = NSSavePanel()
        let ext = PublishDocument.fileExtension(kind: kind ?? .other, format: format)
        panel.nameFieldStringValue = (title.isEmpty ? "document" : title) + "." + ext
        guard panel.runModal() == .OK, let dest = panel.url else { return }
        do {
            if FileManager.default.fileExists(atPath: dest.path) {
                try FileManager.default.removeItem(at: dest)
            }
            try FileManager.default.copyItem(at: url, to: dest)
        } catch {
            note = "Couldn't save the copy: \(error.localizedDescription)"
        }
    }
}

/// PDFKit's view, for a PDF body.
struct PDFDocumentView: NSViewRepresentable {
    let url: URL

    func makeNSView(context: Context) -> PDFView {
        let view = PDFView()
        view.autoScales = true
        view.displayMode = .singlePageContinuous
        view.document = PDFDocument(url: url)
        return view
    }

    func updateNSView(_ view: PDFView, context: Context) {
        if view.document?.documentURL != url {
            view.document = PDFDocument(url: url)
        }
    }
}
