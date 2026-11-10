#if os(iOS)
import SwiftUI
import UIKit
import QuickLook
import UniformTypeIdentifiers

/// Choosing files and saving them on iOS — what `NSOpenPanel` and
/// `NSSavePanel` do on the Mac.
///
/// The Mac panels are modal: `runModal()` returns with the answer. iOS has
/// no such thing, so these are `async` and the caller awaits the picker.
///
/// **Saving is the other way round from the Mac.** There the panel hands
/// back a URL and the caller writes to it. iOS will only export a file
/// that already exists, so the caller hands over the bytes (or a file) and
/// the picker copies them to wherever the user points.
@MainActor
public enum FilePanel {

    /// Let the user pick files. Empty when they cancel.
    ///
    /// The URLs are copies inside the app's own container, so they can be
    /// read at leisure with no security scope to hold open.
    public static func open(
        types: [UTType] = [.item],
        allowsMultiple: Bool = false
    ) async -> [URL] {
        let picker = UIDocumentPickerViewController(forOpeningContentTypes: types, asCopy: true)
        picker.allowsMultipleSelection = allowsMultiple
        return await present(picker)
    }

    /// Let the user pick a folder to write into. Nil when they cancel.
    ///
    /// The folder lies outside the container: call
    /// `startAccessingSecurityScopedResource()` on it before writing and
    /// stop when done.
    public static func chooseFolder() async -> URL? {
        let picker = UIDocumentPickerViewController(forOpeningContentTypes: [.folder])
        return await present(picker).first
    }

    /// Save `data` under `name`, wherever the user chooses.
    /// - returns: whether a copy was saved (false on cancel or failure).
    @discardableResult
    public static func save(_ data: Data, named name: String) async -> Bool {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("export-\(UUID().uuidString)", isDirectory: true)
        let url = dir.appendingPathComponent(sanitized(name))
        do {
            try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
            try data.write(to: url)
        } catch {
            return false
        }
        defer { try? FileManager.default.removeItem(at: dir) }
        return await save(fileAt: url)
    }

    /// Have `write` produce a file called `name`, then save a copy of it
    /// wherever the user chooses.
    ///
    /// The shape of a Mac save panel turned inside out: the caller's
    /// writing code is the same, it just runs before the question rather
    /// than after it.
    /// - returns: the name it was saved under, or nil when the user
    ///   cancelled. Throws only what `write` throws.
    public static func export(named name: String, write: (URL) throws -> Void) async throws -> String? {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("export-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let url = dir.appendingPathComponent(sanitized(name))
        try write(url)
        return await save(fileAt: url) ? url.lastPathComponent : nil
    }

    /// Save copies of files that already exist, wherever the user chooses.
    @discardableResult
    public static func save(filesAt urls: [URL]) async -> Bool {
        guard !urls.isEmpty else { return false }
        let picker = UIDocumentPickerViewController(forExporting: urls, asCopy: true)
        return !(await present(picker)).isEmpty
    }

    @discardableResult
    public static func save(fileAt url: URL) async -> Bool {
        await save(filesAt: [url])
    }

    /// The system share sheet for `items` — the nearest iOS has to
    /// "reveal in Finder": it offers Save to Files, Quick Look, and every
    /// app that takes the type.
    public static func share(_ items: [Any]) {
        guard let host = topViewController() else { return }
        let sheet = UIActivityViewController(activityItems: items, applicationActivities: nil)
        // An iPad shows it as a popover and insists on an anchor.
        sheet.popoverPresentationController?.sourceView = host.view
        sheet.popoverPresentationController?.sourceRect = CGRect(
            x: host.view.bounds.midX, y: host.view.bounds.midY, width: 0, height: 0
        )
        sheet.popoverPresentationController?.permittedArrowDirections = []
        host.present(sheet, animated: true)
    }

    /// Show a file with Quick Look, which previews what it can and offers
    /// the share button for the rest.
    public static func preview(_ url: URL) {
        guard let host = topViewController() else { return }
        let source = PreviewSource(url: url)
        let controller = QLPreviewController()
        controller.dataSource = source
        objc_setAssociatedObject(controller, &delegateKey, source, .OBJC_ASSOCIATION_RETAIN)
        host.present(controller, animated: true)
    }

    // MARK: - presenting

    private static func present(_ picker: UIDocumentPickerViewController) async -> [URL] {
        guard let host = topViewController() else { return [] }
        return await withCheckedContinuation { continuation in
            let delegate = PickerDelegate { urls in
                continuation.resume(returning: urls)
            }
            picker.delegate = delegate
            picker.presentationController?.delegate = delegate
            // The picker holds its delegate weakly; this keeps it alive
            // until the picker itself goes.
            objc_setAssociatedObject(picker, &delegateKey, delegate, .OBJC_ASSOCIATION_RETAIN)
            host.present(picker, animated: true)
        }
    }

    /// The controller a new modal can be presented from: the frontmost
    /// one of the active scene, above any sheet already showing.
    public static func topViewController() -> UIViewController? {
        let scenes = UIApplication.shared.connectedScenes.compactMap { $0 as? UIWindowScene }
        let scene = scenes.first { $0.activationState == .foregroundActive } ?? scenes.first
        let window = scene?.windows.first { $0.isKeyWindow } ?? scene?.windows.first
        var top = window?.rootViewController
        while let presented = top?.presentedViewController, !presented.isBeingDismissed {
            top = presented
        }
        return top
    }

    private static func sanitized(_ name: String) -> String {
        let cleaned = name
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: ":", with: "_")
            .trimmingCharacters(in: .whitespacesAndNewlines)
        return cleaned.isEmpty ? "file" : cleaned
    }
}

private var delegateKey: UInt8 = 0

/// Answers exactly once, whichever way the picker ends: a choice, the
/// Cancel button, or the sheet swiped away.
private final class PickerDelegate: NSObject, UIDocumentPickerDelegate, UIAdaptivePresentationControllerDelegate {
    private var finish: (([URL]) -> Void)?

    init(finish: @escaping ([URL]) -> Void) {
        self.finish = finish
    }

    private func answer(_ urls: [URL]) {
        let done = finish
        finish = nil
        done?(urls)
    }

    func documentPicker(_: UIDocumentPickerViewController, didPickDocumentsAt urls: [URL]) {
        answer(urls)
    }

    func documentPickerWasCancelled(_: UIDocumentPickerViewController) {
        answer([])
    }

    func presentationControllerDidDismiss(_: UIPresentationController) {
        answer([])
    }
}

private final class PreviewSource: NSObject, QLPreviewControllerDataSource {
    private let url: URL

    init(url: URL) {
        self.url = url
    }

    func numberOfPreviewItems(in _: QLPreviewController) -> Int { 1 }

    func previewController(_: QLPreviewController, previewItemAt _: Int) -> QLPreviewItem {
        url as NSURL
    }
}
#endif
