import AppKit

/// Handing a stored file to the app that understands it.
///
/// Bytes this app keeps are stored under their DID: a 64-character
/// hash with no file extension. Handing that path to the Finder shows
/// the user a file they cannot recognise and macOS cannot type, which
/// is why every "reveal" ended in a shrug. So we stage a copy under
/// the name the file actually has — the HAT's name, the record's
/// title, `<id>.pdf` — and open *that*. Launch Services then picks
/// the right app from the extension, and the window title says
/// something a person can read.
///
/// The staged copy lives in the temporary directory, keyed by the
/// DID, and is reused while it still matches the source, so opening
/// the same file twice copies the bytes once.
public enum FileOpening {

    /// Open `url` in the app macOS associates with `name`.
    ///
    /// - parameters:
    ///   - url: where the bytes are now.
    ///   - name: what the file should be called — with its extension,
    ///     since that is what decides which app opens. Nil or
    ///     extensionless names fall back to opening the bytes as they
    ///     lie.
    /// - returns: whether an app was launched. A false means nothing
    ///   on this Mac claims the type; the caller has already been
    ///   shown the file in the Finder instead.
    @discardableResult
    public static func open(_ url: URL, named name: String?) -> Bool {
        let target = stagedURL(for: url, named: name) ?? url
        if NSWorkspace.shared.open(target) { return true }
        // Nothing claims the type. Revealing is the honest fallback:
        // it at least puts the named copy in the user's hands.
        NSWorkspace.shared.activateFileViewerSelecting([target])
        return false
    }

    /// Show `url` in the Finder under a name that means something,
    /// staging a named copy first when the stored one is a bare DID.
    public static func reveal(_ url: URL, named name: String?) {
        NSWorkspace.shared.activateFileViewerSelecting([stagedURL(for: url, named: name) ?? url])
    }

    // MARK: - staging

    /// A path to the same bytes under a usable name, or nil when the
    /// stored path already is one (a file registered by reference
    /// keeps its original name) or when no better name was given.
    static func stagedURL(for url: URL, named name: String?) -> URL? {
        // A file registered by reference still sits at its original
        // path, extension and all — nothing to improve on.
        guard url.pathExtension.isEmpty else { return nil }
        guard let filename = sanitized(name),
              !(filename as NSString).pathExtension.isEmpty
        else { return nil }
        guard let source = try? attributes(of: url) else { return nil }

        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("FreerOpen", isDirectory: true)
            .appendingPathComponent(url.lastPathComponent, isDirectory: true)
        let target = directory.appendingPathComponent(filename)

        // Reuse a staged copy that still matches the source. Size and
        // modification date are enough: the source is content-addressed
        // and does not change under a stable name.
        if let staged = try? attributes(of: target), staged.matches(source) { return target }

        do {
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
            if FileManager.default.fileExists(atPath: target.path) {
                try FileManager.default.removeItem(at: target)
            }
            try FileManager.default.copyItem(at: url, to: target)
            // Carry the source's date over so the reuse check above
            // matches on the next open rather than copying again.
            try FileManager.default.setAttributes(
                [.modificationDate: source.modified], ofItemAtPath: target.path)
        } catch {
            return nil
        }
        return target
    }

    /// A filename macOS will accept: no path separators, no leading
    /// dot that would hide it, and short enough to write.
    static func sanitized(_ name: String?) -> String? {
        guard let name else { return nil }
        var cleaned = name
            .components(separatedBy: CharacterSet(charactersIn: "/:\\"))
            .joined(separator: "-")
            .trimmingCharacters(in: .whitespacesAndNewlines)
        while cleaned.hasPrefix(".") { cleaned.removeFirst() }
        guard !cleaned.isEmpty else { return nil }
        if cleaned.count > 120 {
            let ext = (cleaned as NSString).pathExtension
            let stem = (cleaned as NSString).deletingPathExtension.prefix(100)
            cleaned = ext.isEmpty ? String(stem) : "\(stem).\(ext)"
        }
        return cleaned
    }

    private struct Stamp {
        let size: Int64
        let modified: Date

        /// Second-level tolerance, because the date we copy across is
        /// not guaranteed to survive a round trip through the
        /// filesystem to the nanosecond. The source is
        /// content-addressed, so a same-size change inside the same
        /// second is not a case that arises.
        func matches(_ other: Stamp) -> Bool {
            size == other.size && abs(modified.timeIntervalSince(other.modified)) < 1
        }
    }

    /// Read through `FileManager` rather than `URL.resourceValues`:
    /// the latter caches on the URL value, and a URL we then hand back
    /// would carry the stale numbers we read before overwriting it.
    private static func attributes(of url: URL) throws -> Stamp {
        let values = try FileManager.default.attributesOfItem(atPath: url.path)
        guard let size = values[.size] as? NSNumber,
              let modified = values[.modificationDate] as? Date
        else { throw CocoaError(.fileReadUnknown) }
        return Stamp(size: size.int64Value, modified: modified)
    }
}
