#if os(iOS)
import SwiftUI
import UIKit
import UniformTypeIdentifiers

// The iOS face of the handful of AppKit names the views are written
// against.
//
// Freer's SwiftUI was written for the Mac first, and what it takes from
// AppKit is narrow: one image type, two background colours, the general
// pasteboard. Giving those same names a UIKit meaning here lets one view
// source serve both platforms, instead of every call site growing an
// `#if os(...)` of its own. Nothing in this file is compiled on macOS,
// where the real AppKit types are used.

public typealias NSImage = UIImage
public typealias NSColor = UIColor
public typealias NSSize = CGSize

public extension UIImage {
    /// AppKit's `NSImage(cgImage:size:)`: `size` is in points, so the
    /// scale is whatever makes the pixels fill it.
    convenience init(cgImage: CGImage, size: CGSize) {
        let scale = size.width > 0 ? CGFloat(cgImage.width) / size.width : 1
        self.init(cgImage: cgImage, scale: max(scale, 1), orientation: .up)
    }

    /// AppKit's `NSImage(contentsOf:)`, for a file URL.
    convenience init?(contentsOf url: URL) {
        self.init(contentsOfFile: url.path)
    }

    /// AppKit's way of asking an image for its bitmap.
    func cgImage(forProposedRect _: UnsafeMutablePointer<CGRect>?, context _: Any?, hints _: [AnyHashable: Any]?) -> CGImage? {
        cgImage
    }
}

public extension Image {
    init(nsImage: UIImage) {
        self.init(uiImage: nsImage)
    }
}

public extension Color {
    init(nsColor: UIColor) {
        self.init(uiColor: nsColor)
    }
}

public extension UIColor {
    /// A card or field well sitting on the window background.
    static var controlBackgroundColor: UIColor { .secondarySystemBackground }
    /// The paper a text editor writes on.
    static var textBackgroundColor: UIColor { .systemBackground }
    static var windowBackgroundColor: UIColor { .systemBackground }
    static var separatorColor: UIColor { .separator }
    static var labelColor: UIColor { .label }
    static var secondaryLabelColor: UIColor { .secondaryLabel }
}

/// The general pasteboard, under the name and the calls AppKit gives it.
public final class NSPasteboard {
    public static let general = NSPasteboard()

    public struct PasteboardType: Hashable {
        let uti: UTType
        public static let string = PasteboardType(uti: .utf8PlainText)
        public static let png = PasteboardType(uti: .png)
        public static let tiff = PasteboardType(uti: .tiff)
    }

    private init() {}

    @discardableResult
    public func clearContents() -> Int {
        UIPasteboard.general.items = []
        return UIPasteboard.general.changeCount
    }

    @discardableResult
    public func setString(_ string: String, forType _: PasteboardType) -> Bool {
        UIPasteboard.general.string = string
        return true
    }

    public func string(forType _: PasteboardType) -> String? {
        UIPasteboard.general.string
    }

    @discardableResult
    public func setData(_ data: Data?, forType type: PasteboardType) -> Bool {
        guard let data else { return false }
        UIPasteboard.general.setData(data, forPasteboardType: type.uti.identifier)
        return true
    }

    /// Images only — the one kind of object the views write.
    @discardableResult
    public func writeObjects(_ objects: [Any]) -> Bool {
        let images = objects.compactMap { $0 as? UIImage }
        guard !images.isEmpty else { return false }
        // Beside whatever `setData` put there, not instead of it.
        UIPasteboard.general.addItems(images.compactMap { image in
            image.pngData().map { [UTType.png.identifier: $0] }
        })
        return true
    }
}

/// PNG encoding under the AppKit name.
public struct NSBitmapImageRep {
    public enum FileType { case png, jpeg }

    private let cgImage: CGImage

    public init(cgImage: CGImage) {
        self.cgImage = cgImage
    }

    public func representation(using type: FileType, properties _: [AnyHashable: Any]) -> Data? {
        let image = UIImage(cgImage: cgImage)
        switch type {
        case .png: return image.pngData()
        case .jpeg: return image.jpegData(compressionQuality: 0.9)
        }
    }
}
#endif
