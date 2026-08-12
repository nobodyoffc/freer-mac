import Foundation
import AppKit
import CoreImage
import CoreImage.CIFilterBuiltins
import ImageIO
import Vision

/// QR encode / decode core. Mirrors the Android `QRCodeGenerator` +
/// `QrCodeActivity` pair (`Freer/qr`): content longer than
/// ``defaultCapacity`` UTF-8 bytes is split into multiple codes, and
/// scanning appends each decoded code so multi-part payloads
/// reassemble by concatenation. The capacity constant must stay in
/// lock-step with Android (`QRCodeGenerator.DEFAULT_CAPACITY`) so
/// codes made on one platform reassemble on the other.
public enum QrCoder {

    public enum Failure: Error, CustomStringConvertible {
        case emptyContent
        case generatorFailed
        case unreadableImage(String)

        public var description: String {
            switch self {
            case .emptyContent:            return "QrCoder: nothing to encode"
            case .generatorFailed:         return "QrCoder: CIFilter.qrCodeGenerator failed"
            case .unreadableImage(let n):  return "QrCoder: cannot read image '\(n)'"
            }
        }
    }

    /// Max UTF-8 bytes encoded into one QR code.
    public static let defaultCapacity = 300

    /// Target pixel side of generated images (Android renders 461).
    public static let imageSide: CGFloat = 461

    private static let ciContext = CIContext()

    // MARK: - split

    /// Split `content` into chunks of at most `capacity` UTF-8 bytes,
    /// never breaking inside a `Character`. Concatenating the chunks
    /// reproduces `content` exactly. A single character wider than
    /// `capacity` still gets its own chunk (force-include, like the
    /// Android splitter) rather than looping forever.
    public static func splitContent(
        _ content: String,
        capacity: Int = defaultCapacity
    ) -> [String] {
        guard content.utf8.count > capacity else { return [content] }

        var chunks: [String] = []
        var current = ""
        var currentBytes = 0
        for ch in content {
            let width = ch.utf8.count
            if currentBytes + width > capacity, !current.isEmpty {
                chunks.append(current)
                current = ""
                currentBytes = 0
            }
            current.append(ch)
            currentBytes += width
        }
        if !current.isEmpty { chunks.append(current) }
        return chunks
    }

    // MARK: - generate

    /// Encode `content` as one or more QR images (one per
    /// ``splitContent(_:capacity:)`` chunk).
    public static func makeImages(
        for content: String,
        capacity: Int = defaultCapacity
    ) throws -> [NSImage] {
        guard !content.isEmpty else { throw Failure.emptyContent }
        return try splitContent(content, capacity: capacity).map { try makeImage(for: $0) }
    }

    /// One chunk → one QR image, error-correction level M. Upscaled
    /// by an integer factor toward ``imageSide`` so modules stay
    /// pixel-crisp.
    public static func makeImage(for chunk: String) throws -> NSImage {
        let filter = CIFilter.qrCodeGenerator()
        filter.message = Data(chunk.utf8)
        filter.correctionLevel = "M"
        guard let raw = filter.outputImage else { throw Failure.generatorFailed }

        let scale = max(1, (imageSide / raw.extent.width).rounded(.down))
        let scaled = raw.transformed(by: CGAffineTransform(scaleX: scale, y: scale))
        guard let cg = ciContext.createCGImage(scaled, from: scaled.extent) else {
            throw Failure.generatorFailed
        }
        return NSImage(
            cgImage: cg,
            size: NSSize(width: scaled.extent.width, height: scaled.extent.height)
        )
    }

    // MARK: - decode

    /// All QR payloads found in `cgImage`, in reading order (top to
    /// bottom, then left to right — Vision's origin is bottom-left).
    /// Duplicate payloads within one image are dropped: Vision can
    /// report the same physical code twice.
    public static func decode(cgImage: CGImage) throws -> [String] {
        let request = VNDetectBarcodesRequest()
        request.symbologies = [.qr]
        try VNImageRequestHandler(cgImage: cgImage, options: [:]).perform([request])

        let ordered = (request.results ?? []).sorted { a, b in
            if abs(a.boundingBox.maxY - b.boundingBox.maxY) > 0.05 {
                return a.boundingBox.maxY > b.boundingBox.maxY
            }
            return a.boundingBox.minX < b.boundingBox.minX
        }
        var seen = Set<String>()
        return ordered.compactMap { obs in
            guard let payload = obs.payloadStringValue,
                  seen.insert(payload).inserted else { return nil }
            return payload
        }
    }

    /// Decode every QR payload in the image file at `url`.
    public static func decodeImage(at url: URL) throws -> [String] {
        guard let source = CGImageSourceCreateWithURL(url as CFURL, nil),
              let cg = CGImageSourceCreateImageAtIndex(source, 0, nil)
        else { throw Failure.unreadableImage(url.lastPathComponent) }
        return try decode(cgImage: cg)
    }

    // MARK: - export

    /// PNG bytes for a generated QR image (for NSSavePanel writes).
    public static func pngData(_ image: NSImage) -> Data? {
        guard let cg = image.cgImage(forProposedRect: nil, context: nil, hints: nil) else {
            return nil
        }
        return NSBitmapImageRep(cgImage: cg).representation(using: .png, properties: [:])
    }
}
