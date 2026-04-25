import Foundation
import AppKit
import CoreGraphics
import ImageIO
import UniformTypeIdentifiers

/// Deterministic procedural avatar generator. Mirrors the Android
/// `AvatarMaker` (`FC-AJDK/feature/avatar`): for any FCH FID, builds
/// the same 150×150 PNG by stacking 10 transparent layers.
///
/// Layer keys come from positions 20–29 of the FID (i.e.
/// `fid[33-4-i]` for `i` in `0..<10`). Each character is mapped through
/// the Base58 alphabet (`1-9 / A-H,J-N,P-Z / a-k,m-z`) to an integer
/// 0–57. Layer `i`'s element is `avatar-elements/<i>/<value>.png`.
///
/// Rendering is cached per-(FID, size) so re-renders cost a dictionary
/// lookup. The cache holds NSImages and is bounded by ``cacheLimit``.
public enum AvatarMaker {

    public enum Failure: Error, CustomStringConvertible {
        case fidTooShort(Int)
        case unknownCharacter(Character)
        case missingResource(String)
        case rendererFailed

        public var description: String {
            switch self {
            case .fidTooShort(let n):       return "AvatarMaker: FID has \(n) chars, need ≥ 30"
            case .unknownCharacter(let c):  return "AvatarMaker: '\(c)' is not a Base58 character"
            case .missingResource(let p):   return "AvatarMaker: bundled resource '\(p)' is missing"
            case .rendererFailed:           return "AvatarMaker: CGContext creation failed"
            }
        }
    }

    public static let layerCount = 10
    public static let nativeSize: CGFloat = 150
    public static let cacheLimit = 64

    /// FCH/Bitcoin Base58 alphabet → element index. Matches the
    /// `data` map in the Java reference exactly. The missing letters
    /// `I`, `O`, `l` follow the standard Base58 omission set.
    static let alphabet: [Character: Int] = {
        let chars = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
        precondition(chars.count == 58, "Base58 alphabet must be 58 characters")
        var map: [Character: Int] = [:]
        for (i, c) in chars.enumerated() { map[c] = i }
        return map
    }()

    private static let cache: NSCache<NSString, NSImage> = {
        let c = NSCache<NSString, NSImage>()
        c.countLimit = cacheLimit
        return c
    }()

    /// Produce the avatar `NSImage` for `fid`, cached by FID.
    /// Returned at native 150×150; SwiftUI scales as needed.
    public static func avatar(for fid: String) throws -> NSImage {
        if let cached = cache.object(forKey: fid as NSString) {
            return cached
        }
        let keys = try layerKeys(for: fid)
        let image = try render(layerKeys: keys)
        cache.setObject(image, forKey: fid as NSString)
        return image
    }

    /// Compute the 10 element indices that drive the layer composite,
    /// without rendering. Useful for tests and for diffing avatars
    /// without bringing up CoreGraphics.
    public static func layerKeys(for fid: String) throws -> [Int] {
        let chars = Array(fid)
        guard chars.count >= 30 else { throw Failure.fidTooShort(chars.count) }
        var keys: [Int] = []
        keys.reserveCapacity(layerCount)
        for i in 0..<layerCount {
            let idx = 33 - 4 - i      // 29, 28, …, 20
            let c = chars[idx]
            guard let v = alphabet[c] else { throw Failure.unknownCharacter(c) }
            keys.append(v)
        }
        return keys
    }

    /// Resolve a `(layer, element)` index pair to its bundled PNG URL.
    /// Returns nil if the asset is missing (which would only happen
    /// if someone broke the resource bundle).
    public static func elementURL(layer: Int, element: Int) -> URL? {
        // SwiftPM bundles resources under
        //   Bundle.module / Resources / avatar-elements / <layer> / <element>.png
        // We use Bundle.module's url(forResource:withExtension:subdirectory:).
        let subdir = "avatar-elements/\(layer)"
        return Bundle.module.url(
            forResource: "\(element)", withExtension: "png", subdirectory: subdir
        )
    }

    /// Composite the 10 layers (base + 9 features) into a 150×150
    /// premultiplied-RGBA `NSImage`. Returns the result wrapped as
    /// an NSImage with one CGImage representation.
    private static func render(layerKeys: [Int]) throws -> NSImage {
        let size = nativeSize
        let width = Int(size)
        let height = Int(size)

        guard let ctx = CGContext(
            data: nil,
            width: width, height: height,
            bitsPerComponent: 8,
            bytesPerRow: 0,                 // let CG pick the row size
            space: CGColorSpaceCreateDeviceRGB(),
            bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue
        ) else {
            throw Failure.rendererFailed
        }
        ctx.interpolationQuality = .high

        for (layer, key) in layerKeys.enumerated() {
            guard let url = elementURL(layer: layer, element: key) else {
                throw Failure.missingResource("avatar-elements/\(layer)/\(key).png")
            }
            guard
                let src = CGImageSourceCreateWithURL(url as CFURL, nil),
                let img = CGImageSourceCreateImageAtIndex(src, 0, nil)
            else {
                throw Failure.missingResource(url.path)
            }
            ctx.draw(img, in: CGRect(x: 0, y: 0, width: size, height: size))
        }

        guard let composite = ctx.makeImage() else {
            throw Failure.rendererFailed
        }
        return NSImage(cgImage: composite, size: NSSize(width: size, height: size))
    }
}
