// Generates Freer.icns from AppIcon.svg beside this script — the mark every
// Freer app uses (the iOS and Android icons are made from the same drawing).
// AppKit draws the SVG itself, once per size, so every slot is crisp rather
// than resampled.
//
//   swift tools/package/make-icon.swift <out.icns>

import AppKit

let source = URL(fileURLWithPath: #filePath)
    .deletingLastPathComponent()
    .appendingPathComponent("AppIcon.svg")
guard let mark = NSImage(contentsOf: source) else {
    fatalError("could not read \(source.path)")
}

/// One icon slot. `px` is the pixel size of the whole canvas; the mark sits
/// inside it at macOS's squircle proportions (824/1024 of the canvas, corner
/// radius 185.4/1024) so the icon lines up with the rest of the Dock.
func draw(px: Int) -> NSBitmapImageRep {
    let rep = NSBitmapImageRep(
        bitmapDataPlanes: nil, pixelsWide: px, pixelsHigh: px,
        bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true, isPlanar: false,
        colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0
    )!
    rep.size = NSSize(width: px, height: px)

    NSGraphicsContext.saveGraphicsState()
    NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)

    let s = CGFloat(px)
    let inset = s * (1024 - 824) / 2 / 1024
    let body = NSRect(x: inset, y: inset, width: s - inset * 2, height: s - inset * 2)
    NSBezierPath(roundedRect: body, xRadius: s * 185.4 / 1024, yRadius: s * 185.4 / 1024).addClip()
    mark.draw(in: body)

    NSGraphicsContext.restoreGraphicsState()
    return rep
}

let out = CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : "Freer.icns"
let iconset = URL(fileURLWithPath: NSTemporaryDirectory())
    .appendingPathComponent("Freer-\(getpid()).iconset")
try! FileManager.default.createDirectory(at: iconset, withIntermediateDirectories: true)

for pt in [16, 32, 128, 256, 512] {
    for scale in [1, 2] {
        let name = scale == 1 ? "icon_\(pt)x\(pt).png" : "icon_\(pt)x\(pt)@2x.png"
        let data = draw(px: pt * scale).representation(using: .png, properties: [:])!
        try! data.write(to: iconset.appendingPathComponent(name))
    }
}

let iconutil = Process()
iconutil.executableURL = URL(fileURLWithPath: "/usr/bin/iconutil")
iconutil.arguments = ["-c", "icns", iconset.path, "-o", out]
try! iconutil.run()
iconutil.waitUntilExit()
try? FileManager.default.removeItem(at: iconset)
exit(iconutil.terminationStatus)
