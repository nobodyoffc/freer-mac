import Foundation

/// Makes a bare `swift run` binary speak the same languages as the packaged app.
///
/// macOS picks a process's language from the localisations its **main bundle**
/// declares, and SwiftUI looks every `Text("…")` literal up there too. In
/// `Freer.app` that is `Contents/Resources/*.lproj`, which `make-dmg.sh`
/// copies in. A SwiftPM executable has no bundle: its "main bundle" is the
/// build directory, and SwiftPM can only put resources in a separate
/// `.bundle` that the lookup never consults. So a development build links the
/// source `.lproj` folders beside the binary instead.
///
/// It has to run before anything asks for `Bundle.main` — the answer is cached
/// on first use — which is why ``Launcher`` calls it ahead of the app's own
/// `main()`. The links point at the source tree, so an edited translation
/// shows on the next launch without a rebuild.
enum DevLocalization {
    static func linkBesideExecutable(sourceFile: String = #filePath) {
        #if DEBUG
        let fm = FileManager.default
        let exeDir = URL(fileURLWithPath: CommandLine.arguments[0])
            .resolvingSymlinksInPath()
            .deletingLastPathComponent()
        // Inside a real .app the packaging script has already done this properly.
        guard !exeDir.path.contains(".app/Contents/") else { return }
        let source = URL(fileURLWithPath: sourceFile)
            .deletingLastPathComponent()
            .appendingPathComponent("Localization")
        guard let names = try? fm.contentsOfDirectory(atPath: source.path) else { return }
        for name in names where name.hasSuffix(".lproj") {
            let link = exeDir.appendingPathComponent(name)
            // `fileExists` follows links, so a link left dangling by a moved
            // checkout reads as absent and is replaced.
            if fm.fileExists(atPath: link.path) { continue }
            try? fm.removeItem(at: link)
            try? fm.createSymbolicLink(at: link, withDestinationURL: source.appendingPathComponent(name))
        }
        #endif
    }
}

@main
enum Launcher {
    static func main() {
        DevLocalization.linkBesideExecutable()
        FreerForMacApp.main()
    }
}
