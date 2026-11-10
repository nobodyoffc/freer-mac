import AppKit

/// Which language Freer shows: the Mac's own choice, or one picked in Settings.
///
/// The pick is stored as `AppleLanguages` in Freer's own defaults domain.
/// Foundation reads that at launch to choose among the app's `.lproj`
/// folders, and it is the same setting System Settings › General ›
/// Language & Region › Applications writes. So this is that setting, not a
/// copy that could disagree with it. It takes effect at the next launch:
/// most strings are translated once, when they are built, so switching live
/// would leave the screen half in the old language.
enum AppLanguage: String, CaseIterable, Identifiable {
    case system
    case english = "en"
    case chinese = "zh-Hans"

    var id: String { rawValue }

    /// A language's own name, so it reads right whichever one is showing.
    var label: String {
        switch self {
        case .system: return String(localized: "Follow system")
        case .english: return "English"
        case .chinese: return "简体中文"
        }
    }

    private static let key = "AppleLanguages"

    /// The domain `UserDefaults.standard` writes for this process.
    private static var domain: String {
        Bundle.main.bundleIdentifier ?? ProcessInfo.processInfo.processName
    }

    /// The saved choice. Read from the app's own domain only: the merged
    /// view would also see the Mac-wide list, which always exists.
    static var chosen: AppLanguage {
        get {
            let list = UserDefaults.standard.persistentDomain(forName: domain)?[key] as? [String]
            guard let first = list?.first else { return .system }
            if first.hasPrefix("zh") { return .chinese }
            if first.hasPrefix("en") { return .english }
            return .system
        }
        set {
            if newValue == .system {
                UserDefaults.standard.removeObject(forKey: key)
            } else {
                UserDefaults.standard.set([newValue.rawValue], forKey: key)
            }
        }
    }

    /// The choice this run started with. ``Launcher`` reads it before
    /// anything else, so a later change shows up as a difference.
    static let atLaunch: AppLanguage = chosen

    /// Start a fresh copy of Freer once this one has quit, then quit.
    ///
    /// The new copy waits for this process to be gone, so the two never hold
    /// the vault at once. A packaged app is reopened through `open`; a bare
    /// development binary is started directly.
    @MainActor
    static func relaunch() {
        let pid = ProcessInfo.processInfo.processIdentifier
        let bundle = Bundle.main.bundleURL
        let start: String
        if bundle.pathExtension == "app" {
            start = "/usr/bin/open -n \(shellQuoted(bundle.path))"
        } else {
            let exe = URL(fileURLWithPath: CommandLine.arguments[0]).resolvingSymlinksInPath().path
            start = "\(shellQuoted(exe)) >/dev/null 2>&1 &"
        }
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/bin/sh")
        task.arguments = ["-c", "while /bin/kill -0 \(pid) 2>/dev/null; do /bin/sleep 0.2; done; \(start)"]
        do {
            try task.run()
        } catch {
            return
        }
        NSApp.terminate(nil)
    }

    private static func shellQuoted(_ s: String) -> String {
        "'" + s.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }
}
