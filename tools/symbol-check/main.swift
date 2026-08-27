import AppKit
import Foundation

// Checks that every SF Symbol name the app asks for actually exists on
// this machine, and fails if any does not.
//
// Why this exists: a missing symbol is not a build error and not a
// crash. SwiftUI renders `Image(systemName:)` for a name that does not
// resolve as *nothing*, so a bordered icon button becomes an empty
// bordered rectangle — a blank bar where a control should be. That is
// how `person.crop.circle.badge.magnifyingglass` sat in eight places
// across this app, on every "find a FID" button, until someone looked
// at one and asked what it was.
//
// It is a runtime fact about the OS, so a compiler cannot help and only
// a machine with the SDK can answer. Cheap to run, silent when clean.
//
// Run: tools/symbol-check/run.sh

let roots = CommandLine.arguments.dropFirst()
guard !roots.isEmpty else {
    FileHandle.standardError.write(Data("usage: symbol-check <dir>…\n".utf8))
    exit(64)
}

/// `systemName: "…"` and `systemImage: "…"`, the two spellings that
/// reach the symbol table.
let pattern = try! NSRegularExpression(
    pattern: #"system(?:Name|Image):\s*"([^"]+)""#
)

struct Use: Hashable {
    let symbol: String
    let file: String
    let line: Int
}

var uses: [Use] = []

for root in roots {
    guard let walker = FileManager.default.enumerator(atPath: root) else { continue }
    for case let path as String in walker where path.hasSuffix(".swift") {
        let full = root + "/" + path
        guard let text = try? String(contentsOfFile: full, encoding: .utf8) else { continue }
        for (offset, lineText) in text.components(separatedBy: "\n").enumerated() {
            let range = NSRange(lineText.startIndex..., in: lineText)
            for match in pattern.matches(in: lineText, range: range) {
                guard let r = Range(match.range(at: 1), in: lineText) else { continue }
                uses.append(Use(symbol: String(lineText[r]), file: full, line: offset + 1))
            }
        }
    }
}

let symbols = Set(uses.map(\.symbol)).sorted()
var missing: [String] = []
for symbol in symbols {
    if NSImage(systemSymbolName: symbol, accessibilityDescription: nil) == nil {
        missing.append(symbol)
    }
}

print("Checked \(symbols.count) distinct symbols across \(uses.count) uses.")

guard missing.isEmpty else {
    print("\nMISSING — these render as nothing:")
    for symbol in missing {
        print("  \(symbol)")
        for use in uses where use.symbol == symbol {
            print("      \(use.file):\(use.line)")
        }
    }
    exit(1)
}
print("All resolve.")
