import Foundation

// Prints exactly what HomeView's sidebar will render, and fails if any
// WalletPane case would be unreachable.
//
// Why this exists: "it compiles" is not verification of a navigation
// change. A pane missing from the sidebar is not a type error — it is a
// case that compiles cleanly, satisfies the exhaustive detail switch,
// and simply never appears. That is exactly how the Files pane shipped
// invisible in 8.4.6, when the sidebar hardcoded its case lists.
//
// The sidebar now derives from `WalletPane.allCases` grouped by
// `WalletPane.Group`, so this should never fail again — which is the
// point of running it: the guarantee is cheap to check and silent when
// it breaks.
//
// Run: tools/sidebar-check/run.sh

for group in WalletPane.Group.allCases {
    print("[\(group.rawValue)]")
    for pane in WalletPane.panes(in: group) {
        let icon = pane.systemImage.padding(toLength: 24, withPad: " ", startingAt: 0)
        print("  \(icon) \(pane.title)")
    }
}

let rendered = WalletPane.Group.allCases.flatMap { WalletPane.panes(in: $0) }
print("\nrendered \(rendered.count) of \(WalletPane.allCases.count) cases")

let missing = Set(WalletPane.allCases.map(\.rawValue))
    .subtracting(rendered.map(\.rawValue))
    .sorted()

if missing.isEmpty {
    print("no unreachable panes")
} else {
    // A pane the user cannot navigate to is not a shipped pane.
    print("UNREACHABLE: \(missing.joined(separator: ", "))")
    print("`WalletPane.panes(in:)` must derive from `allCases` — a hardcoded")
    print("case list is what made the Files pane unreachable in 8.4.6.")
    exit(1)
}
