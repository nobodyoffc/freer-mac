#!/bin/bash
# Compiles WalletPane against a tiny driver and prints the sidebar it
# will produce. Exits non-zero if a pane would be unreachable.
#
# Deliberately does NOT build the app: it needs one enum, not SwiftUI,
# so it runs in about a second and can be used after any pane change.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
out="$(mktemp -d)"
trap 'rm -rf "$out"' EXIT

swiftc -o "$out/sidebar-check" \
    "$root/Sources/FreerForMac/Views/Panes/WalletPane.swift" \
    "$root/tools/sidebar-check/main.swift"

"$out/sidebar-check"
