#!/bin/bash
# Compiles the symbol checker and runs it over the app's SwiftUI source.
#
# Deliberately does NOT build the app: it needs AppKit and a regex, not
# the app's module graph, so it runs in a couple of seconds and can be
# used after any UI change.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
out="$(mktemp -d)"
trap 'rm -rf "$out"' EXIT

swiftc -O -o "$out/symbol-check" "$here/main.swift"
"$out/symbol-check" "$root/Sources" "$root/Packages/FCUI/Sources"
