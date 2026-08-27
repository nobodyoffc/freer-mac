import Foundation

/// JSON pretty-print ⇄ minify, the port of Android's
/// `JsonUtils.jsonToNiceJson` / `niceJsonToJson`.
///
/// This is a recursive-descent reformatter over the raw text rather
/// than a `JSONSerialization` round-trip, for two reasons that both
/// corrupt real data:
///
/// - **Key order.** Decoding into a dictionary loses it, so a signed
///   FEIP payload reformatted here would no longer hash to the same
///   value it was signed under.
/// - **Number literals.** `JSONSerialization` parses every number into
///   `Double`. A satoshi amount past 2^53, or a decimal like
///   `0.00000001`, comes back out as a *different* literal. Numbers are
///   copied through verbatim here — never parsed, never re-rendered.
///
/// Parsing is still strict: malformed JSON throws rather than being
/// echoed back with new whitespace.
public enum JsonFormatter {

    public enum Failure: Error, CustomStringConvertible {
        case unexpectedCharacter(Character, atOffset: Int)
        case unexpectedEnd
        case trailingCharacters(atOffset: Int)

        public var description: String {
            switch self {
            case let .unexpectedCharacter(c, offset):
                return "JSON: unexpected '\(c)' at character \(offset)"
            case .unexpectedEnd:
                return "JSON: the text ends in the middle of a value"
            case let .trailingCharacters(offset):
                return "JSON: extra content after the value, at character \(offset)"
            }
        }
    }

    /// Expanded form: two-space indents, one element per line.
    public static func prettyPrint(_ json: String, indent: String = "  ") throws -> String {
        try format(json, indent: indent)
    }

    /// Compact form: no whitespace outside string literals.
    public static func minify(_ json: String) throws -> String {
        try format(json, indent: nil)
    }

    /// True when `json` is already expanded — the heuristic that lets
    /// the converter toggle with a single button, as Android's does.
    public static func looksPretty(_ json: String) -> Bool {
        json.contains("\n") || json.contains("  ")
    }

    private static func format(_ json: String, indent: String?) throws -> String {
        var parser = Parser(text: Array(json), indent: indent)
        parser.skipWhitespace()
        var out = ""
        try parser.value(into: &out, depth: 0)
        parser.skipWhitespace()
        guard parser.isAtEnd else { throw Failure.trailingCharacters(atOffset: parser.index) }
        return out
    }

    private struct Parser {
        let text: [Character]
        let indent: String?
        var index = 0

        var isAtEnd: Bool { index >= text.count }
        private var pretty: Bool { indent != nil }

        private var current: Character? { isAtEnd ? nil : text[index] }

        mutating func skipWhitespace() {
            while let c = current, c == " " || c == "\n" || c == "\r" || c == "\t" {
                index += 1
            }
        }

        private func newline(_ depth: Int) -> String {
            guard let indent else { return "" }
            return "\n" + String(repeating: indent, count: depth)
        }

        mutating func value(into out: inout String, depth: Int) throws {
            guard let c = current else { throw Failure.unexpectedEnd }
            switch c {
            case "{": try container(into: &out, depth: depth, open: "{", close: "}", isObject: true)
            case "[": try container(into: &out, depth: depth, open: "[", close: "]", isObject: false)
            case "\"": out += try string()
            default: out += try literal()
            }
        }

        /// Objects and arrays differ only in their brackets and in
        /// whether each element carries a `"key":` prefix.
        private mutating func container(
            into out: inout String, depth: Int, open: Character, close: Character, isObject: Bool
        ) throws {
            index += 1  // consume the opening bracket
            out.append(open)
            skipWhitespace()

            if current == close {
                index += 1
                out.append(close)
                return
            }

            var first = true
            while true {
                if !first { out.append(",") }
                first = false
                out += newline(depth + 1)
                skipWhitespace()

                if isObject {
                    guard current == "\"" else {
                        throw current.map { Failure.unexpectedCharacter($0, atOffset: index) }
                            ?? Failure.unexpectedEnd
                    }
                    out += try string()
                    skipWhitespace()
                    guard current == ":" else {
                        throw current.map { Failure.unexpectedCharacter($0, atOffset: index) }
                            ?? Failure.unexpectedEnd
                    }
                    index += 1
                    out += pretty ? ": " : ":"
                    skipWhitespace()
                }

                try value(into: &out, depth: depth + 1)
                skipWhitespace()

                switch current {
                case ",":
                    index += 1
                    continue
                case close:
                    index += 1
                    out += newline(depth)
                    out.append(close)
                    return
                case let other?:
                    throw Failure.unexpectedCharacter(other, atOffset: index)
                case nil:
                    throw Failure.unexpectedEnd
                }
            }
        }

        /// Copied through verbatim, escapes and all — reformatting must
        /// never rewrite the contents of a string.
        private mutating func string() throws -> String {
            var out = "\""
            index += 1  // consume the opening quote
            while true {
                guard let c = current else { throw Failure.unexpectedEnd }
                index += 1
                out.append(c)
                if c == "\\" {
                    guard let escaped = current else { throw Failure.unexpectedEnd }
                    index += 1
                    out.append(escaped)
                    continue
                }
                if c == "\"" { return out }
            }
        }

        /// Numbers, `true`, `false`, `null` — taken as the run of
        /// characters up to the next structural one, then checked for
        /// shape. Number *text* is preserved exactly.
        private mutating func literal() throws -> String {
            let start = index
            while let c = current,
                  !",:[]{} \n\r\t".contains(c) {
                index += 1
            }
            let token = String(text[start..<index])
            guard !token.isEmpty else {
                throw current.map { Failure.unexpectedCharacter($0, atOffset: index) }
                    ?? Failure.unexpectedEnd
            }
            guard token == "true" || token == "false" || token == "null" || isNumber(token) else {
                throw Failure.unexpectedCharacter(text[start], atOffset: start)
            }
            return token
        }

        private func isNumber(_ token: String) -> Bool {
            // RFC 8259 grammar: -?(0|[1-9]\d*)(\.\d+)?([eE][-+]?\d+)?
            var chars = Array(token)[...]
            if chars.first == "-" { chars = chars.dropFirst() }
            guard let first = chars.first, first.isNumber else { return false }
            if first == "0", chars.count > 1, chars[chars.index(after: chars.startIndex)].isNumber {
                return false  // no leading zeros
            }
            var seenDot = false
            var seenExponent = false
            var previous: Character?
            for (offset, c) in chars.enumerated() {
                if c.isNumber { previous = c; continue }
                switch c {
                case ".":
                    guard !seenDot, !seenExponent, previous?.isNumber == true else { return false }
                    seenDot = true
                case "e", "E":
                    guard !seenExponent, previous?.isNumber == true else { return false }
                    seenExponent = true
                case "+", "-":
                    guard previous == "e" || previous == "E" else { return false }
                    _ = offset
                default:
                    return false
                }
                previous = c
            }
            return previous?.isNumber == true
        }
    }
}
