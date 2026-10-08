import Foundation
import FCCore

/// One protocol specification, `<TYPE><SN>V<VER>_<Name>.md`, read the way
/// the retired Java `PublishProtocols` CLI read it, so a document yields the
/// same registration whichever tool carves it:
///
/// - `type`, `sn`, `ver`, `name` come from the Summary table (`Type`, `SN`,
///   `Version`/`Ver`, `Title`);
/// - `desc` is the Abstract section flattened to one line, with `**` and
///   backticks stripped;
/// - `did` is the double SHA-256 of the file's bytes.
public struct ProtocolDoc: Equatable, Sendable {
    public var url: URL
    /// Path relative to the repo root, for links and reports.
    public var relativePath: String
    public var type: String
    public var sn: String
    public var ver: String
    public var name: String
    public var desc: String?
    public var lang: String
    /// The Summary table's `PID` value, when it holds a txid.
    public var pid: String?
    public var did: String

    public var ref: ProtocolRef { ProtocolRef(type: type, sn: sn) }

    public enum Failure: Error, Equatable, CustomStringConvertible {
        case notAProtocolFileName(String)
        case missingField(String, file: String)
        case mismatch(String, file: String)
        case noSummaryTable(String)

        public var description: String {
            switch self {
            case .notAProtocolFileName(let f): return "\(f): not named <TYPE><SN>V<VER>_<Name>.md"
            case .missingField(let k, let f): return "\(f): the Summary table has no \(k)"
            case .mismatch(let why, let f): return "\(f): \(why)"
            case .noSummaryTable(let f): return "\(f): no Summary table"
            }
        }
    }

    /// `FEIP1V7_Protocol.md` → (`FEIP`, `1`, `7`).
    public static func parseFileName(_ name: String) -> (type: String, sn: String, ver: String)? {
        guard name.hasSuffix(".md") else { return nil }
        let stem = name.dropLast(3)
        let type = stem.prefix(while: { $0.isASCII && $0.isUppercase })
        var rest = stem.dropFirst(type.count)
        let sn = rest.prefix(while: { $0.isASCII && $0.isNumber })
        rest = rest.dropFirst(sn.count)
        guard !type.isEmpty, !sn.isEmpty, rest.first == "V" else { return nil }
        rest = rest.dropFirst()
        let ver = rest.prefix(while: { $0.isASCII && $0.isNumber })
        rest = rest.dropFirst(ver.count)
        guard !ver.isEmpty, rest.first == "_" else { return nil }
        return (String(type), String(Int(sn)!), String(Int(ver)!))
    }

    public static func load(url: URL, relativePath: String) throws -> ProtocolDoc {
        let data = try Data(contentsOf: url)
        return try parse(data: data, url: url, relativePath: relativePath)
    }

    public static func parse(data: Data, url: URL, relativePath: String) throws -> ProtocolDoc {
        let file = url.lastPathComponent
        guard let fromName = parseFileName(file) else { throw Failure.notAProtocolFileName(file) }
        let markdown = String(decoding: data, as: UTF8.self)
        let table = summaryTable(markdown)
        guard !table.isEmpty else { throw Failure.noSummaryTable(file) }

        func required(_ keys: String...) throws -> String {
            for key in keys {
                if let v = table[key]?.trimmingCharacters(in: .whitespaces), !v.isEmpty { return v }
            }
            throw Failure.missingField(keys.joined(separator: "/"), file: file)
        }
        let type = try required("Type")
        let snText = try required("SN")
        let ver = try required("Version", "Ver")
        let name = try required("Title")
        // A change proposal ("FIMP (change proposal)") or a doc whose table
        // disagrees with its file name is not the protocol's next version.
        guard type == fromName.type else {
            throw Failure.mismatch("Summary Type \"\(type)\" is not \(fromName.type)", file: file)
        }
        guard let sn = Int(snText).map(String.init), sn == fromName.sn else {
            throw Failure.mismatch("Summary SN \"\(snText)\" is not \(fromName.sn)", file: file)
        }
        guard Int(ver).map(String.init) == fromName.ver else {
            throw Failure.mismatch("Summary Version \"\(ver)\" is not \(fromName.ver)", file: file)
        }
        let pidText = table["PID"]?.trimmingCharacters(in: .whitespaces) ?? ""
        let lang = table["Lang"] ?? table["Language"]
        let desc = abstract(markdown)
        return ProtocolDoc(
            url: url, relativePath: relativePath,
            type: type, sn: sn, ver: ver, name: name,
            desc: desc.isEmpty ? nil : desc,
            lang: (lang?.isEmpty == false ? lang! : "en"),
            pid: isTxid(pidText) ? pidText.lowercased() : nil,
            did: Hex.encode(Hash.doubleSha256(data)).lowercased()
        )
    }

    static func isTxid(_ s: String) -> Bool {
        s.count == 64 && s.allSatisfy { $0.isHexDigit }
    }

    // MARK: - Summary table

    /// The first pipe table under `## Summary`; failing that, the first one
    /// before `## Contents`, else the first in the file. Same fallbacks as
    /// the Java `SummaryTableParser`.
    static func summaryTable(_ markdown: String) -> [String: String] {
        let lines = markdown.components(separatedBy: .newlines)
        guard let range = summaryTableRange(lines) else { return [:] }
        return firstPipeTable(Array(lines[range]))
    }

    /// Where the Summary table is. Used both to read it and to write the
    /// PID into it, so the two always agree.
    static func summaryTableRange(_ lines: [String]) -> Range<Int>? {
        if let body = section(lines, heading: "Summary"),
           let table = firstTableRange(Array(lines[body])) {
            return (body.lowerBound + table.lowerBound)..<(body.lowerBound + table.upperBound)
        }
        if let contents = lines.firstIndex(where: { isHeading($0, "Contents") }) {
            return firstTableRange(Array(lines[..<contents]))
        }
        return firstTableRange(lines)
    }

    /// Line range of a `## <heading>` section's body, up to the next `## `.
    static func section(_ lines: [String], heading: String) -> Range<Int>? {
        guard let start = lines.firstIndex(where: { isHeading($0, heading) }) else { return nil }
        let end = lines[(start + 1)...].firstIndex(where: { $0.hasPrefix("## ") || $0 == "##" }) ?? lines.count
        return (start + 1)..<end
    }

    static func isHeading(_ line: String, _ title: String) -> Bool {
        guard line.hasPrefix("##"), !line.hasPrefix("###") else { return false }
        return line.dropFirst(2).trimmingCharacters(in: .whitespaces) == title
    }

    static func isPipeLine(_ line: String) -> Bool {
        let t = line.trimmingCharacters(in: .whitespaces)
        return t.hasPrefix("|") && t.count > 1 && t.filter({ $0 == "|" }).count >= 2
    }

    /// Index range of the first pipe table in `lines`.
    static func firstTableRange(_ lines: [String]) -> Range<Int>? {
        guard let start = lines.firstIndex(where: isPipeLine) else { return nil }
        let end = lines[start...].firstIndex(where: { !isPipeLine($0) }) ?? lines.count
        return start..<end
    }

    static func firstPipeTable(_ lines: [String]) -> [String: String] {
        guard let range = firstTableRange(lines) else { return [:] }
        var map: [String: String] = [:]
        for line in lines[range] {
            guard let (key, value) = row(line) else { continue }
            if map[key] == nil { map[key] = value }
        }
        return map
    }

    static func row(_ line: String) -> (String, String)? {
        let parts = line.trimmingCharacters(in: .whitespaces).components(separatedBy: "|")
        guard parts.count >= 3 else { return nil }
        let key = parts[1].trimmingCharacters(in: .whitespaces)
        let value = parts[2].trimmingCharacters(in: .whitespaces)
        guard !key.isEmpty else { return nil }
        let rule: (Character) -> Bool = { $0 == "-" || $0 == ":" || $0 == " " }
        if key.allSatisfy(rule) && value.allSatisfy(rule) { return nil }
        if key.caseInsensitiveCompare("Field") == .orderedSame,
           value.caseInsensitiveCompare("Content") == .orderedSame { return nil }
        return (key, value)
    }

    // MARK: - Abstract

    static let maxDescLength = 4000

    static func abstract(_ markdown: String) -> String {
        let lines = markdown.components(separatedBy: .newlines)
        guard let range = section(lines, heading: "Abstract") else { return "" }
        var out = ""
        var inFence = false
        for line in lines[range] {
            let t = line.trimmingCharacters(in: .whitespaces)
            if t.hasPrefix("```") { inFence.toggle(); continue }
            if inFence || t.hasPrefix("#") { continue }
            if !out.isEmpty, out.last != " " { out.append(" ") }
            out.append(t)
        }
        var s = collapse(out)
        s = collapse(stripLinks(s).replacingOccurrences(of: "**", with: "").replacingOccurrences(of: "`", with: ""))
        return s.count > maxDescLength ? String(s.prefix(maxDescLength)) : s
    }

    /// `[text](target)` → `text`: a relative link means nothing on chain.
    static func stripLinks(_ s: String) -> String {
        s.replacingOccurrences(of: #"\[([^\]]*)\]\([^)]*\)"#, with: "$1", options: .regularExpression)
    }

    static func collapse(_ s: String) -> String {
        s.split(whereSeparator: { $0.isWhitespace }).joined(separator: " ")
    }

    // MARK: - PID row

    /// The document with `pid` written into its Summary table: an existing
    /// `PID` row gets the value, otherwise a row is appended to the table.
    /// Everything else, line endings included, is left byte for byte.
    public static func fillingPid(_ pid: String, in data: Data) throws -> Data {
        let text = String(decoding: data, as: UTF8.self)
        let newline = text.contains("\r\n") ? "\r\n" : "\n"
        var lines = text.components(separatedBy: newline)
        guard let table = summaryTableRange(lines) else { throw Failure.noSummaryTable("document") }
        if let i = table.first(where: { row(lines[$0])?.0 == "PID" }) {
            lines[i] = "|PID|\(pid)|"
        } else {
            lines.insert("|PID|\(pid)|", at: table.upperBound)
        }
        return Data(lines.joined(separator: newline).utf8)
    }
}
