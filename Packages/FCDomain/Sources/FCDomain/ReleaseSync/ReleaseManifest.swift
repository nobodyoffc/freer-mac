import Foundation

/// `freeverse-release.json` at a repo root: what Release Sync cannot infer
/// from the tree — which modules are codes, which release assets are apps,
/// and how they link to protocols and to each other.
///
/// See `RELEASE_SYNC_SPEC.md` for the format.
public struct ReleaseManifest: Codable, Equatable, Sendable {

    public static let fileName = "freeverse-release.json"

    /// `owner/repo` on GitHub. Release assets, archive uploads and `home`
    /// links all hang off it.
    public var github: String
    /// Folders, relative to the repo root, searched for protocol documents.
    public var protocolDirs: [String]?
    public var codes: [CodeEntry]?
    public var apps: [AppEntry]?

    public struct CodeEntry: Codable, Equatable, Sendable {
        /// The code's on-chain `name`, and its key: one name, one code.
        public var name: String
        /// Module folder relative to the repo root; `"."` for the whole repo.
        public var path: String
        public var langs: [String]?
        public var desc: String?
        /// Protocol references, `<TYPE><SN>` (e.g. `FEIP1`) or a 64-hex pid.
        public var protocols: [String]?

        public init(name: String, path: String, langs: [String]? = nil, desc: String? = nil, protocols: [String]? = nil) {
            self.name = name
            self.path = path
            self.langs = langs
            self.desc = desc
            self.protocols = protocols
        }
    }

    public struct AppEntry: Codable, Equatable, Sendable {
        /// The app's on-chain `stdName`, and its key.
        public var stdName: String
        /// Release asset name; `*` matches any run of characters, so a
        /// versioned file name (`Freer-*.dmg`) still matches next release.
        public var asset: String
        public var os: String?
        public var types: [String]?
        public var desc: String?
        public var localNames: [String: String]?
        /// Code references: a code `name` in this repo, or `<repo>/<name>`
        /// (repo is the GitHub `owner/repo` or just its last part).
        public var codes: [String]?
        /// Protocol references, `<TYPE><SN>`.
        public var protocols: [String]?

        public init(stdName: String, asset: String, os: String? = nil, types: [String]? = nil,
                    desc: String? = nil, localNames: [String: String]? = nil,
                    codes: [String]? = nil, protocols: [String]? = nil) {
            self.stdName = stdName
            self.asset = asset
            self.os = os
            self.types = types
            self.desc = desc
            self.localNames = localNames
            self.codes = codes
            self.protocols = protocols
        }
    }

    public init(github: String, protocolDirs: [String]? = nil, codes: [CodeEntry]? = nil, apps: [AppEntry]? = nil) {
        self.github = github
        self.protocolDirs = protocolDirs
        self.codes = codes
        self.apps = apps
    }

    public enum Failure: Error, Equatable, CustomStringConvertible {
        case missing(URL)
        case unreadable(URL, String)
        case invalid(String)

        public var description: String {
            switch self {
            case .missing(let url): return "No \(ReleaseManifest.fileName) in \(url.path)."
            case .unreadable(let url, let why): return "\(url.lastPathComponent): \(why)"
            case .invalid(let why): return "\(ReleaseManifest.fileName): \(why)"
            }
        }
    }

    public static func load(repo: URL) throws -> ReleaseManifest {
        let url = repo.appendingPathComponent(fileName)
        guard FileManager.default.fileExists(atPath: url.path) else { throw Failure.missing(repo) }
        let manifest: ReleaseManifest
        do {
            manifest = try JSONDecoder().decode(ReleaseManifest.self, from: Data(contentsOf: url))
        } catch {
            throw Failure.unreadable(url, String(describing: error))
        }
        try manifest.validate()
        return manifest
    }

    /// Rejects what would otherwise surface as a confusing diff: two
    /// entries under one key, or a repo that is not `owner/repo`.
    public func validate() throws {
        let parts = github.split(separator: "/")
        guard parts.count == 2, parts.allSatisfy({ !$0.isEmpty }) else {
            throw Failure.invalid("github must be owner/repo, got \"\(github)\"")
        }
        var names = Set<String>()
        for code in codes ?? [] {
            guard !code.name.isEmpty else { throw Failure.invalid("a code has an empty name") }
            guard names.insert(code.name).inserted else { throw Failure.invalid("code \"\(code.name)\" is listed twice") }
            guard !code.path.hasPrefix("/"), !code.path.split(separator: "/").contains("..") else {
                throw Failure.invalid("code \"\(code.name)\" path must stay inside the repo")
            }
        }
        var stdNames = Set<String>()
        for app in apps ?? [] {
            guard !app.stdName.isEmpty else { throw Failure.invalid("an app has an empty stdName") }
            guard stdNames.insert(app.stdName).inserted else { throw Failure.invalid("app \"\(app.stdName)\" is listed twice") }
            guard !app.asset.isEmpty else { throw Failure.invalid("app \"\(app.stdName)\" has no asset") }
        }
        for ref in (codes ?? []).flatMap({ $0.protocols ?? [] }) + (apps ?? []).flatMap({ $0.protocols ?? [] }) {
            guard ProtocolRef(ref) != nil || Self.isRawId(ref) else {
                throw Failure.invalid("\"\(ref)\" is not a protocol reference like FEIP1, nor a 64-hex pid")
            }
        }
    }

    /// A pid or codeId written as is: what review write-back stores for a
    /// link the user added by id.
    public static func isRawId(_ text: String) -> Bool {
        text.count == 64 && text.allSatisfy { $0.isHexDigit }
    }

    /// The repo's short name, `Freeverse` for `nobodyoffc/Freeverse`.
    public var repoName: String { String(github.split(separator: "/").last ?? "") }

    /// Whether `name` matches an asset pattern; `*` is the only wildcard.
    public static func assetMatches(pattern: String, name: String) -> Bool {
        let pieces = pattern.components(separatedBy: "*")
        guard pieces.count > 1 else { return pattern == name }
        var rest = Substring(name)
        guard rest.hasPrefix(pieces[0]) else { return false }
        rest = rest.dropFirst(pieces[0].count)
        for piece in pieces.dropFirst().dropLast() where !piece.isEmpty {
            guard let range = rest.range(of: piece) else { return false }
            rest = rest[range.upperBound...]
        }
        return rest.hasSuffix(pieces.last!)
    }
}

/// `FEIP1` → type `FEIP`, sn `1`: how a manifest names a protocol.
public struct ProtocolRef: Hashable, Sendable, CustomStringConvertible {
    public let type: String
    public let sn: String

    public init(type: String, sn: String) {
        self.type = type
        self.sn = sn
    }

    public init?(_ text: String) {
        let letters = text.prefix(while: { $0.isLetter })
        let digits = text.dropFirst(letters.count)
        guard !letters.isEmpty, !digits.isEmpty, digits.allSatisfy({ $0.isASCII && $0.isNumber }) else { return nil }
        type = String(letters)
        sn = String(Int(digits)!)
    }

    public var description: String { type + sn }
}
