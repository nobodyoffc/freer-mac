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
    /// The FID that must sign this repo's carves, when the repo is not
    /// released by the usual owner (a course signed by its teacher, say).
    /// A scan signed by any other FID marks the repo's entries invalid.
    public var owner: String?
    /// Folders, relative to the repo root, searched for protocol documents.
    public var protocolDirs: [String]?
    public var codes: [CodeEntry]?
    public var apps: [AppEntry]?
    /// Published works: texts, images, sounds and videos (FEIP21, 23–25).
    public var works: [WorkEntry]?

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

    /// One work, published from a release asset or from a file in the repo.
    public struct WorkEntry: Codable, Equatable, Sendable {
        public var kind: WorkKind
        /// The record id, written back after the work is first published,
        /// so a later title change still updates the same record.
        public var id: String?
        public var title: String
        /// Release asset name; `*` matches any run of characters.
        public var asset: String?
        /// File in the repo at the release tag, relative to the root.
        public var path: String?
        /// FEIP21 Text's `type`; texts only.
        public var type: String?
        public var lang: String?
        public var authors: [String]?
        public var format: String?
        public var summary: String?
        /// Further `https://` places that serve the bytes. `{tag}` and
        /// `{name}` are replaced by the release tag and the file name.
        public var mirrors: [String]?
        /// Also carve the file onto DISK permanently and list that DISK.
        public var disk: Bool?
        /// The cover: the `asset` or `path` of an image work in this
        /// manifest, or a 64-hex `imageId`. Not for an image.
        public var cover: String?

        public init(kind: WorkKind, id: String? = nil, title: String, asset: String? = nil, path: String? = nil,
                    type: String? = nil, lang: String? = nil, authors: [String]? = nil, format: String? = nil,
                    summary: String? = nil, mirrors: [String]? = nil, disk: Bool? = nil, cover: String? = nil) {
            self.kind = kind
            self.id = id
            self.title = title
            self.asset = asset
            self.path = path
            self.type = type
            self.lang = lang
            self.authors = authors
            self.format = format
            self.summary = summary
            self.mirrors = mirrors
            self.disk = disk
            self.cover = cover
        }

        /// Where the bytes come from: the asset pattern or the repo path.
        /// Unique within a manifest; with the repo name, a work's key.
        public var source: String { asset ?? path ?? "" }
    }

    public init(github: String, owner: String? = nil, protocolDirs: [String]? = nil, codes: [CodeEntry]? = nil,
                apps: [AppEntry]? = nil, works: [WorkEntry]? = nil) {
        self.github = github
        self.owner = owner
        self.protocolDirs = protocolDirs
        self.codes = codes
        self.apps = apps
        self.works = works
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
        var sources = Set<String>()
        for work in works ?? [] {
            let label = "work \"\(work.title)\""
            guard !work.title.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
                throw Failure.invalid("a \(work.kind.rawValue) work has an empty title")
            }
            guard (work.asset == nil) != (work.path == nil), !work.source.isEmpty else {
                throw Failure.invalid("\(label) needs exactly one of asset and path")
            }
            guard sources.insert(work.source).inserted else { throw Failure.invalid("\(work.source) is listed as two works") }
            if let path = work.path, path.hasPrefix("/") || path.split(separator: "/").contains("..") {
                throw Failure.invalid("\(label) path must stay inside the repo")
            }
            if work.type != nil, work.kind != .text { throw Failure.invalid("\(label): only a text has a type") }
            if let id = work.id, !Self.isRawId(id) { throw Failure.invalid("\(label): id must be 64 hex digits") }
            for mirror in work.mirrors ?? [] where !mirror.hasPrefix("https://") {
                throw Failure.invalid("\(label): mirror \(mirror) is not an https:// URL")
            }
        }
        for work in works ?? [] {
            guard let cover = work.cover else { continue }
            let label = "work \"\(work.title)\""
            if work.kind == .image { throw Failure.invalid("\(label): an image has no cover") }
            if Self.isRawId(cover) { continue }
            guard let target = works?.first(where: { $0.source == cover }) else {
                throw Failure.invalid("\(label): cover \(cover) is neither a work here nor a 64-hex imageId")
            }
            guard target.kind == .image else { throw Failure.invalid("\(label): cover \(cover) is not an image") }
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
