import Foundation
import FCCore

/// Runs `git` and `gh`. An app opened from the Finder gets a bare PATH, so
/// the usual install folders are searched explicitly.
public enum ShellTool {

    public struct Failure: Error, CustomStringConvertible {
        public let command: String
        public let status: Int32
        public let stderr: String
        public var description: String {
            let detail = stderr.trimmingCharacters(in: .whitespacesAndNewlines)
            return "\(command) failed (\(status))" + (detail.isEmpty ? "" : ": \(detail)")
        }
    }

    public struct NotInstalled: Error, CustomStringConvertible {
        public let tool: String
        public var description: String { "\(tool) is not installed (looked in /opt/homebrew/bin, /usr/local/bin, /usr/bin)." }
    }

    static let searchPath = ["/opt/homebrew/bin", "/usr/local/bin", "/usr/bin"]

    public static func locate(_ tool: String) -> URL? {
        for dir in searchPath {
            let url = URL(fileURLWithPath: dir).appendingPathComponent(tool)
            if FileManager.default.isExecutableFile(atPath: url.path) { return url }
        }
        return nil
    }

    /// Runs `tool args…`, feeding `input` on stdin, and returns stdout.
    /// Blocking — call it off the main actor.
    public static func run(_ tool: String, _ args: [String], input: Data? = nil, in directory: URL? = nil) throws -> Data {
        guard let exe = locate(tool) else { throw NotInstalled(tool: tool) }
        let process = Process()
        process.executableURL = exe
        process.arguments = args
        if let directory { process.currentDirectoryURL = directory }
        var env = ProcessInfo.processInfo.environment
        env["PATH"] = (searchPath + [env["PATH"] ?? ""]).joined(separator: ":")
        env["GIT_TERMINAL_PROMPT"] = "0"
        env["GH_PROMPT_DISABLED"] = "1"
        process.environment = env

        let stdout = Pipe(), stderr = Pipe()
        process.standardOutput = stdout
        process.standardError = stderr
        // A file, not a pipe, for stdin: a large input written to a pipe
        // would block until the child reads, and the child blocks on its
        // own full stdout, which nobody reads until the write is done.
        var inputFile: URL?
        if let input {
            let url = FileManager.default.temporaryDirectory.appendingPathComponent("rs-\(UUID().uuidString)")
            try input.write(to: url)
            inputFile = url
            process.standardInput = try FileHandle(forReadingFrom: url)
        } else {
            process.standardInput = FileHandle.nullDevice
        }
        defer { if let inputFile { try? FileManager.default.removeItem(at: inputFile) } }

        var out = Data(), err = Data()
        let group = DispatchGroup()
        group.enter()
        DispatchQueue.global().async { out = stdout.fileHandleForReading.readDataToEndOfFile(); group.leave() }
        group.enter()
        DispatchQueue.global().async { err = stderr.fileHandleForReading.readDataToEndOfFile(); group.leave() }
        try process.run()
        process.waitUntilExit()
        group.wait()
        guard process.terminationStatus == 0 else {
            throw Failure(command: ([tool] + args.prefix(3)).joined(separator: " "),
                          status: process.terminationStatus,
                          stderr: String(decoding: err, as: UTF8.self))
        }
        return out
    }
}

/// Read-only access to a local clone.
public struct GitRepo: Sendable {
    public let root: URL

    public init(root: URL) {
        self.root = root
    }

    func git(_ args: [String], input: Data? = nil) throws -> Data {
        try ShellTool.run("git", ["-C", root.path] + args, input: input)
    }

    public func hasTag(_ tag: String) -> Bool {
        (try? git(["rev-parse", "--verify", "--quiet", "refs/tags/\(tag)^{commit}"])) != nil
    }

    /// Fetches tags so a release made on another machine is visible.
    public func fetchTags() throws {
        _ = try git(["fetch", "--tags", "--quiet"])
    }

    public func currentBranch() -> String? {
        guard let out = try? git(["rev-parse", "--abbrev-ref", "HEAD"]) else { return nil }
        let name = String(decoding: out, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
        return name == "HEAD" || name.isEmpty ? nil : name
    }

    /// Whether a working-tree file differs from HEAD or is untracked.
    public func isDirty(_ relativePath: String) -> Bool {
        guard let out = try? git(["status", "--porcelain", "--", relativePath]) else { return false }
        return !out.isEmpty
    }

    /// The files under `path` at `tag`, as zip entries named
    /// `<prefix>/<path relative to the module>`. Submodules are left out;
    /// a symlink is stored as a file holding its target.
    public func archiveEntries(tag: String, path: String, prefix: String) throws -> [DeterministicZip.Entry] {
        let module = (path == "." || path.isEmpty) ? "" : path.hasSuffix("/") ? path : path + "/"
        var args = ["ls-tree", "-r", "-z", "--full-tree", tag]
        if !module.isEmpty { args += ["--", module] }
        let listing = try git(args)
        struct Item { let mode: String; let oid: String; let path: String }
        var items: [Item] = []
        for record in listing.split(separator: 0) {
            // "<mode> <type> <oid>\t<path>"
            guard let tab = record.firstIndex(of: 0x09) else { continue }
            let meta = String(decoding: record[record.startIndex..<tab], as: UTF8.self).split(separator: " ")
            let path = String(decoding: record[(tab + 1)...], as: UTF8.self)
            guard meta.count == 3, meta[1] == "blob" else { continue }
            items.append(Item(mode: String(meta[0]), oid: String(meta[2]), path: path))
        }
        guard !items.isEmpty else { return [] }

        let request = Data(items.map { $0.oid + "\n" }.joined().utf8)
        let blobs = try git(["cat-file", "--batch"], input: request)
        var entries: [DeterministicZip.Entry] = []
        var cursor = blobs.startIndex
        for item in items {
            // "<oid> blob <size>\n<content>\n"
            guard let lineEnd = blobs[cursor...].firstIndex(of: 0x0A) else { throw ArchiveFailure.truncated(item.path) }
            let header = String(decoding: blobs[cursor..<lineEnd], as: UTF8.self).split(separator: " ")
            guard header.count == 3, header[0] == item.oid, let size = Int(header[2]) else {
                throw ArchiveFailure.truncated(item.path)
            }
            let start = lineEnd + 1
            guard start + size <= blobs.endIndex else { throw ArchiveFailure.truncated(item.path) }
            let content = Data(blobs[start..<(start + size)])
            cursor = start + size + 1
            let inner = String(item.path.dropFirst(module.count))
            entries.append(.init(path: prefix + "/" + inner, data: content, executable: item.mode == "100755"))
        }
        return entries
    }

    public enum ArchiveFailure: Error, CustomStringConvertible {
        case truncated(String)
        case empty(String)
        public var description: String {
            switch self {
            case .truncated(let p): return "git cat-file output ended early at \(p)"
            case .empty(let p): return "nothing is tracked under \(p)"
            }
        }
    }
}

/// GitHub releases through the `gh` CLI, which carries the user's login.
public struct GitHubReleases: Sendable {
    public let repo: String

    public init(repo: String) {
        self.repo = repo
    }

    public struct Release: Decodable, Equatable, Sendable {
        public let tagName: String
        public let name: String?
        public let isPrerelease: Bool
        public let isDraft: Bool
        public let publishedAt: String?
    }

    public struct Asset: Decodable, Equatable, Sendable {
        public let name: String
        public let size: Int64
        /// The browser download URL — what goes into an app's `link`.
        public let url: String
        /// `sha256:<hex>` when GitHub has hashed the file.
        public let digest: String?

        public init(name: String, size: Int64, url: String, digest: String?) {
            self.name = name
            self.size = size
            self.url = url
            self.digest = digest
        }

        /// The DID straight from GitHub's SHA-256: the double hash is the
        /// hash of the single one, so the file need not be downloaded.
        public var did: String? {
            guard let digest, digest.hasPrefix("sha256:") else { return nil }
            let hex = String(digest.dropFirst(7))
            guard hex.count == 64, let single = try? Hex.decode(hex) else { return nil }
            return Hex.encode(Hash.sha256(single)).lowercased()
        }
    }

    public func releases(limit: Int = 30) throws -> [Release] {
        let out = try ShellTool.run("gh", ["release", "list", "-R", repo, "-L", String(limit),
                                             "--json", "tagName,name,isPrerelease,isDraft,publishedAt"])
        return try JSONDecoder().decode([Release].self, from: out)
    }

    public func assets(tag: String) throws -> [Asset] {
        struct View: Decodable { let assets: [Asset] }
        let out = try ShellTool.run("gh", ["release", "view", tag, "-R", repo, "--json", "assets"])
        return try JSONDecoder().decode(View.self, from: out).assets
    }

    /// Uploads `file` to the release, replacing an asset of the same name.
    public func upload(_ file: URL, tag: String) throws {
        _ = try ShellTool.run("gh", ["release", "upload", tag, file.path, "-R", repo, "--clobber"])
    }

    public func releasePage(tag: String) -> String { "https://github.com/\(repo)/releases/tag/\(tag)" }
    public func assetLink(tag: String, name: String) -> String { "https://github.com/\(repo)/releases/download/\(tag)/\(name)" }
    public func treeLink(tag: String, path: String) -> String {
        path == "." || path.isEmpty ? "https://github.com/\(repo)/tree/\(tag)" : "https://github.com/\(repo)/tree/\(tag)/\(path)"
    }
    public func blobLink(ref: String, path: String) -> String { "https://github.com/\(repo)/blob/\(ref)/\(path)" }
}
