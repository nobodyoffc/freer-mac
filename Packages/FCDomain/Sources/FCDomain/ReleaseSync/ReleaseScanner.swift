import Foundation
import FCCore

/// Reads one repo folder into a ``RepoScan``. Blocking (git, gh, hashing,
/// downloads) — run it off the main actor.
public struct ReleaseScanner: Sendable {
    /// Where archives and downloaded assets are written.
    public let workDir: URL
    public let downloader: @Sendable (URL, URL) async throws -> Void

    public init(workDir: URL,
                downloader: @escaping @Sendable (URL, URL) async throws -> Void = ReleaseScanner.download) {
        self.workDir = workDir
        self.downloader = downloader
    }

    /// The default tag: the newest non-draft release that is not a
    /// `protocols-*` bundle. Pre-releases count; every Freeverse release
    /// so far is one.
    public static func defaultTag(_ releases: [GitHubReleases.Release]) -> String? {
        releases.first { !$0.isDraft && !$0.tagName.hasPrefix("protocols-") }?.tagName
    }

    public func scan(root: URL, tag: String?, progress: @Sendable (String) -> Void = { _ in }) async throws -> RepoScan {
        let manifest = try ReleaseManifest.load(repo: root)
        let git = GitRepo(root: root)
        var scan = RepoScan(root: root, manifest: manifest, tag: tag, branch: git.currentBranch() ?? "main")

        progress("Reading protocol documents in \(manifest.repoName)…")
        (scan.protocols, scan.problems) = Self.protocolDocs(root: root, dirs: manifest.protocolDirs ?? [])

        let hasCodes = !(manifest.codes ?? []).isEmpty, hasApps = !(manifest.apps ?? []).isEmpty
        guard hasCodes || hasApps else { return scan }
        guard let tag else {
            scan.problems.append("\(manifest.repoName): no release tag chosen, so its codes and apps were skipped")
            return scan
        }
        if !git.hasTag(tag) { try? git.fetchTags() }
        guard git.hasTag(tag) else {
            scan.problems.append("\(manifest.repoName): tag \(tag) is not in the local clone; codes skipped")
            return try await withApps(scan, manifest, tag, progress)
        }

        for entry in manifest.codes ?? [] {
            progress("Archiving \(entry.name) at \(tag)…")
            do {
                scan.codes.append(try archive(entry, git: git, tag: tag, repoName: manifest.repoName))
            } catch {
                scan.problems.append("code \(entry.name): \(error)")
            }
        }
        return try await withApps(scan, manifest, tag, progress)
    }

    private func withApps(_ scan: RepoScan, _ manifest: ReleaseManifest, _ tag: String,
                          _ progress: @Sendable (String) -> Void) async throws -> RepoScan {
        var scan = scan
        guard let entries = manifest.apps, !entries.isEmpty else { return scan }
        progress("Listing the assets of \(manifest.github) \(tag)…")
        let assets: [GitHubReleases.Asset]
        do {
            assets = try GitHubReleases(repo: manifest.github).assets(tag: tag)
        } catch {
            scan.problems.append("\(manifest.repoName): cannot list release assets: \(error)")
            return scan
        }
        for entry in entries {
            let matches = assets.filter { ReleaseManifest.assetMatches(pattern: entry.asset, name: $0.name) }
            guard matches.count == 1, let asset = matches.first else {
                scan.problems.append("app \(entry.stdName): \(matches.isEmpty ? "no" : "\(matches.count)") release assets match \"\(entry.asset)\"")
                continue
            }
            do {
                let did: String
                if let fromDigest = asset.did {
                    did = fromDigest
                } else {
                    progress("Downloading \(asset.name)…")
                    let file = workDir.appendingPathComponent("assets/\(manifest.repoName)/\(tag)/\(asset.name)")
                    try FileManager.default.createDirectory(at: file.deletingLastPathComponent(), withIntermediateDirectories: true)
                    if !FileManager.default.fileExists(atPath: file.path) {
                        try await downloader(URL(string: asset.url)!, file)
                    }
                    did = Hex.encode(try Hash.doubleSha256(fileAt: file)).lowercased()
                }
                scan.apps.append(LocalApp(entry: entry, tag: tag, asset: asset, did: did))
            } catch {
                scan.problems.append("app \(entry.stdName): \(error)")
            }
        }
        return scan
    }

    func archive(_ entry: ReleaseManifest.CodeEntry, git: GitRepo, tag: String, repoName: String) throws -> LocalCode {
        let entries = try git.archiveEntries(tag: tag, path: entry.path, prefix: entry.name)
        guard !entries.isEmpty else { throw GitRepo.ArchiveFailure.empty(entry.path) }
        let zip = DeterministicZip.archive(entries)
        let assetName = "\(entry.name)-\(tag).zip"
        let url = workDir.appendingPathComponent("archives/\(repoName)/\(assetName)")
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        try zip.write(to: url, options: .atomic)
        return LocalCode(entry: entry, tag: tag, zipURL: url, assetName: assetName,
                         did: Hex.encode(Hash.doubleSha256(zip)).lowercased(),
                         fileCount: entries.count, byteCount: zip.count)
    }

    /// Every `<TYPE><SN>V<VER>_<Name>.md` under `dirs`. Lower versions are
    /// kept too; the planner picks the highest per type+sn across repos.
    static func protocolDocs(root: URL, dirs: [String]) -> ([ProtocolDoc], [String]) {
        var docs: [ProtocolDoc] = [], problems: [String] = []
        let rootPath = root.standardizedFileURL.path
        for dir in dirs {
            let base = root.appendingPathComponent(dir)
            guard let walker = FileManager.default.enumerator(at: base, includingPropertiesForKeys: [.isRegularFileKey]) else {
                problems.append("\(dir): not a folder")
                continue
            }
            for case let url as URL in walker {
                guard ProtocolDoc.parseFileName(url.lastPathComponent) != nil else { continue }
                var relative = url.standardizedFileURL.path
                if relative.hasPrefix(rootPath + "/") { relative = String(relative.dropFirst(rootPath.count + 1)) }
                do {
                    docs.append(try ProtocolDoc.load(url: url, relativePath: relative))
                } catch {
                    problems.append(String(describing: error))
                }
            }
        }
        // Keep only the highest version of each type+sn within the repo,
        // so a stray older copy cannot trip the duplicate check.
        var best: [ProtocolDoc] = []
        for (_, group) in Dictionary(grouping: docs, by: \.ref) {
            let top = group.map { Int($0.ver) ?? 0 }.max()!
            let latest = group.filter { (Int($0.ver) ?? 0) == top }.sorted { $0.relativePath < $1.relativePath }
            if Set(latest.map(\.did)).count > 1 {
                problems.append("\(latest.map(\.relativePath).joined(separator: " and ")) are all \(latest[0].ref)V\(top); using \(latest[0].relativePath)")
            }
            best.append(latest[0])
        }
        return (best, problems)
    }

    public static let download: @Sendable (URL, URL) async throws -> Void = { from, to in
        let (temp, response) = try await URLSession.shared.download(from: from)
        if let http = response as? HTTPURLResponse, http.statusCode != 200 {
            throw URLError(.badServerResponse)
        }
        try? FileManager.default.removeItem(at: to)
        try FileManager.default.moveItem(at: temp, to: to)
    }
}
