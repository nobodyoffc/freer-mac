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

        progress(String(localized: "Reading protocol documents in \(manifest.repoName)…"))
        (scan.protocols, scan.problems) = Self.protocolDocs(root: root, dirs: manifest.protocolDirs ?? [])

        let hasCodes = !(manifest.codes ?? []).isEmpty, hasApps = !(manifest.apps ?? []).isEmpty
        let hasWorks = !(manifest.works ?? []).isEmpty
        guard hasCodes || hasApps || hasWorks else { return scan }
        guard let tag else {
            scan.problems.append(String(localized: "\(manifest.repoName): no release tag chosen, so its codes, apps and works were skipped"))
            return scan
        }
        if !git.hasTag(tag) { try? git.fetchTags() }
        guard git.hasTag(tag) else {
            scan.problems.append(String(localized: "\(manifest.repoName): tag \(tag) is not in the local clone; codes and repo files skipped"))
            scan = try await withApps(scan, manifest, tag, progress)
            return await withWorks(scan, manifest, tag, git: nil, progress)
        }

        for entry in manifest.codes ?? [] {
            progress(String(localized: "Archiving \(entry.name) at \(tag)…"))
            do {
                scan.codes.append(try archive(entry, git: git, tag: tag, repoName: manifest.repoName))
            } catch {
                scan.problems.append(String(localized: "code \(entry.name): \(String(describing: error))"))
            }
        }
        scan = try await withApps(scan, manifest, tag, progress)
        return await withWorks(scan, manifest, tag, git: git, progress)
    }

    /// Each work's file and DID. A release asset's DID comes from GitHub's
    /// SHA-256 when it has one; the file is downloaded only when it has
    /// not, or when it goes onto DISK. A repo file is read at the tag.
    private func withWorks(_ scan: RepoScan, _ manifest: ReleaseManifest, _ tag: String, git: GitRepo?,
                           _ progress: @Sendable (String) -> Void) async -> RepoScan {
        var scan = scan
        guard let entries = manifest.works, !entries.isEmpty else { return scan }
        let github = GitHubReleases(repo: manifest.github)
        var assets: [GitHubReleases.Asset]?
        if entries.contains(where: { $0.asset != nil }) {
            progress(String(localized: "Listing the assets of \(manifest.github) \(tag)…"))
            do {
                assets = try github.assets(tag: tag)
            } catch {
                scan.problems.append(String(localized: "\(manifest.repoName): cannot list release assets for its works: \(String(describing: error))"))
            }
        }
        for entry in entries {
            do {
                let fileName: String, link: String, did: String
                var file: URL?, size: Int64?
                if let pattern = entry.asset {
                    guard let assets else { continue }
                    let matches = assets.filter { ReleaseManifest.assetMatches(pattern: pattern, name: $0.name) }
                    guard matches.count == 1, let asset = matches.first else {
                        scan.problems.append(String(localized: "work \(entry.title): \(matches.isEmpty ? "no" : "\(matches.count)") release assets match \"\(pattern)\""))
                        continue
                    }
                    fileName = asset.name
                    link = asset.url
                    size = asset.size
                    if let fromDigest = asset.did, entry.disk != true {
                        did = fromDigest
                    } else {
                        progress(String(localized: "Downloading \(asset.name)…"))
                        let local = workDir.appendingPathComponent("assets/\(manifest.repoName)/\(tag)/\(asset.name)")
                        try FileManager.default.createDirectory(at: local.deletingLastPathComponent(), withIntermediateDirectories: true)
                        if !FileManager.default.fileExists(atPath: local.path) {
                            try await downloader(URL(string: asset.url)!, local)
                        }
                        did = Hex.encode(try Hash.doubleSha256(fileAt: local)).lowercased()
                        if let fromDigest = asset.did, fromDigest != did {
                            throw RunFailure.didChanged(asset.name)
                        }
                        file = local
                    }
                } else if let path = entry.path {
                    guard let git else {
                        scan.problems.append(String(localized: "work \(entry.title): \(path) cannot be read without tag \(tag) in the local clone"))
                        continue
                    }
                    progress(String(localized: "Reading \(path) at \(tag)…"))
                    let data = try git.file(tag: tag, path: path)
                    let local = workDir.appendingPathComponent("files/\(manifest.repoName)/\(tag)/\(path)")
                    try FileManager.default.createDirectory(at: local.deletingLastPathComponent(), withIntermediateDirectories: true)
                    try data.write(to: local, options: .atomic)
                    fileName = (path as NSString).lastPathComponent
                    link = github.rawLink(tag: tag, path: path)
                    size = Int64(data.count)
                    did = Hex.encode(Hash.doubleSha256(data)).lowercased()
                    file = local
                } else {
                    continue
                }
                let (locas, dropped) = LocalWork.locas(link: link, entry: entry, tag: tag, fileName: fileName)
                if !dropped.isEmpty {
                    scan.problems.append(String(localized: "work \(entry.title): at most \(String(LocalWork.maxLocas)) locations, so \(dropped.joined(separator: ", ")) is left out"))
                }
                scan.works.append(LocalWork(entry: entry, tag: tag, fileName: fileName, fileURL: file,
                                            did: did, size: size, locas: locas))
            } catch {
                scan.problems.append(String(localized: "work \(entry.title): \(String(describing: error))"))
            }
        }
        return scan
    }

    private func withApps(_ scan: RepoScan, _ manifest: ReleaseManifest, _ tag: String,
                          _ progress: @Sendable (String) -> Void) async throws -> RepoScan {
        var scan = scan
        guard let entries = manifest.apps, !entries.isEmpty else { return scan }
        progress(String(localized: "Listing the assets of \(manifest.github) \(tag)…"))
        let assets: [GitHubReleases.Asset]
        do {
            assets = try GitHubReleases(repo: manifest.github).assets(tag: tag)
        } catch {
            scan.problems.append(String(localized: "\(manifest.repoName): cannot list release assets: \(String(describing: error))"))
            return scan
        }
        for entry in entries {
            let matches = assets.filter { ReleaseManifest.assetMatches(pattern: entry.asset, name: $0.name) }
            guard matches.count == 1, let asset = matches.first else {
                scan.problems.append(String(localized: "app \(entry.stdName): \(matches.isEmpty ? "no" : "\(matches.count)") release assets match \"\(entry.asset)\""))
                continue
            }
            do {
                let did: String
                if let fromDigest = asset.did {
                    did = fromDigest
                } else {
                    progress(String(localized: "Downloading \(asset.name)…"))
                    let file = workDir.appendingPathComponent("assets/\(manifest.repoName)/\(tag)/\(asset.name)")
                    try FileManager.default.createDirectory(at: file.deletingLastPathComponent(), withIntermediateDirectories: true)
                    if !FileManager.default.fileExists(atPath: file.path) {
                        try await downloader(URL(string: asset.url)!, file)
                    }
                    did = Hex.encode(try Hash.doubleSha256(fileAt: file)).lowercased()
                }
                scan.apps.append(LocalApp(entry: entry, tag: tag, asset: asset, did: did))
            } catch {
                scan.problems.append(String(localized: "app \(entry.stdName): \(String(describing: error))"))
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
                problems.append(String(localized: "\(dir): not a folder"))
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
                problems.append(String(localized: "\(latest.map(\.relativePath).joined(separator: " and ")) are all \(String(describing: latest[0].ref))V\(String(top)); using \(latest[0].relativePath)"))
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
