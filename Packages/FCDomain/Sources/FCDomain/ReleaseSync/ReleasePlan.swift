import Foundation
import FCCore

/// What Release Sync found in one repo folder: its manifest, its protocol
/// documents, and the codes and apps of the chosen release tag, all with
/// their DIDs computed.
public struct RepoScan: Sendable {
    public var root: URL
    public var manifest: ReleaseManifest
    public var tag: String?
    /// Branch the protocol `home` links point at.
    public var branch: String
    public var protocols: [ProtocolDoc]
    public var codes: [LocalCode]
    public var apps: [LocalApp]
    /// Files or entries skipped, with the reason.
    public var problems: [String]

    public init(root: URL, manifest: ReleaseManifest, tag: String?, branch: String,
                protocols: [ProtocolDoc] = [], codes: [LocalCode] = [], apps: [LocalApp] = [],
                problems: [String] = []) {
        self.root = root
        self.manifest = manifest
        self.tag = tag
        self.branch = branch
        self.protocols = protocols
        self.codes = codes
        self.apps = apps
        self.problems = problems
    }

    public var github: GitHubReleases { GitHubReleases(repo: manifest.github) }
}

public struct LocalCode: Sendable {
    public var entry: ReleaseManifest.CodeEntry
    public var tag: String
    /// The archive, written to the work folder.
    public var zipURL: URL
    /// `<name>-<tag>.zip`, its asset name on the release.
    public var assetName: String
    public var did: String
    public var fileCount: Int
    public var byteCount: Int

    public init(entry: ReleaseManifest.CodeEntry, tag: String, zipURL: URL, assetName: String,
                did: String, fileCount: Int, byteCount: Int) {
        self.entry = entry
        self.tag = tag
        self.zipURL = zipURL
        self.assetName = assetName
        self.did = did
        self.fileCount = fileCount
        self.byteCount = byteCount
    }
}

public struct LocalApp: Sendable {
    public var entry: ReleaseManifest.AppEntry
    public var tag: String
    public var asset: GitHubReleases.Asset
    public var did: String

    public init(entry: ReleaseManifest.AppEntry, tag: String, asset: GitHubReleases.Asset, did: String) {
        self.entry = entry
        self.tag = tag
        self.asset = asset
        self.did = did
    }
}

/// What one entity needs.
public enum ReleaseAction: Equatable, Sendable {
    case publish
    case update(id: String)
    case unchanged(id: String)
    /// The record exists but cannot take an update (closed, or stopped:
    /// the parsers ignore an update to an inactive record).
    case blocked(id: String, reason: String)
    /// More than one on-chain record has this key; the user must choose.
    case ambiguous(ids: [String])
    /// The local side could not be read or would not fit an OP_RETURN.
    case invalid(String)
    /// Carved by an earlier run (same DID, per the run log) and not on
    /// chain yet. `id` is the entity's id once it lands: the txid for a
    /// publish. `stale` after ``ReleasePlanner/pendingExpiry`` without
    /// confirming: the broadcast may have been dropped.
    case pending(id: String, txid: String, since: Date, stale: Bool)

    public var carves: Bool {
        switch self {
        case .publish, .update: return true
        default: return false
        }
    }

    public var targetId: String? {
        switch self {
        case .update(let id), .unchanged(let id), .blocked(let id, _), .pending(let id, _, _, _): return id
        default: return nil
        }
    }
}

/// A reference to an id that may not exist until an earlier carve of the
/// same run goes out.
public enum IdRef: Hashable, Sendable, CustomStringConvertible {
    case known(String)
    case protocolInRun(ProtocolRef)
    case codeInRun(String)
    /// Named in a manifest but found neither on chain nor in this run.
    case unresolved(String)

    public var description: String {
        switch self {
        case .known(let id): return id
        case .protocolInRun(let ref): return "‹pid of \(ref)›"
        case .codeInRun(let name): return "‹codeId of \(name)›"
        case .unresolved(let name): return "‹unknown \(name)›"
        }
    }

    public var knownId: String? {
        if case .known(let id) = self { return id }
        return nil
    }
}

public struct ProtocolPlanItem: Identifiable, Sendable {
    public var id: String { doc.ref.description }
    public var doc: ProtocolDoc
    public var repo: URL
    public var action: ReleaseAction
    public var record: ProtocolSpec?
    public var home: [String: String]?
    /// The document's DID as it will be carved: with the PID filled in for
    /// an update, as-is for a publish.
    public var carveDid: String
    public var desc: String?
}

public struct CodePlanItem: Identifiable, Sendable {
    public var id: String { local.entry.name }
    public var local: LocalCode
    public var repo: RepoScan
    public var action: ReleaseAction
    public var record: Code?
    public var protocols: [IdRef]
    public var home: [String: String]
    public var desc: String?
}

public struct AppPlanItem: Identifiable, Sendable {
    public var id: String { local.entry.stdName }
    public var local: LocalApp
    public var repo: RepoScan
    public var action: ReleaseAction
    public var record: AppRecord?
    public var protocols: [IdRef]
    public var codes: [IdRef]
    public var home: [String: String]
    public var desc: String?
}

public struct ReleasePlan: Sendable {
    public var owner: String
    public var protocols: [ProtocolPlanItem]
    public var codes: [CodePlanItem]
    public var apps: [AppPlanItem]
    /// On-chain records of the owner that no local entity claims.
    public var orphanProtocols: [ProtocolSpec]
    public var orphanCodes: [Code]
    public var orphanApps: [AppRecord]
    public var problems: [String]

    public var carveCount: Int {
        protocols.filter { $0.action.carves }.count
            + codes.filter { $0.action.carves }.count
            + apps.filter { $0.action.carves }.count
    }
}

/// Diffs the scanned repos against the chain. Pure: no I/O.
public enum ReleasePlanner {

    /// Key of an entity for ``plan(scans:chain:owner:choices:)``'s `choices`.
    public static func choiceKey(protocol ref: ProtocolRef) -> String { "protocol:\(ref)" }
    public static func choiceKey(code name: String) -> String { "code:\(name)" }
    public static func choiceKey(app stdName: String) -> String { "app:\(stdName)" }

    /// - Parameter choices: for a key with several on-chain records, the
    ///   record the user picked (see the `choiceKey` functions).
    /// How long a carve may stay unconfirmed before it is shown as
    /// possibly dropped, the same expiry the app gives other pending carves.
    public static let pendingExpiry: TimeInterval = 2 * 3600

    /// - Parameter log: carves of earlier runs. An entity whose carve is
    ///   logged for the same DID but not on chain yet is ``ReleaseAction/pending``.
    public static func plan(scans: [RepoScan], chain: ReleaseChainState, owner: String,
                            choices: [String: String] = [:], log: ReleaseRunLog = ReleaseRunLog(),
                            now: Date = Date()) -> ReleasePlan {
        var problems = scans.flatMap(\.problems)
        func pending(_ action: ReleaseAction, key: String, did: String) -> ReleaseAction {
            guard action.carves, let entry = log.entries[key] else { return action }
            // A second publish while the first is unconfirmed would make a
            // duplicate record, so a pending publish holds whatever the DID
            // is now; the edit becomes an update once it lands. A later
            // update just supersedes a pending one, so only the same DID holds.
            if case .update = action, entry.did != did { return action }
            return .pending(id: entry.id, txid: entry.txid, since: entry.at,
                            stale: now.timeIntervalSince(entry.at) > pendingExpiry)
        }
        func pick<T: Identifiable>(_ all: [T], _ key: String) -> [T] where T.ID == String {
            guard all.count > 1, let id = choices[key], let one = all.first(where: { $0.id == id }) else { return all }
            return [one]
        }

        // MARK: protocols — one per type+sn across every repo, highest ver.
        var chosen: [ProtocolRef: (ProtocolDoc, URL, RepoScan)] = [:]
        for scan in scans {
            for doc in scan.protocols {
                if let (have, _, _) = chosen[doc.ref] {
                    let a = Int(have.ver) ?? 0, b = Int(doc.ver) ?? 0
                    if b > a {
                        chosen[doc.ref] = (doc, scan.root, scan)
                    } else if a == b && have.did != doc.did {
                        problems.append("\(have.relativePath) and \(doc.relativePath) are both \(doc.ref)V\(doc.ver) but differ; using \(have.relativePath)")
                    }
                } else {
                    chosen[doc.ref] = (doc, scan.root, scan)
                }
            }
        }
        let chainByRef = Dictionary(grouping: chain.protocols) { p in
            ProtocolRef(type: p.type ?? "", sn: p.sn.flatMap { Int($0) }.map(String.init) ?? (p.sn ?? ""))
        }
        let chainById = Dictionary(chain.protocols.map { ($0.id, $0) }, uniquingKeysWith: { a, _ in a })
        var claimed = Set<String>()
        var protocolItems: [ProtocolPlanItem] = []
        for (ref, (doc, root, scan)) in chosen.sorted(by: { refOrder($0.key, $1.key) }) {
            let found: [ProtocolSpec]
            if let pid = doc.pid {
                if let record = chainById[pid] {
                    found = [record]
                } else {
                    protocolItems.append(protocolItem(doc, root, scan, action: .invalid("its PID \(pid.prefix(12))… is not a protocol of \(owner)"), record: nil))
                    continue
                }
            } else {
                found = chainByRef[ref] ?? []
            }
            (chainByRef[ref] ?? []).forEach { claimed.insert($0.id) }
            let candidates = pick(found, choiceKey(protocol: ref))
            candidates.forEach { claimed.insert($0.id) }
            guard let record = candidates.first else {
                protocolItems.append(protocolItem(doc, root, scan, action: .publish, record: nil))
                continue
            }
            guard candidates.count == 1 else {
                protocolItems.append(protocolItem(doc, root, scan, action: .ambiguous(ids: candidates.map(\.id)), record: nil))
                continue
            }
            protocolItems.append(protocolItem(doc, root, scan, action: protocolAction(doc, record), record: record))
        }
        let orphanProtocols = chain.protocols.filter { !claimed.contains($0.id) }
        for i in protocolItems.indices {
            protocolItems[i].action = pending(protocolItems[i].action,
                                              key: choiceKey(protocol: protocolItems[i].doc.ref), did: protocolItems[i].carveDid)
        }

        // MARK: codes
        let protocolIds: [ProtocolRef: IdRef] = Dictionary(uniqueKeysWithValues: protocolItems.map { item in
            switch item.action {
            case .publish: return (item.doc.ref, IdRef.protocolInRun(item.doc.ref))
            default:
                if let id = item.action.targetId { return (item.doc.ref, .known(id)) }
                return (item.doc.ref, .unresolved(item.doc.ref.description))
            }
        })
        func resolveProtocol(_ text: String) -> IdRef {
            if ReleaseManifest.isRawId(text) { return .known(text.lowercased()) }
            guard let ref = ProtocolRef(text) else { return .unresolved(text) }
            if let id = protocolIds[ref] { return id }
            let onChain = chainByRef[ref] ?? []
            if onChain.count == 1 { return .known(onChain[0].id) }
            return .unresolved(text)
        }

        let chainCodes = Dictionary(grouping: chain.codes) { $0.name ?? "" }
        var claimedCodes = Set<String>()
        var codeItems: [CodePlanItem] = []
        for scan in scans {
            for local in scan.codes {
                let all = chainCodes[local.entry.name] ?? []
                let candidates = pick(all, choiceKey(code: local.entry.name))
                all.forEach { claimedCodes.insert($0.id) }
                let refs = (local.entry.protocols ?? []).map(resolveProtocol)
                let github = scan.github
                var home = candidates.count == 1 ? (candidates[0].home ?? [:]) : [:]
                home["src"] = github.treeLink(tag: local.tag, path: local.entry.path)
                home["zip"] = github.assetLink(tag: local.tag, name: local.assetName)
                var item = CodePlanItem(local: local, repo: scan, action: .publish, record: nil,
                                        protocols: refs, home: home, desc: local.entry.desc)
                if candidates.count > 1 {
                    item.action = .ambiguous(ids: candidates.map(\.id))
                } else if let record = candidates.first {
                    item.record = record
                    item.action = codeAction(local, refs, record)
                }
                item.action = pending(item.action, key: choiceKey(code: local.entry.name), did: local.did)
                codeItems.append(item)
            }
        }
        let orphanCodes = chain.codes.filter { !claimedCodes.contains($0.id) }

        // MARK: apps
        func resolveCode(_ text: String) -> IdRef {
            if ReleaseManifest.isRawId(text) { return .known(text.lowercased()) }
            let name = text.split(separator: "/").last.map(String.init) ?? text
            if let item = codeItems.first(where: { $0.local.entry.name == name }) {
                if case .publish = item.action { return .codeInRun(name) }
                if let id = item.action.targetId { return .known(id) }
                return .unresolved(text)
            }
            let onChain = chainCodes[name] ?? []
            return onChain.count == 1 ? .known(onChain[0].id) : .unresolved(text)
        }
        let chainApps = Dictionary(grouping: chain.apps) { $0.stdName ?? "" }
        var claimedApps = Set<String>()
        var appItems: [AppPlanItem] = []
        for scan in scans {
            for local in scan.apps {
                let all = chainApps[local.entry.stdName] ?? []
                let candidates = pick(all, choiceKey(app: local.entry.stdName))
                all.forEach { claimedApps.insert($0.id) }
                let protocols = (local.entry.protocols ?? []).map(resolveProtocol)
                let codes = (local.entry.codes ?? []).map(resolveCode)
                var home = candidates.count == 1 ? (candidates[0].home ?? [:]) : [:]
                home["src"] = scan.github.releasePage(tag: local.tag)
                var item = AppPlanItem(local: local, repo: scan, action: .publish, record: nil,
                                       protocols: protocols, codes: codes, home: home, desc: local.entry.desc)
                if candidates.count > 1 {
                    item.action = .ambiguous(ids: candidates.map(\.id))
                } else if let record = candidates.first {
                    item.record = record
                    item.action = appAction(local, protocols: protocols, codes: codes, record)
                }
                item.action = pending(item.action, key: choiceKey(app: local.entry.stdName), did: local.did)
                appItems.append(item)
            }
        }
        let orphanApps = chain.apps.filter { !claimedApps.contains($0.id) }

        for item in codeItems {
            for case .unresolved(let name) in item.protocols where item.action.carves {
                problems.append("code \(item.local.entry.name): protocol \(name) is neither on chain nor in this run")
            }
        }
        for item in appItems where item.action.carves {
            for case .unresolved(let name) in item.protocols + item.codes {
                problems.append("app \(item.local.entry.stdName): \(name) is neither on chain nor in this run")
            }
        }

        return ReleasePlan(owner: owner, protocols: protocolItems, codes: codeItems, apps: appItems,
                           orphanProtocols: orphanProtocols, orphanCodes: orphanCodes, orphanApps: orphanApps,
                           problems: problems)
    }

    // MARK: - per-entity rules

    static func refOrder(_ a: ProtocolRef, _ b: ProtocolRef) -> Bool {
        a.type != b.type ? a.type < b.type : (Int(a.sn) ?? 0) < (Int(b.sn) ?? 0)
    }

    static func protocolItem(_ doc: ProtocolDoc, _ root: URL, _ scan: RepoScan,
                             action: ReleaseAction, record: ProtocolSpec?) -> ProtocolPlanItem {
        var home = record?.home ?? [:]
        home["src"] = scan.github.blobLink(ref: scan.branch, path: doc.relativePath)
        var carveDid = doc.did
        var action = action
        if case .update(let pid) = action {
            do {
                carveDid = try ReleaseSyncFiles.didWithPid(pid, doc: doc)
            } catch {
                action = .invalid("cannot write the PID into it: \(error)")
            }
        }
        return ProtocolPlanItem(doc: doc, repo: root, action: action, record: record,
                                home: home, carveDid: carveDid, desc: doc.desc)
    }

    /// Decided by the DID alone: the document is the protocol. A document
    /// that differs only by its own PID row (filled in by a previous run
    /// and not yet saved, say) is the same document.
    static func protocolAction(_ doc: ProtocolDoc, _ record: ProtocolSpec) -> ReleaseAction {
        if record.closed == true { return .blocked(id: record.id, reason: "closed on chain") }
        if record.did == doc.did { return .unchanged(id: record.id) }
        if doc.pid == nil, let filled = try? ReleaseSyncFiles.didWithPid(record.id, doc: doc), filled == record.did {
            return .unchanged(id: record.id)
        }
        if record.active == false { return .blocked(id: record.id, reason: "stopped on chain; recover it first") }
        return .update(id: record.id)
    }

    /// A code changes when its archive does, or when the manifest says
    /// something new about it.
    static func codeAction(_ local: LocalCode, _ refs: [IdRef], _ record: Code) -> ReleaseAction {
        if record.closed == true { return .blocked(id: record.id, reason: "closed on chain") }
        let same = record.did == local.did
            && clean(record.desc) == clean(local.entry.desc)
            && Set(record.langs ?? []) == Set(local.entry.langs ?? [])
            && Set(record.protocols ?? []) == Set(refs.map(\.description))
        if same { return .unchanged(id: record.id) }
        if record.active == false { return .blocked(id: record.id, reason: "stopped on chain; recover it first") }
        return .update(id: record.id)
    }

    static func appAction(_ local: LocalApp, protocols: [IdRef], codes: [IdRef], _ record: AppRecord) -> ReleaseAction {
        if record.closed == true { return .blocked(id: record.id, reason: "closed on chain") }
        let same = Set((record.downloads ?? []).compactMap(\.did)) == [local.did]
            && clean(record.desc) == clean(local.entry.desc)
            && Set(record.types ?? []) == Set(local.entry.types ?? [])
            && Set(record.protocols ?? []) == Set(protocols.map(\.description))
            && Set(record.codes ?? []) == Set(codes.map(\.description))
        if same { return .unchanged(id: record.id) }
        if record.active == false { return .blocked(id: record.id, reason: "stopped on chain; recover it first") }
        return .update(id: record.id)
    }

    static func clean(_ s: String?) -> String? {
        guard let t = s?.trimmingCharacters(in: .whitespacesAndNewlines), !t.isEmpty else { return nil }
        return t
    }
}

/// File edits Release Sync makes in a repo.
public enum ReleaseSyncFiles {
    public static func didWithPid(_ pid: String, doc: ProtocolDoc) throws -> String {
        let filled = try ProtocolDoc.fillingPid(pid, in: Data(contentsOf: doc.url))
        return Hex.encode(Hash.doubleSha256(filled)).lowercased()
    }

    /// Writes the PID into the document on disk and returns its new DID.
    @discardableResult
    public static func writePid(_ pid: String, doc: ProtocolDoc) throws -> String {
        let filled = try ProtocolDoc.fillingPid(pid, in: Data(contentsOf: doc.url))
        try filled.write(to: doc.url, options: .atomic)
        return Hex.encode(Hash.doubleSha256(filled)).lowercased()
    }
}
