import Foundation
import FCCore

/// The side effects a run needs. ``SessionReleaseBackend`` is the real one.
public protocol ReleaseSyncBackend: Sendable {
    /// Puts the file on DISK permanently, as a HAT in the main FID's Files.
    func storeOnDisk(_ file: URL, name: String) async throws
    /// Uploads the file to a GitHub release, replacing a same-named asset.
    func uploadAsset(_ file: URL, repo: String, tag: String) async throws
    func carveProtocol(_ fields: ProtocolCarve) async throws -> String
    func carveCode(_ fields: CodeCarve) async throws -> String
    func carveApp(_ fields: AppCarve) async throws -> String
    /// Whether the record `id` has absorbed the carve `txid` on chain.
    func isConfirmed(kind: ReleaseEntityKind, id: String, txid: String) async throws -> Bool
}

/// One carve, as it will go out, offered for review before anything is
/// written, uploaded or signed.
public enum ReleaseDraft: Sendable, Equatable {
    case `protocol`(ProtocolCarve)
    case code(CodeCarve)
    case app(AppCarve)
}

/// Shows each carve to the user before it goes out.
public protocol ReleaseReviewer: Sendable {
    /// The fields to carve (possibly edited), or nil to skip this one.
    /// Throws `CancellationError` to stop the run.
    func review(_ draft: ReleaseDraft) async throws -> ReleaseDraft?
}

public enum ReleaseEntityKind: String, Codable, Sendable {
    case `protocol`, code, app
}

/// The fields of one carve, ids resolved. `targetId` nil means publish.
public struct ProtocolCarve: Equatable, Sendable {
    public var targetId: String?
    public var name: String, type: String, sn: String, ver: String, did: String
    public var desc: String?, lang: String?
    public var home: [String: String]?
    public var preDid: String?
    public var waiters: [String]?

    public func json() throws -> String {
        if let targetId {
            return try ProtocolFeip.updateCarve(pid: targetId, sn: sn, name: name, type: type, ver: ver, did: did,
                                                desc: desc, lang: lang, home: home, preDid: preDid, waiters: waiters)
        }
        return try ProtocolFeip.publishCarve(sn: sn, name: name, type: type, ver: ver, did: did,
                                             desc: desc, lang: lang, home: home, preDid: preDid, waiters: waiters)
    }
}

public struct CodeCarve: Equatable, Sendable {
    public var targetId: String?
    public var name: String, ver: String, did: String
    public var desc: String?
    public var langs: [String]?
    public var home: [String: String]?
    public var protocols: [String]?
    public var waiters: [String]?

    public func json() throws -> String {
        if let targetId {
            return try CodeFeip.updateCarve(codeId: targetId, name: name, ver: ver, did: did, desc: desc,
                                            langs: langs, home: home, protocols: protocols, waiters: waiters)
        }
        return try CodeFeip.publishCarve(name: name, ver: ver, did: did, desc: desc,
                                         langs: langs, home: home, protocols: protocols, waiters: waiters)
    }
}

public struct AppCarve: Equatable, Sendable {
    public var targetId: String?
    public var stdName: String, ver: String
    public var localNames: [String: String]?
    public var types: [String]?
    public var desc: String?
    public var home: [String: String]?
    public var downloads: [AppRecord.Download]
    public var waiters: [String]?
    public var protocols: [String]?
    public var codes: [String]?
    public var services: [String]?

    public func json() throws -> String {
        if let targetId {
            return try AppFeip.updateCarve(aid: targetId, stdName: stdName, localNames: localNames, types: types,
                                           desc: desc, ver: ver, home: home, downloads: downloads, waiters: waiters,
                                           protocols: protocols, codes: codes, services: services)
        }
        return try AppFeip.publishCarve(stdName: stdName, localNames: localNames, types: types, desc: desc,
                                        ver: ver, home: home, downloads: downloads, waiters: waiters,
                                        protocols: protocols, codes: codes, services: services)
    }
}

/// Builds the carve for each plan item. With `ids` nil, ids that do not
/// exist yet are stood in for by 64-character placeholders, so the size
/// check sees the real length.
public enum ReleaseCarves {
    static let placeholderId = String(repeating: "0", count: 64)

    static func resolve(_ ref: IdRef, _ ids: [IdRef: String]?) -> String? {
        if let id = ref.knownId { return id }
        guard let ids else { return placeholderId }
        return ids[ref]
    }

    public static func protocolCarve(_ item: ProtocolPlanItem) throws -> ProtocolCarve {
        let doc = item.doc, record = item.record
        var carve = ProtocolCarve(
            targetId: item.action.targetId, name: doc.name, type: doc.type, sn: doc.sn, ver: doc.ver,
            did: item.carveDid, desc: item.desc, lang: doc.lang, home: item.home,
            // An update replaces the whole record: carry over what the
            // document does not say.
            preDid: record?.prePid, waiters: record?.waiters
        )
        carve.desc = try fitDesc(carve.desc) { d in var c = carve; c.desc = d; return try c.json() }
        return carve
    }

    public static func codeCarve(_ item: CodePlanItem, ids: [IdRef: String]?) throws -> CodeCarve {
        let protocols = try item.protocols.map { ref -> String in
            guard let id = resolve(ref, ids) else { throw RunFailure.unresolved(ref.description) }
            return id
        }
        var carve = CodeCarve(
            targetId: item.action.targetId, name: item.local.entry.name, ver: item.local.tag, did: item.local.did,
            desc: item.desc, langs: item.local.entry.langs, home: item.home,
            protocols: protocols.isEmpty ? nil : protocols, waiters: item.record?.waiters
        )
        carve.desc = try fitDesc(carve.desc) { d in var c = carve; c.desc = d; return try c.json() }
        return carve
    }

    public static func appCarve(_ item: AppPlanItem, ids: [IdRef: String]?) throws -> AppCarve {
        func resolved(_ refs: [IdRef]) throws -> [String]? {
            let out = try refs.map { ref -> String in
                guard let id = resolve(ref, ids) else { throw RunFailure.unresolved(ref.description) }
                return id
            }
            return out.isEmpty ? nil : out
        }
        let local = item.local, record = item.record
        var carve = AppCarve(
            targetId: item.action.targetId, stdName: local.entry.stdName, ver: local.tag,
            localNames: local.entry.localNames ?? record?.localNames, types: local.entry.types,
            desc: item.desc, home: item.home,
            downloads: [AppRecord.Download(os: local.entry.os, link: local.asset.url, did: local.did)],
            waiters: record?.waiters, protocols: try resolved(item.protocols), codes: try resolved(item.codes),
            services: record?.services
        )
        carve.desc = try fitDesc(carve.desc) { d in var c = carve; c.desc = d; return try c.json() }
        return carve
    }

    /// The longest prefix of `desc` (cut at a word, ending in "…") with
    /// which `build` fits the OP_RETURN; `build`'s own error if even no
    /// description is too big.
    static func fitDesc(_ desc: String?, _ build: (String?) throws -> String) throws -> String? {
        guard let desc, !desc.isEmpty else { _ = try build(nil); return nil }
        if (try? build(desc)) != nil { return desc }
        _ = try build(nil)
        let chars = Array(desc)
        var lo = 0, hi = chars.count
        while lo < hi {
            let mid = (lo + hi + 1) / 2
            if (try? build(clip(chars, mid))) != nil { lo = mid } else { hi = mid - 1 }
        }
        return lo == 0 ? nil : clip(chars, lo)
    }

    static func clip(_ chars: [Character], _ n: Int) -> String {
        var s = String(chars.prefix(max(0, n - 1)))
        if let space = s.lastIndex(of: " "), s.distance(from: space, to: s.endIndex) < 40 {
            s = String(s[..<space])
        }
        return s + "…"
    }
}

public enum RunFailure: Error, CustomStringConvertible, Equatable {
    case unresolved(String)
    case didChanged(String)

    public var description: String {
        switch self {
        case .unresolved(let what): return "\(what) has no id: its own carve did not go out"
        case .didChanged(let file): return "\(file) changed after the scan; scan again"
        }
    }
}

/// What a run has carved, kept on disk so an interrupted run resumes
/// without carving anything twice.
public struct ReleaseRunLog: Codable, Equatable, Sendable {
    public struct Entry: Codable, Equatable, Sendable {
        public var kind: ReleaseEntityKind
        /// The entity's id after this carve: the txid for a publish.
        public var id: String
        public var txid: String
        public var did: String
        public var at: Date
    }
    /// Keyed by ``ReleasePlanner`` choice keys (`protocol:FEIP1`, …).
    public var entries: [String: Entry] = [:]

    public init() {}

    public static func load(_ url: URL) -> ReleaseRunLog {
        (try? JSONDecoder().decode(ReleaseRunLog.self, from: Data(contentsOf: url))) ?? ReleaseRunLog()
    }

    /// Forgets one carve, so the entity can be carved again: for a
    /// broadcast that never confirmed.
    public static func forget(_ key: String, at url: URL) throws {
        var log = load(url)
        log.entries[key] = nil
        try log.save(url)
    }

    public func save(_ url: URL) throws {
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        try encoder.encode(self).write(to: url, options: .atomic)
    }
}

public enum ReleaseRunEvent: Sendable, Equatable {
    case step(key: String, String)
    case carved(key: String, txid: String)
    case skipped(key: String, String)
    case failed(key: String, String)
    case waiting(unconfirmed: Int)
    case pidWritten(file: String)
    /// Review edits written back to a repo's manifest.
    case manifestUpdated(file: String)
}

struct ReviewSkipped: Error {}

/// Carries out a plan: protocols, then codes, then apps.
public struct ReleaseRunner: Sendable {
    public let backend: any ReleaseSyncBackend
    public let logURL: URL
    public var maxUnconfirmed = 20
    public var pollInterval: Duration = .seconds(30)
    /// Asked before each carve; nil carves without asking.
    public var reviewer: (any ReleaseReviewer)?

    public init(backend: any ReleaseSyncBackend, logURL: URL) {
        self.backend = backend
        self.logURL = logURL
    }

    struct Pending { let kind: ReleaseEntityKind; let id: String; let txid: String }

    /// - Parameter selected: plan item keys (choice keys) to carve.
    public func run(_ plan: ReleasePlan, selected: Set<String>,
                    events: @Sendable (ReleaseRunEvent) -> Void) async throws {
        var log = ReleaseRunLog.load(logURL)
        var ids: [IdRef: String] = [:]
        var pending: [Pending] = []

        func record(_ key: String, _ kind: ReleaseEntityKind, id: String, txid: String, did: String) throws {
            log.entries[key] = .init(kind: kind, id: id, txid: txid, did: did, at: Date())
            try log.save(logURL)
            pending.append(Pending(kind: kind, id: id, txid: txid))
            events(.carved(key: key, txid: txid))
        }

        func waitForRoom() async throws {
            while pending.count >= maxUnconfirmed {
                events(.waiting(unconfirmed: pending.count))
                try await Task.sleep(for: pollInterval)
                var still: [Pending] = []
                for p in pending {
                    let done = (try? await backend.isConfirmed(kind: p.kind, id: p.id, txid: p.txid)) ?? false
                    if !done { still.append(p) }
                }
                pending = still
            }
        }

        /// A carve already in the log for the same DID is not repeated.
        func alreadyCarved(_ key: String, did: String) -> ReleaseRunLog.Entry? {
            guard let entry = log.entries[key], entry.did == did else { return nil }
            return entry
        }

        // Ids carved by an earlier run, whether or not their items are
        // selected now: a code published last run and not parsed yet is
        // still `publish` in the plan, and an app picked alone this run
        // must reference it.
        for item in plan.protocols where item.action.carves {
            if let entry = alreadyCarved(ReleasePlanner.choiceKey(protocol: item.doc.ref), did: item.carveDid) {
                ids[.protocolInRun(item.doc.ref)] = entry.id
            }
        }
        for item in plan.codes where item.action.carves {
            if let entry = alreadyCarved(ReleasePlanner.choiceKey(code: item.local.entry.name), did: item.local.did) {
                ids[.codeInRun(item.local.entry.name)] = entry.id
            }
        }

        // MARK: protocols
        for item in plan.protocols where item.action.carves {
            let key = ReleasePlanner.choiceKey(protocol: item.doc.ref)
            let ref = IdRef.protocolInRun(item.doc.ref)
            guard selected.contains(key) else { continue }
            if let entry = alreadyCarved(key, did: item.carveDid) {
                ids[ref] = entry.id
                events(.skipped(key: key, "already carved in \(entry.txid.prefix(12))…"))
                continue
            }
            do {
                try Task.checkCancellation()
                var carve = try ReleaseCarves.protocolCarve(item)
                if let reviewer {
                    guard case .protocol(let reviewed)? = try await reviewer.review(.protocol(carve)) else {
                        throw ReviewSkipped()
                    }
                    carve = reviewed
                }
                if case .update(let pid) = item.action, item.doc.pid != pid {
                    let did = try ReleaseSyncFiles.writePid(pid, doc: item.doc)
                    guard did == item.carveDid else { throw RunFailure.didChanged(item.doc.relativePath) }
                    events(.pidWritten(file: item.doc.relativePath))
                } else {
                    let did = Hex.encode(Hash.doubleSha256(try Data(contentsOf: item.doc.url))).lowercased()
                    guard did == item.carveDid else { throw RunFailure.didChanged(item.doc.relativePath) }
                }
                events(.step(key: key, "storing \(item.doc.url.lastPathComponent) on DISK"))
                try await backend.storeOnDisk(item.doc.url, name: item.doc.url.lastPathComponent)
                try await waitForRoom()
                events(.step(key: key, "carving"))
                let txid = try await backend.carveProtocol(carve)
                let id = item.action.targetId ?? txid
                ids[ref] = id
                try record(key, .protocol, id: id, txid: txid, did: item.carveDid)
            } catch is CancellationError {
                throw CancellationError()
            } catch is ReviewSkipped {
                events(.skipped(key: key, "skipped in review"))
            } catch {
                events(.failed(key: key, String(describing: error)))
            }
        }

        // MARK: codes
        for item in plan.codes where item.action.carves {
            let key = ReleasePlanner.choiceKey(code: item.local.entry.name)
            let ref = IdRef.codeInRun(item.local.entry.name)
            guard selected.contains(key) else { continue }
            if let entry = alreadyCarved(key, did: item.local.did) {
                ids[ref] = entry.id
                events(.skipped(key: key, "already carved in \(entry.txid.prefix(12))…"))
                continue
            }
            do {
                try Task.checkCancellation()
                var carve = try ReleaseCarves.codeCarve(item, ids: ids)
                let original = carve
                if let reviewer {
                    guard case .code(let reviewed)? = try await reviewer.review(.code(carve)) else {
                        throw ReviewSkipped()
                    }
                    carve = reviewed
                }
                events(.step(key: key, "storing \(item.local.assetName) on DISK"))
                try await backend.storeOnDisk(item.local.zipURL, name: item.local.assetName)
                events(.step(key: key, "uploading \(item.local.assetName) to GitHub"))
                try await backend.uploadAsset(item.local.zipURL, repo: item.repo.manifest.github, tag: item.local.tag)
                try await waitForRoom()
                events(.step(key: key, "carving"))
                let txid = try await backend.carveCode(carve)
                let id = item.action.targetId ?? txid
                ids[ref] = id
                try record(key, .code, id: id, txid: txid, did: item.local.did)
                if try ReleaseManifestEditor.writeBack(original: original, reviewed: carve, item: item) {
                    events(.manifestUpdated(file: item.repo.root.appendingPathComponent(ReleaseManifest.fileName).path))
                }
            } catch is CancellationError {
                throw CancellationError()
            } catch is ReviewSkipped {
                events(.skipped(key: key, "skipped in review"))
            } catch {
                events(.failed(key: key, String(describing: error)))
            }
        }

        // MARK: apps
        for item in plan.apps where item.action.carves {
            let key = ReleasePlanner.choiceKey(app: item.local.entry.stdName)
            guard selected.contains(key) else { continue }
            if let entry = alreadyCarved(key, did: item.local.did) {
                events(.skipped(key: key, "already carved in \(entry.txid.prefix(12))…"))
                continue
            }
            do {
                try Task.checkCancellation()
                var carve = try ReleaseCarves.appCarve(item, ids: ids)
                let original = carve
                if let reviewer {
                    guard case .app(let reviewed)? = try await reviewer.review(.app(carve)) else {
                        throw ReviewSkipped()
                    }
                    carve = reviewed
                }
                try await waitForRoom()
                events(.step(key: key, "carving"))
                let txid = try await backend.carveApp(carve)
                try record(key, .app, id: item.action.targetId ?? txid, txid: txid, did: item.local.did)
                if try ReleaseManifestEditor.writeBack(original: original, reviewed: carve, item: item) {
                    events(.manifestUpdated(file: item.repo.root.appendingPathComponent(ReleaseManifest.fileName).path))
                }
            } catch is CancellationError {
                throw CancellationError()
            } catch is ReviewSkipped {
                events(.skipped(key: key, "skipped in review"))
            } catch {
                events(.failed(key: key, String(describing: error)))
            }
        }
    }
}
