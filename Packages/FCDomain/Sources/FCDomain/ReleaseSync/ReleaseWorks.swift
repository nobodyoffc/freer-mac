import Foundation
import FCCore

/// The published works Release Sync registers: FEIP21 Text, FEIP23 Sound,
/// FEIP24 Image and FEIP25 Video. See FVEP11 section 5.
public enum WorkKind: String, Codable, CaseIterable, Sendable {
    case text, image, sound, video

    /// Image, Sound and Video share one implementation; Text has its own.
    public var media: MediaKind? {
        switch self {
        case .text: return nil
        case .image: return .image
        case .sound: return .sound
        case .video: return .video
        }
    }

    public var label: String {
        switch self {
        case .text: return "Text"
        case .image: return "Image"
        case .sound: return "Sound"
        case .video: return "Video"
        }
    }

    var entityKind: ReleaseEntityKind {
        switch self {
        case .text: return .text
        case .image: return .image
        case .sound: return .sound
        case .video: return .video
        }
    }

    /// Images first, so a work carved later in the run can name one.
    static let carveOrder: [WorkKind] = [.image, .text, .sound, .video]
}

/// A text or media record of the owner, in the fields Release Sync compares.
public struct WorkRecord: Identifiable, Equatable, Sendable {
    public var id: String
    public var kind: WorkKind
    public var title: String?
    public var type: String?
    public var did: String?
    public var lang: String?
    public var authors: [String]?
    public var format: String?
    public var summary: String?
    public var locas: [String]?
    public var cover: String?
    public var deleted: Bool?
    public var lastTxId: String?

    public init(id: String, kind: WorkKind, title: String? = nil, type: String? = nil, did: String? = nil,
                lang: String? = nil, authors: [String]? = nil, format: String? = nil, summary: String? = nil,
                locas: [String]? = nil, cover: String? = nil, deleted: Bool? = nil, lastTxId: String? = nil) {
        self.id = id
        self.kind = kind
        self.title = title
        self.type = type
        self.did = did
        self.lang = lang
        self.authors = authors
        self.format = format
        self.summary = summary
        self.locas = locas
        self.cover = cover
        self.deleted = deleted
        self.lastTxId = lastTxId
    }

    init(_ r: TextRecord) {
        self.init(id: r.id, kind: .text, title: r.title, type: r.type, did: r.did, lang: r.lang, authors: r.authors,
                  format: r.format, summary: r.summary, locas: r.locas, cover: r.cover, deleted: r.deleted,
                  lastTxId: r.lastTxId)
    }

    init(_ r: MediaRecord, kind: WorkKind) {
        self.init(id: r.id, kind: kind, title: r.title, did: r.did, lang: r.lang, authors: r.authors,
                  format: r.format, summary: r.summary, locas: r.locas, cover: r.cover, deleted: r.deleted,
                  lastTxId: r.lastTxId)
    }
}

/// One work of the chosen release, its DID computed.
public struct LocalWork: Sendable {
    public var entry: ReleaseManifest.WorkEntry
    public var tag: String
    /// The asset's name, or the repo file's last path component.
    public var fileName: String
    /// The bytes on this Mac, when they had to be read: a repo file, an
    /// asset GitHub has not hashed, or one going onto DISK.
    public var fileURL: URL?
    public var did: String
    public var size: Int64?
    /// The `https://` locations, in order: GitHub, then the mirrors.
    public var locas: [String]

    public init(entry: ReleaseManifest.WorkEntry, tag: String, fileName: String, fileURL: URL?,
                did: String, size: Int64?, locas: [String]) {
        self.entry = entry
        self.tag = tag
        self.fileName = fileName
        self.fileURL = fileURL
        self.did = did
        self.size = size
        self.locas = locas
    }

    /// FEIP2x: a publisher SHOULD list no more than 3 locations.
    public static let maxLocas = 3

    /// GitHub's link and the expanded mirrors, cut to what fits beside a
    /// DISK entry when the work goes onto DISK. Returns what was dropped.
    static func locas(link: String, entry: ReleaseManifest.WorkEntry, tag: String, fileName: String) -> ([String], [String]) {
        var all = [link]
        for template in entry.mirrors ?? [] {
            let url = template.replacingOccurrences(of: "{tag}", with: tag)
                .replacingOccurrences(of: "{name}", with: fileName)
            if !all.contains(url) { all.append(url) }
        }
        let room = maxLocas - (entry.disk == true ? 1 : 0)
        return (Array(all.prefix(room)), Array(all.dropFirst(room)))
    }

    /// A location on DISK, as opposed to a URL anyone serves.
    static func isDisk(_ loca: String) -> Bool {
        loca.hasPrefix(Hat.sidLocationPrefix) || loca.hasPrefix(Hat.fudpLocationPrefix)
    }
}

public struct WorkPlanItem: Identifiable, Sendable {
    public var id: String { key }
    /// ``ReleasePlanner/choiceKey(work:repo:)``.
    public var key: String
    public var local: LocalWork
    public var repo: RepoScan
    public var action: ReleaseAction
    public var record: WorkRecord?
    /// The cover image's id, or the image carved earlier in the run.
    public var cover: IdRef?
}

/// The fields of one work carve. `targetId` nil means publish.
public struct WorkCarve: Equatable, Sendable {
    public var kind: WorkKind
    public var targetId: String?
    public var title: String
    public var type: String?
    public var did: String
    public var lang: String?
    public var authors: [String]?
    public var format: String?
    public var summary: String?
    public var locas: [String]?
    /// `imageId` of the cover.
    public var cover: String?
    /// The file goes onto DISK before the carve, and that DISK is put
    /// first in `locas`.
    public var disk: Bool

    public init(kind: WorkKind, targetId: String?, title: String, type: String? = nil, did: String,
                lang: String? = nil, authors: [String]? = nil, format: String? = nil, summary: String? = nil,
                locas: [String]? = nil, cover: String? = nil, disk: Bool = false) {
        self.kind = kind
        self.targetId = targetId
        self.title = title
        self.type = type
        self.did = did
        self.lang = lang
        self.authors = authors
        self.format = format
        self.summary = summary
        self.locas = locas
        self.cover = cover
        self.disk = disk
    }

    /// The OP_RETURN. Before the DISK entry is known, a `(sid)` of full
    /// length stands in for it, so the size check sees the real length.
    public func json() throws -> String {
        var list = locas ?? []
        if disk, !list.contains(where: LocalWork.isDisk) {
            list.insert(Hat.sidLocationPrefix + ReleaseCarves.placeholderId, at: 0)
        }
        return try json(locas: list.isEmpty ? nil : list)
    }

    func json(locas: [String]?) throws -> String {
        guard let media = kind.media else {
            if let targetId {
                return try TextFeip.updateCarve(textId: targetId, title: title, type: type, did: did, lang: lang,
                                                authors: authors, format: format, summary: summary, locas: locas,
                                                cover: cover)
            }
            return try TextFeip.publishCarve(title: title, type: type, did: did, lang: lang,
                                             authors: authors, format: format, summary: summary, locas: locas,
                                             cover: cover)
        }
        if let targetId {
            return try MediaFeip.updateCarve(kind: media, imageId: targetId, title: title, did: did, lang: lang,
                                             authors: authors, format: format, summary: summary, locas: locas,
                                             cover: cover)
        }
        return try MediaFeip.publishCarve(kind: media, title: title, did: did, lang: lang,
                                          authors: authors, format: format, summary: summary, locas: locas,
                                          cover: cover)
    }

    /// The DISK locations, first, then this carve's own, at most
    /// ``LocalWork/maxLocas`` in all.
    func withDisk(_ disk: [String]) -> WorkCarve {
        var c = self
        var list = Array(disk.prefix(1))
        for loca in locas ?? [] where !list.contains(loca) { list.append(loca) }
        c.locas = Array(list.prefix(LocalWork.maxLocas))
        return c
    }
}

extension ReleasePlanner {

    /// A work's key: the repo and the file it comes from, which stay put
    /// when its title changes.
    public static func choiceKey(work source: String, repo: String) -> String { "work:\(repo)/\(source)" }

    static func planWorks(scans: [RepoScan], chain: ReleaseChainState, owner: String,
                          choices: [String: String], log: ReleaseRunLog, now: Date) -> [WorkPlanItem] {
        var items: [WorkPlanItem] = []
        let byId = Dictionary(chain.works.map { ($0.id, $0) }, uniquingKeysWith: { a, _ in a })
        for scan in scans {
            for local in scan.works {
                let entry = local.entry
                let key = choiceKey(work: entry.source, repo: scan.manifest.repoName)
                var item = WorkPlanItem(key: key, local: local, repo: scan, action: .publish, record: nil)
                if let id = entry.id?.lowercased() {
                    if let record = byId[id] {
                        if record.kind == entry.kind {
                            item.record = record
                            item.action = workAction(local, record)
                        } else {
                            item.action = .invalid("its id \(id.prefix(6))…\(id.suffix(6)) is a \(record.kind.rawValue) on chain, not a \(entry.kind.rawValue)")
                        }
                    } else if let logged = log.entries[key], logged.id == id {
                        item.action = .pending(id: id, txid: logged.txid, since: logged.at,
                                               stale: now.timeIntervalSince(logged.at) > pendingExpiry)
                    } else {
                        item.action = .invalid("its id \(id.prefix(6))…\(id.suffix(6)) is not a \(entry.kind.rawValue) of \(owner)")
                    }
                } else {
                    // Matched by title; the id written back after the
                    // publish takes over from then on.
                    let all = chain.works.filter { $0.kind == entry.kind && clean($0.title) == clean(entry.title) }
                    var candidates = all
                    if all.count > 1, let chosen = choices[key], let one = all.first(where: { $0.id == chosen }) {
                        candidates = [one]
                    }
                    if candidates.count > 1 {
                        item.action = .ambiguous(ids: candidates.map(\.id))
                    } else if let record = candidates.first {
                        item.record = record
                        item.action = workAction(local, record)
                    }
                }
                // Same rule as the other entities: a pending publish holds,
                // a pending update holds while its DID is the one logged.
                if item.action.carves, let logged = log.entries[key] {
                    if case .update = item.action, logged.did != local.did {
                    } else {
                        item.action = .pending(id: logged.id, txid: logged.txid, since: logged.at,
                                               stale: now.timeIntervalSince(logged.at) > pendingExpiry)
                    }
                }
                items.append(item)
            }
        }
        // Covers, now that every image of the run has its action. An
        // unchanged record whose cover now points elsewhere is an update.
        for i in items.indices {
            guard let ref = items[i].local.entry.cover else { continue }
            let resolved: IdRef
            if ReleaseManifest.isRawId(ref) {
                resolved = .known(ref.lowercased())
            } else if let image = items.first(where: { $0.repo.root == items[i].repo.root && $0.local.entry.source == ref }) {
                if case .publish = image.action { resolved = .workInRun(image.key) }
                else if let id = image.action.targetId { resolved = .known(id) }
                else { resolved = .unresolved(ref) }
            } else {
                resolved = .unresolved(ref)
            }
            items[i].cover = resolved
            if case .unchanged(let id) = items[i].action, items[i].record?.cover != resolved.knownId {
                items[i].action = items[i].record?.deleted == true
                    ? .blocked(id: id, reason: "deleted on chain; recover it first") : .update(id: id)
            }
        }
        for i in items.indices where items[i].local.entry.cover == nil {
            if case .unchanged(let id) = items[i].action, items[i].record?.cover != nil {
                items[i].action = .update(id: id)
            }
        }
        return items
    }

    /// A work changes when its file does, or when the manifest says
    /// something new about it. Its DISK entry is the app's own, so only
    /// its presence is compared.
    static func workAction(_ local: LocalWork, _ record: WorkRecord) -> ReleaseAction {
        let e = local.entry
        let recordLocas = record.locas ?? []
        let same = record.did == local.did
            && clean(record.title) == clean(e.title)
            && clean(record.type) == clean(e.type)
            && clean(record.lang) == clean(e.lang)
            && clean(record.format) == clean(e.format)
            && clean(record.summary) == clean(e.summary)
            && (record.authors ?? []) == (e.authors ?? [])
            && recordLocas.filter { !LocalWork.isDisk($0) } == local.locas
            && (e.disk != true || recordLocas.contains(where: LocalWork.isDisk))
        if same { return .unchanged(id: record.id) }
        if record.deleted == true { return .blocked(id: record.id, reason: "deleted on chain; recover it first") }
        return .update(id: record.id)
    }
}

extension ReleaseCarves {
    /// - Parameter ids: ids carved earlier in the run; nil stands a
    ///   placeholder in for a cover not carved yet, for the size check.
    public static func workCarve(_ item: WorkPlanItem, ids: [IdRef: String]? = nil) throws -> WorkCarve {
        let e = item.local.entry
        var cover: String?
        if let ref = item.cover {
            guard let id = resolve(ref, ids) else { throw RunFailure.unresolved(ref.description) }
            cover = id
        }
        var carve = WorkCarve(
            kind: e.kind, targetId: item.action.targetId, title: e.title, type: e.type, did: item.local.did,
            lang: e.lang, authors: (e.authors ?? []).isEmpty ? nil : e.authors, format: e.format,
            summary: e.summary, locas: item.local.locas.isEmpty ? nil : item.local.locas, cover: cover,
            disk: e.disk == true
        )
        carve.summary = try fitDesc(carve.summary) { s in var c = carve; c.summary = s; return try c.json() }
        return carve
    }
}

extension ReleaseManifestEditor {
    /// Writes a published work's id, and the user's review edits, back
    /// into its manifest entry.
    @discardableResult
    public static func writeBack(original: WorkCarve, reviewed: WorkCarve, item: WorkPlanItem,
                                 publishedId: String?) throws -> Bool {
        guard original != reviewed || publishedId != nil else { return false }
        let source = item.local.entry.source
        return try edit(root: item.repo.root) { manifest in
            guard let i = manifest.works?.firstIndex(where: { $0.source == source }) else { return }
            if let publishedId { manifest.works![i].id = publishedId }
            if reviewed.title != original.title { manifest.works![i].title = reviewed.title }
            if reviewed.type != original.type { manifest.works![i].type = reviewed.type }
            if reviewed.lang != original.lang { manifest.works![i].lang = reviewed.lang }
            if reviewed.authors != original.authors { manifest.works![i].authors = reviewed.authors }
            if reviewed.format != original.format { manifest.works![i].format = reviewed.format }
            if reviewed.summary != original.summary { manifest.works![i].summary = reviewed.summary }
        }
    }
}
