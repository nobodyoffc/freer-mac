import Foundation
import FCCore

/// A published annotation — the Swift mirror of the Java
/// `feipData.Remark`, and the record type of the `remark` index.
///
/// A remark is a ``TextRecord`` with one field added and one taken
/// away: it gains ``onDid``, which says what is being remarked on, and
/// loses `type`, because a remark is only ever one kind of thing. Its
/// lifecycle, its `ver` counter, its CDD-weighted rating and its soft
/// delete are FEIP21's, op for op.
///
/// **``onDid`` holds the target's record id — the publish txid — not
/// the target's `did`.** The spec's wording allows either and the
/// indexer stores one opaque keyword, so a client has to choose and
/// stay chosen. The txid is what every screen already has in hand, it
/// exists even for a work published with no `did` at all, and it makes
/// the anchor uniform across everything remarkable: a text, an image, a
/// sound, a video, or another remark — which is what makes a thread.
/// See the Phase 8.8 notes in `PLAN.md`.
///
/// **The remark's own body is not in here either.** ``did`` points at
/// it, on DISK, exactly as ``TextRecord/did`` does; ``summary`` is the
/// on-chain preview a thread can draw without fetching anything.
public struct Remark: Codable, Equatable, Sendable, Identifiable {

    // MARK: - wire fields, in Java declaration order

    public var title: String?
    public var ver: String?
    /// Where this remark's own body lives.
    public var did: String?
    /// What is being remarked on — see the type note.
    public var onDid: String?
    public var authors: [String]?
    public var lang: String?
    public var format: String?
    public var summary: String?
    public var publisher: String?
    public var birthTime: Int64?
    public var birthHeight: Int64?
    public var lastTxId: String?
    public var lastTime: Int64?
    public var lastHeight: Int64?
    public var tCdd: Int64?
    public var tRate: Float?
    public var deleted: Bool?

    public var id: String

    // MARK: - local bookkeeping

    public var onChain: Bool?
    public var addedAt: Date
    public var updatedAt: Date

    private enum CodingKeys: String, CodingKey {
        case title, ver, did, onDid, authors, lang, format, summary
        case publisher, birthTime, birthHeight, lastTxId, lastTime, lastHeight
        case tCdd, tRate, deleted, id
        case onChain, addedAt, updatedAt
    }

    public init(
        id: String,
        title: String? = nil,
        ver: String? = nil,
        did: String? = nil,
        onDid: String? = nil,
        authors: [String]? = nil,
        lang: String? = nil,
        format: String? = nil,
        summary: String? = nil,
        publisher: String? = nil,
        birthTime: Int64? = nil,
        birthHeight: Int64? = nil,
        lastTxId: String? = nil,
        lastTime: Int64? = nil,
        lastHeight: Int64? = nil,
        tCdd: Int64? = nil,
        tRate: Float? = nil,
        deleted: Bool? = nil,
        onChain: Bool? = nil,
        addedAt: Date = Date(),
        updatedAt: Date = Date()
    ) {
        self.id = id
        self.title = title
        self.ver = ver
        self.did = did
        self.onDid = onDid
        self.authors = authors
        self.lang = lang
        self.format = format
        self.summary = summary
        self.publisher = publisher
        self.birthTime = birthTime
        self.birthHeight = birthHeight
        self.lastTxId = lastTxId
        self.lastTime = lastTime
        self.lastHeight = lastHeight
        self.tCdd = tCdd
        self.tRate = tRate
        self.deleted = deleted
        self.onChain = onChain
        self.addedAt = addedAt
        self.updatedAt = updatedAt
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = (try c.decodeIfPresent(String.self, forKey: .id)) ?? ""
        title = try c.decodeIfPresent(String.self, forKey: .title)
        if let s = try? c.decodeIfPresent(String.self, forKey: .ver) {
            ver = s
        } else if let n = try? c.decodeIfPresent(Int64.self, forKey: .ver) {
            ver = String(n)
        } else {
            ver = nil
        }
        did = try c.decodeIfPresent(String.self, forKey: .did)
        onDid = try c.decodeIfPresent(String.self, forKey: .onDid)
        authors = try c.decodeIfPresent([String].self, forKey: .authors)
        lang = try c.decodeIfPresent(String.self, forKey: .lang)
        format = try c.decodeIfPresent(String.self, forKey: .format)
        summary = try c.decodeIfPresent(String.self, forKey: .summary)
        publisher = try c.decodeIfPresent(String.self, forKey: .publisher)
        birthTime = try c.decodeIfPresent(Int64.self, forKey: .birthTime)
        birthHeight = try c.decodeIfPresent(Int64.self, forKey: .birthHeight)
        lastTxId = try c.decodeIfPresent(String.self, forKey: .lastTxId)
        lastTime = try c.decodeIfPresent(Int64.self, forKey: .lastTime)
        lastHeight = try c.decodeIfPresent(Int64.self, forKey: .lastHeight)
        tCdd = try c.decodeIfPresent(Int64.self, forKey: .tCdd)
        tRate = try c.decodeIfPresent(Float.self, forKey: .tRate)
        deleted = try c.decodeIfPresent(Bool.self, forKey: .deleted)
        onChain = try c.decodeIfPresent(Bool.self, forKey: .onChain)
        addedAt = (try c.decodeIfPresent(Date.self, forKey: .addedAt)) ?? Date()
        updatedAt = (try c.decodeIfPresent(Date.self, forKey: .updatedAt)) ?? Date()
    }

    // MARK: - derived state

    public var name: String {
        if let title, !title.isEmpty { return title }
        return id
    }

    public var isDeleted: Bool { deleted == true }

    public var edition: Int { Int(ver ?? "") ?? 1 }

    public func canUpdate(as fid: String) -> Bool {
        onChain != false && !isDeleted && publisher == fid
    }

    public func canDelete(as fid: String) -> Bool {
        onChain != false && !isDeleted && publisher == fid
    }

    public func canRecover(as fid: String) -> Bool {
        onChain != false && isDeleted && publisher == fid
    }

    public func canRate(as fid: String) -> Bool {
        onChain != false && !isDeleted && publisher != fid
    }

    public func matches(query: String) -> Bool {
        let needle = query.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !needle.isEmpty else { return false }
        func hit(_ s: String?) -> Bool {
            guard let s else { return false }
            return s.lowercased().contains(needle)
        }
        if hit(title) || hit(summary) || hit(publisher) || hit(id)
            || hit(onDid) || hit(lang) || hit(did) { return true }
        return (authors ?? []).contains { hit($0) }
    }

    // MARK: - local id

    public static func localId(
        title: String?,
        did: String?,
        onDid: String?,
        lang: String?,
        authors: [String]?,
        format: String?,
        summary: String?
    ) -> String {
        let op = (try? RemarkFeip.publishOp(
            title: title, did: did, onDid: onDid, lang: lang,
            authors: authors, format: format, summary: summary
        )) ?? "\(title ?? "")\u{1F}\(onDid ?? "")"
        // The envelope, so the `sn` is in the digest — see
        // ``TextRecord/localId(title:type:did:lang:authors:format:summary:)``.
        return Hex.encode(Hash.doubleSha256(Data(RemarkFeip.envelope(opJson: op).utf8)))
    }

    public static func createLocal(
        title: String,
        did: String? = nil,
        onDid: String? = nil,
        lang: String? = nil,
        authors: [String]? = nil,
        format: String? = nil,
        summary: String? = nil,
        publisher: String
    ) -> Remark {
        Remark(
            id: localId(
                title: title, did: did, onDid: onDid, lang: lang,
                authors: authors, format: format, summary: summary
            ),
            title: title,
            did: did,
            onDid: onDid,
            authors: authors,
            lang: lang,
            format: format,
            summary: summary,
            publisher: publisher,
            deleted: false,
            onChain: false
        )
    }
}
