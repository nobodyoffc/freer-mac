import Foundation
import FCCore

/// A published text work — the Swift mirror of the Java
/// `feipData.Text`, and the record type of the `text` index that
/// `base.search` reads.
///
/// **Named `TextRecord`, not `Text`.** SwiftUI's `Text` is in scope in
/// every view file, and a domain type that shadowed it would make the
/// pane that displays this record unable to draw a label. The same
/// collision produced ``ProtocolSpec`` and ``AppRecord``.
///
/// **The work is not in here.** FEIP21 carries no content field: what
/// goes on the chain is the catalogue entry — a title, an optional
/// summary, and ``did``, a pointer to wherever the body lives. This
/// app carves the body's own DID (hex `sha256x2` of the bytes, the
/// same id a ``Hat`` is keyed by) and stores those bytes on DISK, so
/// the pointer is self-verifying: see ``PublishBody``.
///
/// **``ver`` is the indexer's edition counter, not the publisher's
/// claim.** It is `"1"` on publish and bumps by one on every update,
/// and it is optional here because rows published before the reference
/// parser was fixed carry null forever — see the Phase 8.8 notes.
///
/// **``onChain`` is three-valued**, exactly as on ``Proof``: `true`
/// means a block confirms it, `false` means this row is a local draft
/// that has never been carved, and `nil` means a carve was broadcast
/// and no block has confirmed it yet.
public struct TextRecord: Codable, Equatable, Sendable, Identifiable {

    // MARK: - wire fields, in Java declaration order

    public var title: String?
    /// Edition counter as a decimal string. Optional — see the type note.
    public var ver: String?
    /// Where the body lives. In this app, the hex `sha256x2` of the
    /// body's bytes; opaque to the indexer, which never dereferences it.
    public var did: String?
    public var authors: [String]?
    public var lang: String?
    /// A free-text category hint (`essay`, `note`, `article`). The one
    /// field Text has that Image, Sound and Video do not.
    public var type: String?
    public var format: String?
    public var summary: String?
    public var publisher: String?
    public var birthTime: Int64?
    public var birthHeight: Int64?
    public var lastTxId: String?
    /// Seconds since the epoch, like ``News/time`` and unlike the
    /// millisecond fields on the IM path.
    public var lastTime: Int64?
    public var lastHeight: Int64?
    /// Cumulative coin-days behind ``tRate``. Zero raters leaves both nil.
    public var tCdd: Int64?
    /// CDD-weighted average rating.
    public var tRate: Float?
    public var deleted: Bool?

    /// The carve txid once carved; a locally derived digest before that.
    /// See ``localId(title:type:did:lang:authors:format:summary:)``.
    public var id: String

    // MARK: - local bookkeeping
    //
    // Not on the wire — the `text` index has no such fields.

    /// Confirmed / broadcast-unconfirmed / local-only — see the type's
    /// note.
    public var onChain: Bool?
    public var addedAt: Date
    public var updatedAt: Date

    private enum CodingKeys: String, CodingKey {
        case title, ver, did, authors, lang, type, format, summary
        case publisher, birthTime, birthHeight, lastTxId, lastTime, lastHeight
        case tCdd, tRate, deleted, id
        case onChain, addedAt, updatedAt
    }

    public init(
        id: String,
        title: String? = nil,
        ver: String? = nil,
        did: String? = nil,
        authors: [String]? = nil,
        lang: String? = nil,
        type: String? = nil,
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
        self.authors = authors
        self.lang = lang
        self.type = type
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
        // A server row without an id is unusable, but throwing would
        // fail the whole page; the service drops those rows instead.
        id = (try c.decodeIfPresent(String.self, forKey: .id)) ?? ""
        title = try c.decodeIfPresent(String.self, forKey: .title)
        // `ver` is a string on the wire, but a client that wrote a
        // number would still be readable here — the field is a counter
        // and refusing the whole record over its JSON type would lose
        // the work rather than the formatting.
        ver = try Self.decodeLooseString(c, .ver)
        did = try c.decodeIfPresent(String.self, forKey: .did)
        authors = try c.decodeIfPresent([String].self, forKey: .authors)
        lang = try c.decodeIfPresent(String.self, forKey: .lang)
        type = try c.decodeIfPresent(String.self, forKey: .type)
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

    /// A string field that a sloppy producer may have written as a
    /// number. Used for ``ver`` only, which is a decimal counter.
    private static func decodeLooseString(
        _ c: KeyedDecodingContainer<CodingKeys>, _ key: CodingKeys
    ) throws -> String? {
        if let s = try? c.decodeIfPresent(String.self, forKey: key) { return s }
        if let n = try? c.decodeIfPresent(Int64.self, forKey: key) { return String(n) }
        return nil
    }

    // MARK: - derived state

    /// List label: the title, else the id. A record with no title is
    /// refused by the parser, but a row that arrived some other way
    /// should still be identifiable.
    public var name: String {
        if let title, !title.isEmpty { return title }
        return id
    }

    /// Whether the publisher has retired this record.
    ///
    /// **A missing flag means not deleted.** `deleted != true` and
    /// `deleted == false` disagree exactly on the rows where the
    /// indexer omitted it, and a list that picks the wrong one shows a
    /// different set.
    public var isDeleted: Bool { deleted == true }

    /// The edition number, or 1 when the row predates the `ver` fix.
    /// Displayed as "—" rather than "1" where the difference matters;
    /// this is for comparison, not for showing.
    public var edition: Int { Int(ver ?? "") ?? 1 }

    /// `fid` may update this record: it exists on chain, is not
    /// deleted, and `fid` is the publisher. The reference parser does
    /// **not** apply the FEIP6 master bypass on update — only on delete
    /// and recover — so neither does this.
    public func canUpdate(as fid: String) -> Bool {
        onChain != false && !isDeleted && publisher == fid
    }

    /// `fid` may delete this record. The master bypass exists on this
    /// op, but a master cannot be known from the row alone, so this
    /// answers only for the publisher; a master's delete is offered by
    /// the pane that knows it holds one.
    public func canDelete(as fid: String) -> Bool {
        onChain != false && !isDeleted && publisher == fid
    }

    public func canRecover(as fid: String) -> Bool {
        onChain != false && isDeleted && publisher == fid
    }

    /// Anyone but the publisher may rate — rule 13 of FEIP21, and the
    /// reason a publisher cannot inflate their own average.
    public func canRate(as fid: String) -> Bool {
        onChain != false && !isDeleted && publisher != fid
    }

    /// Case-insensitive substring match across the fields the chain
    /// index can search, so filtering loaded rows and searching the
    /// chain agree about what a query means.
    public func matches(query: String) -> Bool {
        let needle = query.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !needle.isEmpty else { return false }
        func hit(_ s: String?) -> Bool {
            guard let s else { return false }
            return s.lowercased().contains(needle)
        }
        if hit(title) || hit(summary) || hit(publisher) || hit(id)
            || hit(type) || hit(lang) || hit(did) { return true }
        return (authors ?? []).contains { hit($0) }
    }

    // MARK: - local id

    /// The id a record carries before it has a txid — `sha256x2` of the
    /// exact publish op that will be carved, hex.
    ///
    /// Hashing the op rather than the whole struct keeps a draft's id
    /// stable across a save and reload, which is the only property the
    /// id has to have. It is 32 bytes of hex either way, so it can
    /// never collide with a txid of a different preimage, and it never
    /// leaves the device: once carved, the txid replaces it.
    public static func localId(
        title: String?,
        type: String?,
        did: String?,
        lang: String?,
        authors: [String]?,
        format: String?,
        summary: String?
    ) -> String {
        let op = (try? TextFeip.publishOp(
            title: title, type: type, did: did, lang: lang,
            authors: authors, format: format, summary: summary
        )) ?? "\(title ?? "")\u{1F}\(did ?? "")"
        // The **envelope**, not the bare op. Two Publish protocols emit
        // byte-identical op JSON for the same title and did — nothing
        // in an op says which protocol it belongs to — so hashing the
        // op alone gave a text draft and an image draft with the same
        // fields the same id. The envelope carries the `sn`.
        return Hex.encode(Hash.doubleSha256(Data(TextFeip.envelope(opJson: op).utf8)))
    }

    /// A brand-new local-only draft, not yet carved.
    ///
    /// ``ver`` stays nil rather than `"1"`: the edition counter is the
    /// *indexer's*, and a draft no indexer has seen has no edition.
    public static func createLocal(
        title: String,
        type: String? = nil,
        did: String? = nil,
        lang: String? = nil,
        authors: [String]? = nil,
        format: String? = nil,
        summary: String? = nil,
        publisher: String
    ) -> TextRecord {
        TextRecord(
            id: localId(
                title: title, type: type, did: did, lang: lang,
                authors: authors, format: format, summary: summary
            ),
            title: title,
            did: did,
            authors: authors,
            lang: lang,
            type: type,
            format: format,
            summary: summary,
            publisher: publisher,
            deleted: false,
            onChain: false
        )
    }
}
