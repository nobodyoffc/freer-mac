import Foundation
import FCCore

/// A formal, irrevocable statement — the Swift mirror of the Java
/// `feipData.Statement`, and the record type of the `statement` index.
///
/// **The odd one of the Publish six, and every difference is a
/// subtraction.** There is no `op` field, because there is only one
/// thing you can do. There is no `update`, no `delete`, no `recover`,
/// no `deleted` flag, no `ver`, no `rate`, no `tRate`. There is no
/// `did` either: **the content is carved on the chain itself**, not
/// stored on DISK, which is the whole point — a statement whose text
/// lived somewhere else would be a statement somebody else could take
/// down.
///
/// What is left is a title, a body, a publisher and a timestamp, and
/// none of them can ever change. FEIP8's `confirm` phrase exists to
/// make sure the publisher knew that before they paid: see
/// ``StatementFeip/confirmPhrase``.
///
/// **``onChain`` is three-valued**, as elsewhere in this family: `true`
/// confirmed, `false` a local draft, `nil` broadcast and not yet in a
/// block. A draft is the only mutable form a statement ever has.
public struct Statement: Codable, Equatable, Sendable, Identifiable {

    // MARK: - wire fields, in Java declaration order

    public var title: String?
    /// The statement itself, **in the transaction**. Unlike every other
    /// Publish record this is not a pointer.
    public var content: String?
    public var publisher: String?
    /// Seconds since the epoch, like ``News/time``.
    public var birthTime: Int64?
    public var birthHeight: Int64?

    /// The carve txid once carved; a locally derived digest before that.
    public var id: String

    // MARK: - local bookkeeping

    public var onChain: Bool?
    public var addedAt: Date
    public var updatedAt: Date

    private enum CodingKeys: String, CodingKey {
        case title, content, publisher, birthTime, birthHeight, id
        case onChain, addedAt, updatedAt
    }

    public init(
        id: String,
        title: String? = nil,
        content: String? = nil,
        publisher: String? = nil,
        birthTime: Int64? = nil,
        birthHeight: Int64? = nil,
        onChain: Bool? = nil,
        addedAt: Date = Date(),
        updatedAt: Date = Date()
    ) {
        self.id = id
        self.title = title
        self.content = content
        self.publisher = publisher
        self.birthTime = birthTime
        self.birthHeight = birthHeight
        self.onChain = onChain
        self.addedAt = addedAt
        self.updatedAt = updatedAt
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = (try c.decodeIfPresent(String.self, forKey: .id)) ?? ""
        title = try c.decodeIfPresent(String.self, forKey: .title)
        content = try c.decodeIfPresent(String.self, forKey: .content)
        publisher = try c.decodeIfPresent(String.self, forKey: .publisher)
        birthTime = try c.decodeIfPresent(Int64.self, forKey: .birthTime)
        birthHeight = try c.decodeIfPresent(Int64.self, forKey: .birthHeight)
        onChain = try c.decodeIfPresent(Bool.self, forKey: .onChain)
        addedAt = (try c.decodeIfPresent(Date.self, forKey: .addedAt)) ?? Date()
        updatedAt = (try c.decodeIfPresent(Date.self, forKey: .updatedAt)) ?? Date()
    }

    // MARK: - derived state

    /// List label. A statement may legally have **no title** — FEIP8
    /// requires only that one of title and content be present — so this
    /// falls back to the opening of the content before it falls back to
    /// the id.
    public var name: String {
        if let title, !title.isEmpty { return title }
        if let content, !content.isEmpty {
            let firstLine = content.split(separator: "\n").first.map(String.init) ?? content
            return firstLine.count > 60 ? String(firstLine.prefix(60)) + "…" : firstLine
        }
        return id
    }

    /// Case-insensitive substring match across the fields the index can
    /// search.
    public func matches(query: String) -> Bool {
        let needle = query.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !needle.isEmpty else { return false }
        func hit(_ s: String?) -> Bool {
            guard let s else { return false }
            return s.lowercased().contains(needle)
        }
        return hit(title) || hit(content) || hit(publisher) || hit(id)
    }

    // MARK: - local id

    /// The id a draft carries before it has a txid — `sha256x2` of the
    /// envelope it will carve, hex.
    ///
    /// The **envelope**, not the bare data, for the reason
    /// ``TextRecord/localId(title:type:did:lang:authors:format:summary:)``
    /// gives: two Publish protocols can emit identical payloads, and
    /// only the envelope carries the `sn` that tells them apart.
    public static func localId(title: String?, content: String?) -> String {
        let op = (try? StatementFeip.statementData(title: title, content: content))
            ?? "\(title ?? "")\u{1F}\(content ?? "")"
        return Hex.encode(Hash.doubleSha256(Data(StatementFeip.envelope(dataJson: op).utf8)))
    }

    /// A brand-new local-only draft, not yet carved. The only editable
    /// form a statement has.
    public static func createLocal(
        title: String?,
        content: String?,
        publisher: String
    ) -> Statement {
        Statement(
            id: localId(title: title, content: content),
            title: title,
            content: content,
            publisher: publisher,
            onChain: false
        )
    }
}
