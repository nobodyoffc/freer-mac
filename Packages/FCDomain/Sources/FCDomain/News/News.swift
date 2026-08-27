import Foundation

/// One on-chain activity record — the Mac port of FC-AJDK's
/// `data/fcData/News.java`, and the row type of the `news` index that
/// `base.search` reads.
///
/// A news item is not content of its own: it is a *pointer* saying
/// "this FID did this thing to this object at this height". The object
/// is named by protocol (``objectType`` is a FEIP `sn`), by name and by
/// id, with a short ``objectBrief`` the indexer lifts out of the
/// payload. Everything here is public chain data — there is no cipher
/// on this path, which is why the service that reads it needs no key
/// and works for a watch-only identity.
///
/// **``isNew`` is local, not wire.** The indexer has no idea what this
/// device has already seen; the flag is set on arrival by comparing
/// ``height`` against a locally-kept watermark (see ``NewsStore``).
public struct News: Codable, Equatable, Sendable, Identifiable {

    // MARK: - wire fields, in Java declaration order

    /// The FID that acted — the signer of the transaction behind this
    /// record.
    public var doer: String?
    /// The op, as the protocol spells it (`register`, `update`,
    /// `delete`, `take over`, …). Multi-word ops carry their space:
    /// this is protocol text, never something to localise.
    public var act: String?
    /// FEIP protocol serial number of the object acted on.
    public var objectType: String?
    /// Name / stdName / title of the object, per its protocol.
    public var objectName: String?
    /// Indexer-supplied excerpt of the object's content or description.
    public var objectBrief: String?
    /// Id of the object acted on. Distinct from ``id``, which is the
    /// id of *this record*.
    public var objectId: String?
    public var height: Int64?
    /// Seconds since the epoch — the chain's `news` index stores a
    /// short timestamp, like ``Mail/birthTime`` and unlike the
    /// millisecond fields elsewhere in the app.
    public var time: Int64?
    /// Unseen since the last refresh. Local only — see the type's note.
    public var isNew: Bool?
    /// The index's document id, and the tiebreaker in the default
    /// `time, id` sort — which makes it the second half of a page
    /// cursor. See ``cursor``.
    public var id: String?

    public init(
        doer: String? = nil,
        act: String? = nil,
        objectType: String? = nil,
        objectName: String? = nil,
        objectBrief: String? = nil,
        objectId: String? = nil,
        height: Int64? = nil,
        time: Int64? = nil,
        isNew: Bool? = nil,
        id: String? = nil
    ) {
        self.doer = doer
        self.act = act
        self.objectType = objectType
        self.objectName = objectName
        self.objectBrief = objectBrief
        self.objectId = objectId
        self.height = height
        self.time = time
        self.isNew = isNew
        self.id = id
    }

    // MARK: - paging

    /// Cursor for a `time, id`-sorted page — the pair the server's
    /// `after` expects, built from *this* record.
    ///
    /// Only valid for the default sort. A search sorted by any other
    /// field must page with the server's own `last`, because
    /// `search_after` compares against the sort keys actually used.
    /// Android builds `[time, id]` unconditionally, including for
    /// doer/type/name sorts, which silently breaks paging on those —
    /// logged in the Android bug list rather than reproduced here.
    public var cursor: [String]? {
        guard let time, let id else { return nil }
        return [String(time), id]
    }

    // MARK: - fields the server will search and sort on

    /// A queryable field: the wire name the FCDSL carries, and the
    /// label a picker shows. The label is display text and stays on
    /// this side of the Phase 11 line; `name` is wire format.
    public struct Field: Equatable, Hashable, Sendable, Identifiable {
        public let name: String
        public let label: String
        public var id: String { name }

        public init(name: String, label: String) {
            self.name = name
            self.label = label
        }
    }

    public static let doerField = Field(name: "doer", label: "Doer")
    public static let actField = Field(name: "act", label: "Action")
    public static let objectTypeField = Field(name: "objectType", label: "Type")
    public static let objectNameField = Field(name: "objectName", label: "Name")
    public static let objectBriefField = Field(name: "objectBrief", label: "Brief")
    public static let idField = Field(name: "id", label: "ID")
    public static let timeField = Field(name: "time", label: "Time")

    /// Mirrors `News.getSearchableFields()`.
    public static let searchableFields: [Field] = [
        doerField, objectTypeField, actField, objectNameField, objectBriefField, idField
    ]

    /// Mirrors `News.getSortableFields()`.
    public static let sortableFields: [Field] = [
        doerField, objectTypeField, actField, timeField, objectNameField
    ]

    // MARK: - local filtering

    /// Case-insensitive substring match over the fields a reader can
    /// see. Used to narrow the page already on screen; the server-side
    /// search is a different thing and lives in ``NewsService``.
    public func matches(query: String) -> Bool {
        let needle = query.trimmingCharacters(in: .whitespaces).lowercased()
        guard !needle.isEmpty else { return true }
        for field in [doer, act, objectType, objectName, objectBrief, objectId, id] {
            if let field, field.lowercased().contains(needle) { return true }
        }
        return false
    }
}
