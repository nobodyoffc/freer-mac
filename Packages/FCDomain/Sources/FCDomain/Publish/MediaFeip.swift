import Foundation

/// Builders for the three media FEIPs — `Image` (sn 24), `Sound`
/// (sn 23) and `Video` (sn 25) — which are one protocol written three
/// times. Mirrors the Java `ImageOpData` / `SoundOpData` /
/// `VideoOpData` trio, which are likewise one class three times:
///
/// ```json
/// {"type":"FEIP","sn":"24","ver":"1","name":"Image",
///  "data":{"op":"publish","title":"…","did":"…","lang":"en",
///          "authors":["…"],"format":"image/png","summary":"…"}}
/// ```
///
/// **Every builder takes a ``MediaKind``**, which supplies the serial
/// number, the envelope name and the subject key. That last one is the
/// hazard the parameter exists for: `imageId` / `soundId` / `videoId`
/// is the only thing distinguishing three otherwise identical ops, so
/// it is derived once from the kind rather than typed three times.
///
/// **Nothing here is encrypted, and the media is not here at all.**
/// What this carves is a catalogue entry; the file goes to DISK and is
/// named by ``MediaRecord/did``. Everything that *is* here — title,
/// summary, author list — is public and permanent, which is why
/// ``publishCarve(kind:title:did:lang:authors:format:summary:)``
/// enforces the OP_RETURN limit before anything is signed.
///
/// **The subject is never supplied on publish.** The record's id *is*
/// the carve's txid, so a publish op that named one would be claiming
/// an id the chain is about to overrule. Only ``updateOp(kind:imageId:title:did:lang:authors:format:summary:)``
/// and ``rateOp(kind:imageId:rate:)`` carry it.
public enum MediaFeip {


    /// The largest OP_RETURN the chain accepts — the same limit
    /// ``MailFeip/maxOpReturnSize`` enforces, and for the same reason.
    public static let maxOpReturnSize = MailFeip.maxOpReturnSize

    /// The five ops the protocol defines.
    public enum Op: String, CaseIterable, Sendable {
        case publish
        case update
        case delete
        case recover
        case rate
    }

    public enum Failure: Error, CustomStringConvertible {
        case encoding(underlying: Error)
        case emptyTitle
        case missingImageId
        case noImageIds
        case tooLarge(bytes: Int)

        public var description: String {
            switch self {
            case .encoding(let e):
                return "MediaFeip: JSON encoding failed — \(e)"
            case .emptyTitle:
                return "MediaFeip: a published work needs a title — the parser refuses a publish or an update without one"
            case .missingImageId:
                return "MediaFeip: this op names the text it acts on, and no id was given"
            case .noImageIds:
                return "MediaFeip: no texts given"
            case .tooLarge(let bytes):
                return "MediaFeip: the carve is \(bytes) bytes, over the \(maxOpReturnSize)-byte OP_RETURN limit. Shorten the summary or the author list — the file itself is not in the carve."
            }
        }
    }

    // MARK: - op payloads

    /// `{"op":"publish",…}` — catalogue a new work.
    ///
    /// Empty and nil fields are omitted rather than sent as `""` or
    /// `[]`: the parser copies only non-null values into the history,
    /// so an empty key buys nothing and every omitted byte is
    /// OP_RETURN budget something else can use.
    public static func publishOp(
        kind: MediaKind,
        title: String?,
        did: String? = nil,
        lang: String? = nil,
        authors: [String]? = nil,
        format: String? = nil,
        summary: String? = nil
    ) throws -> String {
        var dict: [String: Any] = ["op": Op.publish.rawValue]
        put(&dict, "title", title)
        put(&dict, "did", did)
        put(&dict, "lang", lang)
        if let authors, !authors.isEmpty { dict["authors"] = authors }
        put(&dict, "format", format)
        put(&dict, "summary", summary)
        return try jsonString(dict)
    }

    /// `{"op":"update","imageId":…}` — publish a new edition.
    ///
    /// **Every mutable field is sent, every time.** The reference
    /// parser assigns the history's fields onto the entity including
    /// nulls, so an update that mentions only the title clears the
    /// summary, the language, the authors, the format and the `did`.
    /// Callers therefore pass the record's current values for anything
    /// they are not changing; that is what ``updateCarve`` takes a whole
    /// record's worth of arguments for.
    public static func updateOp(
        kind: MediaKind,
        imageId: String,
        title: String?,
        did: String? = nil,
        lang: String? = nil,
        authors: [String]? = nil,
        format: String? = nil,
        summary: String? = nil
    ) throws -> String {
        var dict: [String: Any] = ["op": Op.update.rawValue, kind.subjectKey: imageId]
        put(&dict, "title", title)
        put(&dict, "did", did)
        put(&dict, "lang", lang)
        if let authors, !authors.isEmpty { dict["authors"] = authors }
        put(&dict, "format", format)
        put(&dict, "summary", summary)
        return try jsonString(dict)
    }

    /// `{"op":"delete","imageIds":[…]}` — retire records you published.
    ///
    /// A list because the protocol takes one, and because for a paid
    /// operation that is the difference between one miner fee and
    /// several. The deletion is soft: the row stays, flagged.
    public static func deleteOp(kind: MediaKind, imageIds: [String]) throws -> String {
        guard !imageIds.isEmpty else { throw Failure.noImageIds }
        return try jsonString(["op": Op.delete.rawValue, kind.subjectsKey: imageIds])
    }

    /// `{"op":"recover","imageIds":[…]}` — clear the deleted flag.
    public static func recoverOp(kind: MediaKind, imageIds: [String]) throws -> String {
        guard !imageIds.isEmpty else { throw Failure.noImageIds }
        return try jsonString(["op": Op.recover.rawValue, kind.subjectsKey: imageIds])
    }

    /// `{"op":"rate","imageId":…,"rate":n}` — weigh in on somebody
    /// else's work.
    ///
    /// **Built, not yet wired** — see ``TextFeip/rateOp(textId:rate:)``.
    public static func rateOp(kind: MediaKind, imageId: String, rate: Int) throws -> String {
        guard !imageId.isEmpty else { throw Failure.missingImageId }
        return try jsonString(["op": Op.rate.rawValue, kind.subjectKey: imageId, "rate": rate])
    }

    // MARK: - complete carves

    /// The full OP_RETURN payload for a `publish`, with the title guard
    /// and the size check applied before a caller can spend anything.
    public static func publishCarve(
        kind: MediaKind,
        title: String,
        did: String? = nil,
        lang: String? = nil,
        authors: [String]? = nil,
        format: String? = nil,
        summary: String? = nil
    ) throws -> String {
        guard !title.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw Failure.emptyTitle
        }
        return try sized(envelope(kind: kind, opJson: publishOp(
            kind: kind, title: title, did: did, lang: lang,
            authors: authors, format: format, summary: summary
        )))
    }

    /// The full OP_RETURN payload for an `update`. Takes the record's
    /// whole mutable half for the reason ``updateOp`` documents.
    public static func updateCarve(
        kind: MediaKind,
        imageId: String,
        title: String,
        did: String? = nil,
        lang: String? = nil,
        authors: [String]? = nil,
        format: String? = nil,
        summary: String? = nil
    ) throws -> String {
        guard !imageId.isEmpty else { throw Failure.missingImageId }
        guard !title.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw Failure.emptyTitle
        }
        return try sized(envelope(kind: kind, opJson: updateOp(
            kind: kind, imageId: imageId, title: title, did: did, lang: lang,
            authors: authors, format: format, summary: summary
        )))
    }

    /// How many more UTF-8 bytes of `summary` a carve can take before
    /// it exceeds the OP_RETURN limit, given everything else already
    /// filled in. Negative once over.
    ///
    /// Measured on the encoded envelope rather than estimated, because
    /// JSON escaping makes a character count wrong by an unpredictable
    /// margin — a quotation mark costs two bytes, an emoji four. The
    /// probe keeps the `summary` key present even when the summary is
    /// empty, so the budget shown to an empty form is one the first
    /// keystroke does not immediately spend.
    public static func remainingSummaryBytes(
        kind: MediaKind,
        imageId: String? = nil,
        title: String,
        did: String? = nil,
        lang: String? = nil,
        authors: [String]? = nil,
        format: String? = nil,
        summary: String
    ) -> Int {
        let probe = summary.isEmpty ? "x" : summary
        let opJson: String?
        if let imageId, !imageId.isEmpty {
            opJson = try? updateOp(
                kind: kind, imageId: imageId, title: title, did: did,
                lang: lang, authors: authors, format: format, summary: probe)
        } else {
            opJson = try? publishOp(
                kind: kind, title: title, did: did,
                lang: lang, authors: authors, format: format, summary: probe)
        }
        let json = opJson.map { envelope(kind: kind, opJson: $0) } ?? ""
        let used = Data(json.utf8).count - (summary.isEmpty ? 1 : 0)
        return maxOpReturnSize - used
    }

    // MARK: - envelope

    public static func envelope(kind: MediaKind, opJson: String) -> String {
        #"{"type":"FEIP","sn":"\#(kind.sn)","ver":"\#(kind.ver)","name":"\#(kind.protocolName)","data":\#(opJson)}"#
    }

    static func sized(_ json: String) throws -> String {
        let bytes = Data(json.utf8).count
        guard bytes <= maxOpReturnSize else { throw Failure.tooLarge(bytes: bytes) }
        return json
    }

    private static func put(_ dict: inout [String: Any], _ key: String, _ value: String?) {
        guard let value, !value.isEmpty else { return }
        dict[key] = value
    }

    private static func jsonString(_ object: [String: Any]) throws -> String {
        do {
            let data = try JSONSerialization.data(
                withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes]
            )
            guard let s = String(data: data, encoding: .utf8) else {
                throw Failure.encoding(underlying: NSError(
                    domain: "MediaFeip", code: -1,
                    userInfo: [NSLocalizedDescriptionKey: "non-utf8 JSON output"]
                ))
            }
            return s
        } catch let e as Failure {
            throw e
        } catch {
            throw Failure.encoding(underlying: error)
        }
    }
}
