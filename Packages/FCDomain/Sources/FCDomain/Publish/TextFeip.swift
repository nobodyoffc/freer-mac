import Foundation

/// Builders for the FEIP `Text` protocol (sn 21, ver 1) — the
/// OP_RETURN JSON that carves a published text work onto the FCH chain.
/// Mirrors the Java `Feip.FeipProtocol.TEXT` + `TextOpData` pair:
///
/// ```json
/// {"type":"FEIP","sn":"21","ver":"1","name":"Text",
///  "data":{"op":"publish","title":"…","type":"essay",
///          "did":"…","lang":"en","authors":["…"],
///          "format":"markdown","summary":"…"}}
/// ```
///
/// **Nothing here is encrypted, and the body is not here at all.** What
/// this carves is a catalogue entry; the work itself goes to DISK and
/// is named by ``TextRecord/did``. Everything that *is* here — title,
/// summary, author list — is public and permanent, which is why
/// ``publishCarve(title:type:did:lang:authors:format:summary:)``
/// enforces the OP_RETURN limit before anything is signed.
///
/// **`textId` is never supplied on publish.** Rule 1 of FEIP21: the
/// record's id *is* the carve's txid, so a publish op that named one
/// would be claiming an id the chain is about to overrule. Only
/// ``updateOp`` and ``rateOp`` carry it.
public enum TextFeip {

    public static let sn = "21"
    public static let ver = "1"
    public static let protocolName = "Text"

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
        case missingTextId
        case noTextIds
        case tooLarge(bytes: Int)

        public var description: String {
            switch self {
            case .encoding(let e):
                return "TextFeip: JSON encoding failed — \(e)"
            case .emptyTitle:
                return "TextFeip: a text needs a title — the parser refuses a publish or an update without one"
            case .missingTextId:
                return "TextFeip: this op names the text it acts on, and no id was given"
            case .noTextIds:
                return "TextFeip: no texts given"
            case .tooLarge(let bytes):
                return "TextFeip: the carve is \(bytes) bytes, over the \(maxOpReturnSize)-byte OP_RETURN limit. Shorten the summary or the author list — the body itself is not in the carve."
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
        title: String?,
        type: String? = nil,
        did: String? = nil,
        lang: String? = nil,
        authors: [String]? = nil,
        format: String? = nil,
        summary: String? = nil
    ) throws -> String {
        var dict: [String: Any] = ["op": Op.publish.rawValue]
        put(&dict, "title", title)
        put(&dict, "type", type)
        put(&dict, "did", did)
        put(&dict, "lang", lang)
        if let authors, !authors.isEmpty { dict["authors"] = authors }
        put(&dict, "format", format)
        put(&dict, "summary", summary)
        return try jsonString(dict)
    }

    /// `{"op":"update","textId":…}` — publish a new edition.
    ///
    /// **Every mutable field is sent, every time.** The reference
    /// parser assigns the history's fields onto the entity including
    /// nulls, so an update that mentions only the title clears the
    /// summary, the language, the authors, the format and the `did`.
    /// Callers therefore pass the record's current values for anything
    /// they are not changing; that is what ``updateCarve`` takes a whole
    /// record's worth of arguments for.
    public static func updateOp(
        textId: String,
        title: String?,
        type: String? = nil,
        did: String? = nil,
        lang: String? = nil,
        authors: [String]? = nil,
        format: String? = nil,
        summary: String? = nil
    ) throws -> String {
        var dict: [String: Any] = ["op": Op.update.rawValue, "textId": textId]
        put(&dict, "title", title)
        put(&dict, "type", type)
        put(&dict, "did", did)
        put(&dict, "lang", lang)
        if let authors, !authors.isEmpty { dict["authors"] = authors }
        put(&dict, "format", format)
        put(&dict, "summary", summary)
        return try jsonString(dict)
    }

    /// `{"op":"delete","textIds":[…]}` — retire records you published.
    ///
    /// A list because the protocol takes one, and because for a paid
    /// operation that is the difference between one miner fee and
    /// several. The deletion is soft: the row stays, flagged.
    public static func deleteOp(textIds: [String]) throws -> String {
        guard !textIds.isEmpty else { throw Failure.noTextIds }
        return try jsonString(["op": Op.delete.rawValue, "textIds": textIds])
    }

    /// `{"op":"recover","textIds":[…]}` — clear the deleted flag.
    public static func recoverOp(textIds: [String]) throws -> String {
        guard !textIds.isEmpty else { throw Failure.noTextIds }
        return try jsonString(["op": Op.recover.rawValue, "textIds": textIds])
    }

    /// `{"op":"rate","textId":…,"rate":n}` — weigh in on somebody
    /// else's work.
    ///
    /// **Built, not yet wired** — see Phase 8.8's notes, and 8.7.5's.
    /// The rating's weight is the coin-days the carrying transaction
    /// destroys, so an action that offers no control over the coins
    /// spent offers no control over how much the vote counts. The
    /// publisher may not rate their own record (rule 13); that is the
    /// parser's check, not this builder's, since this builder does not
    /// know who is signing.
    public static func rateOp(textId: String, rate: Int) throws -> String {
        guard !textId.isEmpty else { throw Failure.missingTextId }
        return try jsonString(["op": Op.rate.rawValue, "textId": textId, "rate": rate])
    }

    // MARK: - complete carves

    /// The full OP_RETURN payload for a `publish`, with the title guard
    /// and the size check applied before a caller can spend anything.
    public static func publishCarve(
        title: String,
        type: String? = nil,
        did: String? = nil,
        lang: String? = nil,
        authors: [String]? = nil,
        format: String? = nil,
        summary: String? = nil
    ) throws -> String {
        guard !title.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw Failure.emptyTitle
        }
        return try sized(envelope(opJson: publishOp(
            title: title, type: type, did: did, lang: lang,
            authors: authors, format: format, summary: summary
        )))
    }

    /// The full OP_RETURN payload for an `update`. Takes the record's
    /// whole mutable half for the reason ``updateOp`` documents.
    public static func updateCarve(
        textId: String,
        title: String,
        type: String? = nil,
        did: String? = nil,
        lang: String? = nil,
        authors: [String]? = nil,
        format: String? = nil,
        summary: String? = nil
    ) throws -> String {
        guard !textId.isEmpty else { throw Failure.missingTextId }
        guard !title.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw Failure.emptyTitle
        }
        return try sized(envelope(opJson: updateOp(
            textId: textId, title: title, type: type, did: did, lang: lang,
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
        textId: String? = nil,
        title: String,
        type: String? = nil,
        did: String? = nil,
        lang: String? = nil,
        authors: [String]? = nil,
        format: String? = nil,
        summary: String
    ) -> Int {
        let probe = summary.isEmpty ? "x" : summary
        let opJson: String?
        if let textId, !textId.isEmpty {
            opJson = try? updateOp(
                textId: textId, title: title, type: type, did: did,
                lang: lang, authors: authors, format: format, summary: probe)
        } else {
            opJson = try? publishOp(
                title: title, type: type, did: did,
                lang: lang, authors: authors, format: format, summary: probe)
        }
        let json = opJson.map(envelope(opJson:)) ?? ""
        let used = Data(json.utf8).count - (summary.isEmpty ? 1 : 0)
        return maxOpReturnSize - used
    }

    // MARK: - envelope

    public static func envelope(opJson: String) -> String {
        #"{"type":"FEIP","sn":"\#(sn)","ver":"\#(ver)","name":"\#(protocolName)","data":\#(opJson)}"#
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
                    domain: "TextFeip", code: -1,
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
