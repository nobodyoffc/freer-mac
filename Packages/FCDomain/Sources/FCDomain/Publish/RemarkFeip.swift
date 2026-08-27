import Foundation

/// Builders for the FEIP `Remark` protocol (sn 22, ver 1) — the
/// OP_RETURN JSON that anchors an annotation to something already
/// published. Mirrors the Java `Feip.FeipProtocol.REMARK` +
/// `RemarkOpData` pair:
///
/// ```json
/// {"type":"FEIP","sn":"22","ver":"1","name":"Remark",
///  "data":{"op":"publish","title":"Errata for section 3",
///          "onDid":"<target publish txid>","did":"…",
///          "summary":"Suggested correction."}}
/// ```
///
/// Everything ``TextFeip`` says applies here, with the two differences
/// the protocols have: the subject field is **`remarkId`** / and there
/// is **`onDid`**, which this app fills with the *target's record id*
/// (see ``Remark``). A remark carries no `type`.
public enum RemarkFeip {

    public static let sn = "22"
    public static let ver = "1"
    public static let protocolName = "Remark"

    public static let maxOpReturnSize = MailFeip.maxOpReturnSize

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
        case missingRemarkId
        case noRemarkIds
        case noTarget
        case tooLarge(bytes: Int)

        public var description: String {
            switch self {
            case .encoding(let e):
                return "RemarkFeip: JSON encoding failed — \(e)"
            case .emptyTitle:
                return "RemarkFeip: a remark needs a title — the parser refuses a publish or an update without one"
            case .missingRemarkId:
                return "RemarkFeip: this op names the remark it acts on, and no id was given"
            case .noRemarkIds:
                return "RemarkFeip: no remarks given"
            case .noTarget:
                return "RemarkFeip: a remark needs something to be about — onDid was empty"
            case .tooLarge(let bytes):
                return "RemarkFeip: the carve is \(bytes) bytes, over the \(maxOpReturnSize)-byte OP_RETURN limit. Shorten the summary — the remark's own text is not in the carve."
            }
        }
    }

    // MARK: - op payloads

    public static func publishOp(
        title: String?,
        did: String? = nil,
        onDid: String? = nil,
        lang: String? = nil,
        authors: [String]? = nil,
        format: String? = nil,
        summary: String? = nil
    ) throws -> String {
        var dict: [String: Any] = ["op": Op.publish.rawValue]
        put(&dict, "title", title)
        put(&dict, "did", did)
        put(&dict, "onDid", onDid)
        put(&dict, "lang", lang)
        if let authors, !authors.isEmpty { dict["authors"] = authors }
        put(&dict, "format", format)
        put(&dict, "summary", summary)
        return try jsonString(dict)
    }

    /// Sends every mutable field, for the reason ``TextFeip/updateOp``
    /// documents: the reference parser copies nulls onto the entity, so
    /// an omitted field is a cleared field.
    public static func updateOp(
        remarkId: String,
        title: String?,
        did: String? = nil,
        onDid: String? = nil,
        lang: String? = nil,
        authors: [String]? = nil,
        format: String? = nil,
        summary: String? = nil
    ) throws -> String {
        var dict: [String: Any] = ["op": Op.update.rawValue, "remarkId": remarkId]
        put(&dict, "title", title)
        put(&dict, "did", did)
        put(&dict, "onDid", onDid)
        put(&dict, "lang", lang)
        if let authors, !authors.isEmpty { dict["authors"] = authors }
        put(&dict, "format", format)
        put(&dict, "summary", summary)
        return try jsonString(dict)
    }

    public static func deleteOp(remarkIds: [String]) throws -> String {
        guard !remarkIds.isEmpty else { throw Failure.noRemarkIds }
        return try jsonString(["op": Op.delete.rawValue, "remarkIds": remarkIds])
    }

    public static func recoverOp(remarkIds: [String]) throws -> String {
        guard !remarkIds.isEmpty else { throw Failure.noRemarkIds }
        return try jsonString(["op": Op.recover.rawValue, "remarkIds": remarkIds])
    }

    /// Built, not yet wired — see ``TextFeip/rateOp(textId:rate:)``.
    public static func rateOp(remarkId: String, rate: Int) throws -> String {
        guard !remarkId.isEmpty else { throw Failure.missingRemarkId }
        return try jsonString(["op": Op.rate.rawValue, "remarkId": remarkId, "rate": rate])
    }

    // MARK: - complete carves

    /// A publish carve. **`onDid` is required here even though the
    /// protocol lists it as optional**: a remark about nothing is a
    /// text with extra steps, and the pane has no way to show one.
    public static func publishCarve(
        title: String,
        onDid: String,
        did: String? = nil,
        lang: String? = nil,
        authors: [String]? = nil,
        format: String? = nil,
        summary: String? = nil
    ) throws -> String {
        guard !title.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw Failure.emptyTitle
        }
        guard !onDid.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw Failure.noTarget
        }
        return try sized(envelope(opJson: publishOp(
            title: title, did: did, onDid: onDid, lang: lang,
            authors: authors, format: format, summary: summary
        )))
    }

    public static func updateCarve(
        remarkId: String,
        title: String,
        onDid: String,
        did: String? = nil,
        lang: String? = nil,
        authors: [String]? = nil,
        format: String? = nil,
        summary: String? = nil
    ) throws -> String {
        guard !remarkId.isEmpty else { throw Failure.missingRemarkId }
        guard !title.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw Failure.emptyTitle
        }
        guard !onDid.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw Failure.noTarget
        }
        return try sized(envelope(opJson: updateOp(
            remarkId: remarkId, title: title, did: did, onDid: onDid,
            lang: lang, authors: authors, format: format, summary: summary
        )))
    }

    /// See ``TextFeip/remainingSummaryBytes(textId:title:type:did:lang:authors:format:summary:)``.
    public static func remainingSummaryBytes(
        remarkId: String? = nil,
        title: String,
        onDid: String,
        did: String? = nil,
        lang: String? = nil,
        authors: [String]? = nil,
        format: String? = nil,
        summary: String
    ) -> Int {
        let probe = summary.isEmpty ? "x" : summary
        let opJson: String?
        if let remarkId, !remarkId.isEmpty {
            opJson = try? updateOp(
                remarkId: remarkId, title: title, did: did, onDid: onDid,
                lang: lang, authors: authors, format: format, summary: probe)
        } else {
            opJson = try? publishOp(
                title: title, did: did, onDid: onDid,
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
                    domain: "RemarkFeip", code: -1,
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
