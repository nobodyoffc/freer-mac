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
        case rateOutOfRange(Int)
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
            case .rateOutOfRange(let r):
                return "RemarkFeip: a rating is 0 to 5, not \(r)"
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
    /// `{"op":"rate","remarkId":…,"rate":n,"cause":"…"}` — score a remark 0–5.
    ///
    /// The score's *weight* is not in this payload: the chain counts the
    /// coin-days the rating transaction destroys, so an action that
    /// offers no control over the coins spent offers no control over how
    /// much the vote counts. ``ActiveSession/carveRemarkRateOnChain(remarkId:rate:cause:weightCd:feePerByte:timeoutMs:)``
    /// takes the weight as a CoinDay floor and hands it to coin
    /// selection.
    ///
    /// `cause` is the optional reason. It is trimmed, and an empty one
    /// is omitted rather than carved as `""` — the same rule
    /// ``ReputationFeip/carve(ratee:rate:cause:)`` follows.
    ///
    /// **The range is checked here as well as on chain.** The publish
    /// parsers used to require only a non-null `rate`, so a 99 was
    /// indexed and folded into `tRate` permanently; they now bound it
    /// to `0...MAX_RATE` like the Construct four always did. Refusing
    /// it here too is not redundancy — a client that leaves the range
    /// to the chain reports the failure as a lost fee rather than as a
    /// bad number in a field.
    ///
    /// The publisher may not rate their own record; that is the
    /// parser's check, not this builder's, since this builder does not
    /// know who is signing.
    public static func rateOp(remarkId: String, rate: Int, cause: String? = nil) throws -> String {
        guard !remarkId.isEmpty else { throw Failure.missingRemarkId }
        guard (0...5).contains(rate) else { throw Failure.rateOutOfRange(rate) }
        var data: [String: Any] = ["op": Op.rate.rawValue, "remarkId": remarkId, "rate": rate]
        if let trimmed = cause?.trimmingCharacters(in: .whitespacesAndNewlines),
           !trimmed.isEmpty {
            data["cause"] = trimmed
        }
        return try jsonString(data)
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

    /// The full OP_RETURN payload for a `rate`, size-checked before a
    /// caller can spend anything on it.
    ///
    /// The size guard is why `cause` belongs here and not only on the op
    /// builder: a reason long enough to overflow the carve should fail
    /// while it is still text in a field, not after the coins are
    /// selected.
    public static func rateCarve(remarkId: String, rate: Int, cause: String? = nil) throws -> String {
        try sized(envelope(opJson: rateOp(remarkId: remarkId, rate: rate, cause: cause)))
    }

    /// How many more UTF-8 bytes of `cause` a rating carve can take
    /// before it exceeds the OP_RETURN limit. Negative once over.
    ///
    /// Measured on the encoded envelope, so it counts what JSON actually
    /// costs: an escaped character, or any character outside ASCII,
    /// spends more than one byte. ``rateCarve(remarkId:rate:cause:)`` is the
    /// authority; this is what to draw a counter against.
    public static func remainingCauseBytes(remarkId: String, rate: Int, cause: String) -> Int {
        guard let full = try? envelope(opJson: rateOp(remarkId: remarkId, rate: rate, cause: cause)).utf8.count else { return 0 }
        return maxOpReturnSize - full
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
