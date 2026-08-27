import Foundation

/// Builder for the FEIP `Statement` protocol (sn 8, ver 1) — the
/// OP_RETURN JSON that carves an irrevocable statement onto the FCH
/// chain. Mirrors the Java `StatementOpData`:
///
/// ```json
/// {"type":"FEIP","sn":"8","ver":"1","name":"Statement",
///  "data":{"title":"…","content":"…",
///          "confirm":"This is a formal and irrevocable statement."}}
/// ```
///
/// **There is no `op`.** Every other FEIP in this app names an
/// operation; this one has exactly one thing you can do, so the data is
/// the statement itself. A builder that emitted an `op` field out of
/// habit would carve a record the parser reads straight past — it never
/// looks for one — so a test asserts its absence.
///
/// **The content is on the chain, not on DISK.** This is the one
/// Publish protocol with no `did`, and the difference is deliberate: a
/// statement whose text lived on a server would be a statement somebody
/// else could take down. The consequence is that the OP_RETURN limit is
/// a *real* constraint here, the way it is for a ``ProofFeip`` and not
/// the way it is for a ``TextFeip`` — see ``remainingContentBytes(title:content:)``.
public enum StatementFeip {

    public static let sn = "8"
    public static let ver = "1"
    public static let protocolName = "Statement"

    public static let maxOpReturnSize = MailFeip.maxOpReturnSize

    /// The exact sentence FEIP8 requires in `confirm`, byte for byte —
    /// Java's `StatementOpData.CONFIRM` and the parser's
    /// `FeipConstants.CONFIRM_STATEMENT`.
    ///
    /// **The parser compares it with `equals`.** Case, punctuation and
    /// the trailing full stop all matter; a statement carved with so
    /// much as a different capital is silently ignored, with the fee
    /// paid. It is spelled once, here, and never assembled at a call
    /// site.
    public static let confirmPhrase = "This is a formal and irrevocable statement."

    public enum Failure: Error, CustomStringConvertible {
        case encoding(underlying: Error)
        case empty
        case tooLarge(bytes: Int)

        public var description: String {
            switch self {
            case .encoding(let e):
                return "StatementFeip: JSON encoding failed — \(e)"
            case .empty:
                return "StatementFeip: a statement needs a title or content — FEIP8 requires at least one"
            case .tooLarge(let bytes):
                return "StatementFeip: the carve is \(bytes) bytes, over the \(maxOpReturnSize)-byte OP_RETURN limit. A statement's text is carved in full and is neither compressed nor stored off-chain — shorten it, or publish it as a Text, whose body goes to DISK."
            }
        }
    }

    // MARK: - the payload

    /// `{"title":…,"content":…,"confirm":…}` — the whole of `data`.
    ///
    /// Empty fields are omitted, and `confirm` never is: the parser
    /// rejects anything whose `confirm` is missing or different, so it
    /// is not the caller's to supply or to vary.
    public static func statementData(title: String?, content: String?) throws -> String {
        var dict: [String: Any] = ["confirm": confirmPhrase]
        if let title, !title.isEmpty { dict["title"] = title }
        if let content, !content.isEmpty { dict["content"] = content }
        return try jsonString(dict)
    }

    /// The full OP_RETURN payload, with FEIP8's one content rule and
    /// the size check applied before a caller can spend anything.
    public static func carve(title: String?, content: String?) throws -> String {
        let t = title?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        let c = content?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        guard !t.isEmpty || !c.isEmpty else { throw Failure.empty }

        let json = envelope(dataJson: try statementData(title: title, content: content))
        let bytes = Data(json.utf8).count
        guard bytes <= maxOpReturnSize else { throw Failure.tooLarge(bytes: bytes) }
        return json
    }

    /// How many more UTF-8 bytes of `content` a statement can take
    /// before it exceeds the OP_RETURN limit. Negative once over.
    ///
    /// **This budget is the feature, not a formality.** A statement's
    /// text is carved in full, so the ceiling is reached by ordinary
    /// prose rather than by pathological input — three paragraphs and
    /// it is gone. Measured on the encoded envelope rather than
    /// estimated, because JSON escaping makes a character count wrong
    /// by an unpredictable margin, and with the `content` key present
    /// even when the content is empty, so the first keystroke does not
    /// spend bytes the form said were free.
    public static func remainingContentBytes(title: String?, content: String) -> Int {
        let probe = content.isEmpty ? "x" : content
        let json = (try? envelope(dataJson: statementData(title: title, content: probe))) ?? ""
        let used = Data(json.utf8).count - (content.isEmpty ? 1 : 0)
        return maxOpReturnSize - used
    }

    // MARK: - envelope

    public static func envelope(dataJson: String) -> String {
        #"{"type":"FEIP","sn":"\#(sn)","ver":"\#(ver)","name":"\#(protocolName)","data":\#(dataJson)}"#
    }

    private static func jsonString(_ object: [String: Any]) throws -> String {
        do {
            let data = try JSONSerialization.data(
                withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes]
            )
            guard let s = String(data: data, encoding: .utf8) else {
                throw Failure.encoding(underlying: NSError(
                    domain: "StatementFeip", code: -1,
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
