import Foundation

/// Builders for the FEIP `Proof` protocol (sn 14, ver 1) — the
/// OP_RETURN JSON that carves a proof onto the FCH chain. Mirrors the
/// Java `Feip.fromName(PROOF)` + `ProofOpData` pair:
///
/// ```json
/// {"type":"FEIP","sn":"14","ver":"1","name":"Proof",
///  "data":{"op":"issue","title":"…","content":"…",
///          "cosigners":["…"],"transferable":true,
///          "allSignsRequired":false}}
/// ```
///
/// **Nothing here is encrypted.** A proof is a public statement; the
/// title and body go on the chain in the clear, which is why
/// ``issueCarve(title:content:cosigners:transferable:allSignsRequired:)``
/// enforces the OP_RETURN size limit *before* anything is signed and
/// why the UI says so before the user types.
public enum ProofFeip {

    public static let sn = "14"
    public static let ver = "1"
    public static let protocolName = "Proof"

    /// The largest OP_RETURN the chain accepts — the same limit
    /// ``MailFeip/maxOpReturnSize`` enforces, and for the same reason.
    public static let maxOpReturnSize = MailFeip.maxOpReturnSize

    /// The four ops the protocol defines. `issue` mints, `sign`
    /// countersigns, `transfer` moves ownership, `destroy` retires.
    /// There is no `update`: a proof whose text could be rewritten
    /// after signing would not be a proof.
    public enum Op: String, CaseIterable, Sendable {
        case issue
        case sign
        case transfer
        case destroy
    }

    public enum Failure: Error, CustomStringConvertible {
        case encoding(underlying: Error)
        case emptyTitle
        case emptyContent
        case noProofIds
        case tooLarge(bytes: Int)

        public var description: String {
            switch self {
            case .encoding(let e):
                return "ProofFeip: JSON encoding failed — \(e)"
            case .emptyTitle:
                return "ProofFeip: a proof needs a title"
            case .emptyContent:
                return "ProofFeip: a proof needs content — an empty proof proves nothing"
            case .noProofIds:
                return "ProofFeip: no proofs given to destroy"
            case .tooLarge(let bytes):
                return "ProofFeip: the carve is \(bytes) bytes, over the \(maxOpReturnSize)-byte OP_RETURN limit. A proof's text is not compressed or encrypted — shorten it, or put the long form in a file and carve its hash."
            }
        }
    }

    // MARK: - op payloads

    /// `{"op":"issue",…}` — mint a proof.
    ///
    /// Empty cosigner lists are omitted rather than sent as `[]`: an
    /// absent key and an empty array read the same to the indexer, and
    /// every omitted byte is OP_RETURN budget the content can use.
    public static func issueOp(
        title: String?,
        content: String?,
        cosigners: [String]?,
        transferable: Bool?,
        allSignsRequired: Bool?
    ) throws -> String {
        var dict: [String: Any] = ["op": Op.issue.rawValue]
        if let title, !title.isEmpty { dict["title"] = title }
        if let content, !content.isEmpty { dict["content"] = content }
        if let cosigners, !cosigners.isEmpty { dict["cosigners"] = cosigners }
        if let transferable { dict["transferable"] = transferable }
        if let allSignsRequired { dict["allSignsRequired"] = allSignsRequired }
        return try jsonString(dict)
    }

    /// `{"op":"sign","proofId":…}` — countersign one proof you were
    /// invited to.
    public static func signOp(proofId: String) throws -> String {
        try jsonString(["op": Op.sign.rawValue, "proofId": proofId])
    }

    /// `{"op":"transfer","proofId":…}` — hand ownership to whoever the
    /// carve pays. The recipient is *not* in this payload: the protocol
    /// reads it off the transaction's output, which is why a transfer
    /// must go through the paying carve path.
    public static func transferOp(proofId: String) throws -> String {
        try jsonString(["op": Op.transfer.rawValue, "proofId": proofId])
    }

    /// `{"op":"destroy","proofIds":[…]}` — retire proofs you own. Takes
    /// a list because the protocol does, and for a paid operation that
    /// is the difference between one miner fee and several.
    public static func destroyOp(proofIds: [String]) throws -> String {
        guard !proofIds.isEmpty else { throw Failure.noProofIds }
        return try jsonString(["op": Op.destroy.rawValue, "proofIds": proofIds])
    }

    // MARK: - complete carves

    /// The full OP_RETURN payload for an `issue`, with the two content
    /// guards and the size check applied before a caller can spend
    /// anything on it.
    public static func issueCarve(
        title: String,
        content: String,
        cosigners: [String]? = nil,
        transferable: Bool? = nil,
        allSignsRequired: Bool? = nil
    ) throws -> String {
        guard !title.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw Failure.emptyTitle
        }
        guard !content.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw Failure.emptyContent
        }
        let json = envelope(opJson: try issueOp(
            title: title, content: content, cosigners: cosigners,
            transferable: transferable, allSignsRequired: allSignsRequired
        ))
        let bytes = Data(json.utf8).count
        guard bytes <= maxOpReturnSize else { throw Failure.tooLarge(bytes: bytes) }
        return json
    }

    /// How many more UTF-8 bytes of `content` an issue carve can take
    /// before it exceeds the OP_RETURN limit, given everything else
    /// already filled in. Negative once over.
    ///
    /// Exists so the compose form can show a live budget instead of
    /// letting the user write three paragraphs and discover at the
    /// Carve button that none of it fits. Measured on the encoded
    /// envelope rather than estimated, because JSON escaping makes a
    /// character count wrong by an unpredictable margin — a quotation
    /// mark costs two bytes, an emoji four before escaping.
    ///
    /// **Measured with the `content` key present even when the content
    /// is empty.** ``issueOp(title:content:cosigners:transferable:allSignsRequired:)``
    /// omits empty fields, so measuring an empty draft directly would
    /// count the `"content":""` overhead as free and promise a dozen
    /// bytes that the first keystroke immediately spends — a budget
    /// that shrinks faster than what you type is worse than none.
    public static func remainingContentBytes(
        title: String,
        content: String,
        cosigners: [String]? = nil,
        transferable: Bool? = nil,
        allSignsRequired: Bool? = nil
    ) -> Int {
        let probe = content.isEmpty ? "x" : content
        let json = (try? envelope(opJson: issueOp(
            title: title, content: probe, cosigners: cosigners,
            transferable: transferable, allSignsRequired: allSignsRequired
        ))) ?? ""
        let used = Data(json.utf8).count - (content.isEmpty ? 1 : 0)
        return maxOpReturnSize - used
    }

    // MARK: - envelope

    public static func envelope(opJson: String) -> String {
        #"{"type":"FEIP","sn":"\#(sn)","ver":"\#(ver)","name":"\#(protocolName)","data":\#(opJson)}"#
    }

    private static func jsonString(_ object: [String: Any]) throws -> String {
        do {
            let data = try JSONSerialization.data(
                withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes]
            )
            guard let s = String(data: data, encoding: .utf8) else {
                throw Failure.encoding(underlying: NSError(
                    domain: "ProofFeip", code: -1,
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
