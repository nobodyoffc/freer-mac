import Foundation

/// Builders for the FEIP `Secret` protocol (sn 17, ver 3) — the
/// OP_RETURN JSON that carves a secret onto the FCH chain. Mirrors the
/// Java `Feip.fromName(SECRET)` + `SecretOpData` pair:
///
/// ```json
/// {"type":"FEIP","sn":"17","ver":"3","name":"Secret",
///  "data":{"op":"add","cipher":"<CryptoDataStr JSON>"}}
/// ```
public enum SecretFeip {

    public static let sn = "17"
    public static let ver = "3"
    public static let protocolName = "Secret"

    public enum Failure: Error, CustomStringConvertible {
        case encoding(underlying: Error)

        public var description: String {
            switch self {
            case .encoding(let e):
                return "SecretFeip: JSON encoding failed — \(e)"
            }
        }
    }

    // MARK: - detail plaintext

    /// The plaintext that gets encrypted into the carve's `cipher`:
    /// what Android serializes via `secret.toJson()` in
    /// `makeAddSecretFeip` — the `{type,title,content,memo}` block,
    /// nil fields omitted (Gson behaviour).
    public static func detailJson(
        type: String?, title: String?, content: String, memo: String?
    ) throws -> String {
        var dict: [String: Any] = ["content": content]
        if let type, !type.isEmpty { dict["type"] = type }
        if let title, !title.isEmpty { dict["title"] = title }
        if let memo, !memo.isEmpty { dict["memo"] = memo }
        return try jsonString(dict)
    }

    // MARK: - op payloads

    /// `{"op":"add","cipher":…}` — `alg` stays absent, matching
    /// `SecretOpData.makeAdd(null, cipher)`.
    public static func addOp(cipher: String) throws -> String {
        try jsonString(["op": "add", "cipher": cipher])
    }

    /// `{"op":"update","secretId":…,"cipher":…}` — replace the detail
    /// of an existing carve.
    public static func updateOp(secretId: String, cipher: String) throws -> String {
        try jsonString(["op": "update", "secretId": secretId, "cipher": cipher])
    }

    /// `{"op":"delete","secretIds":[…]}` — deactivate carves by id.
    public static func deleteOp(secretIds: [String]) throws -> String {
        try jsonString(["op": "delete", "secretIds": secretIds])
    }

    /// `{"op":"recover","secretIds":[…]}` — reactivate deleted carves.
    public static func recoverOp(secretIds: [String]) throws -> String {
        try jsonString(["op": "recover", "secretIds": secretIds])
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
                    domain: "SecretFeip", code: -1,
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
