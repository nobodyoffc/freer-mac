import Foundation

/// Builders for the FEIP `Mail` protocol (sn 7, ver 4) — the OP_RETURN
/// JSON that carves a mail onto the FCH chain. Mirrors the Java
/// `Feip.fromName(MAIL)` + `MailOpData` pair:
///
/// ```json
/// {"type":"FEIP","sn":"7","ver":"4","name":"Mail",
///  "data":{"op":"send","cipher":"<CryptoDataStr JSON>"}}
/// ```
///
/// The carve carries no `from` or `to`: the sender is whoever signed the
/// transaction and the recipient is whoever the transaction pays. That is
/// also why sending a mail costs a notice fee — the payment *is* the
/// addressing.
public enum MailFeip {

    public static let sn = "7"
    public static let ver = "4"
    public static let protocolName = "Mail"

    /// The largest body an OP_RETURN can carry, and the limit Android's
    /// compose screen enforces before it will let you send.
    public static let maxOpReturnSize = 4096

    public enum Failure: Error, CustomStringConvertible {
        case encoding(underlying: Error)
        case tooLarge(bytes: Int)

        public var description: String {
            switch self {
            case .encoding(let e):
                return "MailFeip: JSON encoding failed — \(e)"
            case .tooLarge(let bytes):
                return "MailFeip: the carve is \(bytes) bytes, over the \(maxOpReturnSize)-byte OP_RETURN limit"
            }
        }
    }

    // MARK: - op payloads

    /// `{"op":"send","cipher":…}` — `MailOpData.makeSend`, which sets only
    /// the `cipher`. The `alg`, `cipherSend`, `cipherReci` and `textId`
    /// fields the protocol allows are left absent, as Android leaves them.
    public static func sendOp(cipher: String) throws -> String {
        try jsonString(["op": "send", "cipher": cipher])
    }

    /// `{"op":"delete","mailIds":[…]}` — deactivate carves by id.
    public static func deleteOp(mailIds: [String]) throws -> String {
        try jsonString(["op": "delete", "mailIds": mailIds])
    }

    /// `{"op":"recover","mailIds":[…]}` — reactivate deleted carves.
    public static func recoverOp(mailIds: [String]) throws -> String {
        try jsonString(["op": "recover", "mailIds": mailIds])
    }

    // MARK: - envelope

    public static func envelope(opJson: String) -> String {
        #"{"type":"FEIP","sn":"\#(sn)","ver":"\#(ver)","name":"\#(protocolName)","data":\#(opJson)}"#
    }

    /// The complete OP_RETURN payload for a send, with the size check the
    /// compose screen needs. Checking the *carve* rather than the body is
    /// the point: the envelope and the base64 ciphertext are most of the
    /// bytes, so a body that looks comfortably under the limit can still
    /// produce a transaction the chain rejects.
    public static func sendCarve(cipher: String) throws -> String {
        let carve = envelope(opJson: try sendOp(cipher: cipher))
        let bytes = carve.utf8.count
        guard bytes <= maxOpReturnSize else { throw Failure.tooLarge(bytes: bytes) }
        return carve
    }

    private static func jsonString(_ object: [String: Any]) throws -> String {
        do {
            let data = try JSONSerialization.data(
                withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes]
            )
            guard let s = String(data: data, encoding: .utf8) else {
                throw Failure.encoding(underlying: NSError(
                    domain: "MailFeip", code: -1,
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
