import Foundation

/// Builders for the FEIP `CONTACT` protocol (sn 12, ver 3) — the
/// OP_RETURN JSON that carves a contact onto the FCH chain. Mirrors
/// the Java `Feip` + `ContactOpData` pair:
///
/// ```json
/// {"type":"FEIP","sn":"12","ver":"3","name":"Contact",
///  "data":{"op":"add","cipher":"<CryptoDataStr JSON>"}}
/// ```
///
/// Key order differs from Gson's field-declaration order (we emit
/// sorted keys); every parser in the ecosystem is field-name based,
/// so this is cosmetic.
public enum ContactFeip {

    public static let sn = "12"
    public static let ver = "3"
    public static let protocolName = "Contact"

    /// Below this block height the chain doesn't enforce the
    /// 1-CoinDay carve requirement. Mirrors `Feip.CDD_CHECK_HEIGHT`.
    public static let cddCheckHeight: Int64 = 4_000_000
    /// CoinDays the carve inputs must jointly destroy once the chain
    /// passes ``cddCheckHeight``. Mirrors `Feip.CD_REQUIRED`.
    public static let cdRequired: Int64 = 1

    public enum Failure: Error, CustomStringConvertible {
        case encoding(underlying: Error)

        public var description: String {
            switch self {
            case .encoding(let e):
                return "ContactFeip: JSON encoding failed — \(e)"
            }
        }
    }

    // MARK: - detail plaintext

    /// The plaintext that gets encrypted into the carve's `cipher`:
    /// the contact's editable detail block, exactly the fields
    /// Android's `sendContactOnChain` copies into `contactForChain`
    /// before `contact.toJson()` (nil fields omitted, like Gson).
    public static func detailJson(for contact: Contact) throws -> String {
        var dict: [String: Any] = ["fid": contact.id]
        if let v = contact.titles { dict["titles"] = v }
        if let v = contact.memo { dict["memo"] = v }
        if let v = contact.seeStatement { dict["seeStatement"] = v }
        if let v = contact.seeWritings { dict["seeWritings"] = v }
        return try jsonString(dict)
    }

    // MARK: - op payloads

    /// `{"op":"add","cipher":…}` — carve a new contact.
    /// `alg` stays absent, matching `ContactOpData.makeAdd(null, cipher)`.
    public static func addOp(cipher: String) throws -> String {
        try jsonString(["op": "add", "cipher": cipher])
    }

    /// `{"op":"update","contactId":…,"cipher":…}` — replace the detail
    /// of an existing carve. `contactId` is the carve record id
    /// (sha256x2 of the original op), not the contact's FID.
    public static func updateOp(contactId: String, cipher: String) throws -> String {
        try jsonString(["op": "update", "contactId": contactId, "cipher": cipher])
    }

    /// `{"op":"delete","contactIds":[…]}` — deactivate carves by id.
    public static func deleteOp(contactIds: [String]) throws -> String {
        try jsonString(["op": "delete", "contactIds": contactIds])
    }

    /// `{"op":"recover","contactIds":[…]}` — reactivate deleted carves.
    public static func recoverOp(contactIds: [String]) throws -> String {
        try jsonString(["op": "recover", "contactIds": contactIds])
    }

    // MARK: - envelope

    /// Wrap an op payload in the FEIP envelope. `opJson` must be a
    /// complete JSON object (output of one of the op builders above).
    public static func envelope(opJson: String) -> String {
        #"{"type":"FEIP","sn":"\#(sn)","ver":"\#(ver)","name":"\#(protocolName)","data":\#(opJson)}"#
    }

    private static func jsonString(_ object: [String: Any]) throws -> String {
        do {
            let data = try JSONSerialization.data(
                withJSONObject: object, options: [.sortedKeys]
            )
            guard let s = String(data: data, encoding: .utf8) else {
                throw Failure.encoding(underlying: NSError(
                    domain: "ContactFeip", code: -1,
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
