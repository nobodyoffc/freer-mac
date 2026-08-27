import Foundation

/// Builders for the FEIP `Master` protocol (sn 6, ver 1) — the
/// OP_RETURN JSON that names another FID as this one's master. Mirrors
/// the Java `Feip.fromProtocolName(MASTER)` + `MasterOpData` pair:
///
/// ```json
/// {"type":"FEIP","sn":"6","ver":"1","name":"Master",
///  "data":{"master":"F…","promise":"The master owns all my rights.",
///          "cipherPriKey":"<CryptoDataStr JSON>"}}
/// ```
///
/// **Read `cipherPriKey` before using any of this.** A Master carve is
/// not a label or a pointer — it publishes *this FID's private key*,
/// encrypted to the master's pubkey, in a permanent public record. The
/// promise sentence is the protocol saying so in words. Anyone holding
/// the master's private key can decrypt it and has, from then on, the
/// same power over this FID that its owner has: spend its coins, sign
/// as it, read everything ever encrypted to it.
///
/// Nothing undoes that. A later carve can name a *different* master,
/// but the bytes of the first one stay on chain forever, so the first
/// master keeps the key it was given. Treat setting a master as
/// handing over the identity, because that is what it is.
///
/// **There is no `op` field.** Unlike Contact, Secret and the rest of
/// the FEIP family, `MasterOpData` carries no verb — the presence of
/// the record *is* the operation. That asymmetry is in the Java data
/// class, and matching it is why this builder has one op-payload
/// method rather than the usual add/update/delete set.
public enum MasterFeip {

    public static let sn = "6"
    public static let ver = "1"
    public static let protocolName = "Master"

    /// The exact sentence the protocol requires. Protocol text, not
    /// display text — it is hashed into the chain record verbatim, so
    /// it is never localised, reworded or punctuated differently.
    public static let promise = "The master owns all my rights."

    public enum Failure: Error, CustomStringConvertible {
        case encoding(underlying: Error)

        public var description: String {
            switch self {
            case .encoding(let e):
                return "MasterFeip: JSON encoding failed — \(e)"
            }
        }
    }

    // MARK: - op payload

    /// `{"master":…,"promise":…,"cipherPriKey":…}` — matching
    /// `MasterOpData.makeMaster(master, cipherPriKey, alg)`, with `alg`
    /// omitted when nil exactly as the Java setter leaves it unset.
    ///
    /// `cipherPriKey` is the carving FID's own private key sealed to
    /// the master's pubkey — see the type's note.
    public static func setOp(
        master: String, cipherPriKey: String, alg: String? = nil
    ) throws -> String {
        var dict: [String: Any] = [
            "master": master,
            "promise": promise,
            "cipherPriKey": cipherPriKey,
        ]
        if let alg, !alg.isEmpty { dict["alg"] = alg }
        return try jsonString(dict)
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
                    domain: "MasterFeip", code: -1,
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
