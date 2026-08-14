import Foundation
import FCCore

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

    /// The largest OP_RETURN the chain accepts. Android's compose
    /// screen checks the *body* against this number, which is far too
    /// generous — see ``maxBodyBytes``.
    public static let maxOpReturnSize = 4096

    /// The largest UTF-8 body that still fits in a carve, once the FEIP
    /// wrapper, the AsyTwoWay envelope, the GCM tag, base64 expansion
    /// and JSON escaping have taken their share.
    ///
    /// It is far below ``maxOpReturnSize``: base64 alone costs a third,
    /// so roughly 2 700 bytes of text is the real ceiling. Android
    /// checks `content.length() > MaxOpReturnSize` and lets you write
    /// 4 000 characters, which then fails at broadcast — after the mail
    /// has been encrypted, the fee decided and the transaction signed
    /// (Android issue C10). This is the number a compose screen should
    /// count down from.
    ///
    /// Measured rather than derived: the constant is found by binary
    /// search over a synthetic envelope of exactly the shape
    /// ``AsyTwoWayCipher/encrypt(plaintext:privkeyA:toPubkey:)``
    /// produces, so it cannot drift away from the real encoder the way
    /// a hand-computed formula would. A note to self is sealed
    /// AsyOneWay, whose envelope is ~70 bytes shorter, so this figure
    /// is the conservative one for both.
    public static let maxBodyBytes: Int = {
        var best = 0
        var lo = 0
        var hi = maxOpReturnSize
        while lo <= hi {
            let mid = (lo + hi) / 2
            if (try? sendCarve(cipher: syntheticEnvelope(bodyBytes: mid))) != nil {
                best = mid
                lo = mid + 1
            } else {
                hi = mid - 1
            }
        }
        return best
    }()

    /// A stand-in for a real sealed envelope with the same *length* as
    /// one wrapping `bodyBytes` of plaintext: 12-byte iv, 16-byte GCM
    /// tag, two 33-byte pubkeys, all hex/base64 as the real encoder
    /// emits them. Only its size is meaningful.
    static func syntheticEnvelope(bodyBytes: Int) -> String {
        let cipherB64 = Data(count: bodyBytes + AesGcm256.tagLength).base64EncodedString()
        let pubkeyHex = String(repeating: "a", count: 66)
        let ivHex = String(repeating: "a", count: 24)
        return #"{"type":"AsyTwoWay","alg":"\#(AsyOneWayCipher.algGcm)","cipher":"\#(cipherB64)","pubkeyA":"\#(pubkeyHex)","pubkeyB":"\#(pubkeyHex)","iv":"\#(ivHex)"}"#
    }

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
